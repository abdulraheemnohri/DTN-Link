//! Phase 12 cross-layer interop tests: every transport combination
//! must carry real bundles end to end, including BPSec-signed and
//! BCB-encrypted bundles over KISS-framed links.

use dtn_bench::codec::bench_codec;
use dtn_bench::contact::{
    bench_duplex_contact, bench_tcp_contact, bench_tcpclv4_contact, v4_exchange, Framing,
};
use dtn_bench::report::LatencySamples;
use dtn_bench::store::bench_store;
use dtn_bpsec::bcb::{decrypt_bundle, encrypt_bundle, Key, NonceBytes};
use dtn_bpsec::{sign_bundle, verify_bundle, VerifyOutcome};
use dtn_bpv7::Bundle;
use dtn_core::{Node, Strategy};
use dtn_transport::{duplex, exchange_framed, KissCodec};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn mem_node(number: u64) -> Arc<Mutex<Node>> {
    Arc::new(Mutex::new(
        Node::open(number, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap(),
    ))
}

#[test]
fn codec_bench_roundtrips_and_reports_sane() {
    let r = bench_codec(1024, 100);
    assert_eq!(r.iterations, 100);
    assert!(r.total_bytes > 0, "wire bytes must be counted");
    assert!(r.ops_per_sec() > 0.0, "a live benchmark must report throughput");
}

#[test]
fn percentiles_are_exact_on_known_vector() {
    let mut s = LatencySamples::default();
    for ms in [10u64, 20, 30, 40, 50] {
        s.push(Duration::from_millis(ms));
    }
    assert_eq!(s.median().unwrap(), Duration::from_millis(30));
    assert_eq!(s.percentile(100.0).unwrap(), Duration::from_millis(50));
    assert_eq!(s.percentile(1.0).unwrap(), Duration::from_millis(10));
    assert_eq!(s.p95().unwrap(), Duration::from_millis(50));
    assert!(LatencySamples::default().median().is_none());
}

#[test]
fn store_bench_persists_and_queries() {
    let tmp = std::env::temp_dir();
    let r = bench_store(&tmp, 50, 128).unwrap();
    assert_eq!(r.iterations, 100, "50 puts + 50 query passes");
    assert!(r.total_bytes > 0);
}

#[test]
fn duplex_length_prefix_contact_delivers_all_bundles() {
    let r = bench_duplex_contact(Framing::LengthPrefix, 25, 256);
    assert_eq!(r.iterations, 25);
    assert!(r.ops_per_sec() > 0.0);
}

#[test]
fn kiss_duplex_contact_delivers_all_bundles() {
    let r = bench_duplex_contact(Framing::Kiss, 25, 256);
    assert_eq!(r.iterations, 25);
}

#[test]
fn tcp_contact_delivers_all_bundles() {
    let r = bench_tcp_contact(25, 256).unwrap();
    assert_eq!(r.iterations, 25);
}

#[test]
fn tcpclv4_session_delivers_all_bundles() {
    let r = bench_tcpclv4_contact(25, 256);
    assert_eq!(r.iterations, 25);
}

#[test]
fn tcpclv4_exchange_two_way_over_tcp() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let node_b = mem_node(2);
    let node_a = mem_node(1);

    // Both nodes hold a bundle for the other.
    let a_eid = node_a.lock().unwrap().eid();
    let b_eid = node_b.lock().unwrap().eid();
    node_a
        .lock()
        .unwrap()
        .send(b_eid.clone(), b"v4 request".to_vec(), 3600)
        .unwrap();
    node_b
        .lock()
        .unwrap()
        .send(a_eid.clone(), b"v4 reply".to_vec(), 3600)
        .unwrap();

    let nb = node_b.clone();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        v4_exchange(&nb, stream, false).unwrap();
    });

    let stream = std::net::TcpStream::connect(addr).unwrap();
    v4_exchange(&node_a, stream, true).unwrap();
    server.join().unwrap();

    assert_eq!(node_a.lock().unwrap().inbox().unwrap().len(), 1, "B's reply must reach A");
    assert_eq!(node_b.lock().unwrap().inbox().unwrap().len(), 1, "A's request must reach B");
}

#[test]
fn signed_and_encrypted_bundle_survives_kiss_contact() {
    // Cross-layer interop: BIB signature + BCB encryption + KISS
    // framing over an in-memory link, delivered through the full
    // node engine, then decrypt-then-verify at the receiver.
    const KEY: Key = [7u8; 32];
    const NONCE: NonceBytes = [9u8; 12];

    let node_a = mem_node(1);
    let node_b = mem_node(2);
    let plaintext = b"phase 12 cross-layer interop".to_vec();
    let b_eid = node_b.lock().unwrap().eid();

    // Build, sign with A's identity, then encrypt (the payload block is
    // replaced by AES-256-GCM ciphertext).
    let (secured, key_a, wire) = {
        let a = node_a.lock().unwrap();
        let plain = Bundle::new(
            a.eid(),
            b_eid.clone(),
            plaintext.clone(),
            3600,
            1,
            dtn_storage::now(),
        );
        let signed = sign_bundle(&plain, &a.identity);
        let secured = encrypt_bundle(&signed, &KEY, &NONCE);
        (secured.clone(), a.identity.public_key(), secured.encode())
    };

    // The plaintext must never appear on the wire.
    assert!(
        !wire.windows(plaintext.len()).any(|w| w == plaintext.as_slice()),
        "encrypted bundle must not leak plaintext bytes"
    );

    // Store the secured bundle in A, as the node engine would.
    assert!(node_a.lock().unwrap().store.put(&secured).unwrap());

    // One full contact over KISS framing.
    let (mut a_side, mut b_side) = duplex::pair();
    let na = node_a.clone();
    let nb = node_b.clone();
    let t1 = std::thread::spawn(move || {
        let mut codec = KissCodec::new();
        exchange_framed(&na, &mut a_side, &mut codec)
    });
    let t2 = std::thread::spawn(move || {
        let mut codec = KissCodec::new();
        exchange_framed(&nb, &mut b_side, &mut codec)
    });
    t1.join().unwrap().unwrap();
    t2.join().unwrap().unwrap();

    let inbox = node_b.lock().unwrap().inbox().unwrap();
    assert_eq!(inbox.len(), 1, "the secured bundle must arrive");
    let received = &inbox[0];

    // Still encrypted in flight; the receiver decrypts with the
    // shared key, then verifies the signature over the plaintext.
    let decrypted = decrypt_bundle(received, &KEY).expect("receiver key must decrypt");
    assert_eq!(decrypted.payload().unwrap(), plaintext.as_slice());
    assert_eq!(verify_bundle(&decrypted, &key_a), VerifyOutcome::Valid);
}
