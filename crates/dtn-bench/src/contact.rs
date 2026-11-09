//! Full-contact benchmarks over real links: in-memory duplex pairs
//! (length-prefix and KISS framing), real loopback TCP with the
//! TCPCL-lite wire format, real RFC 9174 TCPCLv4 sessions, and
//! per-contact TCP latency sampling.

use crate::codec::deterministic_payload;
use crate::report::{BenchReport, LatencySamples};
use dtn_bpv7::Eid;
use dtn_core::{Node, Strategy};
use dtn_tcpcl::v4::{Event, Session, SessionError, TERM_OTHER};
use dtn_transport::{duplex, exchange_framed, FrameCodec, KissCodec, LengthPrefixCodec};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Framing used for a duplex-link contact benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// u32 length-prefixed frames (TCPCL-lite wire format).
    LengthPrefix,
    /// KISS framing (LoRa TNC / serial radio modems).
    Kiss,
}

fn make_codec(framing: Framing) -> Box<dyn FrameCodec> {
    match framing {
        Framing::LengthPrefix => Box::new(LengthPrefixCodec::new()),
        Framing::Kiss => Box::new(KissCodec::new()),
    }
}

fn mem_node(number: u64) -> Arc<Mutex<Node>> {
    Arc::new(Mutex::new(
        Node::open(number, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap(),
    ))
}

/// Preloads `bundles` bundles addressed to node b into node a's store.
fn load(a: &Arc<Mutex<Node>>, b_eid: Eid, bundles: u64, payload_size: usize) {
    let mut n = a.lock().unwrap();
    for _ in 0..bundles {
        n.send(b_eid.clone(), deterministic_payload(payload_size), 3600)
            .unwrap();
    }
}

/// Total encoded size of everything in a node's store (the wire bytes
/// the next contact would push).
fn stored_wire_bytes(n: &Node) -> u64 {
    n.store.all().unwrap().iter().map(|r| r.data.len() as u64).sum()
}

/// One full TCPCL-lite contact over an in-memory duplex link with the
/// chosen framing. Asserts every preloaded bundle is delivered.
pub fn bench_duplex_contact(framing: Framing, bundles: u64, payload_size: usize) -> BenchReport {
    let (mut a_side, mut b_side) = duplex::pair();
    let node_a = mem_node(1);
    let node_b = mem_node(2);
    let b_eid = node_b.lock().unwrap().eid();
    load(&node_a, b_eid, bundles, payload_size);
    let total_bytes = stored_wire_bytes(&node_a.lock().unwrap());

    let start = Instant::now();
    let na = node_a.clone();
    let nb = node_b.clone();
    let fa = framing;
    let fb = framing;
    let t1 = std::thread::spawn(move || {
        let mut codec = make_codec(fa);
        exchange_framed(&na, &mut a_side, codec.as_mut())
    });
    let t2 = std::thread::spawn(move || {
        let mut codec = make_codec(fb);
        exchange_framed(&nb, &mut b_side, codec.as_mut())
    });
    t1.join().unwrap().unwrap();
    t2.join().unwrap().unwrap();
    let elapsed = start.elapsed();

    let delivered = node_b.lock().unwrap().inbox().unwrap().len() as u64;
    assert_eq!(
        delivered, bundles,
        "every preloaded bundle must be delivered by the contact"
    );
    BenchReport::new(
        format!(
            "duplex contact ({:?} framing, {} bundles x {} B)",
            framing, bundles, payload_size
        ),
        delivered,
        total_bytes,
        elapsed,
    )
}

/// One full TCPCL-lite contact over real loopback TCP (the same wire
/// format the daemon speaks). Asserts full delivery.
pub fn bench_tcp_contact(bundles: u64, payload_size: usize) -> std::io::Result<BenchReport> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr().unwrap();
    let node_b = mem_node(2);
    let nb = node_b.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        dtn_transport::exchange(&nb, &mut stream).unwrap();
    });

    let node_a = mem_node(1);
    let b_eid = node_b.lock().unwrap().eid();
    load(&node_a, b_eid, bundles, payload_size);
    let total_bytes = stored_wire_bytes(&node_a.lock().unwrap());

    let mut stream = TcpStream::connect(addr)?;
    let start = Instant::now();
    dtn_transport::exchange(&node_a, &mut stream).unwrap();
    let elapsed = start.elapsed();
    server.join().unwrap();

    let delivered = node_b.lock().unwrap().inbox().unwrap().len() as u64;
    assert_eq!(delivered, bundles, "every bundle must cross the TCP contact");
    Ok(BenchReport::new(
        format!(
            "TCPCL-lite over loopback TCP ({} bundles x {} B)",
            bundles, payload_size
        ),
        delivered,
        total_bytes,
        elapsed,
    ))
}

/// One full RFC 9174 TCPCLv4 session between two nodes: contact
/// handshake, acknowledged single-segment transfers both ways, clean
/// SESS_TERM shutdown. Mirrors the daemon's exchange_v4.
pub fn v4_exchange(
    node: &Arc<Mutex<Node>>,
    stream: TcpStream,
    active: bool,
) -> Result<String, SessionError> {
    let local_uri = node.lock().unwrap().eid().as_uri();
    let mut sess = Session::new(stream, &local_uri, 30);
    sess.handshake(active)?;
    let peer_eid = {
        let raw = String::from_utf8_lossy(&sess.peer_eid).into_owned();
        Eid::dtn(raw.trim().trim_start_matches("dtn://").trim_end_matches('/'))
    };

    let outbound = {
        let mut n = node.lock().unwrap();
        n.select_outbound(&peer_eid).unwrap_or_default()
    };
    for ob in &outbound {
        let tid = sess.send_bundle(&ob.bundle.encode())?;
        loop {
            match sess.pump()? {
                Some(Event::Bundle(bytes)) => {
                    let _ = node.lock().unwrap().receive(&bytes);
                }
                Some(Event::Acked { transfer_id, .. }) if transfer_id == tid => break,
                Some(Event::Terminated { .. }) => break,
                _ => {}
            }
        }
    }
    sess.send_sess_term(0, TERM_OTHER)?;

    loop {
        match sess.pump() {
            Ok(Some(Event::Bundle(bytes))) => {
                let _ = node.lock().unwrap().receive(&bytes);
            }
            Ok(Some(Event::Terminated { .. })) => break,
            Ok(_) => {}
            Err(SessionError::Closed) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(local_uri)
}

/// One TCPCLv4 session over real loopback TCP carrying `bundles`
/// acknowledged transfers. Asserts full delivery.
pub fn bench_tcpclv4_contact(bundles: u64, payload_size: usize) -> BenchReport {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let node_b = mem_node(2);
    let nb = node_b.clone();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        v4_exchange(&nb, stream, false).unwrap();
    });

    let node_a = mem_node(1);
    let b_eid = node_b.lock().unwrap().eid();
    load(&node_a, b_eid, bundles, payload_size);
    let total_bytes = stored_wire_bytes(&node_a.lock().unwrap());

    let stream = TcpStream::connect(addr).unwrap();
    let start = Instant::now();
    v4_exchange(&node_a, stream, true).unwrap();
    let elapsed = start.elapsed();
    server.join().unwrap();

    let delivered = node_b.lock().unwrap().inbox().unwrap().len() as u64;
    assert_eq!(delivered, bundles, "every bundle must cross the TCPCLv4 session");
    BenchReport::new(
        format!(
            "TCPCLv4 session over loopback TCP ({} bundles x {} B)",
            bundles, payload_size
        ),
        delivered,
        total_bytes,
        elapsed,
    )
}

/// Samples per-contact latency: each sample is one complete TCPCL-lite
/// contact (connect, full exchange, close) over loopback TCP carrying
/// one bundle. Returns the latency samples.
pub fn bench_tcp_contact_latency(samples: u64, payload_size: usize) -> LatencySamples {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..samples {
            let Ok((mut stream, _)) = listener.accept() else { break };
            let node = mem_node(20);
            let _ = dtn_transport::exchange(&node, &mut stream);
        }
    });

    let mut latencies = LatencySamples::default();
    let dest = Eid::ipn(20, 0);
    for _ in 0..samples {
        let node_a = mem_node(21);
        node_a
            .lock()
            .unwrap()
            .send(dest.clone(), deterministic_payload(payload_size), 3600)
            .unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        let start = Instant::now();
        dtn_transport::exchange(&node_a, &mut stream).unwrap();
        latencies.push(start.elapsed());
    }
    server.join().unwrap();
    latencies
}
