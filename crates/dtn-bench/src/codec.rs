//! BPv7 CBOR codec throughput: real Bundle encode + decode with
//! per-roundtrip verification.

use crate::report::BenchReport;
use dtn_bpv7::{Bundle, Eid};
use std::time::Instant;

/// Deterministic pseudo-random payload (xorshift) so benchmark inputs
/// are reproducible without a random-number dependency.
pub fn deterministic_payload(size: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def0u64;
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 56) as u8
        })
        .collect()
}

/// A sample bundle sized for benchmarking, with a fresh sequence number
/// so dedup never collapses two samples into one.
pub fn sample_bundle(payload_size: usize, seq: u64) -> Bundle {
    Bundle::new(
        Eid::dtn("bench-source"),
        Eid::dtn("bench-dest"),
        deterministic_payload(payload_size),
        3600,
        seq,
        dtn_storage::now(),
    )
}

/// Encode + decode `iterations` bundles of `payload_size` payload
/// bytes, verifying every roundtrip. Returns the measured report.
pub fn bench_codec(payload_size: usize, iterations: u64) -> BenchReport {
    let mut total_bytes = 0u64;
    let start = Instant::now();
    for seq in 1..=iterations {
        let bundle = sample_bundle(payload_size, seq);
        let wire = bundle.encode();
        total_bytes += wire.len() as u64;
        let back = Bundle::decode(&wire).expect("encoded bundle must decode");
        assert_eq!(
            back.payload().unwrap(),
            bundle.payload().unwrap(),
            "codec roundtrip must preserve the payload"
        );
    }
    BenchReport::new(
        format!("BPv7 encode+decode ({} B payload)", payload_size),
        iterations,
        total_bytes,
        start.elapsed(),
    )
}
