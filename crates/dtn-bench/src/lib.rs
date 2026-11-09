//! dtn-bench — Phase 12: interop + performance testing for DTN-Link.
//!
//! Everything here measures the REAL stack: real CBOR encode/decode,
//! real SQLite storage, real in-memory byte links, real loopback TCP
//! sockets and real RFC 9174 TCPCLv4 sessions. No fake transports and
//! no synthetic numbers — every report is produced by moving actual
//! bundles through the same code paths the daemon uses.
//!
//! Layout:
//! * report   — BenchReport / LatencySamples with percentile helpers.
//! * codec    — BPv7 CBOR encode+decode throughput.
//! * store    — SQLite put + query throughput through the node engine.
//! * contact  — full contact benchmarks: duplex memory links with
//!              length-prefix or KISS framing, real loopback TCP
//!              (TCPCL-lite wire format), TCPCLv4 sessions, and
//!              per-contact TCP latency sampling.
//!
//! The binary (src/main.rs) runs the whole suite and prints a markdown
//! table; tests/interop.rs proves cross-layer interop (BPSec-signed,
//! BCB-encrypted bundles riding a KISS-framed contact).

pub mod codec;
pub mod contact;
pub mod report;
pub mod store;
