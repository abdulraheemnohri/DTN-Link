# DTN-Link benchmarks and interop testing (Phase 12)

The dtn-bench crate (crates/dtn-bench) measures the real stack — no
mocked transports and no synthetic numbers. Every report is produced
by moving actual BPv7 bundles through the real CBOR codec, the real
SQLite store, real in-memory byte links, real loopback TCP sockets and
a real RFC 9174 TCPCLv4 session.

## What is measured

| benchmark | what happens |
|---|---|
| BPv7 encode+decode | real Bundle encode and decode roundtrips, every one verified |
| SQLite store | real Node send (store put) passes plus full-table query passes |
| duplex contact | full contact exchange over an in-memory link with length-prefix or KISS framing |
| TCPCL-lite over TCP | full contact over real loopback TCP, daemon wire format |
| TCPCLv4 session | full RFC 9174 session: handshake, acknowledged transfers, SESS_TERM |
| TCP contact latency | one complete contact per sample; median and p95 reported |

Run it:

    cargo run -p dtn-bench --release

Numbers are machine-dependent; only compare runs from the same machine.

## Interop guarantees (tests)

The integration tests in crates/dtn-bench/tests/interop.rs prove:

- codec benchmark bundles roundtrip byte-for-byte,
- the store benchmark really persists and queries bundles,
- length-prefix and KISS framed duplex contacts deliver every bundle,
- real loopback TCP contacts deliver every bundle,
- TCPCLv4 sessions deliver every bundle with per-transfer acks,
- TCPCLv4 exchange works both ways over TCP,
- a bundle that is Ed25519-signed (BIB) and AES-256-GCM encrypted (BCB)
  survives a KISS-framed contact end to end: the plaintext never
  appears on the wire, the receiver decrypts with the shared key and
  the signature verifies under the sender's public key,
- latency percentile helpers are exact on a known vector.

Run the suite:

    cargo test -p dtn-bench

## Honest scope

- Results depend on the host (CPU, disk, loopback TCP); the suite
  reports measured numbers, it does not assert performance targets.
- No criterion-style statistical analysis (warmup, confidence
  intervals) yet; the harness is std-only on purpose.
- Hardware serial/LoRa and Bluetooth RFCOMM links are exercised by the
  same contact functions once a port is opened (serial is behind the
  cargo feature "serial"); CI runs the in-memory and TCP paths.
