# Changelog

## 0.1.0 (2026-11-04)

Phase 1 — Rust core foundation.

- dtn-bpv7: canonical CBOR encoder/decoder, BPv7 primary block, payload
  block, EIDs (dtn/ipn), bundle ID, lifetime/expiry rules, unit tests.
- dtn-identity: Ed25519 key pairs, sign/verify, deterministic seed.
- dtn-storage: SQLite bundle store with duplicate suppression, delivery
  receipts, expiry cleanup, indexed metadata.
- dtn-core: Node engine (send/receive/inbox), two-node tests, restart
  persistence test.
- cli: dtn-link init/status/send/receive/bundles/decode/version.
- CI: format, clippy, tests on every push; daily maintenance workflow at
  02:00 PKT with cargo audit.
