# Changelog

## 0.4.0 (2026-11-05)

Phase 6 (security part 2) — bundle confidentiality.

- dtn-bpsec::bcb: Block Confidentiality Block (RFC 9172 type 12)
  with AES-256-GCM payload encryption; 12-byte nonce + ciphertext +
  GCM tag stored in the BCB; the payload block is replaced by the
  ciphertext so plaintext never appears on the wire.
- decrypt_bundle returns typed errors: NoConfidentialityBlock /
  MultipleConfidentialityBlocks / Malformed / DecryptionFailed.
- 9 BCB tests: roundtrip (incl. wire), wrong key, tampered ciphertext,
  tampered nonce, unencrypted bundle, multi-BCB, malformed, and a
  wire test asserting the plaintext is absent from encoded bytes.
- cli: new `encrypt <key-hex>` and `decrypt <key-hex>` commands.
- Honest scope: key distribution/rotation and RFC 9173 context
  identifiers are future work.

## 0.3.0 (2026-11-05)

Phase 5 — bundle security (BPSec-aligned integrity).

- dtn-bpsec: Block Integrity Block (type 11) carrying an Ed25519
  signature over the payload; sign_bundle / verify_bundle with
  Valid / NoIntegrityBlock / Invalid / MultipleIntegrityBlocks
  outcomes; tests for tampered payload, tampered signature, wrong
  key, unsigned bundles and malformed multi-BIB bundles.
- cli: new `verify <pubkey-hex>` command that checks a bundle from
  stdin against a public key.
- Honest scope: RFC 9173 contexts (HMAC) and BCB confidentiality
  are the next milestone; this block uses an Ed25519 context.

## 0.2.0 (2026-11-04)

Phases 2-4 — multi-hop forwarding, hybrid routing, TCP transport.

- dtn-routing: epidemic, spray-and-wait (bounded copy budget) and
  opportunistic (encounter history) strategies, explainable decisions,
  unit tests for each strategy.
- dtn-core: `select_outbound(peer)` store-carry-forward selection;
  multi-hop A→B→C test, partition/resume test, restart persistence test.
- dtn-tcpcl: real TCP transport, length-prefixed frames, 16 MiB frame
  limit, loopback transfer tests, oversized-frame rejection test.
- dtn-daemon: TCP node daemon with peer sync loop and expiry cleanup;
  two-node TCP delivery test and A→B→C multi-hop-over-TCP test.
- cli: new `forward` (routing dry-run) and `daemon` commands.
- docs: architecture updated with multi-hop flow and contact protocol.

## 0.1.0 (2026-11-04)

Phase 1 — Rust core foundation (BPv7 CBOR, identity, SQLite store, node
engine, CLI, CI).
