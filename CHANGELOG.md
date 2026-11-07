# Changelog

## 0.7.0 (2026-11-07)

Phase 8 — security integrated into the data path.

- dtn-core: `Node::open_persistent` persists the identity seed in a
  sidecar file (0600 on Unix) so a node keeps the same Ed25519 key
  pair across restarts; restart-identity test added.
- dtn-daemon: optional `SecurityCtx` (keyring + identity). When
  enabled: TCPCL-lite hello now carries the node's Ed25519 public key
  (second frame) and peers TOFU-learn it into their keyring; outbound
  bundles are signed (BIB); incoming signed bundles are verified
  against the trusted key for the source EID and Invalid/Multiple-BIB
  bundles are DROPPED; unsigned and unknown-source signed bundles are
  accepted with a log line.
- New tests: secured contact learns both keys over TCP and delivers a
  BIB-valid bundle; tampered signed bundle rejected by
  secured_receive; unsigned still accepted.
- cli: `init` now uses the persistent identity and prints the node's
  public key; `daemon` wires the keyring automatically
  (`--insecure` disables).
- Honest scope: hello-key mismatch currently warns without enforcing
  (MITM hardening), key rotation and TLS remain future work; TCPCLv4
  sessions sign/verify but do not carry hello keys.

## 0.7.0 (2026-11-06)

Phase 8/10 groundwork — modular transport adapters (KISS/LoRa, serial,
stream abstraction for Bluetooth / Wi-Fi Direct).

- dtn-transport (new crate): FrameCodec framing abstraction over any
  Read+Write byte link; LengthPrefixCodec (wire-compatible with the
  dtn-daemon TCPCL-lite contact protocol) and KissCodec (KISS framing
  as used by LoRa TNCs and serial radio modems).
- exchange_framed: full contact exchange (EID greeting, routing-driven
  outbound push, inbound receive loop) over any byte stream — TCP,
  serial, Bluetooth RFCOMM, Wi-Fi Direct group-owner sockets.
- KISS framing with FEND/FESC escaping, non-data command-frame
  skipping, line-noise resync; tests for roundtrips, escape bytes,
  multi-frame streams and malformed-escape rejection.
- Interop test proving exchange_framed + LengthPrefixCodec completes a
  real two-node contact against dtn-daemon::exchange over TCP.
- In-memory duplex stream pair (mpsc-backed) for adapter testing, with
  bidirectional transfer tests.
- Feature-gated serial glue (serialport crate): open real LoRa TNC /
  radio-modem ports and run a KISS contact exchange over them.
- Honest scope: Bluetooth RFCOMM / Wi-Fi Direct platform glue (OS
  socket creation, pairing UI) is the next milestone — the transport
  layer consumes any such stream once opened.


## 0.6.0 (2026-11-06)

Phase 6 (security part 3) — key distribution / trust store.

- dtn-keyring: SQLite-backed trust store mapping EID URIs to trusted
  Ed25519 public keys (trust-on-first-use, operator managed). put /
  get / remove / list / count, with disk-persistence test.
- verify_signed_bundle: verifies a signed bundle against the key
  trusted for its source EID — Valid / Invalid / UnknownSource /
  NoIntegrityBlock / MultipleIntegrityBlocks.
- cli: new keyring add|list|remove commands; verify now works
  without an explicit pubkey by consulting the keyring.
- 10 keyring tests including tamper and persistence coverage.
- Honest scope: automatic key exchange during contacts, signed key
  rotation and web-of-trust are future work.


## 0.5.0 (2026-11-05)

Phase 7 — full RFC 9174 TCPCLv4 session protocol.

- dtn-tcpcl::sdnv: RFC 5050 self-delimiting numeric values with
  canonical encoding, truncation/overflow errors and tests including
  u64::MAX roundtrips.
- dtn-tcpcl::v4: wire-level TCPCLv4 — "dtn!" contact header with
  version 4, SESS_INIT/SESS_ACK handshake (contact flags, keepalive
  negotiation as the minimum of both offers, session EID exchange),
  SESS_REFUSE on version mismatch, KEEPALIVE, MSG_REJECT for unknown
  message types, XFER_INIT/XFER_SEGMENT/XFER_ACK/XFER_REFUSE
  acknowledged transfers (single START/END segment per RFC 9174
  section 3.6 minimum-overhead policy) and SESS_TERM termination with
  reason codes.
- dtn-tcpcl::v4::Session: streaming session driver over any
  Read+Write transport, emitting typed events (Bundle, Acked,
  Refused, Keepalive, Terminated, Rejected). Tests: full loopback
  session (handshake, two-way acked transfers, SESS_TERM), keepalive
  roundtrip, unknown-message-type rejection, bad-version refusal.
- dtn-daemon: exchange_v4() — TCPCLv4 contact with handshake,
  acked outbound transfers, inbound bundles through the node engine
  and clean shutdown; tests for one-way and two-way delivery.
- Honest scope: TLS (RFC 9174 section 4.4), extension items and
  multi-segment transfers remain future work.

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
- cli: new encrypt <key-hex> and decrypt <key-hex> commands.
- Honest scope: key distribution/rotation and RFC 9173 context
  identifiers are future work.

## 0.3.0 (2026-11-05)

Phase 5 — bundle security (BPSec-aligned integrity).

- dtn-bpsec: Block Integrity Block (type 11) carrying an Ed25519
  signature over the payload; sign_bundle / verify_bundle with
  Valid / NoIntegrityBlock / Invalid / MultipleIntegrityBlocks
  outcomes; tests for tampered payload, tampered signature, wrong
  key, unsigned bundles and malformed multi-BIB bundles.
- cli: new verify <pubkey-hex> command that checks a bundle from
  stdin against a public key.
- Honest scope: RFC 9173 contexts (HMAC) and BCB confidentiality
  are the next milestone; this block uses an Ed25519 context.

## 0.2.0 (2026-11-04)

Phases 2-4 — multi-hop forwarding, hybrid routing, TCP transport.

- dtn-routing: epidemic, spray-and-wait (bounded copy budget) and
  opportunistic (encounter history) strategies, explainable decisions,
  unit tests for each strategy.
- dtn-core: select_outbound(peer) store-carry-forward selection;
  multi-hop A→B→C test, partition/resume test, restart persistence test.
- dtn-tcpcl: real TCP transport, length-prefixed frames, 16 MiB frame
  limit, loopback transfer tests, oversized-frame rejection test.
- dtn-daemon: TCP node daemon with peer sync loop and expiry cleanup;
  two-node TCP delivery test and A→B→C multi-hop-over-TCP test.
- cli: new forward (routing dry-run) and daemon commands.
- docs: architecture updated with multi-hop flow and contact protocol.

## 0.1.0 (2026-11-04)

Phase 1 — Rust core foundation (BPv7 CBOR, identity, SQLite store, node
engine, CLI, CI).
