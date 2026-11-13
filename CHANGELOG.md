# Changelog

## 0.15.0 (2026-11-13)

Phase 16 — RFC 9173 default security context identifiers.

- dtn-bpsec::rfc9173 (new module): the two RFC 9173 context ids are
  now carried on the wire. BIB-HMAC-SHA2 (context id 1): HMAC-SHA256
  over the payload with a shared symmetric key, block data
  [0x01][key_id u32 BE][32-byte tag], constant-time verification;
  sign_hmac / verify_hmac with typed outcomes (Valid /
  NoIntegrityBlock / MultipleIntegrityBlocks / UnknownContext /
  Invalid). Validated against the RFC 4231 test case 1 vector.
- BCB-AES-GCM (context id 2): AES-256-GCM payload encryption with the
  AAD scope covering the CBOR-encoded primary block (RFC 9173
  section 4.2.2.1) — swapping the destination (or any primary-block
  field) after encryption fails decryption. Block data
  [0x02][12-byte nonce][ciphertext || 16-byte tag];
  encrypt_aes_gcm / decrypt_aes_gcm with typed errors.
- Legacy Phase 5/6 formats unchanged and coexisting: the context id
  byte distinguishes the families; the HMAC BIB uses block number 4
  so a bundle can carry both integrity contexts; each verifier
  refuses mixed bundles instead of mis-verifying.
- 17 new tests: roundtrips (incl. wire), context-id / key-id / nonce
  wire layout, RFC 4231 vector, tampered payload / ciphertext /
  nonce, wrong keys, AAD-bound primary-block swap, unknown contexts,
  malformed lengths, multi-block refusal, re-encryption replacement,
  combined HMAC+GCM pipeline with plaintext never on the wire, and
  legacy coexistence.
- docs: architecture.md gains the RFC 9173 section and roadmap
  update; README status table + standards updated; workspace bumped
  to 0.15.0.
- Honest scope: security-parameter negotiation, key distribution and
  rotation remain future work.


## 0.14.0 (2026-11-12)

Phase 15 — management completion: real per-contact bundle counters,
kind-tagged contact logging across daemon / gateway / federation,
per-region security policies and the federation CLI.

- dtn-diagnostics: ContactRecord gains per-contact bundle counters
  (sent / received, filled by the new counted exchange variants) and
  a kind tag — Kind::Peer / Gateway / Federation with as_str/parse
  round-trip. ContactLog::open migrates older databases in place
  (ALTER TABLE + 'peer' backfill; existing rows survive, tested
  against a simulated pre-kind schema). New summary_of(kind)
  aggregates per contact kind; summary() still spans all kinds.
- dtn-daemon: exchange_counted / exchange_v4_counted return
  ContactCounts (bundles pushed, bundles newly stored — duplicates
  and rejected forgeries are not counted); exchange / exchange_v4
  remain the compatibility wrappers. The daemon's serve and sync
  loops now record sent/received counters into the contact log;
  exchange_v4_logged logs TCPCLv4 sessions as kind=peer.
- dtn-gateway: ContactReport gains `sent`; new contact_counted
  performs the full gateway contact and records the outcome (success
  with counters, or failure with the dial address) into the contact
  log tagged Kind::Gateway. contact() delegates unchanged.
- dtn-federation: per-region security policy — plan lines
  `policy <region> require-signed|allow-plain` (parse/to_text
  round-trip, duplicate-policy rejection, policy_of lookup defaulting
  to allow-plain). A require-signed region is never contacted
  without a SecurityCtx: the sweep reports it in the new
  FedSweepReport::blocked (with reason) and nothing crosses the
  wire; allow-plain regions contact normally. sweep_logged records
  every federation contact (success with counters, failure with the
  dial address) tagged Kind::Federation; sweep delegates unchanged.
- cli: new `dtn-link federation show|route|sweep` commands (plan +
  region-map parsing, routing decisions, real sweeps against the
  local node database with keyring security unless --insecure);
  usage text and version string updated (0.14.0).
- docs: federation guide (policies + CLI), diagnostics guide
  (counters, kinds, migration), architecture roadmap Phase 15 done.


## 0.13.0 (2026-11-11)

Phase 14 — federation + Bluetooth RFCOMM glue.

- dtn-federation (new crate): inter-region routing policy on top of
  real contacts. RegionMap maps EID URI prefixes to regions (longest
  prefix wins, text format with parse/to_text round-trip); Federation
  holds the local region plus one gateway peer per remote region
  (text plan: "local <region>" + "<region> <gateway-eid> <addr>"
  lines, parse/to_text round-trip); route_to() returns an explainable
  Local / ViaGateway / NoRoute decision for any destination
  (including known-region-no-gateway).
- Federation::sweep: scans the real store, finds remote regions with
  pending (not-yet-delivered) bundles and performs a full dtn-gateway
  contact — the same TCPCL-lite exchange with the optional security
  stack the daemon uses — against each responsible gateway.
  Per-gateway failure isolation (a dead gateway never blocks a live
  one); pending regions without a configured gateway are reported as
  skipped. Intra-region and unknown-region destinations trigger no
  contact at all.
- dtn-transport::bluetooth: RFCOMM glue — contact_stream runs the
  standard wire format over any OS-provided RFCOMM byte link
  (/dev/rfcomm0, Windows SPP COM ports, macOS serial-port devices);
  retry() is a hardware-independent retry helper for intermittent
  Bluetooth links (retries connection failures, reports protocol
  errors immediately); feature-gated open_rfcomm/contact/
  contact_with_retry open an OS-paired Bluetooth SPP serial device
  via the serialport crate.
- 13 new tests, all live: federation over real loopback TCP (a field
  node federates a bundle to an hq gateway node which holds it for
  the last hop; local + unknown-region destinations trigger no
  contact; dead-gateway failure isolation), region-map longest-prefix
  + round-trips + parse errors, plan round-trip + parse errors,
  route_to decisions, RFCOMM contact two-way over a byte link, retry
  semantics (success after transient failures, immediate protocol
  errors, exhausted retries, zero-attempts-still-dials-once).
- docs: new docs/federation.md; adapters.md gains the Bluetooth
  RFCOMM section and updated honest scope; architecture.md marks the
  federation layer implemented and updates the roadmap; workspace
  bumped to 0.13.0.
- Honest scope: federation is routing policy, not a topology database
  (the receiving gateway forwards with its own routing engine); no
  per-region security policy; no CLI command yet. RFCOMM pairing and
  socket creation belong to the OS — an OS-paired SPP serial device
  works today via the serial feature.


## 0.12.0 (2026-11-10)

Phase 13 — management/diagnostics layer.

- dtn-diagnostics (new crate): the management layer. HealthReport
  scans the real store — totals, delivered/pending-inbox counts,
  expired-now (same criterion as the daemon cleanup),
  expiring-within-horizon, corrupt rows (bytes that no longer
  decode), store size — with a HEALTHY/ATTENTION verdict and a text
  rendering for the CLI.
- ContactLog: SQLite-backed contact history (peer, direction in/out,
  outcome, timestamp) with per-peer aggregation (contact count,
  successes, last contact, staleness) and an unreachable flag for
  peers that only ever failed. Disk persistence tested.
- dtn-daemon: DaemonConfig::contact_log — every accepted TCPCL-lite
  connection and every sync attempt is recorded (best-effort; logging
  never breaks a contact); startup prints whether the contact log is
  ON.
- cli: new `dtn-link doctor [soon-seconds]` command — prints the
  health report plus the per-peer contact history; `daemon` wires the
  contact log automatically.
- 8 new tests: health classification (pending/delivered/expired/
  expiring-soon), healthy-node verdict, corrupt-row detection (row
  mutated through a second SQLite connection), contact-log aggregation
  + staleness + unreachable, direction round-trip, disk persistence,
  daemon outcome recording, log-disabled no-op.
- docs: new docs/diagnostics.md; architecture.md marks the management
  layer implemented and updates the roadmap; workspace bumped to
  0.12.0.
- Honest scope: per-contact bundle counters are not recorded yet
  (exchange() returns no counts), TCPCLv4 sessions and gateway
  contacts are not logged yet, and the log is local to one node
  (no network-wide management plane).

## 0.11.0 (2026-11-09)

Phase 12 — interop + performance testing suite.

- dtn-bench (new crate): live benchmarks over the real stack — no
  mocked transports, no synthetic numbers. Every report is produced
  by moving actual BPv7 bundles through the same code paths the
  daemon uses.
- report: BenchReport (ops/s, MiB/s, markdown rows) and LatencySamples
  with exact nearest-rank median/p95 helpers.
- codec: BPv7 CBOR encode+decode throughput with per-roundtrip
  verification and deterministic (xorshift) payloads.
- store: real on-disk SQLite put + full-table query passes through
  the node engine (database removed afterwards).
- contact: full contact benchmarks — duplex memory links with
  length-prefix and KISS framing, real loopback TCP with the
  TCPCL-lite wire format, real RFC 9174 TCPCLv4 sessions (handshake +
  acknowledged transfers + SESS_TERM), and per-contact TCP latency
  sampling with median/p95 reporting.
- Binary: cargo run -p dtn-bench --release prints a markdown
  benchmark table plus latency percentiles.
- 10 new tests: cross-layer interop (Ed25519-signed + AES-256-GCM
  encrypted bundle over a KISS-framed contact; plaintext never on the
  wire; decrypt-then-verify at the receiver), two-way TCPCLv4
  exchange, per-transport full-delivery benchmarks, codec/store
  roundtrips, percentile exactness on a known vector.
- fix: dtn-transport's daemon interop test still called the daemon
  exchange with the pre-Phase-8 two-argument signature; updated to
  pass the security context (None).
- docs: new docs/benchmarks.md; architecture.md marks Phase 12 done
  (next: management/diagnostics layer, federation, Bluetooth RFCOMM
  glue); workspace bumped to 0.11.0.
- Honest scope: measured numbers are machine-dependent (the suite
  reports them, it does not assert performance targets); no
  warmup/confidence statistics; hardware serial/LoRa links reuse the
  same contact functions once a port is opened (feature "serial").

## 0.10.0 (2026-11-08)

Phase 11 — internet + satellite gateways.

- dtn-gateway (new crate): the gateway layer decides WHEN to
  contact a peer, then performs a real TCPCL-lite contact
  (dtn-daemon exchange with the optional SecurityCtx) — same wire
  protocol as every other DTN-Link component, no faked transports.
- ContactPlan: text-format contact plans (addr, optional
  unix-seconds window, # comments) with parse/to_text round-trip
  and explicit, tested window math (inclusive start, exclusive
  end, opens_in).
- internet::InternetGateway: contact every always-on peer per
  sweep; per-peer failures isolated and reported (a dead relay
  never blocks the rest); SweepReport/ContactReport with peer EID
  + inbound count; blocking run loop.
- satellite::SatelliteGateway: pass-window scheduling —
  run_pass(now) contacts only peers whose windows are open and
  reports seconds to the next pass; blocking wall-clock run
  driver sleeps between passes.
- 11 new tests, all live over real loopback TCP: plan parsing
  round-trip + validation errors, window bounds math, sweep
  delivery with inbound counting, dead-peer failure isolation,
  closed-window no-contact with next-pass reporting, open-pass
  queue draining, expired-window semantics, earliest-next-pass
  selection.
- docs: new docs/gateways.md; architecture.md marks the gateway
  layer implemented and updates the roadmap; adapters.md points to
  the gateway crate; workspace bumped to 0.10.0.
- Honest scope: static plan files (no TLE-driven pass prediction
  yet); gateway-only routing policies are future work.

## 0.9.0 (2026-11-07)

Phase 9 (adapters) — Wi-Fi Direct platform glue.

- dtn-transport::wifi_direct: a Wi-Fi Direct group is a normal IP
  network once the platform negotiates it (wpa_supplicant p2p_* /
  Android WifiP2pManager), so the convergence layer is plain TCP —
  GroupOwner binds the group-owner listener and serves one full
  TCPCL-lite-compatible contact per member (serve_contact / serve),
  contact_owner connects a member to the group owner, and
  contact_owner_with_retry keeps dialing while the group is still
  forming. A retried contact cannot duplicate bundles (the node
  engine dedups on source EID + creation timestamp).
- New tests over real loopback TCP: two-way bundle delivery between
  group owner and member, member retry succeeding after the owner
  binds late, one owner serving members sequentially, and immediate
  reporting of protocol-level errors (no retry masking).
- docs: adapters.md gains a Wi-Fi Direct section; architecture.md
  marks convergence layer Wi-Fi Direct part done.
- Honest scope: group formation / WPS negotiation belongs to the OS;
  Bluetooth RFCOMM glue is the next adapter milestone — an
  OS-provided RFCOMM serial port already works today through the
  serial feature.

## 0.8.0 (2026-11-07)

Phase 8 — security integrated into the data path.

- dtn-core: `Node::open_persistent` persists the identity seed in a
  sidecar file (0600 on Unix) so the node keeps the same Ed25519 key
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

