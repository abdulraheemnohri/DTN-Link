# DTN-Link Architecture

## Layered model (target)

1. Application layer — messaging, files, alerts
2. Identity layer — Ed25519 node identities [implemented]
3. Bundle layer — BPv7 (RFC 9171) creation/validation [implemented]
4. Security layer — BPSec (RFC 9172) [BIB integrity implemented]
5. Routing layer — epidemic, spray-and-wait, opportunistic [implemented]
6. Storage layer — persistent SQLite queue with dedup + expiry [implemented]
7. Convergence layer — transports [TCPCL-lite + Wi-Fi Direct owner/member + Bluetooth RFCOMM glue implemented]
8. Gateway layer — internet/satellite gateways [implemented — dtn-gateway (Phase 11)]
9. Management layer — monitoring, diagnostics, configuration [implemented — dtn-diagnostics (health reports + contact log)]
10. Federation layer — inter-region routing via gateway peers [implemented — dtn-federation (Phase 14)]

## Current implementation (Phases 1-14)

```
+--------------------------------------------------------+
| cli: init/status/send/receive/bundles/forward/daemon/   |
|     doctor/verify/decode                                |
+--------------------------------------------------------+
| dtn-daemon: contacts with sign/verify + TOFU key learn |
|   + contact-outcome logging (dtn-diagnostics)           |
| dtn-transport: framing codecs (length-prefix, KISS) +   |
|   streams + Wi-Fi Direct group owner/member glue +       |
|   Bluetooth RFCOMM glue (contact + retry + SPP serial)  |
+--------------------------------------------------------+
| dtn-federation: RegionMap + gateway plan + sweeps      |
|   over real dtn-gateway contacts (inter-region routing)  |
| dtn-bpsec: BIB (type 11) Ed25519 sig + BCB (type 12)   |
| dtn-keyring: trusted keys per EID (TOFU trust store)    |
| dtn-diagnostics: HealthReport + ContactLog (doctor)     |
+--------------------------------------------------------+
| dtn-core: Node                                          |
|   send()        -> Bundle -> store                      |
|   receive(wire) -> decode -> dedup -> store             |
|   select_outbound(peer) -> routing decisions + bundles   |
+----------+---------------+---------------+-------------+
| dtn-routing | dtn-identity | dtn-storage (SQLite)      |
+----------+---------------+---------------+-------------+
| dtn-tcpcl: length-prefixed frames + TCPCLv4 (RFC 9174) |
+--------------------------------------------------------+
| dtn-bpv7: CBOR, PrimaryBlock, CanonicalBlock, Eid      |
+--------------------------------------------------------+
```

### Security model (Phases 5-6)

- **Integrity**: `dtn_bpsec::sign_bundle` appends a Block Integrity
  Block (BPSec type 11) containing an Ed25519 signature over the
  payload bytes. `verify_bundle` checks it against a VerifyingKey and
  returns Valid / NoIntegrityBlock / Invalid / MultipleIntegrityBlocks.
- Tampering with payload or signature → Invalid. Wrong key → Invalid.
- **Confidentiality**: `dtn_bpsec::bcb::encrypt_bundle` replaces the
  payload with AES-256-GCM ciphertext and appends a BCB (type 12)
  holding the nonce; `decrypt_bundle` restores the plaintext with the
  shared 32-byte key and returns typed errors on wrong key or tampering.
  Wrong key, tampered ciphertext or tampered nonce all fail closed.
- **Honest scope**: RFC 9173 context identifiers, AAD scope over the
  primary block, and key distribution/rotation (knowing which key
  belongs to which node) are planned next.
- A DTN endpoint identifier is NOT proof of identity; only signature
  verification against a known key is.
- **Key distribution**: `dtn_keyring` is the local trust store
  (EID → trusted Ed25519 public key, SQLite). The operator adds keys
  with `dtn-link keyring add` (trust-on-first-use);
  `dtn_keyring::verify_signed_bundle` checks a bundle's BIB against
  the trusted key for its source EID. Honest scope: automatic key
  exchange during the contact protocol, signed key rotation and
  web-of-trust are future work.

### Multi-hop flow

1. A creates a bundle for C and gives it to B (any transport).
2. B `receive()`: decodes, checks expiry, dedups, stores. Bundle is NOT for
   B, so it simply waits (store-carry-forward).
3. Later, on a contact with C, `select_outbound(C)` consults the routing
   engine; if the decision is `forward`, the bundle is sent.
4. C receives, stores, and the bundle appears in C's inbox.
5. Dedup via (source EID, creation timestamp) prevents loops and repeats.

### Routing strategies

- **Epidemic** — replicate every stored bundle to every encountered peer.
- **Spray-and-Wait** — fixed copy budget per bundle (default 8); refuses
  further copies once exhausted.
- **Opportunistic** — forward only to peers with encounter history
  (≥ 2 recorded contacts).

Every decision carries an explainable reason string.

### Secured contacts (Phase 8)

When a keyring is configured, a TCPCL-lite contact becomes:

1. Hello: EID frame + 32-byte Ed25519 public key frame (both sides).
2. TOFU: each side stores the peer's key in its keyring on first
   contact; a changed key logs a warning (no enforcement yet — MITM
   hardening is future work).
3. Outbound bundles are signed (BIB) with the node identity; the
   identity seed persists across restarts (`Node::open_persistent`).
4. Inbound: signed bundles are verified against the trusted key for
   the source EID — Invalid / malformed are dropped; unsigned and
   unknown-source signed bundles are accepted with a log line.

TCPCLv4 contacts sign/verify too, but the RFC 9174 session EID carries
no key — hello key learning is TCPCL-lite only (honest limitation).

### Contact protocol

Two transports exist:

- **TCPCL-lite**: `[u32 BE length][bytes]` frames, zero = end-of-batch,
  hello-then-batches exchange (dtn-daemon `exchange()`).
- **TCPCLv4 (RFC 9174)**: full wire-level session protocol
  (dtn-tcpcl::v4) — `dtn!` contact header, SESS_INIT/SESS_ACK
  handshake with session EIDs and keepalive negotiation, KEEPALIVE,
  XFER_INIT/XFER_SEGMENT/XFER_ACK/XFER_REFUSE acknowledged transfers
  (single START/END segment policy), SESS_REFUSE on version mismatch,
  MSG_REJECT for unknown types, SESS_TERM with reason codes.
  Streaming `Session` driver over any Read+Write transport with typed
  events. dtn-daemon `exchange_v4()` uses it for contacts.

Honest limitation: TLS (RFC 9174 §4.4), extension items and
multi-segment transfers remain future work.

### Generic transport adapters (dtn-transport)

- `FrameCodec` framing abstraction over any Read+Write byte link:
  `LengthPrefixCodec` (wire-compatible with TCPCL-lite contacts) and
  `KissCodec` (KISS framing as used by LoRa TNCs / serial radio modems).
- `exchange_framed`: full contact exchange (EID greeting, routing-driven
  outbound push, inbound receive) over any byte stream — TCP, serial,
  Bluetooth RFCOMM, Wi-Fi Direct group-owner sockets.
- Feature-gated serial glue (`serialport`, cargo feature "serial") opens
  real LoRa TNC / radio-modem ports.
- **Wi-Fi Direct (Phase 9)**: a Wi-Fi Direct group is a normal IP
  network once the platform negotiates it, so the convergence layer is
  plain TCP. `wifi_direct::GroupOwner` binds the group-owner listener
  (`serve_contact` / `serve` run one full contact per member),
  `contact_owner` connects a member, and `contact_owner_with_retry`
  keeps dialing while the group is still forming. Group formation
  (WPS pairing, owner election) stays in the OS; tests exercise both
  sides over real loopback TCP.
- **Bluetooth RFCOMM (Phase 14)**: `bluetooth::contact_stream` runs
  the standard wire format over any OS-provided RFCOMM byte link;
  `bluetooth::retry` is a hardware-independent retry helper for
  intermittent Bluetooth links (io failures retried, protocol errors
  reported immediately); with cargo feature "serial",
  `open_rfcomm`/`contact`/`contact_with_retry` open an OS-paired
  Bluetooth SPP serial device (/dev/rfcomm0, Windows SPP COM ports).
  Pairing and RFCOMM socket creation belong to the OS; tests prove the
  contact path over a byte link plus the retry semantics.

### Gateways (Phase 11)

dtn-gateway decides WHEN to contact a peer and then performs a
real contact using the same wire protocol as the daemon and
adapters (TCPCL-lite exchange, optional BPSec SecurityCtx):

- **ContactPlan** — text-format plans ("addr" always open,
  "addr start end" unix-seconds window, # comments), parse/to_text
  round-trip, explicit tested window math (inclusive start,
  exclusive end, opens_in).
- **InternetGateway** — always-on peers; sweep() contacts every
  peer with per-peer failure isolation; blocking run loop.
- **SatelliteGateway** — pass windows: run_pass(now) contacts only
  peers whose window is open and reports seconds to the next pass;
  the blocking run driver sleeps between passes.

See docs/gateways.md. Honest scope: static plan files (no
TLE-driven pass prediction yet); gateway-only routing policies are
future work.

### Diagnostics (management layer)

dtn-diagnostics answers two operational questions without moving
any bundles:

- **HealthReport::scan(&Node, now, soon)** — store-wide scan: totals,
  delivered vs pending-inbox, expired-now (the daemon cleanup
  criterion), expiring-within-horizon, corrupt rows, store size;
  HEALTHY/ATTENTION verdict; text rendering for the CLI.
- **ContactLog** — SQLite-backed contact history. The daemon records
  every accepted TCPCL-lite connection and every sync attempt (peer
  EID or dial address, direction, outcome, timestamp); summary()
  aggregates per peer (contact count, successes, last contact,
  staleness) and flags never-succeeded peers as unreachable.

CLI: `dtn-link doctor [soon-seconds]` prints the health report plus
the per-peer contact history. See docs/diagnostics.md. Honest scope:
per-contact bundle counters, TCPCLv4/gateway contact logging and a
network-wide management plane are future work.

### Federation (Phase 14 — inter-region routing)

dtn-federation is routing policy plus real contacts: RegionMap
assigns EIDs to regions (prefix match, longest wins), the
Federation plan names one gateway peer per remote region, and
route_to() answers Local / ViaGateway / NoRoute for any
destination. sweep() scans the store for pending bundles destined
to remote regions and contacts each responsible gateway with a full
dtn-gateway contact — per-gateway failure isolation; pending
regions without a gateway are reported as skipped. Intra-region and
unknown-region destinations trigger no contact at all. See
docs/federation.md. Honest scope: the receiving gateway forwards
with its own routing engine (policy only, no topology database);
no per-region security policy; no CLI command yet.

## Roadmap

- Phases 5-6, 8 security (done): BIB integrity, BCB confidentiality, keyring trust store, secured contacts with TOFU key learning. Next: key rotation, MITM enforcement, RFC 9173 contexts, TLS (RFC 9174 §4.4).
- Done: Wi-Fi Direct platform glue — GroupOwner listener + member contacts with retry (dtn-transport::wifi_direct).
- Done: Bluetooth RFCOMM glue — dtn-transport::bluetooth (contact_stream + retry; feature-gated OS SPP serial opening).
- Phases 7-9: platform apps.
- Done: serial/LoRa adapters (feature-gated serial + KISS framing).
- Done: Phase 12 interop + performance testing — dtn-bench (live codec/store/contact benchmarks over real transports: duplex length-prefix + KISS, loopback TCP, TCPCLv4 sessions; cross-layer interop tests including signed + encrypted bundles over KISS; docs/benchmarks.md).
- Done: management/diagnostics layer — dtn-diagnostics (HealthReport + ContactLog, dtn-link doctor, daemon contact recording; docs/diagnostics.md).
- Done: federation layer — dtn-federation (RegionMap, gateway plan, route_to policy, sweep over real gateway contacts; docs/federation.md).
- Next: per-contact bundle counters, TCPCLv4/gateway/federation contact logging, a network-wide management plane, per-region security policy, a federation CLI command; later: RFC 9173 contexts, TLS (RFC 9174 §4.4), key rotation, MITM enforcement, TLE-driven pass prediction.
