# DTN-Link Architecture

## Layered model (target)

1. Application layer — messaging, files, alerts [messaging implemented — dtn-app (Phase 18); files/alerts future]
2. Identity layer — Ed25519 node identities [implemented]
3. Bundle layer — BPv7 (RFC 9171) creation/validation [implemented]
4. Security layer — BPSec (RFC 9172) [BIB + BCB implemented, RFC 9173 contexts BIB-HMAC-SHA2 / BCB-AES-GCM]
5. Routing layer — epidemic, spray-and-wait, opportunistic [implemented]
6. Storage layer — persistent SQLite queue with dedup + expiry [implemented]
7. Convergence layer — transports [TCPCL-lite + Wi-Fi Direct owner/member + Bluetooth RFCOMM glue implemented]
8. Gateway layer — internet/satellite gateways [implemented — dtn-gateway (Phase 11)]
9. Management layer — monitoring, diagnostics, configuration [implemented — dtn-diagnostics (health reports + contact log)]
10. Federation layer — inter-region routing via gateway peers [implemented — dtn-federation (Phase 14)]
11. Platform shell boundary — C ABI over the application layer [implemented — dtn-ffi (Phase 19); desktop shell dtn-shell (Phase 20)]

## Current implementation (Phases 1-20)

```
+--------------------------------------------------------+
| cli: init/status/send/receive/bundles/chat/forward/     |
|     daemon/doctor/verify/decode                         |
+--------------------------------------------------------+
| dtn-ffi: C ABI over the app engine for platform         |
|   UI shells (libdtn_ffi + dtn_app_ffi.h, Phase 19)      |
| dtn-app: contacts, conversations, unread tracking,      |
|   poll-based inbox (Phase 18 application layer)         |
| dtn-daemon: contacts with sign/verify + TOFU key learn |
|   + MITM enforcement + signed key rotation (Phase 17)   |
|   + contact-outcome logging (dtn-diagnostics)           |
| dtn-transport: framing codecs (length-prefix, KISS) +   |
|   streams + Wi-Fi Direct group owner/member glue +       |
|   Bluetooth RFCOMM glue (contact + retry + SPP serial)  |
+--------------------------------------------------------+
| dtn-federation: RegionMap + gateway plan + sweeps      |
|   over real dtn-gateway contacts (inter-region routing)  |
| dtn-bpsec: BIB (type 11) Ed25519 sig + BCB (type 12)   |
| dtn-keyring: trusted keys per EID (TOFU trust store)   |
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
- **Honest scope**: web-of-trust and security-parameter negotiation
  are future work; RFC 9173 context identifiers and the primary-block
  AAD scope landed in Phase 16 (see below).
- A DTN endpoint identifier is NOT proof of identity; only signature
  verification against a known key is.
- **Key distribution**: `dtn_keyring` is the local trust store
  (EID → trusted Ed25519 public key, SQLite). The operator adds keys
  with `dtn-link keyring add` (trust-on-first-use);
  `dtn_keyring::verify_signed_bundle` checks a bundle's BIB against
  the trusted key for its source EID. Honest scope: web-of-trust is
  future work; automatic in-contact key learning and signed rotation
  landed in Phases 8 and 17.

### RFC 9173 security contexts (Phase 16)

dtn-bpsec::rfc9173 implements the two RFC 9173 default context
identifiers. Because the codebase's CanonicalBlock has no separate
context-id field, the context id is the first byte of the block data:

- **BIB-HMAC-SHA2 (context id 1)** — HMAC-SHA256 over the payload
  bytes with a shared symmetric key; block data
  `[0x01][key_id u32 BE][32-byte tag]`, verified in constant time.
  Validated against the RFC 4231 test vector.
- **BCB-AES-GCM (context id 2)** — AES-256-GCM over the payload with
  the AAD scope covering the CBOR-encoded primary block (RFC 9173
  section 4.2.2.1): swapping source, destination, timestamp or
  lifetime after encryption breaks decryption. Block data
  `[0x02][12-byte nonce][ciphertext || 16-byte tag]`.

The Phase 5/6 legacy formats (raw Ed25519 BIB, nonce-first BCB)
remain wire-compatible; each verifier applies to exactly one context
family and reports UnknownContext / refuses mixed bundles. Honest
scope: security-parameter negotiation remains future work.

### MITM enforcement + signed key rotation (Phase 17)

The Phase 8 TOFU hello logged a warning when a peer presented a
different key than the trusted one and continued. Phase 17 hardens
this:

- **TOFU classification** — `Keyring::check(eid, key)` returns
  New / Match / Mismatch without mutating the store.
- **Enforcement** — `SecurityCtx::enforce_tofu` (default ON in the
  daemon and CLI; opt out with `--no-enforce-tofu`): a hello key that
  differs from the trusted key FAILS the contact
  (`FrameError::Protocol`), nothing is stored, and the trusted entry
  is untouched. Strict mode also DROPS signed bundles from sources
  with no trusted key (previously accepted with a log line).
- **Signed key rotation** — a node that rotated its identity key
  announces the change in the hello via
  `SecurityCtx::pending_rotation`: a `dtn_keyring::KeyChange` wire
  record (`DTNKC1` magic, EID, new key, timestamp) signed by the OLD
  (previously trusted) key. The peer verifies the signature against
  the key it currently trusts and only then applies
  `Keyring::rotate` — an attacker without the old private key cannot
  rotate a peer's entry, and a forged announcement fails the enforced
  contact.
- Live tests: enforced mismatch fails the contact with nothing
  stored; legacy warn-mode completes but still BIB-rejects the
  impostor's bundle; a validly signed rotation is accepted, applied
  to the keyring and the new-key-signed bundle is delivered; a forged
  rotation is rejected; strict mode drops unknown-source bundles.

Honest scope: a rotation announcement is only understood by peers on
>= 0.16 (announcing to an older peer degrades that one contact);
web-of-trust and operator-confirmed pinning remain future work.

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

1. Hello: EID frame + 32-byte Ed25519 public key frame (both sides),
   plus an optional signed key-rotation announcement frame (Phase 17).
2. TOFU: each side stores the peer's key in its keyring on first
   contact; a changed key fails the contact under enforcement
   (Phase 17) unless a valid signed rotation is presented.
3. Outbound bundles are signed (BIB) with the node identity; the
   identity seed persists across restarts (`Node::open_persistent`).
4. Inbound: signed bundles are verified against the trusted key for
   the source EID — Invalid / malformed are dropped; unsigned bundles
   are accepted; unknown-source signed bundles follow the strict-mode
   policy (Phase 17).

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

dtn-diagnostics answers two operational questions without moving any
bundles:

- **HealthReport::scan(&Node, now, soon)** — store-wide scan: totals,
  delivered vs pending-inbox, expired-now (the daemon cleanup
  criterion), expiring-within-horizon, corrupt rows, store size;
  HEALTHY/ATTENTION verdict; text rendering for the CLI.
- **ContactLog** — SQLite-backed contact history. The daemon records
  every accepted TCPCL-lite connection and every sync attempt (peer
  EID or dial address, direction, outcome, timestamp); summary()
  aggregates per peer (contact count, successes, last contact,
  staleness) and flags never-succeeded peers as unreachable.

Phase 15 update: contacts now carry per-contact bundle counters and a
kind tag (peer / gateway / federation); the daemon, gateways and the
federation sweep all record into the same log (counted exchange
variants, old databases migrate in place). CLI: `dtn-link doctor
[soon-seconds]` prints the health report plus the per-peer contact
history. See docs/diagnostics.md. Honest scope: the log is local to
one node — a network-wide management plane is future work.

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
docs/federation.md. Phase 15: per-region security policies
(`policy <region> require-signed|allow-plain` in the plan — a
require-signed region is never contacted without the BPSec stack)
and the `dtn-link federation show/route/sweep` CLI commands. Honest
scope: the receiving gateway forwards with its own routing engine
(policy only, no topology database).

### Platform application layer (Phase 18)

dtn-app is the embeddable messaging-app engine that platform
frontends (Android, iOS, desktop) build on. It sits on the node
engine and persists app state in a sidecar SQLite database
(`<node-db>.app`):

- **Contacts** — alias → EID URI (add/update, resolve, list).
- **Conversations** — per-peer message threads with direction (in/out),
  body, timestamp, read state and the carrying bundle's identity key
  for status correlation.
- **Unread tracking** — per-conversation and total counters plus
  mark-read per peer (the notification-badge data).
- **Poll-based inbox** — `App::poll_inbox()` drains the node engine's
  pending inbox into conversation rows and marks the consumed bundles
  delivered in the store; idempotent (dedup + delivered flag).
- **Text rendering** — conversation list and history renderers used by
  the `dtn-link chat` CLI (contacts add/list, send <alias|eid>, poll,
  list [peer]).

The node engine keeps store-carry-forward, dedup, expiry and BPSec;
`send_text()` hands the message to the engine as a bundle that waits
in the store for the next contact. See docs/apps.md. Honest scope:
this is the shared engine, not the platform UI shells — GUI toolkits,
attachments and remote read receipts are future work.

### FFI boundary (Phase 19)

dtn-ffi exposes the dtn-app engine through a plain C ABI
(`libdtn_ffi` + `include/dtn_app_ffi.h`), the stable boundary that
Android (JNI), iOS (Swift bridge) and desktop shells compile
against:

- **Lifecycle** — `dtn_app_open(node_number, db_path, strategy)` /
  `dtn_app_close` over an opaque handle (internally `Mutex<App>`,
  so any entry point is callable from any thread).
- **Messaging** — `dtn_app_send` (dtn://, ipn:, dtn:none or bare-name
  EIDs), `dtn_app_poll_inbox`, `dtn_app_conversations`,
  `dtn_app_history` (JSON arrays via an internal escaper — no new
  dependencies), `dtn_app_unread_total`, `dtn_app_mark_read`.
- **Contacts** — `dtn_app_add_contact`, `dtn_app_resolve_contact`.
- **Error protocol** — every fallible entry point returns -1/NULL and
  records a thread-local message retrievable via
  `dtn_app_last_error`; NULL arguments are reported as errors, never
  dereferenced; returned strings are freed with `dtn_string_free`.

Tests drive the C ABI functions directly, including a full two-node
chat with delivery through the real node engine. See docs/ffi.md.
Honest scope: the FFI covers the chat/app engine surface; GUI
toolkits and mobile packaging are future work.

### Desktop shell (Phase 20)

`shells/desktop/dtn-shell` is the first consumer of the FFI
boundary: a dependency-free POSIX C11 terminal chat that links
against the real `libdtn_ffi` and drives the full ABI surface —

- startup: `dtn_app_open` + `dtn_app_eid` + an offline catch-up
  `dtn_app_poll_inbox`;
- `/list`, `/chat` (history), `/msg` (send), `/add`, `/read`,
  `/unread`, `/poll`, `/me` — aliases resolved through
  `dtn_app_resolve_contact`, raw dtn:// / ipn: / bare-name EIDs
  accepted by `dtn_app_send`;
- `shells/desktop/json.c` — a small reader for exactly the flat JSON
  array shapes dtn-ffi emits (full-escape decoding incl. \uXXXX
  surrogate pairs); malformed input fails closed.

`make -C shells/desktop test` runs `dtn-ffi-selftest`, which walks
the ABI end to end against the real library: NULL-argument error
protocol (no crashes), lifecycle + EIDs, contacts (created / updated
/ unknown alias), send by EID and by alias, invalid-URI rejection,
conversation/unread state, poll idempotency, close/free no-ops, and
persistence across reopen. See docs/shell.md. Honest scope: outbound
flow + storage are exercised from C; inbound delivery stays covered
by the Rust-side dtn-ffi tests. Android (JNI) and iOS shells are the
remaining platform work on the same ABI.

## Roadmap

- Phases 5-6, 8 security (done): BIB integrity, BCB confidentiality, keyring trust store, secured contacts with TOFU key learning.
- Done: Phase 16 RFC 9173 default security contexts — BIB-HMAC-SHA2 (context id 1, HMAC-SHA256, RFC 4231-vector-tested) and BCB-AES-GCM (context id 2, AES-256-GCM with the AAD scope over the CBOR-encoded primary block) in dtn-bpsec::rfc9173.
- Done: Phase 17 MITM enforcement + signed key rotation — TOFU classification (New/Match/Mismatch), enforced hello-key mismatch (contact fails, nothing stored), KeyChange announcements signed by the previously trusted key applied via Keyring::rotate, strict-mode dropping of unknown-source signed bundles, `--no-enforce-tofu` opt-out.
- Done: Wi-Fi Direct platform glue — GroupOwner listener + member contacts with retry (dtn-transport::wifi_direct).
- Done: Bluetooth RFCOMM glue — dtn-transport::bluetooth (contact_stream + retry; feature-gated OS SPP serial opening).
- Done: serial/LoRa adapters (feature-gated serial + KISS framing).
- Done: Phase 12 interop + performance testing — dtn-bench (live codec/store/contact benchmarks over real transports: duplex length-prefix + KISS, loopback TCP, TCPCLv4 sessions; cross-layer interop tests including signed + encrypted bundles over KISS; docs/benchmarks.md).
- Done: management/diagnostics layer — dtn-diagnostics (HealthReport + ContactLog, dtn-link doctor, daemon contact recording; docs/diagnostics.md).
- Done: federation layer — dtn-federation (RegionMap, gateway plan, route_to policy, sweep over real gateway contacts; docs/federation.md).
- Done: Phase 15 management completion — per-contact bundle counters (exchange_counted / exchange_v4_counted), kind-tagged contact log (peer/gateway/federation) with in-place migration of older databases, gateway + federation contact logging, per-region security policies (require-signed blocks plaintext sweeps) and the dtn-link federation show/route/sweep CLI.
- Done: Phase 18 platform application layer — dtn-app (contacts, conversations, unread tracking, poll-based inbox, text renderers) + the dtn-link chat CLI (docs/apps.md).
- Done: Phase 19 FFI boundary — dtn-ffi C ABI over the app engine (lifecycle, send/poll/conversations/history/unread/contacts, thread-local error protocol, JSON emission, dtn_app_ffi.h header; docs/ffi.md).
- Done: Phase 20 desktop shell — shells/desktop/dtn-shell (POSIX C11, dependency-free) drives the full dtn-ffi C ABI over the real libdtn_ffi (lifecycle, contacts, send, conversations/history, unread, poll), a flat-JSON reader for the FFI shapes, and make test running dtn-ffi-selftest end-to-end against the built library (docs/shell.md).
- Next: Android (JNI) and iOS (Swift bridge) GUI shells on the same dtn-ffi C ABI; later: attachments, remote read receipts, TLS (RFC 9174 §4.4), web-of-trust, TLE-driven pass prediction, a network-wide management plane.

