# DTN-Link Architecture

## Layered model (target)

1. Application layer — messaging, files, alerts
2. Identity layer — Ed25519 node identities [implemented]
3. Bundle layer — BPv7 (RFC 9171) creation/validation [implemented]
4. Security layer — BPSec (RFC 9172) [BIB integrity implemented]
5. Routing layer — epidemic, spray-and-wait, opportunistic [implemented]
6. Storage layer — persistent SQLite queue with dedup + expiry [implemented]
7. Convergence layer — transports [TCPCL-lite implemented; BLE/Wi-Fi Direct planned]
8. Gateway layer — internet/satellite gateways [planned]
9. Management layer — monitoring, diagnostics, configuration [planned]

## Current implementation (Phases 1-5)

```
+--------------------------------------------------------+
| cli: init/status/send/receive/bundles/forward/daemon/   |
|     verify/decode                                        |
+--------------------------------------------------------+
| dtn-daemon: TCP listener + peer sync loop (contacts)   |
+--------------------------------------------------------+
| dtn-bpsec: BIB (type 11) Ed25519 signature block        |
+--------------------------------------------------------+
| dtn-core: Node                                          |
|   send()        -> Bundle -> store                      |
|   receive(wire) -> decode -> dedup -> store             |
|   select_outbound(peer) -> routing decisions + bundles   |
+----------+---------------+---------------+-------------+
| dtn-routing | dtn-identity | dtn-storage (SQLite)      |
+----------+---------------+---------------+-------------+
| dtn-tcpcl: length-prefixed frames over TCP              |
+--------------------------------------------------------+
| dtn-bpv7: CBOR, PrimaryBlock, CanonicalBlock, Eid      |
+--------------------------------------------------------+
```

### Security model (Phase 5)

- **Integrity**: `dtn_bpsec::sign_bundle` appends a Block Integrity
  Block (BPSec type 11) containing an Ed25519 signature over the
  payload bytes. `verify_bundle` checks it against a VerifyingKey and
  returns Valid / NoIntegrityBlock / Invalid / MultipleIntegrityBlocks.
- Tampering with payload or signature → Invalid. Wrong key → Invalid.
- **Honest scope**: RFC 9173 default contexts (HMAC-SHA256) and the
  Block Confidentiality Block (BCB) are not yet implemented. The
  Ed25519 context provides public-key integrity without a shared
  secret. Application-layer end-to-end encryption and key discovery
  (knowing which key belongs to which node) are planned next.
- A DTN endpoint identifier is NOT proof of identity; only signature
  verification against a known key is.

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

### Contact protocol (TCPCL-lite frames)

Frame = `[u32 BE length][bytes]`, zero-length = end-of-batch.

1. Hello: each side sends its EID URI as one text frame.
2. Each side sends selected outbound bundles (one frame each), then
   end-of-batch.
3. Each side reads frames until end-of-batch, dedups and stores.

Honest limitation: this is not yet full RFC 9174 (no session flags,
keepalives or XFER acknowledgements); it is a real, working TCP transport.

## Roadmap

- Phase 5 (done): BPSec integrity. Next: BCB confidentiality + RFC 9173 contexts.
- Phase 6: BLE + Wi-Fi Direct adapters, discovery.
- Phases 7-9: platform apps.
- Phase 10: serial/LoRa adapters.
- Phase 11: gateways. Phase 12: interop + performance testing.
