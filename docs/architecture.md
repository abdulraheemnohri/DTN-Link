# DTN-Link Architecture

## Layered model (target)

1. Application layer — messaging, files, alerts
2. Identity layer — Ed25519 node identities
3. Bundle layer — BPv7 (RFC 9171) creation/validation
4. Security layer — BPSec (RFC 9172) [planned]
5. Routing layer — epidemic, spray-and-wait, opportunistic [planned]
6. Storage layer — persistent SQLite queue with dedup + expiry
7. Convergence layer — transport adapters (BLE, Wi-Fi Direct, TCPCLv4, LoRa, ...) [planned]
8. Gateway layer — internet/satellite gateways [planned]
9. Management layer — monitoring, diagnostics, configuration [planned]

## Phase 1 (implemented here)

```
+---------------------------------------------------+
| cli (dtn-link init/status/send/receive/bundles)    |
+---------------------------------------------------+
| dtn-core: Node { identity, store, seq }            |
|   send()     -> Bundle -> store                    |
|   receive(wire) -> decode -> dedup -> store        |
|   inbox()    -> bundles for this EID, not delivered |
+----------+----------------+-----------------------+
| dtn-identity (Ed25519) | dtn-storage (SQLite)      |
+----------+----------------+-----------------------+
| dtn-bpv7: CBOR, PrimaryBlock, CanonicalBlock, Eid  |
+---------------------------------------------------+
```

### Bundle wire format

A bundle is a CBOR array: `[ primary_block, canonical_block... ]`.

Primary block (9 elements, CRC fields omitted while crc_type = 0):

```
[version(7), control_flags, crc_type,
 destination_eid, source_node_eid, report_to_eid,
 [creation_ts_secs, creation_ts_seqno],
 lifetime, hop_count]
```

Payload block: `[type_code=1, block_number=1, control_flags=0, bytes]`.

Bundle ID = (source EID, creation timestamp) — used for duplicate
detection in the store (`bundles.id` primary key).

### Storage schema (schema version 1)

- `bundles(id PK, source, destination, creation_ts_secs, creation_ts_seq, lifetime, received_at, data BLOB)`
- `delivered(id PK, delivered_at)`
- `schema_migrations(version PK, applied_at)`
- indexes: `idx_bundles_dest(destination)`, `idx_bundles_expiry(creation_ts_secs, lifetime)`

### Honest limitations (Phase 1)

- No physical transports yet: bundles move via CLI stdin/stdout or the store.
- No BPSec yet: payloads are not yet end-to-end encrypted on the wire.
- EIDs are not identity proof; signatures exist but wire binding comes with BPSec.
- Expiry uses wall-clock seconds since Unix epoch.

## Roadmap

Phases 2-12 follow the master plan: multi-hop forwarding, hybrid routing,
TCPCLv4 + BLE transports, then platform apps and gateways.
