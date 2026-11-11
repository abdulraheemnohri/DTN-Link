# Federation (inter-region routing)

dtn-federation is the DTN-Link federation layer: it lets a node in
one DTN region route bundles to peers in another region through a
gateway peer, using the same wire protocol and security stack as
every other DTN-Link contact.

## Model

- **RegionMap** — EID membership. Each entry maps an EID URI prefix
  to a region; the longest matching prefix wins.
- **Federation plan** — the local region plus one gateway per
  remote region.
- **route_to(destination)** — explainable decision: Local (same
  region, normal store-carry-forward), ViaGateway(gateway) (a remote
  region we have a gateway for), NoRoute (unknown region, or a known
  region without a gateway).
- **sweep()** — the delivery driver: scans the store for pending
  bundles destined to remote regions, then performs a full
  dtn-gateway contact (TCPCL-lite exchange with the optional
  security context) against each responsible gateway. Failures are
  isolated per gateway; remote regions with pending bundles but no
  configured gateway are reported as skipped.

## Region map (text)

```text
# region  eid-prefix
field ipn:1.
hq    ipn:9.
lab   dtn://lab/
broad ipn:
```

An EID is in a region when its URI starts with the entry's prefix;
the longest match wins, so "ipn:9." overrides the broad "ipn:" entry.

## Federation plan (text)

```text
# our region first
local field
# region  gateway-eid   gateway-addr
hq        ipn:10.0      10.0.0.7:4556
lab       dtn://labgw   192.168.1.5:4556
```

## Usage

```rust
use std::sync::{Arc, Mutex};
use dtn_bpv7::Eid;
use dtn_core::{Node, Strategy};
use dtn_federation::{Decision, Federation, RegionMap};

let regions = RegionMap::parse("field ipn:1.\nhq ipn:9.\n")?;
let fed = Federation::parse("local field\nhq ipn:10.0 10.0.0.7:4556\n")?
    .with_regions(regions);

// Policy: what should happen to a bundle for this destination?
match fed.route_to(&Eid::ipn(9, 0)) {
    Decision::Local => { /* intra-region: the daemon handles it */ }
    Decision::ViaGateway(g) => { /* remote region: g.addr is the next hop */ }
    Decision::NoRoute => { /* no membership entry / no gateway */ }
}

// Delivery: sweep contacts every gateway whose region has pending
// bundles (here: any DTN-Link listener works as the gateway).
let node = Arc::new(Mutex::new(
    Node::open(1, &".dtn-link/dtn.db".into(), Strategy::Epidemic)?));
let report = fed.sweep(&node, None);
```

## Sweep semantics (honest)

- The island keeps its copy of the bundle after the contact
  (store-carry-forward: deletion happens on expiry, not on
  forwarding), so retried sweeps cannot lose data — dedup prevents
  duplicates at the gateway.
- The contact is the same dtn-daemon exchange the daemon, adapters
  and gateways use, so a gateway needs nothing special: any
  DTN-Link listener works.
- The receiving gateway forwards with its own routing engine —
  federation is policy (which gateway for which region), not a
  topology database.

## Honest scope

- No per-region security policy (the SecurityCtx is node-wide).
- No CLI command yet — library API today.
- Regions are prefix-based; no automatic region discovery.

## Testing

All federation tests run over real loopback TCP with the actual
daemon exchange on the gateway side: a field node federates a bundle
to an hq gateway (which then holds it for the last hop); local and
unknown-region destinations trigger no contact at all; a dead
gateway never blocks a live one; map and plan parsing round-trip;
route_to covers Local / ViaGateway / NoRoute / known-region-
no-gateway.
