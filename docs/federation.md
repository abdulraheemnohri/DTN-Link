# Federation (inter-region routing)

dtn-federation is the DTN-Link federation layer: it lets a node in
one DTN region route bundles to peers in another region through a
gateway peer, using the same wire protocol and security stack as
every other DTN-Link contact.

## Model

- **RegionMap** — EID membership. Each entry maps an EID URI prefix
  to a region; the longest matching prefix wins.
- **Federation plan** — the local region, one gateway per remote
  region, and optional per-region security policies.
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
- **Per-region security policy (Phase 15)** — a plan line
  `policy <region> require-signed` marks a region as requiring the
  BPSec stack: `sweep` then refuses (blocks) the contact when no
  SecurityCtx is configured instead of sending plaintext into a
  region that forbids it. Unset regions default to `allow-plain`.
- **sweep_logged() (Phase 15)** — the same sweep with contact
  logging: every federation contact (success or failure, with
  per-contact bundle counters) is recorded into a
  dtn-diagnostics ContactLog tagged `Kind::Federation`, so
  `dtn-link doctor` shows inter-region traffic.

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
# optional per-region security policy
policy    hq            require-signed
```

## CLI

```text
dtn-link federation show  <plan-file> [regions-file]
dtn-link federation route <plan-file> <regions-file> <eid>
dtn-link federation sweep <plan-file> <regions-file> [--insecure]
```

- `show` parses the plan (and region map) and prints the local
  region, every gateway and its effective policy.
- `route` answers the routing decision for one destination EID.
- `sweep` performs a real sweep: it opens the node database
  (`DTN_LINK_HOME`, default `.dtn-link`), loads the keyring unless
  `--insecure` is given, and contacts every responsible gateway over
  real TCP — recording each contact in the contact log.

## Usage

```rust
use std::sync::{Arc, Mutex};
use dtn_bpv7::Eid;
use dtn_core::{Node, Strategy};
use dtn_federation::{Decision, Federation, RegionMap};

let regions = RegionMap::parse("field ipn:1.\nhq ipn:9.\n")?;
let fed = Federation::parse(
    "local field\nhq ipn:10.0 10.0.0.7:4556\npolicy hq require-signed\n")?
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
// report.successes / failures / skipped / blocked (policy refusals)
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
- A `require-signed` region blocks (not fails) without a security
  context: the bundle stays stored and the region is reported in
  `FedSweepReport::blocked` with the reason.

## Honest scope

- The security policy is enforced on the SENDING side only: a
  require-signed region is never contacted plaintext. The receiving
  gateway applies its own inbound policy (BPSec verify when a keyring
  is configured).
- Regions are prefix-based; no automatic region discovery.
- One gateway per remote region; no multi-gateway failover yet.

## Testing

All federation tests run over real loopback TCP with the actual
daemon exchange on the gateway side: a field node federates a bundle
to an hq gateway (which then holds it for the last hop); local and
unknown-region destinations trigger no contact at all; a dead
gateway never blocks a live one; map, plan and policy parsing
round-trip; route_to covers Local / ViaGateway / NoRoute /
known-region-no-gateway; a require-signed region blocks a plaintext
sweep (nothing crosses the wire) while allow-plain contacts
normally; sweep_logged records the real contact outcomes with
per-contact bundle counters into a ContactLog, filterable by
`Kind::Federation`.
