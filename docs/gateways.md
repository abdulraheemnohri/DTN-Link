# Gateways (Phase 11)

A DTN-Link gateway turns an intermittently connected island node into
part of a larger DTN. It decides **when** to contact a peer
(scheduling) and then performs a full contact using the **same wire
protocol** as every other DTN-Link component (dtn-daemon TCPCL-lite
`exchange`, with the optional BPSec security context). Nothing is
faked: a gateway is a real peer over a real TCP connection.

The crate is `dtn-gateway`.

## Contact plans

Both gateways are driven by a `ContactPlan`: a list of peers with
optional contact windows. A plan is a plain text file, one entry per
line, `#` comments allowed:

    # internet relays — always contactable
    relay.example.net:4556
    10.0.0.7:4556

    # satellite passes — unix seconds, start (inclusive) end (exclusive)
    gs.example.net:4556 1762600000 1762600540
    gs.example.net:4556 1762686400 1762686940

`ContactPlan::parse` / `to_text` round-trip this format, so a
ground-station pass schedule is literally a file you can put under
cron. Window math is explicit and tested: inclusive start, exclusive
end, `opens_in()` reports the seconds until the next pass.

## Internet gateway (`dtn_gateway::internet`)

For a node with continuous connectivity that bridges DTN islands onto
the internet:

```rust
use std::sync::{Arc, Mutex};
use dtn_core::{Node, Strategy};
use dtn_gateway::internet::InternetGateway;

let node = Arc::new(Mutex::new(
    Node::open(1, &".dtn-link/dtn.db".into(), Strategy::Epidemic).unwrap()));

let gw = InternetGateway::peers(["relay.example.net:4556", "10.0.0.7:4556"]);
let report = gw.sweep(&node, None);          // contact every peer once
assert_eq!(report.contacted(), 2);

// Or run it forever on its own thread:
// gw.run(node, None, std::time::Duration::from_secs(30));
```

Per-peer failures are isolated: a dead relay, a typo'd address or a
firewall drop is reported in `SweepReport::failures` and skipped —
one bad peer never blocks the rest of a sweep. Each successful
contact yields a `ContactReport` with the peer EID and the number of
inbound bundles gained.

## Satellite gateway (`dtn_gateway::satellite`)

For duty-cycled peers — satellites, scheduled radio links:

```rust
use dtn_gateway::satellite::SatelliteGateway;
use dtn_gateway::{ContactPlan, PlannedContact};

let plan = ContactPlan::parse(concat!(
    "gs.example.net:4556 1762600000 1762600540\n",
    "gs.example.net:4556 1762686400 1762686940\n",
)).unwrap();
let gw = SatelliteGateway::new(plan);

// run_pass drives the clock explicitly (deterministic, testable):
let now = dtn_gateway::now_unix();
let pass = gw.run_pass(&node, None, now);
println!("contacts: {}, next pass in: {:?}", pass.contacts.len(), pass.next_pass_in);

// Or run it on wall-clock time forever:
// gw.run(node, None);
```

`run_pass(now)` contacts exactly the peers whose windows are open at
`now` and reports how long until the next pass. Between passes the
blocking `run()` driver just sleeps. A retried or repeated pass
cannot duplicate bundles — the node engine dedups on
(source EID, creation timestamp).

## Security

`contact()` (and therefore every sweep and pass) accepts the same
optional `dtn_daemon::SecurityCtx` as the daemon: hello key learning
(TOFU), signed outbound bundles (BIB) and verified inbound.

## Tests (all over real loopback TCP)

* contact-plan parsing: round-trip, comments, window validation errors,
* window math: inclusive/exclusive bounds, `opens_in`, past windows,
* internet sweep delivers a bundle to a listening peer and counts
  inbound bundles from a two-way contact,
* a dead peer does not block a live peer (failure isolation),
* satellite: a closed window contacts nothing even though the ground
  station is listening, and reports the time to the next pass; an
  open pass empties a two-bundle queue into the station,
* expired windows are "due now" but not open; the earliest future
  window wins in multi-pass plans.

## Honest scope

Plans are static files — fetching pass schedules from a TLE-propagating
scheduler or a feed is future work. A gateway relays using the node's
routing strategy (a gateway is just a node that happens to dial on a
schedule); dedicated gateway-only routing policies come later.
