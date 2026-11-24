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

## TLE pass prediction (`dtn_gateway::tle`, Phase 27)

Phase 11's honest-scope note said pass schedules were hand-maintained
files. Phase 27 closes that: the windows can now be **computed from a
real NORAD two-line element set (TLE)** — the published orbital
elements of every cataloged satellite, refreshed daily from
Space-Track or Celestrak.

- `dtn_gateway::tle::Tle::parse` reads a standard TLE (with or
  without the name line): NORAD id (matched across both lines), the
  `YYDDD.ddddddd` UTC epoch (converted to unix seconds with
  integer-exact calendar math), inclination, RAAN, eccentricity,
  argument of perigee, mean anomaly and mean motion. Element sets
  that the model cannot honor honestly are rejected: mean motion
  outside [1.0, 22.0] rev/day, eccentricity above 0.05
  (near-circular model), inclination outside [0, 180], junk numbers,
  mismatched NORAD ids.
- `Predictor` propagates the orbit with a deterministic
  near-circular Kepler model: semi-major axis from Kepler's third
  law (mu = 398600.4418 km³/s²), position from the argument of
  latitude at the mean motion rate, ECI → ECEF by IAU-1982 GMST, and
  topocentric elevation over a WGS84-shaped `GroundStation`
  (lat/lon/altitude, minimum acceptable elevation, default 10 deg).
  `elevation_at(t)` is finite and valid before and after the epoch.
- `passes_between(from, hours)` returns the windows where the
  elevation is at least the station minimum: non-overlapping,
  ascending, boundaries refined by bisection to sub-second precision,
  each with its maximum elevation. A pass already live at `from`
  starts at `from`; a pass still live at the horizon ends there.
- `next_pass(from)` is the first pass within a 72-hour search — the
  "seconds to the next pass" number the satellite gateway needs.
- `Predictor::to_contact_plan(addr, from, hours)` produces a real
  `ContactPlan` (one windowed `PlannedContact` per pass) that
  `SatelliteGateway` runs unchanged — orbital mechanics becomes a
  gateway schedule with zero glue code.

CLI (Phase 27):

    # when is the ISS over Berlin (min 10 deg elevation, next 24 h)?
    dtn-link tle passes iss.tle 52.52 13.40

    # generate a ready ContactPlan for a ground station peer
    dtn-link tle plan iss.tle 52.52 13.40 gs.example.net:4556 10 48 > pass-plan.txt

`tle passes` also prints the derived orbit altitude/period and the
time to the next pass; `tle plan` prints the plan text in the exact
`ContactPlan` format (`addr start end` unix-seconds lines), so the
output can be handed to the satellite gateway directly.

```rust
use dtn_gateway::tle::{GroundStation, Predictor, Tle};

let tle = Tle::parse(&std::fs::read_to_string("iss.tle").unwrap()).unwrap();
let gs = GroundStation::new(52.52, 13.40);
let p = Predictor::new(&tle, &gs).unwrap();
let plan = p.to_contact_plan("gs.example.net:4556", dtn_gateway::now_unix() as i64, 48.0);
let gw = dtn_gateway::satellite::SatelliteGateway::new(plan);
// gw.run(node, None);
```

### Model honesty

This is a mean-element propagator, **not** full SGP4: the drag term
(B*), the second/third-derivative elements and the secular J2 node
regression are not applied, and a pass shorter than the 15-second
coarse scan step can be missed. For a ~400 km circular orbit the
model keeps the schedule well within a minute of the real window over
a few days from the element epoch — accurate enough for a contact
plan, which is regenerated from a fresh TLE in operation anyway.

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
  window wins in multi-pass plans,
* TLE (Phase 27): real-ISS element-set parsing with the published
  field values, epoch conversion against the known UTC time, the
  Kepler altitude/period for the ISS orbit, rejection of every
  malformed-element class, constant elevation for a synthetic
  geostationary satellite, an equatorial orbit never seen from high
  latitudes, ordered non-overlapping sun-synchronous windows with
  plausible durations, plausible ISS-over-Berlin pass counts,
  deterministic predictions, `next_pass` agreement, zero-horizon
  behavior, station validation, and the ContactPlan bridge
  round-tripping through the text format into the satellite gateway
  (`next_pass_in` matches `next_pass`).

## Honest scope

A gateway relays using the node's routing strategy (a gateway is just
a node that happens to dial on a schedule); dedicated gateway-only
routing policies come later, as does full SGP4 propagation and
automated Space-Track/Celestrak TLE fetching (the TLE file is fetched
by the operator today).
