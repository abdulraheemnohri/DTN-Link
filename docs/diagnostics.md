# Diagnostics (management layer)

The management layer lives in `crates/dtn-diagnostics`. It answers two
operational questions without moving any bundles:

1. **Is this node healthy right now?** — `HealthReport::scan`
2. **Who has this node been talking to, and did it work?** — `ContactLog`

## Health reports

```rust
let report = dtn_diagnostics::HealthReport::scan(&node, now, soon)?;
println!("{}", report.render_text(now, soon));
```

The scan walks the real store (no separate bookkeeping):

- total stored bundles, store size in bytes
- delivered vs pending-inbox counts
- bundles already expired (creation_ts + lifetime < now — the same
  criterion the daemon cleanup uses)
- bundles expiring within the `soon` horizon
- corrupt rows (stored bytes that no longer decode as BPv7)
- overall status: `HEALTHY` when nothing is expired and nothing is
  corrupt, `ATTENTION` otherwise

## Contact log

A SQLite log (`contacts.db` in the node home by default). The daemon
records every accepted TCPCL-lite connection and every sync attempt,
the gateways record every planned contact, and the federation sweep
records every inter-region gateway contact:

| field | meaning |
|---|---|
| peer | peer EID (or dial address when the attempt failed before hello) |
| direction | `in` (accepted connection) / `out` (sync attempt) |
| ok | whether the exchange completed |
| sent | bundles this node pushed to the peer during the contact |
| received | bundles newly stored from the peer (duplicates/rejects not counted) |
| started_at | unix seconds |
| kind | `peer` (daemon contact) / `gateway` (internet or satellite pass) / `federation` (inter-region sweep) |

Phase 15: the counters are filled by the counted exchange variants
(`dtn_daemon::exchange_counted`, `exchange_v4_counted`,
`dtn_gateway::contact_counted`), so `doctor` shows real per-contact
traffic, not just outcomes. Databases written by older versions are
migrated in place on open (existing rows read back as `kind = peer`).

`ContactLog::summary()` aggregates per peer: contact count, successful
count, last-contact time, total sent/received and staleness
(`stale_for(now)`). A peer with attempts but zero successes is
`unreachable()`. `summary_of(kind)` restricts the aggregation to one
contact kind (peers vs gateway passes vs federation traffic).

## CLI

```
dtn-link doctor [expiring-soon-seconds]
```

Prints the health report followed by the per-peer contact history
(`last-contact=123s-ago`, `sent=N received=M`,
`[NEVER SUCCEEDED]` for unreachable peers).

## Honest scope

- TCPCLv4 sessions are counted by `exchange_v4_counted` but the
  daemon's serve loop currently logs TCPCL-lite contacts only.
- The log is local to one node — there is no network-wide management
  plane, no SNMP-style remote queries, no alerting.
