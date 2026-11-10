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
records every accepted TCPCL-lite connection and every sync attempt:

| field | meaning |
|---|---|
| peer | peer EID (or dial address when the attempt failed before hello) |
| direction | `in` (accepted connection) / `out` (sync attempt) |
| ok | whether the exchange completed |
| started_at | unix seconds |

`ContactLog::summary()` aggregates per peer: contact count, successful
count, last-contact time and staleness (`stale_for(now)`). A peer with
attempts but zero successes is `unreachable()`.

## CLI

```
dtn-link doctor [expiring-soon-seconds]
```

Prints the health report followed by the per-peer contact history
(`last-contact=123s-ago`, `[NEVER SUCCEEDED]` for unreachable peers).

## Honest scope

- Per-contact bundle counters are not recorded yet (`exchange()`
  returns no counts); the sent/received columns are reserved.
- TCPCLv4 sessions and gateway contacts are not logged yet.
- The log is local to one node — there is no network-wide management
  plane, no SNMP-style remote queries, no alerting.
