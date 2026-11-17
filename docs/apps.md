# Platform application layer (`dtn-app`)

The application layer is the piece a real messaging app is made of:
contacts, conversations, unread counts and a poll-based inbox. It is
implemented once, in Rust, as the crate `dtn-app`, so every platform
frontend (Android, iOS, Windows, Linux, macOS) embeds the same engine
instead of re-implementing chat state per platform.

## What it provides

- **Contacts** — human aliases mapped to EID URIs, persisted in
  SQLite. `dtn://alice-node` becomes `alice`.
- **Conversations** — per-peer message threads with direction (in/out),
  body, timestamp and read state, in a sidecar database
  (`<node-db>.app`) next to the node's bundle store.
- **Unread tracking** — per-conversation and total unread counters,
  `mark_read` per peer: everything a notification badge needs.
- **Poll-based inbox** — `App::poll_inbox()` drains the node engine's
  pending inbox into conversation rows and marks the consumed bundles
  delivered in the bundle store, so a GUI calls it on a timer or after
  a daemon sync. Polling is idempotent (the node engine dedups and the
  delivered flag prevents double insertion).
- **Text rendering** — `render_conversations()` / `render_history()`
  for text frontends (the CLI uses them directly).

The node engine keeps doing what it does best — store-carry-forward,
dedup, expiry, BPSec signing/verification — the app layer only adds
presentation state. `App::send_text()` hands the message to the node
engine as a bundle; it sits in the store until the next contact (daemon
sync, gateway pass, Wi-Fi Direct / Bluetooth / serial exchange). That
is DTN, not a bug.

## CLI

    dtn-link chat contacts add alice dtn://alice-node
    dtn-link chat contacts list
    dtn-link chat send alice "see you at the pass"
    dtn-link chat poll
    dtn-link chat list            # conversation list with unread badges
    dtn-link chat list alice      # one conversation, marks it read

A full two-node session:

    # Terminal 1 — bob's node
    dtn-link daemon --listen 127.0.0.1:4556

    # Terminal 2 — alice's node
    dtn-link daemon --listen 127.0.0.1:4557 --peers 127.0.0.1:4556
    dtn-link chat contacts add bob dtn://bob
    dtn-link chat send bob "hello over DTN"
    dtn-link chat poll            # after the daemons have synced
    dtn-link chat list bob

## Embedding the engine (platform frontends)

```rust
use dtn_app::{App, Direction};
use dtn_core::Strategy;

let mut app = App::open(1, std::path::Path::new("dtn.db"), Strategy::Epidemic)?;
app.db.add_contact("bob", "dtn://bob")?;
app.send_text(&dtn_bpv7::Eid::dtn("bob"), "hello", 3600)?;

// after a contact (daemon sync, gateway pass, adapter exchange):
for m in app.poll_inbox()? {
    if m.direction == Direction::In {
        println!("{}: {}", m.peer, m.body);
    }
}
println!("unread: {}", app.unread_total()?);
```

Platform UI shells build on this crate through the Phase 19 FFI
boundary (`dtn-ffi`). The desktop terminal shell `dtn-shell`
(Phase 20, shells/desktop) is the first of them; see docs/shell.md.

## Honest scope

- Text bodies are stored lossily-decoded UTF-8; arbitrary payloads are
  consumed, not dropped (binary attachments are future work).
- An inbound message is "delivered" locally when it lands in the
  conversation; there are no remote read receipts or per-bundle
  delivery acknowledgments back to the sender yet.
- The app database is local to one node; there is no conversation
  sync between a user's own devices yet.

