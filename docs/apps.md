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
- **Attachments (Phase 23)** — `App::send_file()` reads a real file
  and sends it as a DTNA1 attachment payload in one normal bundle;
  `poll_inbox()` decodes it on delivery and stores the bytes;
  `App::extract_attachment()` writes them back byte-for-byte.
  Filenames are strictly validated (no path separators, no "..",
  no control characters, 255-byte cap) and content is capped at
  8 MiB, so one attachment always fits in one bundle.
- **Remote read receipts (Phase 24)** — `App::send_read_receipts()`
  sends the peer one receipt bundle acknowledging exactly the bundles
  that carried the not-yet-acknowledged inbound messages;
  `poll_inbox_with_receipts()` applies arriving receipts to the
  conversation (outbound rows confirmed read, `render_history` shows
  `✓read`) without ever creating chat rows for them.

## Read receipts (Phase 24)

Reading is local (a UI calls `mark_read`), acknowledging is a
separate, explicit step over the DTN: `send_read_receipts(&peer,
lifetime)` collects the bundle keys of that peer's inbound messages
that carry no receipt yet, sends ONE receipt bundle and flips local
bookkeeping so nothing is acknowledged twice.

The receipt payload (DTNR1) is strict-decoded on the receiving side:

    [5-byte magic "DTNR1"]
    [u16 BE entry count]
    per entry:
      [u16 BE bundle-key length][bundle-key UTF-8 bytes]
    [u64 BE ack timestamp (unix seconds)]

The bundle key is the `source|creation-ts|seq` identity of the bundle
that carried the original message (the string stored on the sender's
outbound conversation rows), so correlation never depends on clock
agreement and cannot confirm the wrong row. A receipt naming bundles
the receiver never sent — spoofed, corrupted or foreign — confirms
nothing; malformed payloads degrade to lossy chat text, never crash.
Receipts ride every existing transport unchanged (they are normal
store-carry-forward bundles, optionally BPSec-signed like any other).

Example:

```rust
// after poll_inbox() and reading the conversation:
let acknowledged = app.send_read_receipts(&dtn_bpv7::Eid::dtn("bob"), 3600)?;

// on the other side, after the next contact:
let (new_msgs, receipts) = app.poll_inbox_with_receipts()?;
for r in receipts {
    println!("{} confirmed {} messages as read", r.from, r.confirmed);
}
```

`poll_inbox()` still returns only the chat messages, so callers that
do not care about receipts are unaffected.

## CLI

    dtn-link chat contacts add alice dtn://alice-node
    dtn-link chat contacts list
    dtn-link chat send alice "see you at the pass"
    dtn-link chat send-file alice report.pdf
    dtn-link chat extract 3 ./downloads
    dtn-link chat poll            # also applies incoming read receipts
    dtn-link chat list            # conversation list with unread badges
    dtn-link chat list alice      # one conversation, marks it read;
                                  # confirmed rows render with ✓read

A full two-node session:

    # Terminal 1 — bob's node
    dtn-link daemon --listen 127.0.0.1:4556

    # Terminal 2 — alice's node
    dtn-link daemon --listen 127.0.0.1:4557 --peers 127.0.0.1:4556
    dtn-link chat contacts add bob dtn://bob
    dtn-link chat send bob "hello over DTN"
    dtn-link chat poll            # after the daemons have synced
    dtn-link chat list bob        # marks bob's conversation read

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
Honest scope of the FFI for attachments: the JSON conversation layers
show the `[attachment: ...]` marker text; an FFI API for the bytes
(native-side extract) is future work on the same boundary.

## Honest scope

- Text bodies are stored lossily-decoded UTF-8; arbitrary payloads are
  consumed, not dropped. Binary file attachments landed in Phase 23
  (one file per bundle, 8 MiB cap; no chunked multi-bundle resume for
  larger files, no MIME type metadata yet).
- Read receipts landed in Phase 24: they confirm that the peer READ
  the messages (read state came back over the DTN as a receipt
  bundle), not that a message reached the network or was seen on
  screen. Arriving receipts are applied by `chat poll`; the
  `[✓read]` badges render in `chat list <peer>`. Sending receipts is
  engine-level so far: a `chat ack <alias|eid>` command and an FFI
  `dtn_app_*` entry point are the natural next steps.
- The app database is local to one node; there is no conversation
  sync between a user's own devices yet.
