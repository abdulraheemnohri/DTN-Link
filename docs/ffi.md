# FFI: the platform shell boundary (Phase 19)

`crates/dtn-ffi` exposes the `dtn-app` messaging engine through a plain
C ABI so platform frontends can embed DTN-Link without touching Rust.
The first consumer is the desktop terminal shell `dtn-shell`
(Phase 20, shells/desktop; docs/shell.md):

| Platform | How it consumes the FFI |
|---|---|
| Windows / Linux / macOS | desktop shell `dtn-shell` (shells/desktop), or `dtn_ffi` via any FFI-capable UI toolkit |
| Android | JNI wrapper over `libdtn_ffi.so` (next phase) |
| iOS | Swift C bridge over `libdtn_ffi.a` (next phase) |

## Build

    cargo build -p dtn-ffi --release

Artifacts: `target/release/libdtn_ffi.so` (Linux/Android),
`libdtn_ffi.dylib` (macOS/iOS simulator), `dtn_ffi.dll` (Windows).
The C header is `crates/dtn-ffi/include/dtn_app_ffi.h`.

## Calling convention

- `dtn_app_open(node_number, db_path, strategy)` returns an opaque
  handle; `dtn_app_close` releases it. NULL arguments are reported as
  errors through `dtn_app_last_error`, never dereferenced.
- Every fallible function returns `-1` / `NULL` and records a
  thread-local error message; `dtn_app_last_error()` retrieves it
  (valid until the next FFI call on the same thread, do not free).
- Returned strings (`dtn_app_eid`, `dtn_app_poll_inbox`,
  `dtn_app_conversations`, `dtn_app_history`,
  `dtn_app_resolve_contact`) must be released with `dtn_string_free`.
- The handle is internally a `Mutex<App>`: calls from any thread
  serialize; the engine itself is single SQLite store.

## JSON shapes

Messages (poll inbox / history):

    [{"id":1,"peer":"dtn://node-2","direction":"in","body":"hi",
      "created_at":1731700000,"bundle_key":"dtn://node-1|42|0"}, ...]

Conversations (most recently active first):

    [{"peer":"dtn://node-2","last_body":"hi","last_at":1731700000,
      "unread":1,"total":1}, ...]

Inbox drain combined with read receipts (Phase 26,
dtn_app_poll_inbox_with_receipts):

    {"messages":[ ...same message shape as above... ],
     "receipts":[{"from":"dtn://node-2","acked_at":1731700000,
                  "confirmed":2}, ...]}

Receipts are never chat rows; "confirmed" counts the local outbound
messages the receipt acknowledged (spoofed or foreign keys confirm
nothing). Per-message confirmed-read state is also queryable directly:
dtn_app_message_confirmed(handle, id) returns 1 / 0 (-1 on error).
dtn_app_send_read_receipts(handle, peer, lifetime) acknowledges every
inbound message of the peer not yet receipted (0 = nothing pending,
no bundle created).

Attachments (Phase 26, Phase 23 engine semantics):
dtn_app_send_file(handle, peer, path, lifetime) queues a real file as
one DTNA1 bundle (message row id returned, or -1 on unreadable file,
unsafe filename or over-cap size); dtn_app_extract_attachment(handle,
id, dest_dir) writes the stored bytes byte-for-byte into dest_dir and
returns the written path (free with dtn_string_free) or NULL. The
stored filename is re-validated, so nothing escapes dest_dir.

## Minimal C usage

    dtn_app_handle *app = dtn_app_open(1, "/data/node.db",
                                       DTN_STRATEGY_EPIDEMIC);
    char *eid = dtn_app_eid(app);
    dtn_app_send(app, "dtn://far-node", "hello over DTN", 3600);
    char *inbox = dtn_app_poll_inbox(app);   /* "[]" until a contact */
    dtn_string_free(eid);
    dtn_string_free(inbox);
    dtn_app_unread_total(app);               /* notification badge */
    dtn_app_close(app);

## Semantics inherited from dtn-app

- `dtn_app_send` records the message immediately and queues the bundle
  in the node store; it is carried out by a daemon, gateway or adapter
  contact later. That is DTN, not a bug.
- `dtn_app_poll_inbox` drains the node inbox into conversation rows
  and marks the consumed bundles delivered; it is idempotent across
  polls (node-engine dedup + delivered flag).
- Inbound messages are born unread; `dtn_app_mark_read` is idempotent.

## Honest scope

The FFI covers the chat/app engine surface including the Phase 26
read-receipt and attachment surface (`dtn_app_send_read_receipts`,
`dtn_app_poll_inbox_with_receipts`, `dtn_app_message_confirmed`,
`dtn_app_send_file`, `dtn_app_extract_attachment`), mirrored by the
Android JNI shim. The desktop terminal shell (`shells/desktop`,
docs/shell.md) is the working reference consumer; its `json.c` reader
keeps parsing the unchanged flat message shapes (the new entry points
are opt-in). GUI toolkits, desktop packaging and FFI-side transport
progress reporting remain future work; the FFI is the stable boundary
they build on. `dtn_app_resolve_contact` returns NULL both for
unknown aliases and errors; distinguish via `dtn_app_last_error`.

