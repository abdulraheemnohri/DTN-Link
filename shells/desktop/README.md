# DTN-Link desktop shell (`dtn-shell`)

Phase 20 of the DTN-Link master plan: the first real platform UI shell
on top of the Phase 19 FFI boundary — an interactive, dependency-free
POSIX C terminal chat that embeds the `dtn-app` engine through the
real `libdtn_ffi` C ABI. No Rust, no tokio, no JSON library: the
process links against `libdtn_ffi` and speaks the exact ABI documented
in `crates/dtn-ffi/include/dtn_app_ffi.h` and `docs/ffi.md`.

## Build

    cargo build -p dtn-ffi --release   # produces target/release/libdtn_ffi.so
    make -C shells/desktop             # dtn-shell + dtn-ffi-selftest
    make -C shells/desktop test        # run the self test (exit != 0 on failure)

Everything is standard C11 + POSIX (getline, isatty, getpid).

## Run

    ./shells/desktop/dtn-shell -n 1 -d /tmp/node-1.db

With a daemon running for the same node the shell's queued messages go
out on the next sync; run `dtn-link daemon --db /tmp/node-1.db --listen
127.0.0.1:4556` (or any transport adapter) to carry them.

## Commands

    /me                      local EID + unread badge
    /list                    conversations (unread/total, last message)
    /chat <alias|eid>        open/print a conversation
    /back                    leave the open conversation
    /msg <alias|eid> <text>  send a message
    /add <alias> <eid>       add or re-point a contact alias
    /read <alias|eid>        mark a conversation read
    /unread                  total unread
    /poll                    drain delivered bundles into conversations
    /quit

Inside a conversation a bare line sends a message. Aliases resolve
through the FFI contact book; raw `dtn://name`, `ipn:n.s`, `dtn:none`
and bare node names also work.

## What is real here

- Messages leave through `dtn_app_send` and become real BPv7 bundles in
  the real SQLite store; a daemon, gateway or adapter contact carries
  them out. Until then they queue (that is DTN, not a bug).
- Delivery comes back through `dtn_app_poll_inbox` (idempotent, node
  engine dedup + delivered flag), rendered with unread badges from
  `dtn_app_conversations` / `dtn_app_unread_total`.
- The `dtn-ffi-selftest` exercises the same ABI end to end: lifecycle,
  contacts (created/updated/unknown alias), send-by-EID and send-by-
  alias, rejection of invalid EID URIs, conversation/unread state,
  poll idempotency, the full NULL-argument error protocol, and state
  persistence across a reopen of the database.

## Honest scope

- The self test drives outbound flow + storage; inbound delivery is
  covered by the Rust-side dtn-ffi tests (it needs a second engine to
  carry a live bundle, which the ABI alone cannot do).
- `json.c` is a decoder for exactly the flat array shapes dtn-ffi
  emits (docs/ffi.md), not a general JSON parser; malformed input
  fails closed.
- This is the desktop/terminal shell. Android (JNI) and iOS (Swift
  bridges) shells are the remaining platform work on the same ABI.
