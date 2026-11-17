# Desktop shell (Phase 20): `dtn-shell`

The first platform UI shell on the Phase 19 FFI boundary: an
interactive POSIX C terminal chat that embeds the `dtn-app` engine
through the real `libdtn_ffi` C ABI. It lives in `shells/desktop` and
is dependency-free (standard C11 + POSIX only).

## Build

    cargo build -p dtn-ffi --release   # target/release/libdtn_ffi.so
    make -C shells/desktop             # dtn-shell + dtn-ffi-selftest
    make -C shells/desktop test        # self test, exit != 0 on failure

## Run

    ./shells/desktop/dtn-shell -n 1 -d /tmp/node-1.db

Options: `-n node-number`, `-d db-path`, `-s epidemic|spray-wait|opportunistic`.

Pair it with a daemon (or any transport adapter / gateway) on the same
database and the shell's messages ride the real contacts:

    dtn-link daemon --db /tmp/node-1.db --listen 127.0.0.1:4556

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

Inside a conversation a bare line sends; `/back` returns to the
command level. Aliases resolve via the FFI contact book (`/add`),
while raw `dtn://name`, `ipn:n.s`, `dtn:none` and bare node names are
accepted directly by `dtn_app_send`.

## How it maps to the FFI

| Shell action | C ABI call |
|---|---|
| startup | `dtn_app_open`, `dtn_app_eid`, `dtn_app_poll_inbox` |
| `/list` | `dtn_app_conversations` (JSON array, flat fields) |
| `/chat`, `/msg` | `dtn_app_resolve_contact` (alias), `dtn_app_send` |
| `/poll` | `dtn_app_poll_inbox`, `dtn_app_unread_total` |
| `/read`, `/unread` | `dtn_app_mark_read`, `dtn_app_unread_total` |
| `/add` | `dtn_app_add_contact` |
| errors | `dtn_app_last_error` (library-owned, never freed) |
| JSON fields | `shells/desktop/json.c` flat-object reader |
| cleanup | `dtn_string_free`, `dtn_app_close` |

## Self test (`make test`)

`dtn-ffi-selftest` exercises the ABI the way the shell uses it: bad
open (NULL db_path), lifecycle + EIDs, contacts (created vs updated vs
unknown alias), send by EID and by alias (row ids), invalid-URI
rejection, conversation/unread state, `[]` poll idempotency, the full
NULL-argument error protocol (no crashes), close/free no-ops, and
persistence across a reopen of the same database. Exit code 0 only
when every check passes.

## Honest scope

- Inbound delivery is covered by the Rust-side dtn-ffi tests; the ABI
  alone cannot carry a live bundle between two engines.
- `json.c` decodes exactly the flat array shapes dtn-ffi emits
  (docs/ffi.md), not arbitrary JSON; malformed input fails closed.
- Android (JNI) and iOS (Swift bridge) shells remain future work on
  the same ABI, as do GUI toolkits and mobile packaging.
