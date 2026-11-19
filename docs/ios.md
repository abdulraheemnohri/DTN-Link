# iOS shell (Phase 22)

The iOS shell is the second mobile consumer of the dtn-ffi C ABI. It
embeds the real `libdtn_ffi` (built from the same `dtn_app_*` surface the
desktop and Android shells use) through a Swift bridge — no Swift-side
protocol reimplementation, no fake transports.

## Components

```
shells/ios/
├── Package.swift                 SwiftPM manifest (5.7)
├── Sources/CDtnFfi/              C target: module.modulemap + dtn_app_ffi.h
│                                 (kept in sync with crates/dtn-ffi/include)
├── Sources/DtnModels/            Message/Conversation models over the flat
│                                 JSON arrays dtn-ffi emits; malformed input
│                                 fails closed (throws, never guesses)
├── Sources/DtnShell/
│   ├── DtnFfi.swift              safe bridge: open/close lifecycle, EID,
│   │                             send, poll, conversations, history,
│   │                             unread, mark-read, contacts; typed
│   │                             DtnFfiError carrying the native
│   │                             dtn_app_last_error message; strings
│   │                             returned by the library are always
│   │                             released with dtn_string_free
│   └── ChatController.swift      @MainActor ObservableObject: alias/raw
│                                 recipient resolution, unread badges,
│                                 status text, startup catch-up poll
├── Tests/DtnShellTests/          XCTest model suite (DtnModels only, runs
│                                 without the native library)
├── Example/ios/Views/            SwiftUI app: ShellApp entry point +
│                                 ChatView (list, badges, compose, poll,
│                                 add-contact sheet)
└── build.sh                      cargo-ndk-style static-lib build driver
```

Targets:

- **DtnModels** — pure Swift (Foundation only), depends on nothing.
- **CDtnFfi** — the C header, exposed via a custom module map.
- **DtnShell** — depends on `CDtnFfi` (`DtnApp` C module) and links
  `dtn_ffi` (add `libdtn_ffi.a` in Xcode, see below).

## Build

1. Native library (Rust → iOS static archives):

       ./shells/ios/build.sh
       # release archives under target/<triple>/release/libdtn_ffi.a
       # and shells/ios/.build/ios/

2. Model unit tests (no native library needed):

       cd shells/ios && swift test --target DtnModels

3. Example app: open `shells/ios/` as a local Swift package in Xcode (or
   generate a project from `Package.swift`) and add
   `target/aarch64-apple-ios/release/libdtn_ffi.a` to *Frameworks,
   Libraries and Embedded Content* (simulator: the
   `aarch64-apple-ios-sim` archive). Set `DTN_NODE_NUMBER` (env, default
   1) to choose the node database `node-<n>.db` under Application
   Support/DTNLink.

## Wire shape contract

The Swift models decode *exactly* the JSON arrays documented in
`crates/dtn-ffi/include/dtn_app_ffi.h`:

- messages: `id`, `peer`, `direction` (`in`/`out`), `body`,
  `created_at`, `bundle_key` (string or null)
- conversations: `peer`, `last_body`, `last_at`, `unread`, `total`

Unknown fields are ignored (Foundation default); missing or
wrongly-typed known fields throw `DtnJsonError` — the app surfaces an
error instead of showing invented data. Order preservation is asserted
by the tests.

## Error protocol

Mirrors the wrapper policy from the Android shell:

- `dtn_app_open` returning NULL throws with the native last-error text.
- `-1`/NULL returns throw `DtnFfiError(operation:message:)`; the message
  is the thread-local `dtn_app_last_error` copy, or a fallback string.
- `resolveContact` distinguishes "unknown alias" (NULL with no recorded
  error) from a real engine error.
- `DtnFfi` owns the handle; `deinit` closes, so a leaked handle cannot
  happen; `close()` is idempotent (second call is a no-op).

## Honest scope

- The suite tests the model/JSON layer; the `DtnFfi` bridge itself needs
  a live native library and an Apple toolchain, so its wire/storage
  behavior underneath is verified by the Rust-side dtn-ffi tests and
  the desktop self test, exactly as for the Android JNI shim.
- The example is a single-window chat: no attachments, no background
  sync service, no push notifications, no read receipts.
- The header copy under `Sources/CDtnFfi/include/` is kept in sync
  manually with `crates/dtn-ffi/include/dtn_app_ffi.h` (same policy as
  the shell's own json.c contract).
