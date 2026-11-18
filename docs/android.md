# Android shell (link.dtn.shell) — Phase 21

The first mobile consumer of the dtn-ffi C ABI: a minimal, functional
Android chat app that embeds the real `libdtn_ffi` (the same engine the
desktop shell, the FFI self test and the Rust tests drive) through a JNI
shim compiled into that library with the cargo feature `jni`. No Java
reimplementation of the protocol, no fake transports — messaging leaves
through `dtn_app_send` as BPv7 bundles in the real SQLite store and
delivery comes back through `dtn_app_poll_inbox`.

## Components

- `crates/dtn-ffi/src/jni_shim.rs` (cargo feature `jni`) — JNI bindings
  (`Java_link_dtn_shell_Native_*`) over the exact `dtn_app_*` C ABI
  functions, so NULL handling, the thread-local `dtn_app_last_error`
  protocol and `dtn_string_free` ownership semantics are the tested
  Phase 19/20 behaviors, re-used verbatim.
- `app/src/main/java/link/dtn/shell/Native.kt` — the Kotlin side of the
  boundary (an `object` whose `external fun` map 1:1 to the shim).
- `app/src/main/java/link/dtn/shell/DtnFfi.kt` — the safe wrapper:
  a handle type with typed exceptions (`DtnFfiException` carrying the
  FFI last-error message), strategy constants mirroring
  `dtn_app_ffi.h`, contact resolution and unread helpers.
- `app/src/main/java/link/dtn/shell/Messages.kt` — typed models
  (`DtnMessage`, `Conversation`) plus `Messages.parse*` for exactly the
  flat JSON array shapes dtn-ffi emits (the same ones the desktop
  shell's `json.c` reads). Malformed input throws instead of guessing.
- `app/src/main/java/link/dtn/shell/MainActivity.kt` — the functional
  UI: newly arrived messages, conversation list with unread counts,
  contact registration, sending (by alias, resolved through
  `dtn_app_resolve_contact`, or by raw `dtn://` / `ipn:` / bare-name
  EID), and a poll that drains the FFI inbox.
- `app/src/test/java/.../MessagesTest.kt` — JVM unit tests over the
  real FFI JSON shapes (fresh poll, null bundle_key, unread counts,
  ordering preservation, conversation model, malformed-JSON failure).
  Run with `./gradlew :app:testDebugUnitTest`.

## Building the native library

The app loads `libdtn_ffi.so` from `app/src/main/jniLibs/<abi>/`.
Build it with cargo-ndk.

    cargo install cargo-ndk
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
        -o shells/android/app/src/main/jniLibs build --release \
        -p dtn-ffi --features jni

(The `jni` feature adds the `jni` crate; the plain C ABI of
`libdtn_ffi` is unchanged without it.)

## Building and running the app

    cd shells/android
    gradle wrapper   # once, to generate ./gradlew locally
    ./gradlew :app:testDebugUnitTest
    ./gradlew :app:installDebug

Each app install is its own DTN node (one SQLite store per file under
`context.filesDir`); exchange with other nodes happens through the
transport adapters / daemon / gateway contacts as usual — the shell
only does app-engine work on a background thread.

## Honest scope

- The UI is minimal but functional; nothing is stubbed. Attachments,
  alerts, notifications and background sync service are future work on
  the same FFI.
- The JNI shim itself needs a live JVM (device/emulator); it is
  exercised by the app, while the wire/storage behavior underneath is
  covered by the Rust-side dtn-ffi tests and the desktop self test.
- iOS (Swift bridge) remains the next platform shell.
