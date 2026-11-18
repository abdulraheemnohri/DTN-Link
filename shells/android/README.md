# DTN-Link — Android shell (Phase 21)

A minimal, fully functional Android chat app on the dtn-ffi C ABI. It
embeds the real `libdtn_ffi` (one DTN node per install) and drives the
same engine the desktop shell and the Rust tests do: messaging becomes
real BPv7 bundles in a real SQLite store; delivery returns through the
FFI poll inbox. No Java reimplementation, no fake transports.

See [docs/android.md](../../docs/android.md) for the full guide.

## Layout

- `app/src/main/java/link/dtn/shell/Native.kt` — JNI surface (external funs)
- `app/src/main/java/link/dtn/shell/DtnFfi.kt` — safe handle wrapper
- `app/src/main/java/link/dtn/shell/Messages.kt` — typed JSON models
- `app/src/main/java/link/dtn/shell/MainActivity.kt` — the chat UI
- `app/src/test/` — JVM unit tests over the FFI JSON shapes

## Quick start

    # 1. native library (cargo-ndk; per-ABI libdtn_ffi.so into jniLibs)
    cargo install cargo-ndk
    cargo ndk -t arm64-v8a -t x86_64 \
        -o app/src/main/jniLibs build --release -p dtn-ffi --features jni

    # 2. app
    gradle wrapper                 # once, to generate ./gradlew
    ./gradlew :app:testDebugUnitTest
    ./gradlew :app:installDebug

## Note on the Gradle wrapper

The wrapper jar is a binary the repo intentionally does not carry; run
`gradle wrapper` once in this directory (any local Gradle 8.x, or let
Android Studio generate it on first open) and then use `./gradlew` as
above.
