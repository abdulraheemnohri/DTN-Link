#!/bin/sh
# build.sh — Phase 22 iOS shell build driver.
#
# Builds the Rust static library for iOS (libdtn_ffi.a) and wires it into
# the Swift package + example app. Requires:
#   - Rust (rust-toolchain.toml picks the version)
#   - cargo-ndk (cargo install cargo-ndk)
#   - Xcode with iOS SDK and Swift 5.7+
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORKDIR="${DTN_IOS_BUILD:-$HERE/.build/ios}"

# Rust targets for the iOS device and simulator.
TARGETS="aarch64-apple-ios aarch64-apple-ios-sim"

echo "== installing Rust iOS targets =="
for t in $TARGETS; do rustup target add "$t"; done

echo "== building dtn-ffi static libs =="
mkdir -p "$WORKDIR"
for t in $TARGETS; do
    cargo build -p dtn-ffi --release --target "$t"
done

echo "== creating universal simulator lib (arm64) =="
for t in $TARGETS; do
    cp "target/$t/release/libdtn_ffi.a" "$WORKDIR/libdtn_ffi-$t.a"
done

echo "== done =="
cat <<EOF

Next steps (see docs/ios.md for details):
  - Xcode: add target/aarch64-apple-ios/release/libdtn_ffi.a to
    "Frameworks, Libraries and Embedded Content" (device targets)
    or $WORKDIR/libdtn_ffi-aarch64-apple-ios-sim.a (simulator).
  - Add shells/ios/Example/ios/DtnShellApp.xcodeproj sources, or open the
    workspace generated from shells/ios/Package.swift.
  - swift test --target DtnShellTests runs the model suite without the
    native library.
EOF
