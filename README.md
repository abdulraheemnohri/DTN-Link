# DTN-Link

**DTN-Link — Worldwide Decentralized Communication Network**
*Connect Beyond Connectivity.*

DTN-Link is an independent, decentralized communication platform that exchanges
messages, files and emergency alerts using Delay-Tolerant Networking (DTN) —
without requiring a SIM card, cellular subscription or Wi-Fi router for every
communication. It uses Bundle Protocol v7 (RFC 9171), store-carry-forward
routing, modular physical transport adapters and optional internet gateways.

## Status: Phases 1-7 (Rust core, TCP transport, BPSec security stack, keyring, TCPCLv4)

| Component | Status |
|---|---|
| BPv7 bundle encode/decode (CBOR) | implemented (crates/dtn-bpv7) |
| Cryptographic node identity (Ed25519) | implemented (crates/dtn-identity) |
| Persistent SQLite bundle store | implemented (crates/dtn-storage) |
| Hybrid routing (epidemic / spray-and-wait / opportunistic) | implemented (crates/dtn-routing) |
| Multi-hop store-carry-forward (A→B→C) | implemented + tested (crates/dtn-core) |
| TCP transport + daemon (TCPCL-lite + full TCPCLv4) | implemented + tested (crates/dtn-tcpcl, dtn-daemon) |
| BPSec bundle integrity (RFC 9172-aligned BIB, Ed25519) | implemented + tested (crates/dtn-bpsec) |
| BPSec payload confidentiality (BCB, AES-256-GCM) | implemented + tested (crates/dtn-bpsec::bcb) |
| Keyring: trusted public keys per EID (TOFU key distribution) | implemented + tested (crates/dtn-keyring) |
| CLI | implemented — init/status/send/receive/bundles/forward/daemon/verify/keyring/encrypt/decrypt/decode |
| Full RFC 9174 TCPCLv4 session protocol (handshake, keepalive, acked XFER) | implemented + tested (crates/dtn-tcpcl::v4) |
| RFC 9173 context identifiers; automatic key exchange | future |
| Bluetooth / Wi-Fi Direct transports | next phase |
| Android / iOS / Windows / Linux apps | Phases 7-9 |
| LoRa / radio / serial adapters | Phase 10 |
| Internet & satellite gateways | Phase 11 |

## Build

Requires Rust 1.70+.

```bash
cargo build --release
cargo test --workspace
cargo install --path cli  # provides the dtn-link binary
```

## Quick start: two real nodes over TCP

```bash
# Terminal 1 — node B (listener)
dtn-link daemon --listen 127.0.0.1:4556

# Terminal 2 — node A, syncs with B
dtn-link daemon --listen 127.0.0.1:4557 --peers 127.0.0.1:4556
dtn-link send dtn://node-b "hello over DTN"
dtn-link bundles
```

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Standards

- RFC 9171 — Bundle Protocol v7
- RFC 9172 — Bundle Protocol Security (BIB integrity block implemented; Ed25519 context)
- RFC 9173 — Default Security Contexts (planned)
- RFC 9174 — TCP Convergence Layer v4 (TCPCLv4 session protocol implemented: SESS handshake, KEEPALIVE, acked XFER; TLS remaining)

## License

MIT
