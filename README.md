# DTN-Link

**DTN-Link — Worldwide Decentralized Communication Network**
*Connect Beyond Connectivity.*

DTN-Link is an independent, decentralized communication platform that exchanges
messages, files and emergency alerts using Delay-Tolerant Networking (DTN) —
without requiring a SIM card, cellular subscription or Wi-Fi router for every
communication. It uses Bundle Protocol v7 (RFC 9171), store-carry-forward
routing, modular physical transport adapters and optional internet gateways.

## Status: Phases 1-12 + RFC 9173 security contexts + management + federation layers (core, transports, security, adapters, gateways, diagnostics, federation)

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
| Secured contacts: hello key exchange, signed outbound, verified inbound (daemon) | implemented + tested (crates/dtn-daemon) |
| Persistent node identity across restarts | implemented + tested (crates/dtn-core) |
| Full RFC 9174 TCPCLv4 session protocol (handshake, keepalive, acked XFER) | implemented + tested (crates/dtn-tcpcl::v4) |
| Modular transport adapters: framing codecs + generic stream exchange | implemented + tested (crates/dtn-transport) |
| KISS framing for LoRa TNCs / serial radio modems | implemented + tested (crates/dtn-transport::kiss) |
| Serial-port hardware glue (cargo feature "serial") | implemented, feature-gated |
| Internet & satellite gateways (contact plans, pass windows) | implemented + tested (crates/dtn-gateway) |
| Interop + performance benchmark suite | implemented + tested (crates/dtn-bench) |
| Diagnostics: health reports + kind-tagged contact history with per-contact bundle counters (`dtn-link doctor`) | implemented + tested (crates/dtn-diagnostics) |
| CLI | implemented — init/status/send/receive/bundles/forward/daemon/doctor/verify/keyring/encrypt/decrypt/decode/federation |
| RFC 9173 default contexts: BIB-HMAC-SHA2 (ctx 1), BCB-AES-GCM with primary-block AAD (ctx 2) | implemented + tested (crates/dtn-bpsec::rfc9173) |
| Signed key rotation | future |
| Bluetooth RFCOMM platform glue (stream layer ready) | next phase |
| Android / iOS / Windows / Linux apps | Phases 7-9 |
| Federation: region map, gateway plans, per-region security policy, sweeps over real gateway contacts, `dtn-link federation` CLI | implemented + tested (crates/dtn-federation) |

## Build

Requires Rust 1.70+.

    cargo build --release
    cargo test --workspace
    cargo install --path cli  # provides the dtn-link binary

For LoRa TNC / serial radio hardware support:

    cargo build -p dtn-transport --features serial

## Quick start: two real nodes over TCP

    # Terminal 1 — node B (listener)
    dtn-link daemon --listen 127.0.0.1:4556

    # Terminal 2 — node A, syncs with B
    dtn-link daemon --listen 127.0.0.1:4557 --peers 127.0.0.1:4556
    dtn-link send dtn://node-b "hello over DTN"
    dtn-link bundles
    dtn-link doctor      # health report + contact history

## Architecture

See [docs/architecture.md](docs/architecture.md),
[docs/adapters.md](docs/adapters.md) and
[docs/diagnostics.md](docs/diagnostics.md).

## Standards

- RFC 9171 — Bundle Protocol v7
- RFC 9172 — Bundle Protocol Security (BIB integrity block implemented; Ed25519 context)
- RFC 9173 — Default Security Contexts (BIB-HMAC-SHA2 context id 1 and BCB-AES-GCM context id 2 implemented in crates/dtn-bpsec::rfc9173)
- RFC 9174 — TCP Convergence Layer v4 (TCPCLv4 session protocol implemented: SESS handshake, KEEPALIVE, acked XFER; TLS remaining)
- KISS — LoRa TNC / serial radio modem framing (implemented in crates/dtn-transport)

## License

MIT

