# DTN-Link

**DTN-Link — Worldwide Decentralized Communication Network**
*Connect Beyond Connectivity.*

DTN-Link is an independent, decentralized communication platform that exchanges
messages, files and emergency alerts using Delay-Tolerant Networking (DTN) —
without requiring a SIM card, cellular subscription or Wi-Fi router for every
communication. It uses Bundle Protocol v7 (RFC 9171), store-carry-forward
routing, modular physical transport adapters and optional internet gateways.

## Status: Phase 1 (Rust core)

| Component | Status |
|---|---|
| BPv7 bundle encode/decode (CBOR) | implemented (crates/dtn-bpv7) |
| Cryptographic node identity (Ed25519) | implemented (crates/dtn-identity) |
| Persistent SQLite bundle store | implemented (crates/dtn-storage) |
| Node engine (send/receive/inbox/dedup/expiry) | implemented (crates/dtn-core) |
| CLI | implemented (cli) — init/status/send/receive/bundles/decode/version |
| Hybrid routing engine | Phase 3 |
| BPSec (RFC 9172) | Phase 3 |
| TCPCLv4 (RFC 9174) | Phase 4 |
| Bluetooth / Wi-Fi Direct transports | Phase 4 |
| Android / iOS / Windows / Linux apps | Phases 5-7 |
| LoRa / radio / serial adapters | Phase 8 |
| Internet & satellite gateways | Phase 9 |

## Build

Requires Rust 1.70+.

```bash
cargo build --release
cargo test --workspace
cargo install --path cli  # provides the dtn-link binary
```

## CLI usage

```bash
dtn-link init 1                 # create node ipn:1.0
dtn-link status
dtn-link send dtn://node2 "hello offline" 3600
dtn-link receive < bundle.bin
dtn-link bundles
dtn-link version
```

Set `DTN_LINK_HOME` to control where the SQLite database is stored.

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Standards

- RFC 9171 — Bundle Protocol v7
- RFC 9172 — Bundle Protocol Security (planned)
- RFC 9173 — Default Security Contexts (planned)
- RFC 9174 — TCP Convergence Layer v4 (planned)

## License

MIT
