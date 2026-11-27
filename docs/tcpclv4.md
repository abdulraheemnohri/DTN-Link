# TCPCLv4 (RFC 9174) — session protocol

DTN-Link implements the TCP convergence-layer protocol version 4 at the
wire level in `crates/dtn-tcpcl/src/v4.rs`, with an SDNV codec in
`crates/dtn-tcpcl/src/sdnv.rs`.

## Implemented

- Contact header (RFC 9174 section 4.2): magic "dtn!" + version 4.
- SESS_INIT / SESS_ACK handshake (section 4.6): contact flags,
  keepalive interval (negotiated as the minimum of both offers) and
  session EIDs.
- SESS_REFUSE: sent when an unsupported contact version arrives.
- KEEPALIVE (section 5.1.1).
- MSG_REJECT (section 5.1.2) for unknown message types.
- Bundle transfers (section 5.2): XFER_INIT announces the transfer id
  and total length, one or more XFER_SEGMENTs carry the data — a
  single START/END segment with the RFC's minimum-overhead policy
  (section 3.6) or chunked segmentation with `send_bundle_chunked`;
  every XFER_SEGMENT carries its data length as an SDNV between the
  transfer id and the data octets (section 5.2.2); the receiver
  reassembles the segments and answers one XFER_ACK for the full
  transfer. XFER_REFUSE is decoded and surfaced as an event.
- SESS_TERM (section 6.1) with reason codes.

## Segmentation (Phase 28)

    // RFC 9174 section 3.6 "Predictable Message Sizing" policy:
    let tid = sess.send_bundle_chunked(&bytes, 1400)?; // ~MTU-sized segments
    // first segment carries START, the last carries END, the receiver
    // answers one XFER_ACK covering the full transfer. Session::pump
    // reassembles in arrival order and enforces: START only on the
    // first segment, exactly one END, no overshoot of the announced
    // length, and the END segment landing exactly on it.

`send_bundle` keeps the section 3.6 minimum-overhead single-segment
policy. The data-length SDNV in XFER_SEGMENT is a framing detail of
this crate: both sides of a session always come from the same code,
and each side ignores what it does not send.

## TLS session security (Phase 29)

RFC 9174 section 4.4 is implemented in
`crates/dtn-tcpcl/src/v4_tls.rs` behind the cargo feature `tls`
(rustls + rustls-pemfile + sha2; rcgen as a test-only dependency):

    cargo test -p dtn-tcpcl --features tls

Per the RFC, the TLS handshake completes immediately after the TCP
connection is established and BEFORE the contact header; the whole
TCPCLv4 session then runs inside the TLS channel.

- `TlsServerSetup::from_pem(cert_chain_pem, key_pem)` — accept-side
  setup (PEM chain + private key, no client auth). `upgrade(tcp)`
  wraps an accepted stream and completes the handshake, yielding a
  `TlsServerStream`.
- `TlsClientSetup::pinned(cert_pem, server_name)` — dial-side setup
  with TOFU-style certificate pinning: the SHA-256 fingerprint of the
  peer's leaf certificate DER (`cert_pin(cert_pem)`) is the only
  accepted certificate. TLS-level handshake signatures stay fully
  verified by rustls; only the web-PKI trust decision is replaced by
  the pin, so an impostor without the pinned certificate's private key
  cannot complete the handshake, and any re-issued certificate changes
  the pin and fails closed.
- The TLS streams implement `Read + Write`, so they plug straight
  into `v4::Session::new` — the full session protocol (handshake,
  keepalives, acked transfers incl. chunked segmentation, SESS_TERM)
  runs unchanged inside TLS, and `send_bundle_chunked` is exercised
  over TLS in the tests.

Trust model: the pin replaces the web-PKI chain decision only; it is
the transport-level analogue of the keyring's trust-on-first-use pin
of an Ed25519 key. Bundle-layer authentication (BPSec BIB over the
keyring) remains the application-level identity check.

## Daemon and CLI wiring (Phase 30)

The daemon consumes the TLS layer directly, behind the cargo feature
`tls` (enable with `cargo build -p dtn-link-cli --features tls`):

    # Node B — accept TLS contacts (PEM certificate chain + key)
    dtn-link daemon --listen 0.0.0.0:4556 --tls-cert node-b.pem --tls-key node-b-key.pem

    # Node A — dial B over TLS, pinning B's certificate
    dtn-link daemon --listen 0.0.0.0:4557 --peers node-b.example.net:4556 \
        --tls-pin 9f86d081884c7d65... --tls-name node-b.example.net

- `--tls-cert <pem>` + `--tls-key <pem>` — accept side: every
  incoming contact is upgraded to TLS before the contact header
  (RFC 9174 section 4.4) and runs as a full TCPCLv4 session.
- `--tls-pin <hex|@cert.pem>` — dial side: outgoing contacts dial
  TLS and pin the peer certificate to the SHA-256 fingerprint (64
  hex characters, or `@cert.pem` to compute the pin from a PEM
  file; `dtn_daemon::tls_pin_from_spec`). `--tls-name` sets the
  TLS server name (SNI), defaulting to `localhost`.
- Fail closed: TLS flags on a binary built without the `tls`
  feature abort the daemon instead of silently downgrading the
  contacts to plain TCP.

## Not implemented yet (honest scope)

- Well-known-port TLS discovery (RFC 9174 section 4.4 says nodes
  SHOULD listen on a TLS-capable port; operators choose the port) and
  client-certificate (mutual TLS) authentication.
- Transfer/session extension items (sections 4.8 and 5.2.5).
- Per-segment XFER_ACKs and reactive fragmentation on partially
  acknowledged transfers (the receiver acknowledges only the
  transfer-completing segment).

## Using the session driver

    use dtn_tcpcl::v4::{Event, Session};

    let mut sess = Session::new(stream, "dtn://node-1", 30);
    sess.handshake(true)?;            // active side; passive uses false
    let tid = sess.send_bundle(&bundle_bytes)?;
    while let Some(event) = sess.pump()? {
        match event {
            Event::Acked { transfer_id, .. } if transfer_id == tid => break,
            Event::Bundle(bytes) => { /* store via the node engine */ }
            _ => {}
        }
    }
    sess.send_sess_term(0, 0)?;

The daemon uses this via `exchange_v4()`, which performs the full
contact: handshake, acked outbound transfers selected by the routing
engine, inbound bundles stored through the node engine, and a clean
SESS_TERM shutdown.

Over TLS (feature `tls`), pass the upgraded stream to `Session::new`
instead of the raw TCP stream:

    let tls = TlsClientSetup::pinned(&peer_cert_pem, "gateway.example.net")?
        .upgrade(tcp_stream)?;
    let mut sess = Session::new(tls, "dtn://node-1", 30);
