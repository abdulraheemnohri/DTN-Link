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
- Bundle transfers (section 5.2): XFER_INIT announces transfer id and
  length, one XFER_SEGMENT carries all bytes (single START/END segment,
  the RFC's minimum-overhead policy from section 3.6), the receiver
  answers with XFER_ACK; XFER_REFUSE is decoded and surfaced as an
  event.
- SESS_TERM (section 6.1) with reason codes.

## Not implemented yet (honest scope)

- TLS (section 4.4): the CAN_TLS contact flag is never offered.
- Transfer/session extension items (sections 4.8 and 5.2.5).
- Multi-segment transfers: every transfer is one segment, which RFC
  9174 section 3.6 documents as a valid single-segment policy.

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
