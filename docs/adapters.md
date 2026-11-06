# Transport Adapters

DTN-Link treats every link as **a byte stream plus a framing codec**.
The node engine (dtn-core), routing (dtn-routing) and security stack
(dtn-bpsec, dtn-keyring) are transport-independent; the dtn-transport
crate turns any byte link into a convergence layer.

## Architecture

    byte stream (TCP / serial / Bluetooth RFCOMM / Wi-Fi Direct socket)
            |
            v
    FrameCodec  (LengthPrefixCodec | KissCodec | custom)
            |
            v
    exchange_framed()  —  contact protocol:
        1. EID greeting frames both ways
        2. routing engine selects outbound bundles for the peer
        3. bundle frames pushed, then end-of-batch marker
        4. inbound bundles accepted into the node engine
            |
            v
    dtn_core::Node  (store-carry-forward: store, route, re-forward)

## Codecs

| Codec | Wire format | Use |
|---|---|---|
| LengthPrefixCodec | u32 big-endian length + payload; length 0 = end of batch | TCP-like links; wire-compatible with the dtn-daemon TCPCL-lite contact protocol |
| KissCodec | KISS (FEND 0xC0 / FESC 0xDB escaping, port 0 data frames); an empty data frame = end of batch | LoRa TNCs and serial radio modems |

Both codecs are incremental (byte-in, frame-out) so they work on
half-duplex and noisy links. KISS decoding skips line noise and
non-data command frames and resyncs on FEND.

## Streams

exchange_framed<S: Read + Write> accepts any stream:

* **TCP** — the daemon already does this; an interop test proves the
  generic exchange completes a contact against dtn_daemon::exchange.
* **Wi-Fi Direct** — a Wi-Fi Direct group is a normal IP network; the
  group owner listens on TCP and members connect, so the existing TCP
  transport covers Wi-Fi Direct once the platform forms the group.
* **Bluetooth** — once the OS pairing provides an RFCOMM/L2CAP socket
  (byte stream), exchange_framed runs over it unchanged. Platform
  glue for socket creation is the next milestone.
* **Serial / LoRa** — see below.

## Serial and LoRa (feature "serial")

    cargo build -p dtn-transport --features serial

enables real serial-port access through the serialport crate:

    use std::sync::{Arc, Mutex};
    use dtn_core::{Node, Strategy};

    let node = Arc::new(Mutex::new(
        Node::open(1, &".dtn-link/dtn.db".into(), Strategy::Epidemic).unwrap()));

    // KISS contact over a LoRa TNC on /dev/ttyUSB0 at 115200 baud:
    dtn_transport::serial::kiss_exchange(&node, "/dev/ttyUSB0", 115200)?;

The 200 ms port timeout makes a silent radio return a TimedOut error;
retry periodically — a missed contact now is a delivered bundle later.
That is the whole point of delay-tolerant networking.

## Testing adapters

dtn_transport::duplex::pair() returns two connected in-memory byte
streams, so codec and exchange tests run without any hardware. The
test suite covers:

* length-prefix codec roundtrips and oversized-frame rejection,
* KISS roundtrips including FEND/FESC escaping, multi-frame streams,
  line-noise resync, command-frame skipping, invalid escape rejection,
* two-way bundle exchanges over in-memory links (both codecs),
* TCP interop between the generic exchange and dtn-daemon.

## Honest scope

RFCOMM/Bluetooth and Wi-Fi Direct *platform* glue (OS socket creation,
pairing UI, group negotiation) is not in this crate yet; the transport
layer is ready for it. Internet/satellite gateways and federation come
in later phases.
