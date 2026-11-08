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
* **Wi-Fi Direct** — `dtn_transport::wifi_direct` (below): the group
  owner listens on TCP and members connect, with a retrying member
  helper for groups that are still forming.
* **Bluetooth** — once the OS pairing provides an RFCOMM/L2CAP socket
  (byte stream), exchange_framed runs over it unchanged. Platform
  glue for socket creation is the next milestone.
* **Serial / LoRa** — see below.

## Wi-Fi Direct (wifi_direct)

A Wi-Fi Direct group, once the platform negotiates it (wpa_supplicant
`p2p_*` on Linux, WifiP2pManager on Android), is an ordinary IP
network: the group owner is the access point and members are its
clients. So the convergence layer is plain TCP:

```rust
use std::sync::{Arc, Mutex};
use dtn_core::{Node, Strategy};

let node = Arc::new(Mutex::new(
    Node::open(1, &".dtn-link/dtn.db".into(), Strategy::Epidemic).unwrap()));

// Group owner — serve member contacts, one connection at a time:
let owner = dtn_transport::wifi_direct::GroupOwner::bind(4556)?;
let peers = owner.serve(&node, 8)?; // up to 8 member contacts

// Member — contact the group owner (its address on the p2p
// interface), retrying while the group is still forming:
let peer = dtn_transport::wifi_direct::contact_owner_with_retry(
    &node, "192.168.49.1:4556".parse()?, 20,
    std::time::Duration::from_millis(500))?;
```

`serve_contact` runs one full contact per accepted connection and
`contact_owner_with_retry` keeps dialing (groups take seconds to
form). A retried contact cannot duplicate bundles — the node engine
dedups on (source EID, creation timestamp). Group formation itself
(WPS pairing, owner election) belongs to the OS.

Tests exercise the group owner and member sides over real loopback
TCP: two-way bundle delivery, a member retrying until a late owner
binds, sequential service of multiple members by one owner, and
immediate reporting of protocol-level errors.

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
* TCP interop between the generic exchange and dtn-daemon,
* Wi-Fi Direct group-owner/member contacts over real loopback TCP
  (delivery, late-owner retry, sequential members, error reporting).

## Honest scope

Bluetooth RFCOMM platform glue (OS socket creation, pairing UI) is not
in this crate yet; the transport layer is ready for it — and an
OS-provided RFCOMM serial port already works today through the serial
feature. Internet/satellite gateways are implemented in the dtn-gateway crate (docs/gateways.md); federation comes in a later
phases.
