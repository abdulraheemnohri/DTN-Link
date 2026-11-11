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
* **Bluetooth** — `dtn_transport::bluetooth` (below): RFCOMM glue —
  contact_stream runs the standard wire format over any OS-provided
  RFCOMM byte link, retry() handles intermittent links, and the
  serial feature opens OS-paired Bluetooth SPP devices.
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

## Bluetooth RFCOMM (bluetooth)

Once the OS pairs a Bluetooth device and exposes its Serial Port
Profile (SPP) link as a byte stream (/dev/rfcomm0 on Linux, the COM
port Windows creates for a paired SPP device, /dev/tty.<device>-
SerialPort on macOS), RFCOMM is a plain byte link and the standard
contact exchange runs over it unchanged:

```rust
use std::sync::{Arc, Mutex};
use dtn_core::{Node, Strategy};

let node = Arc::new(Mutex::new(
    Node::open(1, &".dtn-link/dtn.db".into(), Strategy::Epidemic).unwrap()));

// Over any platform-created RFCOMM socket / stream:
let peer = dtn_transport::bluetooth::contact_stream(&node, &mut stream)?;

// With cargo feature "serial", over an OS-paired SPP serial device,
// retrying while the peer device is out of range or asleep:
let peer = dtn_transport::bluetooth::contact_with_retry(
    &node, "/dev/rfcomm0", dtn_transport::bluetooth::DEFAULT_BAUD,
    30, std::time::Duration::from_millis(500))?;
```

Bluetooth links are intermittent: `retry` retries connection-level
failures and reports protocol-level errors immediately (retrying
cannot fix a malformed frame). A retried contact cannot duplicate
bundles — the node engine dedups on (source EID, creation
timestamp). Pairing and RFCOMM socket creation belong to the OS
(Bluetooth settings / sdptool / Android BluetoothAdapter).

Tests prove the contact path over an in-memory byte link (the same
code runs over a real RFCOMM port once one is opened) and the retry
semantics: success after transient failures, immediate protocol
errors, exhausted retries, zero-attempts-still-dials-once.

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
  (delivery, late-owner retry, sequential members, error reporting),
* Bluetooth RFCOMM contact over a byte link plus retry semantics
  (transient-failure recovery, immediate protocol errors, exhausted
  retries).

## Honest scope

Pairing and RFCOMM socket creation belong to the OS; an OS-paired
SPP serial device works today via the serial feature, and any
platform-created RFCOMM socket works through contact_stream /
exchange_framed. Internet/satellite gateways are implemented in the
dtn-gateway crate (docs/gateways.md); inter-region federation is
implemented in the dtn-federation crate (docs/federation.md).
