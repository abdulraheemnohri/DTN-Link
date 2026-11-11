//! dtn-transport — pluggable convergence adapters for DTN-Link.
//!
//! Phase 8/10 groundwork: every DTN-Link link is a byte stream plus a
//! framing codec. This crate provides:
//!
//! * FrameCodec — pluggable framing over any byte link.
//! * LengthPrefixCodec — u32 length-prefixed frames, wire-compatible
//!   with the dtn-daemon TCPCL-lite contact protocol (EID greeting
//!   frame, bundle frames, end-of-batch marker).
//! * KissCodec — KISS framing as used by LoRa TNCs and serial radio
//!   modems (FEND/FESC escaping), enabling DTN over LoRa links.
//! * exchange_framed — a full contact exchange (EID greeting,
//!   store-carry-forward outbound push, inbound receive loop) over any
//!   Read + Write stream: TCP sockets, serial ports, Bluetooth RFCOMM
//!   sockets, Wi-Fi Direct group-owner sockets.
//! * duplex — an in-memory byte-stream pair for testing adapters.
//! * bluetooth — RFCOMM glue: the standard contact exchange over
//!   any OS-provided RFCOMM byte link, a hardware-independent retry
//!   helper for intermittent Bluetooth links, and (cargo feature
//!   "serial") opening of OS-paired Bluetooth SPP serial devices
//!   such as /dev/rfcomm0.
//! * serial (cargo feature "serial") — real serial-port glue via
//!   the serialport crate for LoRa TNC / radio-modem hardware.
//! * wifi_direct — Wi-Fi Direct group glue: the group owner listens
//!   on TCP (GroupOwner) and members connect (contact_owner and a
//!   retrying variant for groups that are still forming).
//!
//! The same node engine (dtn_core::Node) is shared by all adapters, so a
//! bundle accepted on any transport is stored, routed and re-forwarded
//! on any other transport.

pub mod bluetooth;
pub mod duplex;
pub mod kiss;
#[cfg(feature = "serial")]
pub mod serial;
pub mod wifi_direct;

use dtn_bpv7::Eid;
use dtn_core::Node;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Maximum single-frame payload accepted from a link (16 MiB),
/// matching dtn-tcpcl's limit.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// Errors surfaced by adapter transports.
#[derive(Debug)]
pub enum TransportError {
    /// Underlying byte stream failed.
    Io(std::io::Error),
    /// Peer announced a frame larger than MAX_FRAME.
    TooLarge(u32),
    /// Link closed cleanly (end of batch / EOF).
    Closed,
    /// The peer sent bytes no valid frame can be built from.
    Malformed(&'static str),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "io error: {e}"),
            TransportError::TooLarge(n) => write!(f, "frame too large: {n}"),
            TransportError::Closed => write!(f, "link closed"),
            TransportError::Malformed(m) => write!(f, "malformed frame: {m}"),
        }
    }
}

impl std::error::Error for TransportError {}
impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}

/// Pluggable framing for a byte link: how payloads (EID greetings,
/// bundles, end-of-batch markers) are delimited on the wire.
pub trait FrameCodec {
    /// Append the wire encoding of one payload to 'out'.
    fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>);
    /// Feed a single received byte; Some(payload) when a complete frame
    /// arrived. An empty payload marks end-of-batch.
    fn push_byte(&mut self, byte: u8) -> Result<Option<Vec<u8>>, TransportError>;
    /// Append the end-of-batch marker to 'out'.
    fn end_of_batch(&mut self, out: &mut Vec<u8>);
}

enum LpState {
    Header,
    Body,
}

/// u32 big-endian length-prefixed frames — the same wire format as the
/// dtn-daemon TCPCL-lite contact protocol (end of batch = length 0).
pub struct LengthPrefixCodec {
    state: LpState,
    header: [u8; 4],
    filled: usize,
    body: Vec<u8>,
    remaining: u32,
}

impl LengthPrefixCodec {
    pub fn new() -> Self {
        LengthPrefixCodec {
            state: LpState::Header,
            header: [0u8; 4],
            filled: 0,
            body: Vec::new(),
            remaining: 0,
        }
    }
}

impl Default for LengthPrefixCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameCodec for LengthPrefixCodec {
    fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
    }

    fn push_byte(&mut self, byte: u8) -> Result<Option<Vec<u8>>, TransportError> {
        match self.state {
            LpState::Header => {
                self.header[self.filled] = byte;
                self.filled += 1;
                if self.filled == 4 {
                    self.filled = 0;
                    let len = u32::from_be_bytes(self.header);
                    if len == 0 {
                        // End-of-batch marker: deliver it as an empty frame.
                        return Ok(Some(Vec::new()));
                    }
                    if len > MAX_FRAME {
                        return Err(TransportError::TooLarge(len));
                    }
                    self.body.clear();
                    self.remaining = len;
                    self.state = LpState::Body;
                }
                Ok(None)
            }
            LpState::Body => {
                self.body.push(byte);
                self.remaining -= 1;
                if self.remaining == 0 {
                    self.state = LpState::Header;
                    return Ok(Some(std::mem::take(&mut self.body)));
                }
                Ok(None)
            }
        }
    }

    fn end_of_batch(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(&0u32.to_be_bytes());
    }
}

/// KISS framing (LoRa TNC / serial radio modems) as a FrameCodec.
pub struct KissCodec {
    dec: kiss::Decoder,
}

impl KissCodec {
    pub fn new() -> Self {
        KissCodec {
            dec: kiss::Decoder::new(),
        }
    }
}

impl Default for KissCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameCodec for KissCodec {
    fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        kiss::encode(payload, kiss::PORT_DATA, out);
    }

    fn push_byte(&mut self, byte: u8) -> Result<Option<Vec<u8>>, TransportError> {
        match self.dec.push_byte(byte) {
            Ok(frame) => Ok(frame),
            Err(kiss::KissError::InvalidEscape) => {
                Err(TransportError::Malformed("invalid KISS escape sequence"))
            }
        }
    }

    fn end_of_batch(&mut self, out: &mut Vec<u8>) {
        // A zero-length KISS data frame signals end of batch.
        kiss::encode(&[], kiss::PORT_DATA, out);
    }
}

fn parse_eid(bytes: &[u8]) -> Eid {
    let s = String::from_utf8_lossy(bytes);
    Eid::dtn(s.trim().trim_start_matches("dtn://").trim_end_matches('/'))
}

fn read_frame_framed<S: Read>(
    stream: &mut S,
    codec: &mut dyn FrameCodec,
) -> Result<Vec<u8>, TransportError> {
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(TransportError::Closed);
        }
        for &b in &buf[..n] {
            if let Some(frame) = codec.push_byte(b)? {
                if frame.is_empty() {
                    return Err(TransportError::Closed);
                }
                return Ok(frame);
            }
        }
    }
}

/// Run one full contact exchange over any byte stream:
///
/// 1. both sides exchange an EID greeting frame,
/// 2. the routing engine selects outbound bundles for the peer,
/// 3. they are pushed, followed by an end-of-batch marker,
/// 4. inbound frames are accepted into the node engine until the peer
///    sends its own end-of-batch marker or closes the link.
///
/// Wire-compatible with dtn_daemon::exchange when used with
/// LengthPrefixCodec; KISS-framed for LoRa/serial when used with
/// KissCodec.
pub fn exchange_framed<S: Read + Write>(
    node: &Arc<Mutex<Node>>,
    stream: &mut S,
    codec: &mut dyn FrameCodec,
) -> Result<Eid, TransportError> {
    let our_eid = node.lock().unwrap().eid();

    let mut out = Vec::new();
    codec.encode(our_eid.as_uri().as_bytes(), &mut out);
    stream.write_all(&out)?;
    stream.flush()?;

    let peer_raw = read_frame_framed(stream, codec)?;
    let peer = parse_eid(&peer_raw);

    let outbound = {
        let mut n = node.lock().unwrap();
        n.select_outbound(&peer).unwrap_or_default()
    };
    let mut out = Vec::new();
    for ob in &outbound {
        codec.encode(&ob.bundle.encode(), &mut out);
    }
    codec.end_of_batch(&mut out);
    stream.write_all(&out)?;
    stream.flush()?;

    loop {
        match read_frame_framed(stream, codec) {
            Ok(bytes) => {
                let mut n = node.lock().unwrap();
                let _ = n.receive(&bytes);
            }
            Err(TransportError::Closed) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(peer)
}

/// Convenience wrapper: TCPCL-lite-compatible exchange (length-prefixed
/// framing) over any stream.
pub fn exchange<S: Read + Write>(
    node: &Arc<Mutex<Node>>,
    stream: &mut S,
) -> Result<Eid, TransportError> {
    let mut codec = LengthPrefixCodec::new();
    exchange_framed(node, stream, &mut codec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_core::Strategy;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::mpsc;

    fn mem_node(n: u64) -> Arc<Mutex<Node>> {
        Arc::new(Mutex::new(
            Node::open(n, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap(),
        ))
    }

    #[test]
    fn length_prefix_codec_roundtrips() {
        let mut codec = LengthPrefixCodec::new();
        let mut wire = Vec::new();
        codec.encode(b"hello", &mut wire);
        codec.encode(b"second frame", &mut wire);
        codec.end_of_batch(&mut wire);

        let mut frames: Vec<Vec<u8>> = Vec::new();
        for &b in &wire {
            if let Some(f) = codec.push_byte(b).unwrap() {
                frames.push(f);
            }
        }
        assert_eq!(
            frames,
            vec![b"hello".to_vec(), b"second frame".to_vec(), Vec::new()]
        );
    }

    #[test]
    fn length_prefix_rejects_oversized_frame() {
        let mut codec = LengthPrefixCodec::new();
        let wire = (MAX_FRAME + 1).to_be_bytes();
        let mut saw_too_large = false;
        for &b in &wire {
            match codec.push_byte(b) {
                Err(TransportError::TooLarge(_)) => {
                    saw_too_large = true;
                    break;
                }
                Ok(_) => {}
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert!(saw_too_large, "oversized header must be rejected");
    }

    #[test]
    fn length_prefix_exchange_two_way_over_memory_link() {
        let (mut a_side, mut b_side) = duplex::pair();
        let node_a = mem_node(1);
        let node_b = mem_node(2);
        node_a
            .lock()
            .unwrap()
            .send(Eid::ipn(2, 0), b"a to b over stream".to_vec(), 3600)
            .unwrap();
        node_b
            .lock()
            .unwrap()
            .send(Eid::ipn(1, 0), b"b to a over stream".to_vec(), 3600)
            .unwrap();

        let na = node_a.clone();
        let nb = node_b.clone();
        let sa = std::thread::spawn(move || {
            let mut c = LengthPrefixCodec::new();
            exchange_framed(&na, &mut a_side, &mut c)
        });
        let sb = std::thread::spawn(move || {
            let mut c = LengthPrefixCodec::new();
            exchange_framed(&nb, &mut b_side, &mut c)
        });
        sa.join().unwrap().unwrap();
        sb.join().unwrap().unwrap();

        assert_eq!(node_a.lock().unwrap().inbox().unwrap().len(), 1);
        assert_eq!(node_b.lock().unwrap().inbox().unwrap().len(), 1);
    }

    #[test]
    fn kiss_exchange_two_way_over_memory_link() {
        let (mut a_side, mut b_side) = duplex::pair();
        let node_a = mem_node(1);
        let node_b = mem_node(2);
        node_a
            .lock()
            .unwrap()
            .send(Eid::ipn(2, 0), b"a to b over kiss".to_vec(), 3600)
            .unwrap();
        node_b
            .lock()
            .unwrap()
            .send(Eid::ipn(1, 0), b"b to a over kiss".to_vec(), 3600)
            .unwrap();

        let na = node_a.clone();
        let nb = node_b.clone();
        let sa = std::thread::spawn(move || {
            let mut c = KissCodec::new();
            exchange_framed(&na, &mut a_side, &mut c)
        });
        let sb = std::thread::spawn(move || {
            let mut c = KissCodec::new();
            exchange_framed(&nb, &mut b_side, &mut c)
        });
        sa.join().unwrap().unwrap();
        sb.join().unwrap().unwrap();

        assert_eq!(node_a.lock().unwrap().inbox().unwrap().len(), 1);
        assert_eq!(node_b.lock().unwrap().inbox().unwrap().len(), 1);
    }

    #[test]
    fn tcpcl_lite_interop_with_daemon_over_tcp() {
        // The generic stream exchange with LengthPrefixCodec must
        // complete a real contact against dtn-daemon's TCPCL-lite
        // exchange over TCP — proving wire compatibility.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let node = mem_node(2);
            let (mut stream, _) = listener.accept().unwrap();
            dtn_daemon::exchange(&node, None, &mut stream).unwrap();
            tx.send(node.lock().unwrap().inbox().unwrap().len()).unwrap();
        });

        let client_node = mem_node(1);
        client_node
            .lock()
            .unwrap()
            .send(Eid::ipn(2, 0), b"from generic transport".to_vec(), 3600)
            .unwrap();

        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        exchange(&client_node, &mut stream).unwrap();

        let delivered = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(delivered, 1, "bundle must cross adapter <-> daemon");
        server.join().unwrap();
    }
}
