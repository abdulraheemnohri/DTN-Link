//! RFC 9174 — TCP Convergence-Layer Protocol version 4 (Phase 7).
//!
//! Wire-level implementation of the TCPCLv4 session protocol:
//!
//! * Contact header validation: magic "dtn!" + version 4, with
//!   SESS_REFUSE sent back on version mismatch.
//! * SESS_INIT / SESS_ACK handshake exchanging contact flags, the
//!   negotiated keepalive interval (minimum of the peers' offers) and
//!   session EIDs.
//! * KEEPALIVE upkeep messages.
//! * MSG_REJECT for unknown message types.
//! * Acknowledged bundle transfer: XFER_INIT announces transfer id and
//!   length, XFER_SEGMENT carries the data, XFER_ACK confirms reception,
//!   XFER_REFUSE rejects a transfer.
//! * SESS_TERM session termination with reason codes.
//!
//! Transfers follow RFC 9174 section 3.6's "minimum overhead" policy:
//! every transfer is a single segment with both the START and END flags
//! set, so receivers need no segment reassembly (a documented single-
//! segment policy case). Honest scope: TLS (section 4.4) is not
//! offered (CAN_TLS is never set) and extension items are future work.

use super::sdnv;
use std::io::{ErrorKind, Read, Write};

/// Contact header magic: ASCII "dtn!".
pub const MAGIC: [u8; 4] = [0x64, 0x74, 0x6e, 0x21];
/// TCPCL protocol version implemented here.
pub const VERSION: u8 = 0x04;

/// TCPCLv4 message types (RFC 9174 message type registry).
pub const MSG_SESS_INIT: u8 = 0x01;
pub const MSG_SESS_ACK: u8 = 0x02;
pub const MSG_SESS_REFUSE: u8 = 0x03;
pub const MSG_KEEPALIVE: u8 = 0x04;
pub const MSG_MSG_REJECT: u8 = 0x05;
pub const MSG_XFER_INIT: u8 = 0x06;
pub const MSG_XFER_REFUSE: u8 = 0x07;
pub const MSG_XFER_ACK: u8 = 0x08;
pub const MSG_XFER_SEGMENT: u8 = 0x09;
pub const MSG_SESS_TERM: u8 = 0x0a;

/// Message header flag: first segment of a transfer.
pub const FLAG_SEG_START: u8 = 0x01;
/// Message header flag: final segment of a transfer.
pub const FLAG_SEG_END: u8 = 0x02;

/// Contact flag: entity can upgrade to TLS.
pub const CF_CAN_TLS: u64 = 0x01;
/// Contact flag: entity can refuse bundles.
pub const CF_BUNDLE_REFUSAL: u64 = 0x02;
/// Contact flag: entity acknowledges segments (XFER_ACK).
pub const CF_SEGMENT_ACK: u64 = 0x04;

/// SESS_REFUSE reason: unspecified.
pub const REFUSE_UNKNOWN: u8 = 0x00;
/// SESS_REFUSE reason: unsupported contact version.
pub const REFUSE_VERSION: u8 = 0x01;
/// SESS_REFUSE reason: unacceptable session EID.
pub const REFUSE_EID: u8 = 0x02;

/// MSG_REJECT reason: unknown message type.
pub const REJECT_UNKNOWN_TYPE: u8 = 0x00;
/// MSG_REJECT reason: malformed message.
pub const REJECT_MALFORMED: u8 = 0x01;

/// SESS_TERM reason: unspecified.
pub const TERM_UNKNOWN: u8 = 0x00;
/// SESS_TERM reason: idle timeout.
pub const TERM_IDLE_TIMEOUT: u8 = 0x01;
/// SESS_TERM reason: local policy / other.
pub const TERM_OTHER: u8 = 0x02;

/// Errors produced by the TCPCLv4 session layer.
#[derive(Debug)]
pub enum SessionError {
    Io(std::io::Error),
    /// The peer closed the connection.
    Closed,
    /// The contact header magic was not "dtn!".
    BadMagic([u8; 4]),
    /// The peer speaks a different TCPCL version.
    UnsupportedVersion(u8),
    /// The peer refused the session (reason code inside).
    Refused(u8),
    /// The peer sent an unknown message type.
    UnknownMessageType(u8),
    /// A protocol violation was detected.
    Protocol(&'static str),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Io(e) => write!(f, "io error: {e}"),
            SessionError::Closed => write!(f, "session closed"),
            SessionError::BadMagic(m) => write!(f, "bad contact magic: {m:02x?}"),
            SessionError::UnsupportedVersion(v) => write!(f, "unsupported TCPCL version: {v}"),
            SessionError::Refused(r) => write!(f, "session refused (reason {r})"),
            SessionError::UnknownMessageType(t) => write!(f, "unknown message type: {t:#04x}"),
            SessionError::Protocol(msg) => write!(f, "protocol violation: {msg}"),
        }
    }
}

impl std::error::Error for SessionError {}

fn map_io(e: std::io::Error) -> SessionError {
    if e.kind() == ErrorKind::UnexpectedEof {
        SessionError::Closed
    } else {
        SessionError::Io(e)
    }
}

/// One decoded TCPCLv4 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Contact flags, offered keepalive interval, session EID.
    SessInit {
        flags: u64,
        keepalive: u16,
        eid: Vec<u8>,
    },
    /// Mirrors SESS_INIT with the acknowledging entity's parameters.
    SessAck {
        flags: u64,
        keepalive: u16,
        eid: Vec<u8>,
    },
    SessRefuse {
        reason: u8,
    },
    /// No payload; session upkeep ping.
    Keepalive,
    MsgReject {
        reason: u8,
    },
    XferInit {
        transfer_id: u64,
        length: u64,
    },
    XferRefuse {
        transfer_id: u64,
        reason: u8,
    },
    XferAck {
        transfer_id: u64,
        ack_flags: u8,
        received: u64,
    },
    XferSegment {
        transfer_id: u64,
        flags: u8,
        data: Vec<u8>,
    },
    SessTerm {
        flags: u8,
        reason: u8,
    },
}

impl Message {
    pub fn message_type(&self) -> u8 {
        match self {
            Message::SessInit { .. } => MSG_SESS_INIT,
            Message::SessAck { .. } => MSG_SESS_ACK,
            Message::SessRefuse { .. } => MSG_SESS_REFUSE,
            Message::Keepalive => MSG_KEEPALIVE,
            Message::MsgReject { .. } => MSG_MSG_REJECT,
            Message::XferInit { .. } => MSG_XFER_INIT,
            Message::XferRefuse { .. } => MSG_XFER_REFUSE,
            Message::XferAck { .. } => MSG_XFER_ACK,
            Message::XferSegment { .. } => MSG_XFER_SEGMENT,
            Message::SessTerm { .. } => MSG_SESS_TERM,
        }
    }

    /// The flag nibble of the message header octet.
    pub fn header_flags(&self) -> u8 {
        match self {
            Message::XferSegment { flags, .. } => flags & (FLAG_SEG_START | FLAG_SEG_END),
            Message::XferAck { ack_flags, .. } => ack_flags & (FLAG_SEG_START | FLAG_SEG_END),
            Message::SessTerm { flags, .. } => flags & 0x01,
            _ => 0,
        }
    }

    /// Encode the complete message, header octet included.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((self.message_type() << 4) | (self.header_flags() & 0x0f));
        match self {
            Message::SessInit { flags, keepalive, eid }
            | Message::SessAck { flags, keepalive, eid } => {
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(&keepalive.to_be_bytes());
                sdnv::encode_into(eid.len() as u64, &mut out);
                out.extend_from_slice(eid);
            }
            Message::SessRefuse { reason } | Message::MsgReject { reason } => out.push(*reason),
            Message::Keepalive => {}
            Message::XferInit { transfer_id, length } => {
                sdnv::encode_into(*transfer_id, &mut out);
                sdnv::encode_into(*length, &mut out);
            }
            Message::XferRefuse { transfer_id, reason } => {
                sdnv::encode_into(*transfer_id, &mut out);
                out.push(*reason);
            }
            Message::XferAck { transfer_id, received, .. } => {
                sdnv::encode_into(*transfer_id, &mut out);
                sdnv::encode_into(*received, &mut out);
            }
            Message::XferSegment { transfer_id, data, .. } => {
                sdnv::encode_into(*transfer_id, &mut out);
                out.extend_from_slice(data);
            }
            Message::SessTerm { reason, .. } => out.push(*reason),
        }
        out
    }

    /// Decode exactly one message from a complete buffer.
    pub fn decode(buf: &[u8]) -> Result<Message, SessionError> {
        if buf.is_empty() {
            return Err(SessionError::Protocol("empty message"));
        }
        Self::decode_body(buf[0], &buf[1..])
    }

    fn decode_body(header: u8, body: &[u8]) -> Result<Message, SessionError> {
        let mtype = header >> 4;
        let flags = header & 0x0f;
        Ok(match mtype {
            MSG_SESS_INIT | MSG_SESS_ACK => {
                if body.len() < 10 {
                    return Err(SessionError::Protocol("short session message"));
                }
                let contact_flags =
                    u64::from_be_bytes(body[0..8].try_into().expect("fixed 8 octets"));
                let keepalive =
                    u16::from_be_bytes(body[8..10].try_into().expect("fixed 2 octets"));
                let (elen, rest) = split_sdnv(&body[10..])?;
                let eid_len = elen as usize;
                if rest.len() < eid_len {
                    return Err(SessionError::Protocol("short session EID"));
                }
                let eid = rest[..eid_len].to_vec();
                if mtype == MSG_SESS_INIT {
                    Message::SessInit { flags: contact_flags, keepalive, eid }
                } else {
                    Message::SessAck { flags: contact_flags, keepalive, eid }
                }
            }
            MSG_SESS_REFUSE => Message::SessRefuse { reason: body[0] },
            MSG_KEEPALIVE => Message::Keepalive,
            MSG_MSG_REJECT => Message::MsgReject { reason: body[0] },
            MSG_XFER_INIT => {
                let (transfer_id, rest) = split_sdnv(body)?;
                let (length, _) = split_sdnv(rest)?;
                Message::XferInit { transfer_id, length }
            }
            MSG_XFER_REFUSE => {
                let (transfer_id, rest) = split_sdnv(body)?;
                match rest.first() {
                    Some(&r) => Message::XferRefuse { transfer_id, reason: r },
                    None => return Err(SessionError::Protocol("short XFER_REFUSE")),
                }
            }
            MSG_XFER_ACK => {
                let (transfer_id, rest) = split_sdnv(body)?;
                let (received, _) = split_sdnv(rest)?;
                Message::XferAck { transfer_id, ack_flags: flags, received }
            }
            MSG_XFER_SEGMENT => {
                let (transfer_id, rest) = split_sdnv(body)?;
                Message::XferSegment { transfer_id, flags, data: rest.to_vec() }
            }
            MSG_SESS_TERM => match body.first() {
                Some(&r) => Message::SessTerm { flags, reason: r },
                None => return Err(SessionError::Protocol("short SESS_TERM")),
            },
            other => return Err(SessionError::UnknownMessageType(other)),
        })
    }
}

fn split_sdnv(buf: &[u8]) -> Result<(u64, &[u8]), SessionError> {
    let (v, n) = sdnv::decode(buf).map_err(|_| SessionError::Protocol("malformed SDNV"))?;
    Ok((v, &buf[n..]))
}

/// Session-level events surfaced by `Session::pump`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A complete incoming transfer (bundle bytes).
    Bundle(Vec<u8>),
    /// The peer acknowledged our transfer.
    Acked { transfer_id: u64, received: u64 },
    /// The peer refused our transfer.
    Refused { transfer_id: u64, reason: u8 },
    /// A KEEPALIVE arrived.
    Keepalive,
    /// The peer terminated the session.
    Terminated { flags: u8, reason: u8 },
    /// The peer rejected one of our messages.
    Rejected { reason: u8 },
}

/// A TCPCLv4 session driving any `Read + Write` transport.
///
/// In-progress incoming transfer state: (transfer id, announced length,
/// accumulated bytes). Under the single-segment policy the announced
/// length fully determines the data extent of the XFER_SEGMENT.
pub struct Session<S: Read + Write> {
    stream: S,
    pub local_eid: Vec<u8>,
    pub peer_eid: Vec<u8>,
    pub local_contact_flags: u64,
    pub peer_contact_flags: u64,
    /// Keepalive interval in seconds, negotiated as the minimum of the
    /// peers' offers.
    pub negotiated_keepalive: u16,
    next_transfer_id: u64,
    incoming: Option<(u64, u64, Vec<u8>)>,
}

impl<S: Read + Write> Session<S> {
    pub fn new(stream: S, local_eid: &str, keepalive_secs: u16) -> Self {
        Session {
            stream,
            local_eid: local_eid.as_bytes().to_vec(),
            peer_eid: Vec::new(),
            local_contact_flags: CF_SEGMENT_ACK,
            peer_contact_flags: 0,
            negotiated_keepalive: keepalive_secs,
            next_transfer_id: 1,
            incoming: None,
        }
    }

    pub fn send_keepalive(&mut self) -> Result<(), SessionError> {
        self.write_msg(&Message::Keepalive)
    }

    pub fn send_reject(&mut self, reason: u8) -> Result<(), SessionError> {
        self.write_msg(&Message::MsgReject { reason })
    }

    pub fn send_sess_term(&mut self, flags: u8, reason: u8) -> Result<(), SessionError> {
        self.write_msg(&Message::SessTerm { flags, reason })
    }

    /// Send one bundle as a transfer; returns the transfer id used.
    ///
    /// Single-segment policy: XFER_INIT announces the length, then one
    /// XFER_SEGMENT carries all bytes with START and END both set.
    pub fn send_bundle(&mut self, data: &[u8]) -> Result<u64, SessionError> {
        let transfer_id = self.next_transfer_id;
        self.next_transfer_id += 1;
        self.write_msg(&Message::XferInit {
            transfer_id,
            length: data.len() as u64,
        })?;
        self.write_msg(&Message::XferSegment {
            transfer_id,
            flags: FLAG_SEG_START | FLAG_SEG_END,
            data: data.to_vec(),
        })?;
        Ok(transfer_id)
    }

    /// Perform the session establishment handshake. The active side
    /// (which opened the TCP connection) sends its contact header first.
    pub fn handshake(&mut self, active: bool) -> Result<(), SessionError> {
        if active {
            self.send_contact()?;
        }
        self.read_contact()?;
        if !active {
            self.send_contact()?;
        }
        self.write_msg(&Message::SessAck {
            flags: self.local_contact_flags,
            keepalive: self.negotiated_keepalive,
            eid: self.local_eid.clone(),
        })?;
        match self.read_message()? {
            Message::SessAck { flags, keepalive, .. } => {
                self.peer_contact_flags = flags;
                let _ = keepalive; // already negotiated from SESS_INIT
                Ok(())
            }
            Message::SessRefuse { reason } => Err(SessionError::Refused(reason)),
            _ => Err(SessionError::Protocol("expected SESS_ACK")),
        }
    }

    /// Contact header + SESS_INIT, per RFC 9174 section 4.2.
    fn send_contact(&mut self) -> Result<(), SessionError> {
        let init = Message::SessInit {
            flags: self.local_contact_flags,
            keepalive: self.negotiated_keepalive,
            eid: self.local_eid.clone(),
        };
        let mut out = Vec::with_capacity(16 + self.local_eid.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&init.encode());
        self.stream.write_all(&out).map_err(SessionError::Io)?;
        self.stream.flush().map_err(SessionError::Io)
    }

    /// Refuse a session after receiving a bad contact header.
    pub fn send_refusal(&mut self, reason: u8) -> Result<(), SessionError> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&Message::SessRefuse { reason }.encode());
        self.stream.write_all(&out).map_err(SessionError::Io)?;
        self.stream.flush().map_err(SessionError::Io)
    }

    /// Read and validate the peer's contact header and first message.
    fn read_contact(&mut self) -> Result<(), SessionError> {
        let head = self.read_exact_n(6)?;
        if head[0..4] != MAGIC[..] {
            return Err(SessionError::BadMagic([head[0], head[1], head[2], head[3]]));
        }
        if head[4] != VERSION {
            let _ = self.send_refusal(REFUSE_VERSION);
            return Err(SessionError::UnsupportedVersion(head[4]));
        }
        let mtype = head[5] >> 4;
        if mtype == MSG_SESS_REFUSE {
            let reason = self.read_u8()?;
            return Err(SessionError::Refused(reason));
        }
        if mtype != MSG_SESS_INIT {
            return Err(SessionError::Protocol("expected SESS_INIT as first message"));
        }
        match self.read_message_body(head[5])? {
            Message::SessInit { flags, keepalive, eid } => {
                self.peer_contact_flags = flags;
                self.peer_eid = eid;
                self.negotiated_keepalive = self.negotiated_keepalive.min(keepalive);
                Ok(())
            }
            _ => Err(SessionError::Protocol("expected SESS_INIT body")),
        }
    }

    /// Read one message from the stream.
    pub fn read_message(&mut self) -> Result<Message, SessionError> {
        let header = self.read_u8()?;
        self.read_message_body(header)
    }

    fn read_message_body(&mut self, header: u8) -> Result<Message, SessionError> {
        let mtype = header >> 4;
        let flags = header & 0x0f;
        Ok(match mtype {
            MSG_SESS_INIT | MSG_SESS_ACK => {
                let fixed = self.read_exact_n(10)?;
                let contact_flags =
                    u64::from_be_bytes(fixed[0..8].try_into().expect("fixed 8 octets"));
                let keepalive =
                    u16::from_be_bytes(fixed[8..10].try_into().expect("fixed 2 octets"));
                let elen = self.read_sdnv()? as usize;
                let eid = self.read_exact_n(elen)?;
                if mtype == MSG_SESS_INIT {
                    Message::SessInit { flags: contact_flags, keepalive, eid }
                } else {
                    Message::SessAck { flags: contact_flags, keepalive, eid }
                }
            }
            MSG_SESS_REFUSE => Message::SessRefuse { reason: self.read_u8()? },
            MSG_KEEPALIVE => Message::Keepalive,
            MSG_MSG_REJECT => Message::MsgReject { reason: self.read_u8()? },
            MSG_XFER_INIT => {
                let transfer_id = self.read_sdnv()?;
                let length = self.read_sdnv()?;
                Message::XferInit { transfer_id, length }
            }
            MSG_XFER_REFUSE => {
                let transfer_id = self.read_sdnv()?;
                Message::XferRefuse { transfer_id, reason: self.read_u8()? }
            }
            MSG_XFER_ACK => {
                let transfer_id = self.read_sdnv()?;
                let received = self.read_sdnv()?;
                Message::XferAck { transfer_id, ack_flags: flags, received }
            }
            MSG_XFER_SEGMENT => {
                let transfer_id = self.read_sdnv()?;
                let (id, length, have) = match self.incoming.as_ref() {
                    Some((id, length, buf)) => (*id, *length, buf.len() as u64),
                    None => {
                        return Err(SessionError::Protocol(
                            "XFER_SEGMENT without a matching XFER_INIT",
                        ))
                    }
                };
                if id != transfer_id {
                    return Err(SessionError::Protocol("XFER_SEGMENT for unknown transfer"));
                }
                let remaining = (length - have) as usize;
                let mut data = self.read_exact_n(remaining)?;
                if let Some((_, _, buf)) = self.incoming.as_mut() {
                    buf.append(&mut data);
                }
                Message::XferSegment { transfer_id, flags, data: Vec::new() }
            }
            MSG_SESS_TERM => {
                let reason = self.read_u8()?;
                Message::SessTerm { flags, reason }
            }
            other => return Err(SessionError::UnknownMessageType(other)),
        })
    }

    /// Read one message and apply session behavior:
    ///
    /// * XFER_INIT registers the incoming transfer.
    /// * XFER_SEGMENT accumulates data (single-segment policy) and, once
    ///   the announced length is reached, emits `Event::Bundle` and
    ///   sends an XFER_ACK back to the peer.
    ///
    /// Returns `None` for messages with no external effect.
    pub fn pump(&mut self) -> Result<Option<Event>, SessionError> {
        let header = self.read_u8()?;
        let msg = self.read_message_body(header)?;
        Ok(match msg {
            Message::XferInit { transfer_id, length } => {
                self.incoming = Some((transfer_id, length, Vec::new()));
                None
            }
            Message::XferSegment { transfer_id, flags, .. } => {
                let complete = match self.incoming.as_ref() {
                    Some((_, length, buf)) => buf.len() as u64 == *length,
                    None => false,
                };
                if !complete {
                    return Err(SessionError::Protocol("incomplete transfer segment"));
                }
                if flags & FLAG_SEG_END == 0 {
                    return Err(SessionError::Protocol(
                        "only single-segment transfers are supported",
                    ));
                }
                let (id, length, buf) = self.incoming.take().expect("incoming transfer");
                // Acknowledge the received segment (RFC 9174 section 5.2.3).
                self.write_msg(&Message::XferAck {
                    transfer_id: id,
                    ack_flags: FLAG_SEG_START | FLAG_SEG_END,
                    received: length,
                })?;
                Some(Event::Bundle(buf))
            }
            Message::XferAck { transfer_id, received, .. } => {
                Some(Event::Acked { transfer_id, received })
            }
            Message::XferRefuse { transfer_id, reason } => {
                Some(Event::Refused { transfer_id, reason })
            }
            Message::Keepalive => Some(Event::Keepalive),
            Message::SessTerm { flags, reason } => Some(Event::Terminated { flags, reason }),
            Message::MsgReject { reason } => Some(Event::Rejected { reason }),
            Message::SessRefuse { reason } => return Err(SessionError::Refused(reason)),
            Message::SessInit { .. } | Message::SessAck { .. } => {
                return Err(SessionError::Protocol("unexpected SESS_INIT/SESS_ACK"))
            }
        })
    }

    fn write_msg(&mut self, msg: &Message) -> Result<(), SessionError> {
        let bytes = msg.encode();
        self.stream.write_all(&bytes).map_err(SessionError::Io)?;
        self.stream.flush().map_err(SessionError::Io)
    }

    fn read_u8(&mut self) -> Result<u8, SessionError> {
        let mut b = [0u8; 1];
        match self.stream.read(&mut b) {
            Ok(0) => Err(SessionError::Closed),
            Ok(_) => Ok(b[0]),
            Err(e) => Err(map_io(e)),
        }
    }

    fn read_exact_n(&mut self, n: usize) -> Result<Vec<u8>, SessionError> {
        let mut buf = vec![0u8; n];
        match self.stream.read_exact(&mut buf) {
            Ok(()) => Ok(buf),
            Err(e) => Err(map_io(e)),
        }
    }

    /// Read one SDNV octet by octet.
    fn read_sdnv(&mut self) -> Result<u64, SessionError> {
        let mut value: u128 = 0;
        let mut count = 0u8;
        loop {
            let b = self.read_u8()?;
            count += 1;
            if count > 10 {
                return Err(SessionError::Protocol("SDNV too long"));
            }
            value = (value << 7) | u128::from(b & 0x7f);
            if b & 0x80 == 0 {
                if value > u64::MAX as u128 {
                    return Err(SessionError::Protocol("SDNV overflows u64"));
                }
                return Ok(value as u64);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// A connected loopback socket pair.
    fn channel() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn message_roundtrips() {
        let msgs = vec![
            Message::SessInit { flags: CF_SEGMENT_ACK, keepalive: 30, eid: b"dtn://node-a".to_vec() },
            Message::SessAck { flags: CF_BUNDLE_REFUSAL, keepalive: 15, eid: b"ipn:2.0".to_vec() },
            Message::SessRefuse { reason: REFUSE_VERSION },
            Message::Keepalive,
            Message::MsgReject { reason: REJECT_UNKNOWN_TYPE },
            Message::XferInit { transfer_id: 7, length: 0x1234 },
            Message::XferRefuse { transfer_id: 7, reason: 0x03 },
            Message::XferAck { transfer_id: 7, ack_flags: FLAG_SEG_START | FLAG_SEG_END, received: 0x1234 },
            Message::XferSegment { transfer_id: 7, flags: FLAG_SEG_START | FLAG_SEG_END, data: b"payload bytes".to_vec() },
            Message::SessTerm { flags: 0, reason: TERM_OTHER },
        ];
        for m in &msgs {
            assert_eq!(&Message::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn unknown_message_type_is_rejected() {
        assert!(matches!(
            Message::decode(&[0xf0]),
            Err(SessionError::UnknownMessageType(0x0f))
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut raw = TcpStream::connect(addr).unwrap();
        raw.write_all(&[0xf0]).unwrap();
        let (sock, _) = listener.accept().unwrap();
        let mut sess = Session::new(sock, "dtn://x", 0);
        match sess.read_message() {
            Err(SessionError::UnknownMessageType(0x0f)) => {}
            other => panic!("expected UnknownMessageType, got {other:?}"),
        }
    }

    #[test]
    fn bad_contact_version_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut raw = TcpStream::connect(addr).unwrap();
        let mut head = Vec::new();
        head.extend_from_slice(&MAGIC);
        head.push(VERSION + 1);
        head.push(MSG_SESS_INIT << 4);
        raw.write_all(&head).unwrap();
        let (sock, _) = listener.accept().unwrap();
        let mut sess = Session::new(sock, "dtn://x", 0);
        match sess.read_contact() {
            Err(SessionError::UnsupportedVersion(v)) => assert_eq!(v, VERSION + 1),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn full_session_bundle_transfer() {
        let (a_sock, p_sock) = channel();
        let mut active = Session::new(a_sock, "dtn://node-a", 30);
        let mut passive = Session::new(p_sock, "dtn://node-b", 45);

        let passive_thread = std::thread::spawn(move || {
            passive.handshake(false).unwrap();
            assert_eq!(passive.peer_eid.as_slice(), b"dtn://node-a");
            assert_eq!(passive.negotiated_keepalive, 30);
            let bundle = loop {
                if let Some(ev) = passive.pump().unwrap() {
                    match ev {
                        Event::Bundle(b) => break b,
                        _ => continue,
                    }
                }
            };
            assert_eq!(bundle, b"first bundle");
            passive.send_bundle(b"reply bundle").unwrap();
            passive.send_sess_term(0, TERM_OTHER).unwrap();
        });

        active.handshake(true).unwrap();
        assert_eq!(active.peer_eid.as_slice(), b"dtn://node-b");
        assert_eq!(active.negotiated_keepalive, 30);

        let tid = active.send_bundle(b"first bundle").unwrap();
        let mut acked = false;
        while !acked {
            match active.pump().unwrap() {
                Some(Event::Acked { transfer_id, received }) => {
                    assert_eq!(transfer_id, tid);
                    assert_eq!(received, b"first bundle".len() as u64);
                    acked = true;
                }
                Some(_) => {}
                None => {}
            }
        }

        let reply = loop {
            match active.pump().unwrap() {
                Some(Event::Bundle(b)) => break b,
                _ => continue,
            }
        };
        assert_eq!(reply, b"reply bundle");

        let reason = loop {
            match active.pump().unwrap() {
                Some(Event::Terminated { reason, .. }) => break reason,
                _ => continue,
            }
        };
        assert_eq!(reason, TERM_OTHER);
        passive_thread.join().unwrap();
    }

    #[test]
    fn keepalive_roundtrip() {
        let (a_sock, p_sock) = channel();
        let mut active = Session::new(a_sock, "dtn://a", 30);
        let mut passive = Session::new(p_sock, "dtn://b", 30);

        let passive_thread = std::thread::spawn(move || {
            passive.handshake(false).unwrap();
            match passive.pump().unwrap() {
                Some(Event::Keepalive) => {}
                other => panic!("expected keepalive, got {other:?}"),
            }
            passive.send_keepalive().unwrap();
        });

        active.handshake(true).unwrap();
        active.send_keepalive().unwrap();
        match active.pump().unwrap() {
            Some(Event::Keepalive) => {}
            other => panic!("expected keepalive, got {other:?}"),
        }
        passive_thread.join().unwrap();
    }
}
