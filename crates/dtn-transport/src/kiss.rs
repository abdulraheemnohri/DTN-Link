//! KISS protocol framing — the de-facto standard used by LoRa TNCs,
//! AX.25 terminal node controllers and serial radio modems.
//!
//! Frame format: FEND, command byte, escaped payload, FEND. The command
//! byte carries a 4-bit port in the low nibble and a 4-bit command in
//! the high nibble (command 0 = asynchronous data). Payload bytes equal
//! to FEND/FESC are escaped as FESC TFEND / FESC TFESC.

/// Frame end delimiter.
pub const FEND: u8 = 0xC0;
/// Frame escape.
pub const FESC: u8 = 0xDB;
/// Transposed frame end (escaped FEND).
pub const TFEND: u8 = 0xDC;
/// Transposed frame escape (escaped FESC).
pub const TFESC: u8 = 0xDD;
/// KISS asynchronous-data command (port 0).
pub const PORT_DATA: u8 = 0x00;

/// KISS decoding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KissError {
    /// A transposition byte appeared without a preceding FESC.
    InvalidEscape,
}

impl std::fmt::Display for KissError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KissError::InvalidEscape => {
                write!(f, "KISS transposition byte outside frame escape")
            }
        }
    }
}

impl std::error::Error for KissError {}

/// Append a KISS data frame for 'port' carrying 'payload' to 'out'.
pub fn encode(payload: &[u8], port: u8, out: &mut Vec<u8>) {
    out.push(FEND);
    out.push(port & 0x0F);
    for &b in payload {
        match b {
            FEND => {
                out.push(FESC);
                out.push(TFEND);
            }
            FESC => {
                out.push(FESC);
                out.push(TFESC);
            }
            other => out.push(other),
        }
    }
    out.push(FEND);
}

#[derive(Debug)]
enum State {
    /// Between frames: waiting for FEND (line noise is skipped).
    Idle,
    /// Right after a FEND: the next byte is the command/port byte.
    Command,
    /// Inside a data frame for the given port.
    Data { port: u8 },
    /// Inside a data frame, right after FESC.
    Escaped { port: u8 },
    /// Skipping a non-data frame (hardware commands) until the next FEND.
    Skip,
}

/// Incremental KISS decoder: feed received bytes, get whole frames back.
pub struct Decoder {
    state: State,
    frame: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Decoder {
            state: State::Idle,
            frame: Vec::new(),
        }
    }

    /// Feed one byte from the link. Returns Some(frame) when a complete
    /// data frame arrived (possibly empty — used as end-of-batch).
    pub fn push_byte(&mut self, byte: u8) -> Result<Option<Vec<u8>>, KissError> {
        match std::mem::replace(&mut self.state, State::Idle) {
            State::Idle => {
                // Ignore line noise between frames.
                if byte == FEND {
                    self.state = State::Command;
                }
                Ok(None)
            }
            State::Command => {
                if byte == FEND {
                    self.state = State::Command;
                } else if byte & 0xF0 == 0 {
                    self.frame.clear();
                    self.state = State::Data {
                        port: byte & 0x0F,
                    };
                } else {
                    // Hardware/config command frame — not bundle data.
                    self.state = State::Skip;
                }
                Ok(None)
            }
            State::Data { port } => {
                if byte == FEND {
                    self.state = State::Command;
                    let frame = std::mem::take(&mut self.frame);
                    Ok(Some(frame))
                } else if byte == FESC {
                    self.state = State::Escaped { port };
                    Ok(None)
                } else {
                    self.frame.push(byte);
                    self.state = State::Data { port };
                    Ok(None)
                }
            }
            State::Escaped { port } => match byte {
                TFEND | TFESC => {
                    self.frame.push(if byte == TFEND { FEND } else { FESC });
                    self.state = State::Data { port };
                    Ok(None)
                }
                _ => Err(KissError::InvalidEscape),
            },
            State::Skip => {
                if byte == FEND {
                    self.state = State::Command;
                } else {
                    self.state = State::Skip;
                }
                Ok(None)
            }
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(dec: &mut Decoder, wire: &[u8]) -> Result<Vec<Vec<u8>>, KissError> {
        let mut frames = Vec::new();
        for &b in wire {
            if let Some(f) = dec.push_byte(b)? {
                frames.push(f);
            }
        }
        Ok(frames)
    }

    #[test]
    fn roundtrip_plain_payload() {
        let mut wire = Vec::new();
        encode(b"hello lora", PORT_DATA, &mut wire);
        let frames = decode_all(&mut Decoder::new(), &wire).unwrap();
        assert_eq!(frames, vec![b"hello lora".to_vec()]);
    }

    #[test]
    fn escapes_special_bytes() {
        let payload = [FEND, FESC, 0x00, 0xFF, FEND];
        let mut wire = Vec::new();
        encode(&payload, PORT_DATA, &mut wire);
        // Exactly two raw FENDs on the wire: the delimiters.
        assert_eq!(wire.iter().filter(|&&b| b == FEND).count(), 2);
        let frames = decode_all(&mut Decoder::new(), &wire).unwrap();
        assert_eq!(frames, vec![payload.to_vec()]);
    }

    #[test]
    fn multiple_frames_in_one_stream() {
        let mut wire = Vec::new();
        encode(b"first", PORT_DATA, &mut wire);
        encode(b"second", PORT_DATA, &mut wire);
        encode(&[], PORT_DATA, &mut wire); // end-of-batch marker
        let frames = decode_all(&mut Decoder::new(), &wire).unwrap();
        assert_eq!(
            frames,
            vec![b"first".to_vec(), b"second".to_vec(), Vec::new()]
        );
    }

    #[test]
    fn resyncs_after_line_noise() {
        let mut wire = vec![0x41, 0x42, 0x0d, 0x0a]; // boot noise
        encode(b"data after noise", PORT_DATA, &mut wire);
        let frames = decode_all(&mut Decoder::new(), &wire).unwrap();
        assert_eq!(frames, vec![b"data after noise".to_vec()]);
    }

    #[test]
    fn skips_non_data_command_frames() {
        let mut wire = Vec::new();
        wire.push(FEND);
        wire.push(0x08); // command 8 (set hardware) — not data
        wire.extend_from_slice(b"params");
        wire.push(FEND);
        encode(b"real data", PORT_DATA, &mut wire);
        let frames = decode_all(&mut Decoder::new(), &wire).unwrap();
        assert_eq!(frames, vec![b"real data".to_vec()]);
    }

    #[test]
    fn invalid_escape_is_rejected() {
        // FESC followed by a byte that is neither TFEND nor TFESC.
        let wire = [FEND, PORT_DATA, b'x', FESC, 0x00, FEND];
        let mut dec = Decoder::new();
        let mut errored = false;
        for &b in &wire {
            if dec.push_byte(b).is_err() {
                errored = true;
            }
        }
        assert!(errored, "invalid escape must be reported");
    }
}
