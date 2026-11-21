//! Phase 24 — remote read receipts carried through the message channel.
//!
//! When a node has read the inbound messages of a conversation, it can
//! send the remote peer one receipt bundle whose payload uses the wire
//! format below. The peer's `poll_inbox_with_receipts` decodes it and
//! confirms exactly the outbound conversation messages whose carrying
//! bundles are named, so a UI can show real "read ✓" state that crossed
//! the DTN as a normal store-carry-forward bundle:
//!
//!   [5-byte magic "DTNR1"]
//!   [u16 BE entry count]
//!   per entry:
//!     [u16 BE bundle-key length][bundle-key UTF-8 bytes]
//!   [u64 BE ack timestamp (unix seconds)]
//!
//! The bundle key is the `source|creation-ts|seq` identity of the
//! bundle that carried the original message (the same string the app
//! database stores on outbound rows via `bundle_key`), so correlation
//! is exact and never depends on clock agreement between the peers.
//!
//! decode() is strict: exact lengths, no trailing bytes, the entry
//! count is capped at MAX_ENTRIES, every bundle key is capped at
//! MAX_KEY_BYTES and must be valid non-empty UTF-8. A receipt never
//! becomes a conversation row; it only flips confirmed-read state.

/// Wire-format magic prefix for read-receipt payloads.
pub const MAGIC: &[u8; 5] = b"DTNR1";
/// Maximum acknowledged bundles per receipt.
pub const MAX_ENTRIES: usize = 256;
/// Maximum bundle-key length in bytes (UTF-8).
pub const MAX_KEY_BYTES: usize = 256;

/// A read receipt: the bundle keys of the acknowledged messages plus
/// the unix-seconds timestamp the sender acknowledged them at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReceipt {
    pub keys: Vec<String>,
    pub acked_at: u64,
}

/// What a receipt application produced on the receiving side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedReceipt {
    /// EID URI of the peer that sent the receipt (the conversation).
    pub from: String,
    /// Unix seconds the sender acknowledged at.
    pub acked_at: u64,
    /// How many of the local outbound conversation rows were confirmed
    /// by this receipt. Keys pointing at messages this node never sent
    /// (spoofed or corrupted receipts) are ignored, never guessed.
    pub confirmed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    TooShort,
    BadMagic,
    TooManyEntries,
    KeyError,
    LengthMismatch,
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::TooShort => write!(f, "read-receipt payload truncated"),
            ReceiptError::BadMagic => write!(f, "not a read-receipt payload (bad magic)"),
            ReceiptError::TooManyEntries => write!(
                f,
                "read receipt acknowledges too many messages (max {MAX_ENTRIES})"
            ),
            ReceiptError::KeyError => write!(
                f,
                "read receipt contains an invalid bundle key (empty, over {} bytes or not UTF-8)",
                MAX_KEY_BYTES
            ),
            ReceiptError::LengthMismatch => write!(
                f,
                "read-receipt length fields do not match the payload"
            ),
        }
    }
}

impl std::error::Error for ReceiptError {}

impl ReadReceipt {
    /// A receipt acknowledging `keys`, timestamped now.
    pub fn new(keys: Vec<String>, acked_at: u64) -> Result<Self, ReceiptError> {
        if keys.len() > MAX_ENTRIES {
            return Err(ReceiptError::TooManyEntries);
        }
        for key in &keys {
            validate_key(key)?;
        }
        Ok(ReadReceipt { keys, acked_at })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(5 + 2 + 8 + self.keys.iter().map(|k| 2 + k.len()).sum::<usize>());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.keys.len() as u16).to_be_bytes());
        for key in &self.keys {
            out.extend_from_slice(&(key.len() as u16).to_be_bytes());
            out.extend_from_slice(key.as_bytes());
        }
        out.extend_from_slice(&self.acked_at.to_be_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, ReceiptError> {
        // Smallest possible payload: magic + count + ack timestamp.
        if data.len() < 5 + 2 + 8 {
            return Err(ReceiptError::TooShort);
        }
        if &data[..5] != MAGIC {
            return Err(ReceiptError::BadMagic);
        }
        let count = u16::from_be_bytes([data[5], data[6]]) as usize;
        if count > MAX_ENTRIES {
            return Err(ReceiptError::TooManyEntries);
        }
        let mut idx = 7usize;
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < idx + 2 {
                return Err(ReceiptError::TooShort);
            }
            let klen = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
            idx += 2;
            if klen == 0 || klen > MAX_KEY_BYTES {
                return Err(ReceiptError::KeyError);
            }
            if data.len() < idx + klen {
                return Err(ReceiptError::TooShort);
            }
            let key = std::str::from_utf8(&data[idx..idx + klen])
                .map_err(|_| ReceiptError::KeyError)?;
            validate_key(key)?;
            keys.push(key.to_string());
            idx += klen;
        }
        if data.len() < idx + 8 {
            return Err(ReceiptError::TooShort);
        }
        let acked_at = u64::from_be_bytes(data[idx..idx + 8].try_into().unwrap());
        idx += 8;
        if idx != data.len() {
            return Err(ReceiptError::LengthMismatch);
        }
        Ok(ReadReceipt { keys, acked_at })
    }
}

/// A bundle key is the app database's `source|ts|seq` correlation
/// string: non-empty, bounded, valid UTF-8 with a plain printable body
/// (it never contains control characters or newline).
fn validate_key(key: &str) -> Result<(), ReceiptError> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(ReceiptError::KeyError);
    }
    if key.chars().any(|c| c.is_control()) {
        return Err(ReceiptError::KeyError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u64) -> String {
        format!("dtn://node{i}|1000|{i}")
    }

    #[test]
    fn roundtrip_is_exact() {
        let r = ReadReceipt::new(vec![key(1), key(7), key(42)], 1_700_000_123).unwrap();
        let d = ReadReceipt::decode(&r.encode()).unwrap();
        assert_eq!(d, r);
        assert_eq!(d.keys.len(), 3);
    }

    #[test]
    fn empty_entry_list_is_valid() {
        // A receipt with nothing to acknowledge never leaves the wire
        // (send_read_receipts refuses), but the codec still round-trips it.
        let r = ReadReceipt::new(vec![], 5).unwrap();
        assert_eq!(ReadReceipt::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn wire_layout() {
        let r = ReadReceipt::new(vec!["a|b|c".to_string()], 9).unwrap();
        let e = r.encode();
        assert_eq!(&e[..5], &b"DTNR1"[..]);
        assert_eq!(&e[5..7], 1u16.to_be_bytes().as_slice());
        assert_eq!(&e[7..9], 5u16.to_be_bytes().as_slice());
        assert_eq!(&e[9..14], &b"a|b|c"[..]);
        assert_eq!(&e[14..], 9u64.to_be_bytes().as_slice());
        assert_eq!(e.len(), 5 + 2 + 2 + 5 + 8);
    }

    #[test]
    fn rejections() {
        assert_eq!(ReadReceipt::decode(&[]), Err(ReceiptError::TooShort));
        assert_eq!(ReadReceipt::decode(&[0u8; 14]), Err(ReceiptError::TooShort));
        // Bad magic (structurally long enough).
        let mut bad = ReadReceipt::new(vec![key(1)], 1).unwrap().encode();
        bad[0] = b'X';
        assert_eq!(ReadReceipt::decode(&bad), Err(ReceiptError::BadMagic));
        // Entry count above the cap.
        let mut many = ReadReceipt::new(vec![key(1)], 1).unwrap().encode();
        many[5..7].copy_from_slice(&(MAX_ENTRIES as u16 + 1).to_be_bytes());
        assert_eq!(ReadReceipt::decode(&many), Err(ReceiptError::TooManyEntries));
        // Zero-length bundle key.
        let mut zerolen = ReadReceipt::new(vec![key(1)], 1).unwrap().encode();
        zerolen[7..9].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(ReadReceipt::decode(&zerolen), Err(ReceiptError::KeyError));
        // Over-long declared key length.
        let mut long = ReadReceipt::new(vec![key(1)], 1).unwrap().encode();
        long[7..9].copy_from_slice(&(MAX_KEY_BYTES as u16 + 1).to_be_bytes());
        assert_eq!(ReadReceipt::decode(&long), Err(ReceiptError::KeyError));
        // Truncated key bytes.
        let e = ReadReceipt::new(vec![key(1)], 1).unwrap().encode();
        assert_eq!(ReadReceipt::decode(&e[..e.len() - 1 - 8]), Err(ReceiptError::TooShort));
        // Truncated ack timestamp.
        assert_eq!(ReadReceipt::decode(&e[..e.len() - 1]), Err(ReceiptError::TooShort));
        // Trailing bytes.
        let mut trail = e.clone();
        trail.push(0);
        assert_eq!(ReadReceipt::decode(&trail), Err(ReceiptError::LengthMismatch));
        // Non-UTF-8 key bytes.
        let mut badutf = ReadReceipt::new(vec![key(1)], 1).unwrap().encode();
        badutf[9] = 0xFF;
        assert_eq!(ReadReceipt::decode(&badutf), Err(ReceiptError::KeyError));
        // Control character inside a key.
        assert_eq!(
            ReadReceipt::new(vec!["a\nb".to_string()], 1),
            Err(ReceiptError::KeyError)
        );
        // Encoder refuses over-cap entry lists before anything is built.
        let overflow: Vec<String> = (0..MAX_ENTRIES + 1).map(key).collect();
        assert_eq!(ReadReceipt::new(overflow, 1), Err(ReceiptError::TooManyEntries));
    }

    #[test]
    fn max_caps_accepted() {
        let keys: Vec<String> = (0..MAX_ENTRIES).map(key).collect();
        let r = ReadReceipt::new(keys, u64::MAX).unwrap();
        assert_eq!(ReadReceipt::decode(&r.encode()).unwrap().keys.len(), MAX_ENTRIES);
        let big = key(1).len();
        assert!(big <= MAX_KEY_BYTES, "test keys must fit the cap");
    }
}
