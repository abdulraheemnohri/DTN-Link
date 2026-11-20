//! Phase 23 — file attachments carried through the message channel.
//!
//! A file rides the normal chat pipeline as one bundle whose payload
//! uses the wire format below. `dtn-app` decodes it on both the send
//! and the receive side, so the conversation shows the standard
//! `[attachment: name (N bytes)]` marker and the bytes live in the
//! app database until `extract_attachment` writes them back to disk:
//!
//!   [5-byte magic "DTNA1"]
//!   [u16 BE filename length][filename UTF-8 bytes]
//!   [u64 BE content length][content bytes]
//!
//! decode() is strict: exact lengths, no trailing bytes, the filename
//! is capped at 255 bytes and validated safe (no path separators, no
//! "..", no control characters), and the content length must match the
//! remaining bytes exactly. Content above MAX_CONTENT_BYTES is refused,
//! so one attachment can never blow past the 16 MiB framing limit of
//! the transport layer inside one bundle.

/// Wire-format magic prefix for attachment payloads.
pub const MAGIC: &[u8; 5] = b"DTNA1";
/// Maximum filename length in bytes (UTF-8).
pub const MAX_FILENAME_BYTES: usize = 255;
/// Maximum attachment content in bytes; stays well under the 16 MiB
/// frame limit of the transport layer once bundle overhead is added.
pub const MAX_CONTENT_BYTES: usize = 8 * 1024 * 1024;

/// One file attachment. The filename is always validated safe, the
/// content is arbitrary bytes (binary-safe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub filename: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentError {
    TooShort,
    BadMagic,
    FilenameTooLong,
    UnsafeFilename,
    ContentTooLarge,
    LengthMismatch,
}

impl std::fmt::Display for AttachmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachmentError::TooShort => write!(f, "attachment payload truncated"),
            AttachmentError::BadMagic => write!(f, "not an attachment payload (bad magic)"),
            AttachmentError::FilenameTooLong => write!(f, "attachment filename too long (max {MAX_FILENAME_BYTES} bytes)"),
            AttachmentError::UnsafeFilename => write!(f, "unsafe attachment filename (path separators, \"..\", control characters)"),
            AttachmentError::ContentTooLarge => write!(f, "attachment too large (max {MAX_CONTENT_BYTES} bytes)"),
            AttachmentError::LengthMismatch => write!(f, "attachment length field does not match the payload"),
        }
    }
}

impl std::error::Error for AttachmentError {}

/// Reject anything that is not a single, plain, safe filename.
pub fn validate_filename(name: &str) -> Result<(), AttachmentError> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(AttachmentError::UnsafeFilename);
    }
    if name.len() > MAX_FILENAME_BYTES {
        return Err(AttachmentError::FilenameTooLong);
    }
    // Control characters, NUL, and both path separators are refused
    // (ASCII byte checks cover '/' and '\\' exactly; the char loop
    // additionally catches non-ASCII control characters).
    if name.bytes().any(|b| b == b'/' || b == b'\\' || b == 0 || (b as char).is_control()) {
        return Err(AttachmentError::UnsafeFilename);
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(AttachmentError::UnsafeFilename);
    }
    Ok(())
}

/// The standard message-body marker for an attachment.
pub fn marker(filename: &str, content_len: usize) -> String {
    format!("[attachment: {filename} ({content_len} bytes)]")
}

impl Attachment {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + 8 + self.filename.len() + self.content.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.filename.len() as u16).to_be_bytes());
        out.extend_from_slice(self.filename.as_bytes());
        out.extend_from_slice(&(self.content.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.content);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, AttachmentError> {
        // Smallest possible payload: magic + 2 filename-length + 8 content-length.
        if data.len() < 5 + 2 + 8 {
            return Err(AttachmentError::TooShort);
        }
        if &data[..5] != MAGIC {
            return Err(AttachmentError::BadMagic);
        }
        let mut idx = 5usize;
        let flen = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;
        if data.len() < idx + flen {
            return Err(AttachmentError::TooShort);
        }
        let filename = std::str::from_utf8(&data[idx..idx + flen])
            .map_err(|_| AttachmentError::UnsafeFilename)?;
        validate_filename(filename)?;
        idx += flen;
        if data.len() < idx + 8 {
            return Err(AttachmentError::TooShort);
        }
        let clen = u64::from_be_bytes(data[idx..idx + 8].try_into().unwrap());
        idx += 8;
        if clen > MAX_CONTENT_BYTES as u64 {
            return Err(AttachmentError::ContentTooLarge);
        }
        let content = &data[idx..];
        if content.len() as u64 != clen {
            return Err(AttachmentError::LengthMismatch);
        }
        Ok(Attachment {
            filename: filename.to_string(),
            content: content.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(name: &str, content: &[u8]) -> Vec<u8> {
        Attachment { filename: name.to_string(), content: content.to_vec() }.encode()
    }

    #[test]
    fn roundtrip_is_binary_safe() {
        let content: Vec<u8> = (0..=u8::MAX).collect();
        let a = Attachment::decode(&encoded("photo.bin", &content)).unwrap();
        assert_eq!(a.filename, "photo.bin");
        assert_eq!(a.content, content);
    }

    #[test]
    fn zero_length_content_roundtrips() {
        let a = Attachment::decode(&encoded("empty.txt", &[])).unwrap();
        assert_eq!(a.filename, "empty.txt");
        assert!(a.content.is_empty());
    }

    #[test]
    fn wire_layout() {
        let e = encoded("ab", &[1, 2, 3]);
        assert_eq!(&e[..5], &b"DTNA1"[..]);
        assert_eq!(&e[5..7], [0u8, 2].as_slice());
        assert_eq!(&e[7..9], &b"ab"[..]);
        assert_eq!(&e[9..17], 3u64.to_be_bytes().as_slice());
        assert_eq!(&e[17..], &[1u8, 2, 3][..]);
        assert_eq!(e.len(), 5 + 2 + 2 + 8 + 3);
    }

    #[test]
    fn rejections() {
        assert_eq!(Attachment::decode(&[]), Err(AttachmentError::TooShort));
        assert_eq!(Attachment::decode(&[0u8; 15]), Err(AttachmentError::TooShort));
        // Bad magic (but structurally long enough).
        let mut bad = encoded("x", b"y");
        bad[0] = b'X';
        assert_eq!(Attachment::decode(&bad), Err(AttachmentError::BadMagic));
        // Truncated filename.
        let e = encoded("abcdef", b"zz");
        assert_eq!(Attachment::decode(&e[..8]), Err(AttachmentError::TooShort));
        assert_eq!(Attachment::decode(&e[..9]), Err(AttachmentError::TooShort));
        // Missing content-length bytes.
        assert_eq!(Attachment::decode(&e[..5 + 2 + 6 + 7]), Err(AttachmentError::TooShort));
        // Content length does not match (bytes missing).
        assert_eq!(Attachment::decode(&e[..e.len() - 1]), Err(AttachmentError::LengthMismatch));
        // Content length does not match (trailing bytes).
        let mut long = e.clone();
        long.push(0xFF);
        assert_eq!(Attachment::decode(&long), Err(AttachmentError::LengthMismatch));
        // Declared content length above the cap — refused without
        // ever materializing 8 MiB.
        let mut huge = encoded("x", b"y");
        let lpos = 5 + 2 + 1; // after magic + flen + "x"
        huge[lpos..lpos + 8].copy_from_slice(&(MAX_CONTENT_BYTES as u64 + 1).to_be_bytes());
        assert_eq!(Attachment::decode(&huge), Err(AttachmentError::ContentTooLarge));
        // Non-UTF-8 filename fails closed.
        let mut badname = encoded("ok.txt", b"z");
        badname[5..7].copy_from_slice(&1u16.to_be_bytes());
        badname[7] = 0xFF;
        assert_eq!(Attachment::decode(&badname), Err(AttachmentError::UnsafeFilename));
    }

    #[test]
    fn filename_validation() {
        for ok in ["notes.txt", "photo 2026.png", ".hidden", "تسویر.png", &"a".repeat(255)] {
            validate_filename(ok).unwrap_or_else(|e| panic!("{ok:?} rejected: {e}"));
        }
        for bad in [
            "", ".", "..", "a/b", "b\\\\c", "..\\\\etc/passwd", "a\u{0}b",
            "a\u{1}b", &"a".repeat(256),
        ] {
            assert!(validate_filename(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn marker_format() {
        assert_eq!(marker("report.pdf", 2048), "[attachment: report.pdf (2048 bytes)]");
        assert_eq!(marker("x", 0), "[attachment: x (0 bytes)]");
    }

    #[test]
    fn cap_exact_declared_length_with_missing_content() {
        // A declared cap-exact length with absent content is a plain
        // LengthMismatch (never a silent success or a huge copy).
        let mut e = encoded("big.bin", b"y");
        let lpos = 5 + 2 + 7;
        e[lpos..lpos + 8].copy_from_slice(&(MAX_CONTENT_BYTES as u64).to_be_bytes());
        assert_eq!(Attachment::decode(&e), Err(AttachmentError::LengthMismatch));
    }
}
