//! SDNV (Self-Delimiting Numeric Value) codec — the variable-length
//! integer encoding used by DTN protocols (RFC 5050) and by the
//! TCPCLv4 message formats (RFC 9174).
//!
//! Each octet carries 7 value bits; bit 7 set means another octet
//! follows. Values are big-endian, canonical (no redundant padding).

/// Errors returned when decoding an SDNV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdnvError {
    /// The buffer ended before the value's final octet.
    Truncated,
    /// The encoded value does not fit in a u64.
    Overflow,
}

impl std::fmt::Display for SdnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdnvError::Truncated => write!(f, "SDNV truncated"),
            SdnvError::Overflow => write!(f, "SDNV overflows u64"),
        }
    }
}

impl std::error::Error for SdnvError {}

/// Encode `value` as a canonical SDNV.
pub fn encode(value: u64) -> Vec<u8> {
    // Collect 7-bit groups, least-significant first.
    let mut groups = Vec::new();
    let mut rest = value;
    loop {
        groups.push((rest & 0x7f) as u8);
        rest >>= 7;
        if rest == 0 {
            break;
        }
    }
    // Emit most-significant group first; every octet except the last
    // carries the continuation bit.
    let n = groups.len();
    let mut out = vec![0u8; n];
    for (i, &g) in groups.iter().enumerate() {
        out[n - 1 - i] = g | if i + 1 < n { 0x80 } else { 0 };
    }
    out
}

/// Append the SDNV encoding of `value` to `out`.
pub fn encode_into(value: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&encode(value));
}

/// Decode a single SDNV from the front of `buf`.
/// Returns the value and the number of octets consumed.
pub fn decode(buf: &[u8]) -> Result<(u64, usize), SdnvError> {
    if buf.is_empty() {
        return Err(SdnvError::Truncated);
    }
    let mut value: u128 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= 10 {
            // 10 octets already provide 70 value bits; anything longer
            // can never fit a u64.
            return Err(SdnvError::Overflow);
        }
        value = (value << 7) | u128::from(b & 0x7f);
        if b & 0x80 == 0 {
            if value > u64::MAX as u128 {
                return Err(SdnvError::Overflow);
            }
            return Ok((value as u64, i + 1));
        }
    }
    Err(SdnvError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_encodings() {
        assert_eq!(encode(0), vec![0x00]);
        assert_eq!(encode(0x7f), vec![0x7f]);
        assert_eq!(encode(0x80), vec![0x81, 0x00]);
        assert_eq!(encode(0xff), vec![0x81, 0x7f]);
        assert_eq!(encode(0x4000), vec![0x81, 0x80, 0x00]);
    }

    #[test]
    fn roundtrips() {
        for &v in &[
            0u64,
            1,
            127,
            128,
            0x1234,
            0xffff_ffff,
            0x7fff_ffff_ffff_ffff,
            u64::MAX,
        ] {
            let enc = encode(v);
            let (got, used) = decode(&enc).unwrap();
            assert_eq!(got, v, "roundtrip failed for {v}");
            assert_eq!(used, enc.len());
        }
    }

    #[test]
    fn truncated_value() {
        assert_eq!(decode(&[]), Err(SdnvError::Truncated));
        assert_eq!(decode(&[0x81]), Err(SdnvError::Truncated));
        assert_eq!(decode(&[0x81, 0x80]), Err(SdnvError::Truncated));
    }

    #[test]
    fn overflow_value() {
        // 11 continuation octets can never fit a u64.
        assert_eq!(decode(&[0xff; 11]), Err(SdnvError::Overflow));
        // 0xff ff ff ff ff ff ff ff ff ff decodes to 70 value bits.
        let ten: Vec<u8> = [0xffu8; 10].to_vec();
        assert_eq!(decode(&ten), Err(SdnvError::Overflow));
    }
}
