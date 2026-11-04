//! Minimal deterministic CBOR encoder/decoder (RFC 8949 subset) for BPv7.
//! Supports: unsigned/negative ints, byte strings, text strings, definite arrays.

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Uint(u64),
    NInt(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
}

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    Truncated,
    Invalid,
}

pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_head(out: &mut Vec<u8>, major: u8, val: u64) {
    let m = major << 5;
    if val < 24 {
        out.push(m | val as u8);
    } else if val <= 0xff {
        out.push(m | 24); out.push(val as u8);
    } else if val <= 0xffff {
        out.push(m | 25); out.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xffff_ffff {
        out.push(m | 26); out.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        out.push(m | 27); out.extend_from_slice(&val.to_be_bytes());
    }
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Uint(u) => encode_head(out, 0, *u),
        Value::NInt(n) => encode_head(out, 1, (-1 - *n) as u64),
        Value::Bytes(b) => { encode_head(out, 2, b.len() as u64); out.extend_from_slice(b); }
        Value::Text(t) => { encode_head(out, 3, t.len() as u64); out.extend_from_slice(t.as_bytes()); }
        Value::Array(items) => {
            encode_head(out, 4, items.len() as u64);
            for it in items { encode_into(it, out); }
        }
    }
}

pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self { Decoder { buf, pos: 0 } }

    fn head(&mut self) -> Result<(u8, u64), DecodeError> {
        if self.pos >= self.buf.len() { return Err(DecodeError::Truncated); }
        let b = self.buf[self.pos]; self.pos += 1;
        let major = b >> 5;
        let info = b & 0x1f;
        let val = match info {
            0..=23 => info as u64,
            24 => self.take(1).map(|s| s[0] as u64)?,
            25 => self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]) as u64)?,
            26 => self.take(4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64)?,
            27 => self.take(8).map(|s| u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))?,
            _ => return Err(DecodeError::Invalid),
        };
        Ok((major, val))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.buf.len() { return Err(DecodeError::Truncated); }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn value(&mut self) -> Result<Value, DecodeError> {
        let (major, val) = self.head()?;
        match major {
            0 => Ok(Value::Uint(val)),
            1 => Ok(Value::NInt(-1 - (val as i64))),
            2 => Ok(Value::Bytes(self.take(val as usize)?.to_vec())),
            3 => Ok(Value::Text(String::from_utf8(self.take(val as usize)?.to_vec()).map_err(|_| DecodeError::Invalid)?)),
            4 => {
                let mut items = Vec::with_capacity(val as usize);
                for _ in 0..val { items.push(self.value()?); }
                Ok(Value::Array(items))
            }
            _ => Err(DecodeError::Invalid),
        }
    }
}

pub fn decode(buf: &[u8]) -> Result<(Value, usize), DecodeError> {
    let mut d = Decoder::new(buf);
    let v = d.value()?;
    Ok((v, d.pos))
}

pub fn text(s: &str) -> Value { Value::Text(s.to_string()) }
pub fn bytes(b: &[u8]) -> Value { Value::Bytes(b.to_vec()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_uint() {
        for v in [0u64, 1, 23, 24, 255, 256, 65535, 65536, u32::MAX as u64, u64::MAX] {
            let e = encode(&Value::Uint(v));
            let (d, used) = decode(&e).unwrap();
            assert_eq!(d, Value::Uint(v));
            assert_eq!(used, e.len());
        }
    }

    #[test]
    fn roundtrip_nested() {
        let v = Value::Array(vec![Value::Uint(7), text("dtn://node/"), bytes(&[1, 2, 3])]);
        let (d, _) = decode(&encode(&v)).unwrap();
        assert_eq!(d, v);
    }

    #[test]
    fn truncated_fails() {
        assert!(decode(&[0x58, 0x05, 0x01]).is_err());
    }
}
