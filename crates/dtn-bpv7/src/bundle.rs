//! BPv7 bundle: primary block, payload block, encode/decode, lifecycle
//! rules per RFC 9171.

use crate::cbor::{self, Value};
use crate::eid::Eid;

pub const BPV7_VERSION: u64 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrcType { None = 0, Crc16 = 1, Crc32 = 2 }

#[derive(Debug, Clone, PartialEq)]
pub struct PrimaryBlock {
    pub version: u64,
    pub control_flags: u64,
    pub crc_type: CrcType,
    pub destination: Eid,
    pub source_node: Eid,
    pub report_to: Eid,
    pub creation_ts: (u64, u64),
    pub lifetime: u64,
    pub hop_count: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalBlock {
    pub type_code: u64,
    pub block_number: u64,
    pub control_flags: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bundle {
    pub primary: PrimaryBlock,
    pub blocks: Vec<CanonicalBlock>,
}

/// Unique bundle identifier per RFC 9171 section 4.3.1
/// (source EID + creation timestamp pair).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BundleId {
    pub source: Eid,
    pub creation_ts: (u64, u64),
}

fn eid_from(v: &Value) -> Result<Eid, String> {
    match v {
        Value::Text(s) => {
            if let Some(rest) = s.strip_prefix("ipn:") {
                Ok(Eid { scheme: "ipn".into(), ssp: rest.to_string() })
            } else {
                let rest = s.trim_start_matches("dtn://").to_string();
                Ok(Eid { scheme: "dtn".into(), ssp: rest })
            }
        }
        _ => Err("EID must be a text string".into()),
    }
}

fn eid_to_value(e: &Eid) -> Value {
    cbor::text(&e.as_uri())
}

fn u64_of(v: &Value) -> Result<u64, String> {
    match v { Value::Uint(u) => Ok(*u), _ => Err("expected unsigned integer".into()) }
}

fn ts_of(v: &Value) -> Result<(u64, u64), String> {
    match v {
        Value::Array(a) if a.len() == 2 => Ok((u64_of(&a[0])?, u64_of(&a[1])?)),
        _ => Err("expected timestamp pair".into()),
    }
}

impl PrimaryBlock {
    pub fn new(source: Eid, destination: Eid, lifetime: u64, seq: u64, now: u64) -> Self {
        PrimaryBlock {
            version: BPV7_VERSION,
            control_flags: 0,
            crc_type: CrcType::None,
            destination,
            source_node: source,
            report_to: Eid::dtn_null(),
            creation_ts: (now, seq),
            lifetime,
            hop_count: 0,
        }
    }

    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.version),
            Value::Uint(self.control_flags),
            Value::Uint(self.crc_type as u64),
            eid_to_value(&self.destination),
            eid_to_value(&self.source_node),
            eid_to_value(&self.report_to),
            Value::Array(vec![Value::Uint(self.creation_ts.0), Value::Uint(self.creation_ts.1)]),
            Value::Uint(self.lifetime),
            Value::Uint(self.hop_count),
        ])
    }

    pub fn from_value(v: &Value) -> Result<Self, String> {
        let a = match v { Value::Array(a) if a.len() == 9 => a, _ => return Err("primary block must be a 9-element array".into()) };
        let version = u64_of(&a[0])?;
        if version != BPV7_VERSION { return Err(format!("unsupported bundle version {version}")); }
        let crc_type = match u64_of(&a[2])? {
            0 => CrcType::None, 1 => CrcType::Crc16, 2 => CrcType::Crc32,
            _ => return Err("invalid CRC type".into()),
        };
        Ok(PrimaryBlock {
            version,
            control_flags: u64_of(&a[1])?,
            crc_type,
            destination: eid_from(&a[3])?,
            source_node: eid_from(&a[4])?,
            report_to: eid_from(&a[5])?,
            creation_ts: ts_of(&a[6])?,
            lifetime: u64_of(&a[7])?,
            hop_count: u64_of(&a[8])?,
        })
    }
}

impl Bundle {
    pub fn new(source: Eid, destination: Eid, payload: Vec<u8>, lifetime: u64, seq: u64, now: u64) -> Self {
        Bundle {
            primary: PrimaryBlock::new(source, destination, lifetime, seq, now),
            blocks: vec![CanonicalBlock { type_code: 1, block_number: 1, control_flags: 0, data: payload }],
        }
    }

    pub fn payload(&self) -> Option<&[u8]> {
        self.blocks.iter().find(|b| b.type_code == 1).map(|b| b.data.as_slice())
    }

    pub fn id(&self) -> BundleId {
        BundleId { source: self.primary.source_node.clone(), creation_ts: self.primary.creation_ts }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.primary.creation_ts.0.saturating_add(self.primary.lifetime) < now
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut elems: Vec<Value> = vec![self.primary.to_value()];
        for b in &self.blocks {
            elems.push(Value::Array(vec![
                Value::Uint(b.type_code),
                Value::Uint(b.block_number),
                Value::Uint(b.control_flags),
                cbor::bytes(&b.data),
            ]));
        }
        cbor::encode(&Value::Array(elems))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, String> {
        let (v, used) = cbor::decode(buf).map_err(|e| format!("CBOR error: {e:?}"))?;
        if used != buf.len() { return Err("trailing bytes after bundle".into()); }
        let a = match v { Value::Array(a) if a.len() >= 2 => a, _ => return Err("bundle must be an array of at least 2 blocks".into()) };
        let primary = PrimaryBlock::from_value(&a[0])?;
        let mut blocks = Vec::new();
        for bv in &a[1..] {
            let ba = match bv { Value::Array(x) if x.len() == 4 => x, _ => return Err("invalid canonical block".into()) };
            let data = match &ba[3] { Value::Bytes(d) => d.clone(), _ => return Err("block data must be byte string".into()) };
            blocks.push(CanonicalBlock {
                type_code: u64_of(&ba[0])?,
                block_number: u64_of(&ba[1])?,
                control_flags: u64_of(&ba[2])?,
                data,
            });
        }
        if !blocks.iter().any(|b| b.type_code == 1) { return Err("missing payload block".into()); }
        Ok(Bundle { primary, blocks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Bundle {
        Bundle::new(Eid::dtn("a"), Eid::dtn("b"), b"hello dtn".to_vec(), 3600, 1, 1000)
    }

    #[test]
    fn roundtrip() {
        let b = sample();
        let d = Bundle::decode(&b.encode()).unwrap();
        assert_eq!(d, b);
    }

    #[test]
    fn bundle_id_stable() {
        let b = sample();
        assert_eq!(b.id(), b.id());
        assert_eq!(b.primary.creation_ts, (1000, 1));
    }

    #[test]
    fn expiry() {
        let b = sample();
        assert!(!b.is_expired(2000));
        assert!(b.is_expired(10_000));
    }

    #[test]
    fn rejects_bad_version() {
        let mut b = sample();
        b.primary.version = 6;
        assert!(Bundle::decode(&b.encode()).is_err());
    }

    #[test]
    fn rejects_malformed() {
        assert!(Bundle::decode(&[0x81, 0x07]).is_err());
    }
}
