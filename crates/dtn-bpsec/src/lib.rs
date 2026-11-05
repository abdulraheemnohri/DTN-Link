//! dtn-bpsec — bundle security (Phase 5).
//!
//! Implements a BPSec (RFC 9172)-aligned Block Integrity Block (BIB):
//! type_code 11, Ed25519 signature over the payload bytes. This is
//! real end-to-end integrity: any tampering with the payload or the
//! signature makes verification fail.
//!
//! Honest scope note: full RFC 9173 mandates specific security contexts
//! (HMAC-SHA256, AES-GCM). This block uses an Ed25519 signature context
//! instead, which provides equivalent integrity with public-key
//! verification (no shared secret needed). Confidentiality (BCB) comes
//! in the next milestone.

use dtn_bpv7::{Bundle, CanonicalBlock};
use dtn_identity::NodeIdentity;
use ed25519_dalek::VerifyingKey;

/// RFC 9172: Block Integrity Block type code.
pub const BIB_TYPE_CODE: u64 = 11;
pub const BIB_BLOCK_NUMBER: u64 = 2;

/// Adds an integrity block: Ed25519 signature over the payload bytes.
/// Returns a new bundle (original unchanged). The primary block is not
/// covered (hop-count and flags change at each hop).
pub fn sign_bundle(bundle: &Bundle, identity: &NodeIdentity) -> Bundle {
    let mut out = bundle.clone();
    let payload = out.payload().unwrap_or(&[]).to_vec();
    let sig = identity.sign(&payload);
    out.blocks.push(CanonicalBlock {
        type_code: BIB_TYPE_CODE,
        block_number: BIB_BLOCK_NUMBER,
        control_flags: 0,
        data: sig.to_bytes().to_vec(),
    });
    out
}

#[derive(Debug, PartialEq)]
pub enum VerifyOutcome {
    /// Bundle has a valid signature from the given key.
    Valid,
    /// Bundle carries no integrity block (unsigned bundle).
    NoIntegrityBlock,
    /// Signature is present but does not match (tampered or wrong key).
    Invalid,
    /// Bundle has multiple integrity blocks — malformed, refuse.
    MultipleIntegrityBlocks,
}

pub fn verify_bundle(bundle: &Bundle, key: &VerifyingKey) -> VerifyOutcome {
    let bibs: Vec<&CanonicalBlock> = bundle.blocks.iter().filter(|b| b.type_code == BIB_TYPE_CODE).collect();
    match bibs.len() {
        0 => return VerifyOutcome::NoIntegrityBlock,
        1 => {}
        _ => return VerifyOutcome::MultipleIntegrityBlocks,
    }
    let bib = bibs[0];
    if bib.data.len() != 64 { return VerifyOutcome::Invalid; }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&bib.data);
    let Ok(sig) = ed25519_dalek::Signature::from_bytes(&sig_bytes) else {
        return VerifyOutcome::Invalid;
    };
    let payload = bundle.payload().unwrap_or(&[]);
    if NodeIdentity::verify(key, payload, &sig) { VerifyOutcome::Valid } else { VerifyOutcome::Invalid }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_bpv7::Eid;

    fn signed() -> (Bundle, NodeIdentity) {
        let a = NodeIdentity::generate(1);
        let b = Bundle::new(Eid::dtn("a"), Eid::dtn("b"), b"secure message".to_vec(), 3600, 1, 1000);
        (sign_bundle(&b, &a), a)
    }

    #[test]
    fn sign_then_verify() {
        let (s, a) = signed();
        assert_eq!(verify_bundle(&s, &a.public_key()), VerifyOutcome::Valid);
        let wire = s.encode();
        assert_eq!(verify_bundle(&Bundle::decode(&wire).unwrap(), &a.public_key()), VerifyOutcome::Valid);
    }

    #[test]
    fn tampered_payload_rejected() {
        let (s, a) = signed();
        let mut t = s.clone();
        if let Some(p) = t.blocks.iter_mut().find(|b| b.type_code == 1) {
            p.data = b"TAMPERED".to_vec();
        }
        assert_eq!(verify_bundle(&t, &a.public_key()), VerifyOutcome::Invalid);
    }

    #[test]
    fn tampered_signature_rejected() {
        let (s, a) = signed();
        let mut t = s.clone();
        if let Some(bib) = t.blocks.iter_mut().find(|b| b.type_code == BIB_TYPE_CODE) {
            bib.data[0] ^= 0xff;
        }
        assert_eq!(verify_bundle(&t, &a.public_key()), VerifyOutcome::Invalid);
    }

    #[test]
    fn wrong_key_rejected() {
        let (s, _) = signed();
        let other = NodeIdentity::generate(99);
        assert_eq!(verify_bundle(&s, &other.public_key()), VerifyOutcome::Invalid);
    }

    #[test]
    fn unsigned_bundle_reported() {
        let (s, a) = signed();
        let unsigned = Bundle::new(Eid::dtn("a"), Eid::dtn("b"), b"plain".to_vec(), 3600, 1, 1000);
        assert_eq!(verify_bundle(&unsigned, &a.public_key()), VerifyOutcome::NoIntegrityBlock);
        let _ = s;
    }

    #[test]
    fn multiple_bibs_rejected() {
        let (s, a) = signed();
        let mut t = s.clone();
        let bib = t.blocks.iter().find(|b| b.type_code == BIB_TYPE_CODE).unwrap().clone();
        t.blocks.push(bib);
        assert_eq!(verify_bundle(&t, &a.public_key()), VerifyOutcome::MultipleIntegrityBlocks);
    }
}
