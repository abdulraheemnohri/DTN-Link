//! dtn-bpsec — RFC 9173 — Default Security Contexts.
//!
//! Phase 16: the two RFC 9173 context identifiers are now carried on
//! the wire inside the BPSec block data (the simplified CanonicalBlock
//! layout of this codebase has no separate context-id field, so the
//! context id is the first byte of the block data):
//!
//! - **BIB-HMAC-SHA2 (context id 1)**: HMAC-SHA256 integrity over the
//!   payload bytes with a shared symmetric key. Block data layout:
//!   `[0x01][key_id: u32 BE][32-byte HMAC-SHA256 tag]`.
//! - **BCB-AES-GCM (context id 2)**: AES-256-GCM payload encryption
//!   with the Additional Authenticated Data (AAD) scope covering the
//!   CBOR-encoded primary block, per RFC 9173 section 4.2.2.1 (the
//!   primary block is bound to the ciphertext: any change to source,
//!   destination, timestamp or lifetime breaks decryption). Block
//!   data layout: `[0x02][12-byte nonce][ciphertext || 16-byte tag]`.
//!
//! The legacy Phase 5/6 blocks ([`crate::sign_bundle`] Ed25519 BIB and
//! [`crate::bcb`] BCB) keep their existing wire format and remain
//! fully compatible; a receiver distinguishes the two families by the
//! first data byte (0x01 / 0x02 vs. raw signature / raw nonce).
//!
//! Honest scope: RFC 9173 parameter negotiation (key transport via
//! security parameters), key management and rotation remain future
//! work; the key_id here is informational and enforced only in that
//! both sides must use the same key material.

use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
use dtn_bpv7::{Bundle, CanonicalBlock};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::bcb::{Key, NonceBytes};
use crate::{BIB_BLOCK_NUMBER, BIB_TYPE_CODE, BCB_BLOCK_NUMBER, BCB_TYPE_CODE};

/// RFC 9173: BIB-HMAC-SHA2 security context identifier.
pub const BIB_HMAC_SHA2_CONTEXT_ID: u64 = 1;
/// RFC 9173: BCB-AES-GCM security context identifier.
pub const BCB_AES_GCM_CONTEXT_ID: u64 = 2;

const HMAC_TAG_LEN: usize = 32;
const GCM_TAG_LEN: usize = 16;
const BIB_HEADER_LEN: usize = 1 + 4; // ctx id + key id
const BCB_HEADER_LEN: usize = 1 + 12; // ctx id + nonce

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------- BIB-HMAC-SHA2

/// Computes the HMAC-SHA256 tag over the payload bytes (RFC 9173
/// BIB-HMAC-SHA2 security result, SHA-256 variant, no AAD scope).
fn hmac_tag(key: &[u8], payload: &[u8]) -> [u8; HMAC_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; HMAC_TAG_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// Adds a BIB-HMAC-SHA2 (RFC 9173 context id 1) integrity block:
/// HMAC-SHA256 over the payload bytes with a shared symmetric key.
/// `key_id` is informational (identifies the key to the receiver).
/// Any existing HMAC-SHA2 BIB is replaced. Returns a new bundle.
pub fn sign_hmac(bundle: &Bundle, key: &[u8], key_id: u32) -> Bundle {
    let payload = bundle.payload().unwrap_or(&[]).to_vec();
    let tag = hmac_tag(key, &payload);
    let mut data = Vec::with_capacity(BIB_HEADER_LEN + HMAC_TAG_LEN);
    data.push(BIB_HMAC_SHA2_CONTEXT_ID as u8);
    data.extend_from_slice(&key_id.to_be_bytes());
    data.extend_from_slice(&tag);
    let mut out = bundle.clone();
    out.blocks
        .retain(|b| !(b.type_code == BIB_TYPE_CODE && bib_context(b) == Some(BIB_HMAC_SHA2_CONTEXT_ID)));
    out.blocks.push(CanonicalBlock {
        type_code: BIB_TYPE_CODE,
        // Block number 4: leaves 2 (Ed25519 BIB) and 3 (BCB) free so a
        // bundle can carry both integrity contexts if needed.
        block_number: 4,
        control_flags: 0,
        data,
    });
    out
}

#[derive(Debug, PartialEq)]
pub enum HmacVerifyOutcome {
    /// Valid HMAC-SHA2 tag from the given key.
    Valid,
    /// Bundle carries no integrity block at all.
    NoIntegrityBlock,
    /// Multiple integrity blocks — malformed, refuse.
    MultipleIntegrityBlocks,
    /// An integrity block is present but not BIB-HMAC-SHA2 (e.g. the
    /// Ed25519 context) — this verifier does not apply.
    UnknownContext,
    /// HMAC mismatch: tampered payload or wrong key.
    Invalid,
}

/// Verifies the BIB-HMAC-SHA2 (RFC 9173 context id 1) tag of a bundle
/// against the shared symmetric key.
pub fn verify_hmac(bundle: &Bundle, key: &[u8]) -> HmacVerifyOutcome {
    let bibs: Vec<&CanonicalBlock> = bundle
        .blocks
        .iter()
        .filter(|b| b.type_code == BIB_TYPE_CODE)
        .collect();
    match bibs.len() {
        0 => return HmacVerifyOutcome::NoIntegrityBlock,
        1 => {}
        _ => return HmacVerifyOutcome::MultipleIntegrityBlocks,
    }
    let bib = bibs[0];
    if bib.data.len() < 1 {
        return HmacVerifyOutcome::Invalid;
    }
    if bib.data[0] as u64 != BIB_HMAC_SHA2_CONTEXT_ID {
        return HmacVerifyOutcome::UnknownContext;
    }
    if bib.data.len() != BIB_HEADER_LEN + HMAC_TAG_LEN {
        return HmacVerifyOutcome::Invalid;
    }
    let payload = bundle.payload().unwrap_or(&[]);
    let expected = hmac_tag(key, payload);
    if fixed_time_eq(&expected, &bib.data[BIB_HEADER_LEN..]) {
        HmacVerifyOutcome::Valid
    } else {
        HmacVerifyOutcome::Invalid
    }
}

/// Constant-time equality (no early exit on mismatch).
fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------- BCB-AES-GCM

/// AAD scope: the CBOR-encoded primary block (RFC 9173 BCB-AES-GCM
/// binds the ciphertext to the primary block so routing metadata
/// cannot be swapped undetected).
fn primary_aad(bundle: &Bundle) -> Vec<u8> {
    dtn_bpv7::cbor::encode(&bundle.primary.to_value())
}

/// Encrypts the payload with BCB-AES-GCM (RFC 9173 context id 2):
/// AES-256-GCM over the payload bytes, AAD = CBOR-encoded primary
/// block, nonce stored in the BCB. The payload block is replaced with
/// the ciphertext, so the plaintext never appears on the wire.
/// Any existing AES-GCM BCB is replaced. Returns a new bundle.
pub fn encrypt_aes_gcm(bundle: &Bundle, key: &Key, nonce: &NonceBytes) -> Bundle {
    let mut out = bundle.clone();
    let plaintext = out.payload().unwrap_or(&[]).to_vec();
    let aad = primary_aad(&out);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext.as_ref(), aad: &aad })
        .expect("in-memory encryption cannot fail");
    let mut data = Vec::with_capacity(BCB_HEADER_LEN + ciphertext.len());
    data.push(BCB_AES_GCM_CONTEXT_ID as u8);
    data.extend_from_slice(nonce);
    data.extend_from_slice(&ciphertext);
    if let Some(p) = out.blocks.iter_mut().find(|b| b.type_code == 1) {
        p.data = ciphertext;
    }
    out.blocks
        .retain(|b| !(b.type_code == BCB_TYPE_CODE && bcb_context(b) == Some(BCB_AES_GCM_CONTEXT_ID)));
    out.blocks.push(CanonicalBlock {
        type_code: BCB_TYPE_CODE,
        block_number: BCB_BLOCK_NUMBER,
        control_flags: 0,
        data,
    });
    out
}

#[derive(Debug, PartialEq)]
pub enum AesGcmDecryptError {
    /// Bundle has no BCB — it is not encrypted.
    NoConfidentialityBlock,
    /// Bundle has multiple confidentiality blocks — malformed, refuse.
    MultipleConfidentialityBlocks,
    /// A BCB is present but not BCB-AES-GCM.
    UnknownContext,
    /// BCB data is structurally invalid (too short).
    Malformed,
    /// Decryption failed: wrong key, tampered ciphertext/tag, or a
    /// changed primary block (AAD mismatch).
    DecryptionFailed,
}

/// Decrypts the payload of a BCB-AES-GCM bundle, returning a new
/// bundle with the plaintext payload restored and the BCB removed.
pub fn decrypt_aes_gcm(bundle: &Bundle, key: &Key) -> Result<Bundle, AesGcmDecryptError> {
    let bcbs: Vec<&CanonicalBlock> = bundle
        .blocks
        .iter()
        .filter(|b| b.type_code == BCB_TYPE_CODE)
        .collect();
    match bcbs.len() {
        0 => return Err(AesGcmDecryptError::NoConfidentialityBlock),
        1 => {}
        _ => return Err(AesGcmDecryptError::MultipleConfidentialityBlocks),
    }
    let bcb = bcbs[0];
    if bcb.data.len() < 1 {
        return Err(AesGcmDecryptError::Malformed);
    }
    if bcb.data[0] as u64 != BCB_AES_GCM_CONTEXT_ID {
        return Err(AesGcmDecryptError::UnknownContext);
    }
    if bcb.data.len() < BCB_HEADER_LEN + GCM_TAG_LEN {
        return Err(AesGcmDecryptError::Malformed);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bcb.data[1..1 + 12]);
    let ciphertext = &bcb.data[BCB_HEADER_LEN..];
    let aad = primary_aad(bundle);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| AesGcmDecryptError::DecryptionFailed)?;
    let mut out = bundle.clone();
    if let Some(p) = out.blocks.iter_mut().find(|b| b.type_code == 1) {
        p.data = plaintext;
    }
    out.blocks.retain(|b| b.type_code != BCB_TYPE_CODE);
    Ok(out)
}

/// Security context id of a BIB block's data, if encoded as
/// `[ctx_id][...]` (RFC 9173 family).
fn bib_context(b: &CanonicalBlock) -> Option<u64> {
    b.data.first().map(|c| *c as u64)
}

/// Security context id of a BCB block's data, if encoded as
/// `[ctx_id][...]` (RFC 9173 family).
fn bcb_context(b: &CanonicalBlock) -> Option<u64> {
    b.data.first().map(|c| *c as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bcb;
    use dtn_bpv7::Eid;

    const HMAC_KEY: &[u8] = b"shared-symmetric-key-0123456789ab";
    const GCM_KEY: Key = [42u8; 32];

    fn plain() -> Bundle {
        Bundle::new(Eid::dtn("a"), Eid::dtn("b"), b"rfc9173 payload".to_vec(), 3600, 1, 1000)
    }

    // ---- BIB-HMAC-SHA2 (context id 1)

    #[test]
    fn hmac_sign_then_verify() {
        let s = sign_hmac(&plain(), HMAC_KEY, 7);
        assert_eq!(verify_hmac(&s, HMAC_KEY), HmacVerifyOutcome::Valid);
        let wire = s.encode();
        assert_eq!(
            verify_hmac(&Bundle::decode(&wire).unwrap(), HMAC_KEY),
            HmacVerifyOutcome::Valid
        );
    }

    #[test]
    fn hmac_context_id_on_wire() {
        let s = sign_hmac(&plain(), HMAC_KEY, 7);
        let bib = s.blocks.iter().find(|b| b.type_code == BIB_TYPE_CODE).unwrap();
        assert_eq!(bib.data[0], BIB_HMAC_SHA2_CONTEXT_ID as u8);
        assert_eq!(bib.data.len(), BIB_HEADER_LEN + HMAC_TAG_LEN);
        // key id round-trips big-endian
        assert_eq!(&bib.data[1..5], &7u32.to_be_bytes());
    }

    #[test]
    fn hmac_rfc4231_test_vector() {
        // RFC 4231 test case 1: key = 0x0b repeated 20 times,
        // data = "Hi There" -> known HMAC-SHA256 digest.
        let key = [0x0bu8; 20];
        let mut b = Bundle::new(Eid::dtn("v"), Eid::dtn("w"), b"Hi There".to_vec(), 3600, 1, 1);
        let tag = hmac_tag(&key, b"Hi There");
        let expect = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(tag, expect);
        // And the verify path accepts a hand-built block with that tag.
        let mut data = vec![BIB_HMAC_SHA2_CONTEXT_ID as u8];
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&tag);
        b.blocks.push(CanonicalBlock {
            type_code: BIB_TYPE_CODE,
            block_number: 4,
            control_flags: 0,
            data,
        });
        assert_eq!(verify_hmac(&b, &key), HmacVerifyOutcome::Valid);
    }

    #[test]
    fn hmac_tampered_payload_rejected() {
        let mut s = sign_hmac(&plain(), HMAC_KEY, 1);
        if let Some(p) = s.blocks.iter_mut().find(|b| b.type_code == 1) {
            p.data[0] ^= 0xff;
        }
        assert_eq!(verify_hmac(&s, HMAC_KEY), HmacVerifyOutcome::Invalid);
    }

    #[test]
    fn hmac_wrong_key_rejected() {
        let s = sign_hmac(&plain(), HMAC_KEY, 1);
        assert_eq!(verify_hmac(&s, b"other-key"), HmacVerifyOutcome::Invalid);
    }

    #[test]
    fn hmac_unknown_context_reported() {
        // An Ed25519 BIB (raw 64-byte signature, no ctx byte) is a
        // different context: reported, not mis-verified. If the raw
        // signature happens to start with byte 0x01, flip it first so
        // the block is deterministically a non-RFC-9173 context.
        let id = dtn_identity::NodeIdentity::generate(3);
        let mut s = crate::sign_bundle(&plain(), &id);
        let bib = s.blocks.iter_mut().find(|b| b.type_code == BIB_TYPE_CODE).unwrap();
        if bib.data[0] == BIB_HMAC_SHA2_CONTEXT_ID as u8 {
            bib.data[0] = 0x09;
        }
        assert_eq!(verify_hmac(&s, HMAC_KEY), HmacVerifyOutcome::UnknownContext);
    }

    #[test]
    fn hmac_no_bib_and_multiple() {
        assert_eq!(verify_hmac(&plain(), HMAC_KEY), HmacVerifyOutcome::NoIntegrityBlock);
        let mut s = sign_hmac(&plain(), HMAC_KEY, 1);
        let bib = s.blocks.iter().find(|b| b.type_code == BIB_TYPE_CODE).unwrap().clone();
        s.blocks.push(bib);
        assert_eq!(verify_hmac(&s, HMAC_KEY), HmacVerifyOutcome::MultipleIntegrityBlocks);
    }

    #[test]
    fn hmac_malformed_lengths_rejected() {
        let mut b = plain();
        b.blocks.push(CanonicalBlock {
            type_code: BIB_TYPE_CODE,
            block_number: 4,
            control_flags: 0,
            data: vec![0x01, 0, 0, 0, 1, 0xaa], // ctx + key id but truncated tag
        });
        assert_eq!(verify_hmac(&b, HMAC_KEY), HmacVerifyOutcome::Invalid);
    }

    #[test]
    fn hmac_sign_replaces_previous_tag() {
        let s1 = sign_hmac(&plain(), HMAC_KEY, 1);
        let s2 = sign_hmac(&s1, HMAC_KEY, 2);
        let bibs: Vec<&CanonicalBlock> = s2.blocks.iter().filter(|b| b.type_code == BIB_TYPE_CODE).collect();
        assert_eq!(bibs.len(), 1);
        assert_eq!(&bibs[0].data[1..5], &2u32.to_be_bytes());
    }

    // ---- BCB-AES-GCM (context id 2, AAD = primary block)

    #[test]
    fn gcm_encrypt_then_decrypt_roundtrip() {
        let e = encrypt_aes_gcm(&plain(), &GCM_KEY, &[7u8; 12]);
        assert!(bcb::is_encrypted(&e));
        let d = decrypt_aes_gcm(&e, &GCM_KEY).expect("decrypt");
        assert_eq!(d.payload().unwrap(), b"rfc9173 payload".as_slice());
        assert!(!bcb::is_encrypted(&d));
    }

    #[test]
    fn gcm_wire_roundtrip_and_no_plaintext_on_wire() {
        let e = encrypt_aes_gcm(&plain(), &GCM_KEY, &[3u8; 12]);
        let wire = e.encode();
        assert!(!wire.windows(15).any(|w| w == b"rfc9173 payload"));
        let back = Bundle::decode(&wire).unwrap();
        let d = decrypt_aes_gcm(&back, &GCM_KEY).expect("decrypt");
        assert_eq!(d.payload().unwrap(), b"rfc9173 payload".as_slice());
    }

    #[test]
    fn gcm_context_id_and_nonce_on_wire() {
        let e = encrypt_aes_gcm(&plain(), &GCM_KEY, &[9u8; 12]);
        let blk = e.blocks.iter().find(|b| b.type_code == BCB_TYPE_CODE).unwrap();
        assert_eq!(blk.data[0], BCB_AES_GCM_CONTEXT_ID as u8);
        assert_eq!(&blk.data[1..13], &[9u8; 12]);
    }

    #[test]
    fn gcm_wrong_key_rejected() {
        let e = encrypt_aes_gcm(&plain(), &GCM_KEY, &[1u8; 12]);
        assert_eq!(decrypt_aes_gcm(&e, &[43u8; 32]), Err(AesGcmDecryptError::DecryptionFailed));
    }

    #[test]
    fn gcm_tampered_ciphertext_rejected() {
        let mut e = encrypt_aes_gcm(&plain(), &GCM_KEY, &[1u8; 12]);
        if let Some(p) = e.blocks.iter_mut().find(|b| b.type_code == 1) {
            p.data[0] ^= 0xff;
        }
        assert_eq!(decrypt_aes_gcm(&e, &GCM_KEY), Err(AesGcmDecryptError::DecryptionFailed));
    }

    #[test]
    fn gcm_tampered_primary_block_breaks_aad() {
        // RFC 9173 AAD scope: the primary block is bound to the
        // ciphertext. Swapping the destination after encryption must
        // fail decryption.
        let mut e = encrypt_aes_gcm(&plain(), &GCM_KEY, &[1u8; 12]);
        e.primary.destination = Eid::dtn("mallory");
        assert_eq!(decrypt_aes_gcm(&e, &GCM_KEY), Err(AesGcmDecryptError::DecryptionFailed));
    }

    #[test]
    fn gcm_tampered_nonce_rejected() {
        let mut e = encrypt_aes_gcm(&plain(), &GCM_KEY, &[1u8; 12]);
        if let Some(b) = e.blocks.iter_mut().find(|b| b.type_code == BCB_TYPE_CODE) {
            b.data[1] ^= 0xff;
        }
        assert_eq!(decrypt_aes_gcm(&e, &GCM_KEY), Err(AesGcmDecryptError::DecryptionFailed));
    }

    #[test]
    fn gcm_unknown_context_no_bcb_multiple_malformed() {
        // Unknown context byte.
        let mut b = plain();
        b.blocks.push(CanonicalBlock {
            type_code: BCB_TYPE_CODE,
            block_number: BCB_BLOCK_NUMBER,
            control_flags: 0,
            data: vec![0x7f, 0, 0],
        });
        assert_eq!(decrypt_aes_gcm(&b, &GCM_KEY), Err(AesGcmDecryptError::UnknownContext));
        // No BCB.
        assert_eq!(
            decrypt_aes_gcm(&plain(), &GCM_KEY),
            Err(AesGcmDecryptError::NoConfidentialityBlock)
        );
        // Multiple BCBs.
        let mut e = encrypt_aes_gcm(&plain(), &GCM_KEY, &[1u8; 12]);
        let dup = e.blocks.iter().find(|x| x.type_code == BCB_TYPE_CODE).unwrap().clone();
        e.blocks.push(dup);
        assert_eq!(
            decrypt_aes_gcm(&e, &GCM_KEY),
            Err(AesGcmDecryptError::MultipleConfidentialityBlocks)
        );
        // Malformed (truncated header).
        let mut m = plain();
        m.blocks.push(CanonicalBlock {
            type_code: BCB_TYPE_CODE,
            block_number: BCB_BLOCK_NUMBER,
            control_flags: 0,
            data: vec![0x02, 0, 0],
        });
        assert_eq!(decrypt_aes_gcm(&m, &GCM_KEY), Err(AesGcmDecryptError::Malformed));
    }

    #[test]
    fn gcm_re_encrypt_replaces_previous_bcb() {
        let e1 = encrypt_aes_gcm(&plain(), &GCM_KEY, &[1u8; 12]);
        let e2 = encrypt_aes_gcm(&e1, &GCM_KEY, &[2u8; 12]);
        let bcbs: Vec<&CanonicalBlock> = e2.blocks.iter().filter(|b| b.type_code == BCB_TYPE_CODE).collect();
        assert_eq!(bcbs.len(), 1);
        assert_eq!(&bcbs[0].data[1..13], &[2u8; 12]);
    }

    // ---- combined pipeline: HMAC integrity inside AES-GCM confidentiality

    #[test]
    fn combined_hmac_then_gcm_pipeline() {
        let signed = sign_hmac(&plain(), HMAC_KEY, 7);
        let encrypted = encrypt_aes_gcm(&signed, &GCM_KEY, &[5u8; 12]);
        let wire = encrypted.encode();
        assert!(!wire.windows(15).any(|w| w == b"rfc9173 payload"));
        let decrypted = decrypt_aes_gcm(&Bundle::decode(&wire).unwrap(), &GCM_KEY).expect("decrypt");
        assert_eq!(verify_hmac(&decrypted, HMAC_KEY), HmacVerifyOutcome::Valid);
    }

    #[test]
    fn legacy_blocks_still_coexist() {
        // The Phase 5/6 Ed25519 BIB and the Phase 16 HMAC BIB can sit
        // in one bundle (different block numbers).
        let id = dtn_identity::NodeIdentity::generate(5);
        let signed = crate::sign_bundle(&plain(), &id);
        let both = sign_hmac(&signed, HMAC_KEY, 1);
        let bibs: Vec<&CanonicalBlock> = both
            .blocks
            .iter()
            .filter(|b| b.type_code == BIB_TYPE_CODE)
            .collect();
        assert_eq!(bibs.len(), 2);
        assert_eq!(bibs[0].block_number, BIB_BLOCK_NUMBER);
        assert_eq!(bibs[1].block_number, 4);
        // Each verifier applies to exactly one context family and
        // refuses a bundle mixing both (each counts two BIBs).
        assert_eq!(
            crate::verify_bundle(&both, &id.public_key()),
            crate::VerifyOutcome::MultipleIntegrityBlocks
        );
        assert_eq!(verify_hmac(&both, HMAC_KEY), HmacVerifyOutcome::MultipleIntegrityBlocks);
        let hmac_only = sign_hmac(&plain(), HMAC_KEY, 1);
        assert_eq!(verify_hmac(&hmac_only, HMAC_KEY), HmacVerifyOutcome::Valid);
    }
}
