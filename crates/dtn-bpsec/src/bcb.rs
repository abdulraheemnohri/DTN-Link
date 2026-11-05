//! BCB — Block Confidentiality Block (BCB, RFC 9172 type 12).
//!
//! Payload confidentiality using AES-256-GCM (RFC 9173 AAD-AES-GCM
//! aligned). The BCB block data layout is:
//!
//!   [ 12-byte nonce ][ ciphertext || 16-byte GCM tag ]
//!
//! The original payload block is replaced with the ciphertext, so the
//! plaintext never appears on the wire. Intermediate hops see only
//! source/destination EIDs and bundle metadata (necessary for routing).
//!
//! Honest scope: RFC 9173 specifies AES-GCM with an AAD scope covering
//! the primary block; this implementation encrypts the payload with the
//! GCM tag bound to the nonce + key only. Key distribution / key rotation
//! is out of scope here and will come with the identity/keyring module.

use dtn_bpv7::Bundle;
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};

/// RFC 9172: Block Confidentiality Block type code.
pub const BCB_TYPE_CODE: u64 = 12;
pub const BCB_BLOCK_NUMBER: u64 = 3;

/// 32-byte AES-256 key.
pub type Key = [u8; 32];
/// 12-byte GCM nonce.
pub type NonceBytes = [u8; 12];

#[derive(Debug, PartialEq)]
pub enum DecryptError {
    /// Bundle has no BCB — it is not encrypted.
    NoConfidentialityBlock,
    /// Bundle has multiple BCBs — malformed, refuse.
    MultipleConfidentialityBlocks,
    /// BCB data is structurally invalid (too short).
    Malformed,
    /// Decryption failed: wrong key, tampered ciphertext, or corrupted tag.
    DecryptionFailed,
}

/// Returns true if the bundle carries a BCB.
pub fn is_encrypted(bundle: &Bundle) -> bool {
    bundle.blocks.iter().any(|b| b.type_code == BCB_TYPE_CODE)
}

/// Encrypts the payload in place (returns a new bundle):
/// payload -> AES-256-GCM ciphertext, plus a BCB block carrying the nonce.
pub fn encrypt_bundle(bundle: &Bundle, key: &Key, nonce: &NonceBytes) -> Bundle {
    let mut out = bundle.clone();
    let plaintext = out.payload().unwrap_or(&[]).to_vec();
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext.as_ref())
        .expect("in-memory encryption cannot fail");
    let mut bcb_data = Vec::with_capacity(12 + ciphertext.len());
    bcb_data.extend_from_slice(nonce);
    bcb_data.extend_from_slice(&ciphertext);
    // Replace the payload block content with the ciphertext.
    if let Some(p) = out.blocks.iter_mut().find(|b| b.type_code == 1) {
        p.data = ciphertext;
    }
    // Remove any existing BCB (re-encryption replaces it).
    out.blocks.retain(|b| b.type_code != BCB_TYPE_CODE);
    out.blocks.push(dtn_bpv7::CanonicalBlock {
        type_code: BCB_TYPE_CODE,
        block_number: BCB_BLOCK_NUMBER,
        control_flags: 0,
        data: bcb_data,
    });
    out
}

/// Decrypts the payload of a BCB-carrying bundle, returning a new bundle
/// with the plaintext payload restored and the BCB removed.
pub fn decrypt_bundle(bundle: &Bundle, key: &Key) -> Result<Bundle, DecryptError> {
    let bcbs: Vec<&dtn_bpv7::CanonicalBlock> =
        bundle.blocks.iter().filter(|b| b.type_code == BCB_TYPE_CODE).collect();
    match bcbs.len() {
        0 => return Err(DecryptError::NoConfidentialityBlock),
        1 => {}
        _ => return Err(DecryptError::MultipleConfidentialityBlocks),
    }
    let bcb = bcbs[0];
    if bcb.data.len() < 12 + 16 { return Err(DecryptError::Malformed); }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bcb.data[..12]);
    let ciphertext = &bcb.data[12..];
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| DecryptError::DecryptionFailed)?;
    let mut out = bundle.clone();
    if let Some(p) = out.blocks.iter_mut().find(|b| b.type_code == 1) {
        p.data = plaintext;
    }
    out.blocks.retain(|b| b.type_code != BCB_TYPE_CODE);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_bpv7::Eid;

    const KEY: Key = [42u8; 32];

    fn plain() -> Bundle {
        Bundle::new(Eid::dtn("a"), Eid::dtn("b"), b"secret payload".to_vec(), 3600, 1, 1000)
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let e = encrypt_bundle(&plain(), &KEY, &[7u8; 12]);
        assert!(is_encrypted(&e));
        // Plaintext must not appear on the wire.
        let wire = e.encode();
        assert!(!contains(&wire, b"secret payload"));
        let d = decrypt_bundle(&e, &KEY).expect("decrypt");
        assert_eq!(d.payload().unwrap(), b"secret payload".as_slice());
        assert!(!is_encrypted(&d));
    }

    #[test]
    fn wire_roundtrip_preserves_encryption() {
        let e = encrypt_bundle(&plain(), &KEY, &[1u8; 12]);
        let wire = e.encode();
        let back = Bundle::decode(&wire).unwrap();
        let d = decrypt_bundle(&back, &KEY).expect("decrypt");
        assert_eq!(d.payload().unwrap(), b"secret payload".as_slice());
    }

    #[test]
    fn wrong_key_rejected() {
        let e = encrypt_bundle(&plain(), &KEY, &[1u8; 12]);
        let wrong = [43u8; 32];
        assert_eq!(decrypt_bundle(&e, &wrong), Err(DecryptError::DecryptionFailed));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut e = encrypt_bundle(&plain(), &KEY, &[1u8; 12]);
        if let Some(p) = e.blocks.iter_mut().find(|b| b.type_code == 1) {
            p.data[0] ^= 0xff;
        }
        assert_eq!(decrypt_bundle(&e, &KEY), Err(DecryptError::DecryptionFailed));
    }

    #[test]
    fn tampered_nonce_rejected() {
        let mut e = encrypt_bundle(&plain(), &KEY, &[1u8; 12]);
        if let Some(bcb) = e.blocks.iter_mut().find(|b| b.type_code == BCB_TYPE_CODE) {
            bcb.data[0] ^= 0xff;
        }
        assert_eq!(decrypt_bundle(&e, &KEY), Err(DecryptError::DecryptionFailed));
    }

    #[test]
    fn unencrypted_bundle_reports_no_bcb() {
        assert_eq!(decrypt_bundle(&plain(), &KEY), Err(DecryptError::NoConfidentialityBlock));
        assert!(!is_encrypted(&plain()));
    }

    #[test]
    fn multiple_bcbs_rejected() {
        let mut e = encrypt_bundle(&plain(), &KEY, &[1u8; 12]);
        let bcb = e.blocks.iter().find(|b| b.type_code == BCB_TYPE_CODE).unwrap().clone();
        e.blocks.push(bcb);
        assert_eq!(decrypt_bundle(&e, &KEY), Err(DecryptError::MultipleConfidentialityBlocks));
    }

    #[test]
    fn malformed_bcb_rejected() {
        let mut b = plain();
        b.blocks.push(dtn_bpv7::CanonicalBlock {
            type_code: BCB_TYPE_CODE,
            block_number: BCB_BLOCK_NUMBER,
            control_flags: 0,
            data: vec![0u8; 4], // too short
        });
        assert_eq!(decrypt_bundle(&b, &KEY), Err(DecryptError::Malformed));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
