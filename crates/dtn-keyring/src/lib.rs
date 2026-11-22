//! dtn-keyring — trusted public keys per EID (key distribution).
//!
//! An EID alone is NEVER proof of identity. This crate is the local
//! trust store: it maps an endpoint (EID URI) to the Ed25519 public
//! key that the operator has decided to trust for that endpoint.
//! BPSec verification then answers "is this bundle really signed by
//! the key I trust for this sender?".
//!
//! Phase 17 — MITM hardening:
//!   * `Keyring::check` classifies a presented hello key as
//!     New / Match / Mismatch against the trusted key.
//!   * Signed key rotation: a `KeyChange` announcement carries the
//!     new public key plus an Ed25519 signature made by the PREVIOUS
//!     (currently trusted) key. `Keyring::rotate` only applies a
//!     change whose signature verifies against the key it is
//!     replacing — an attacker without the old private key cannot
//!     rotate a peer's entry.
//!
//! Honest scope: this remains a trust-on-first-use (TOFU) store —
//! the FIRST key seen for an EID is trusted (operator-managed via
//! the CLI or learned during a contact). signed web-of-trust key
//! introductions live in `dtn_keyring::wot` (Phase 25); the keyring
//! itself stays the TOFU enforcement store.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{params, Connection};
use std::path::Path;

pub mod wot;

pub struct Keyring {
    conn: Connection,
}

#[derive(Debug, PartialEq)]
pub struct TrustedKey {
    pub eid: String,
    pub pubkey_hex: String,
    pub added_at: u64,
}

#[derive(Debug, PartialEq)]
pub enum LookupError {
    /// EID not in the keyring — cannot verify.
    UnknownKey,
}

/// Result of comparing a presented key with the trusted key for an
/// EID (Phase 17 TOFU classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TofuCheck {
    /// No trusted key yet — first contact (trust-on-first-use).
    New,
    /// Presented key equals the trusted key.
    Match,
    /// Presented key DIFFERS from the trusted key: either a genuine
    /// rotation or a man-in-the-middle. Callers decide enforcement.
    Mismatch,
}

/// Outcome of a signed key-rotation attempt (Phase 17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRotation {
    /// The trusted key was replaced with the announced new key.
    Rotated,
    /// No trusted key exists for this EID — there is nothing to
    /// rotate from (a first key must be TOFU'd or added manually).
    UnknownKey,
    /// The announcement's signature does not verify against the
    /// currently trusted key — rejected.
    InvalidSignature,
}

/// Wire-format errors for `KeyChange::decode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyChangeError {
    /// Wrong magic, truncated fields, trailing bytes or a key that is
    /// not a valid Ed25519 point.
    Malformed,
}

/// Magic prefix of an encoded `KeyChange` announcement.
pub const KEYCHANGE_MAGIC: &[u8; 6] = b"DTNKC1";

/// A signed key-rotation announcement (Phase 17).
///
/// The node that rotated its identity key signs the NEW public key
/// with the OLD (previously trusted) private key. Peers holding the
/// old key can verify the change and update their trust store;
/// an attacker who does not control the old key cannot.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyChange {
    /// EID whose key is being rotated.
    pub eid: String,
    /// The new public key.
    pub new_key: VerifyingKey,
    /// Unix seconds when the rotation was performed.
    pub rotated_at: u64,
    /// Ed25519 signature by the OLD key over
    /// `eid || new_key || rotated_at`.
    pub signature: Signature,
}

impl KeyChange {
    /// Bytes covered by the signature.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(self.eid.len() + 40);
        msg.extend_from_slice(self.eid.as_bytes());
        msg.extend_from_slice(self.new_key.as_bytes());
        msg.extend_from_slice(&self.rotated_at.to_be_bytes());
        msg
    }

    /// Create a rotation announcement signed with the OLD signing key.
    pub fn sign(
        eid: &str,
        old_signing: &SigningKey,
        new_key: &VerifyingKey,
        rotated_at: u64,
    ) -> KeyChange {
        let mut kc = KeyChange {
            eid: eid.to_string(),
            new_key: *new_key,
            rotated_at,
            signature: Signature::from_bytes(&[0u8; 64]),
        };
        kc.signature = old_signing.sign(&kc.signed_bytes());
        kc
    }

    /// Verify the announcement against a candidate OLD (trusted) key.
    pub fn verify_signature(&self, trusted: &VerifyingKey) -> bool {
        trusted.verify(&self.signed_bytes(), &self.signature).is_ok()
    }

    /// Wire encoding:
    /// `[DTNKC1][u16 eid len][eid][32-byte new key][u64 rotated_at][64-byte sig]`
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + 2 + self.eid.len() + 32 + 8 + 64);
        out.extend_from_slice(KEYCHANGE_MAGIC);
        out.extend_from_slice(&(self.eid.len() as u16).to_be_bytes());
        out.extend_from_slice(self.eid.as_bytes());
        out.extend_from_slice(self.new_key.as_bytes());
        out.extend_from_slice(&self.rotated_at.to_be_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    /// Strict decoder: exact field lengths, no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<KeyChange, KeyChangeError> {
        if bytes.len() < 6 + 2 + 32 + 8 + 64 || &bytes[..6] != KEYCHANGE_MAGIC {
            return Err(KeyChangeError::Malformed);
        }
        let mut i = 6;
        let eid_len = u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize;
        i += 2;
        if bytes.len() != i + eid_len + 32 + 8 + 64 {
            return Err(KeyChangeError::Malformed);
        }
        let eid = String::from_utf8(bytes[i..i + eid_len].to_vec())
            .map_err(|_| KeyChangeError::Malformed)?;
        i += eid_len;
        let mut kb = [0u8; 32];
        kb.copy_from_slice(&bytes[i..i + 32]);
        i += 32;
        let new_key = VerifyingKey::from_bytes(&kb).map_err(|_| KeyChangeError::Malformed)?;
        let mut tb = [0u8; 8];
        tb.copy_from_slice(&bytes[i..i + 8]);
        i += 8;
        let rotated_at = u64::from_be_bytes(tb);
        let mut sb = [0u8; 64];
        sb.copy_from_slice(&bytes[i..i + 64]);
        let signature = Signature::from_bytes(&sb);
        Ok(KeyChange { eid, new_key, rotated_at, signature })
    }
}

impl Keyring {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS trusted_keys (
               eid TEXT PRIMARY KEY,
               pubkey BLOB NOT NULL,
               added_at INTEGER NOT NULL);")?;
        Ok(Keyring { conn })
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(Path::new(":memory:"))
    }

    /// Insert or replace the trusted key for an EID. Returns true if a
    /// new row was inserted (false if an existing key was replaced).
    pub fn put(&mut self, eid: &str, key: &VerifyingKey) -> Result<bool, rusqlite::Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let existing = self.get(eid)?;
        self.conn.execute(
            "INSERT INTO trusted_keys (eid, pubkey, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(eid) DO UPDATE SET pubkey = ?2, added_at = ?3",
            params![eid, key.as_bytes().to_vec(), now as i64])?;
        Ok(existing.is_none())
    }

    pub fn get(&self, eid: &str) -> Result<Option<VerifyingKey>, rusqlite::Error> {
        let raw: Option<Vec<u8>> = self.conn.query_row(
            "SELECT pubkey FROM trusted_keys WHERE eid = ?1",
            params![eid], |r| r.get(0)).map(Some).or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        match raw {
            None => Ok(None),
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                VerifyingKey::from_bytes(&arr).map(Some).map_err(|e| {
                    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
                })
            }
            Some(_) => Err(rusqlite::Error::InvalidQuery),
        }
    }

    /// Classify a presented key against the trusted key for an EID
    /// (Phase 17). Never mutates the store.
    pub fn check(&self, eid: &str, key: &VerifyingKey) -> Result<TofuCheck, rusqlite::Error> {
        match self.get(eid)? {
            None => Ok(TofuCheck::New),
            Some(trusted) if trusted.as_bytes() == key.as_bytes() => Ok(TofuCheck::Match),
            Some(_) => Ok(TofuCheck::Mismatch),
        }
    }

    /// Apply a signed key-rotation announcement (Phase 17). The
    /// announcement's signature must verify against the key that is
    /// CURRENTLY trusted for the EID; otherwise the store is not
    /// touched.
    pub fn rotate(&mut self, change: &KeyChange) -> Result<KeyRotation, rusqlite::Error> {
        let Some(trusted) = self.get(&change.eid)? else {
            return Ok(KeyRotation::UnknownKey);
        };
        if !change.verify_signature(&trusted) {
            return Ok(KeyRotation::InvalidSignature);
        }
        self.put(&change.eid, &change.new_key)?;
        Ok(KeyRotation::Rotated)
    }

    pub fn remove(&mut self, eid: &str) -> Result<bool, rusqlite::Error> {
        let n = self.conn.execute("DELETE FROM trusted_keys WHERE eid = ?1", params![eid])?;
        Ok(n == 1)
    }

    pub fn list(&self) -> Result<Vec<TrustedKey>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT eid, pubkey, added_at FROM trusted_keys ORDER BY eid")?;
        let rows = stmt.query_map([], |r| {
            let bytes: Vec<u8> = r.get(1)?;
            Ok(TrustedKey {
                eid: r.get(0)?,
                pubkey_hex: bytes.iter().map(|b| format!("{b:02x}")).collect(),
                added_at: r.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect()
    }

    pub fn count(&self) -> Result<i64, rusqlite::Error> {
        self.conn.query_row("SELECT COUNT(*) FROM trusted_keys", [], |r| r.get(0))
    }
}

/// Verify a signed bundle against the key trusted for its source EID.
#[derive(Debug, PartialEq)]
pub enum KeyringVerifyOutcome {
    /// Signature valid under the trusted key for this source.
    Valid,
    /// Signature invalid — key mismatch or tampering.
    Invalid,
    /// Source EID has no trusted key; cannot verify.
    UnknownSource,
    /// Bundle has no integrity block.
    NoIntegrityBlock,
    /// Malformed: multiple integrity blocks.
    MultipleIntegrityBlocks,
}

pub fn verify_signed_bundle(bundle: &dtn_bpv7::Bundle, keyring: &Keyring) -> Result<KeyringVerifyOutcome, rusqlite::Error> {
    use dtn_bpsec::VerifyOutcome;
    let source = bundle.primary.source_node.as_uri();
    let Some(key) = keyring.get(&source)? else {
        // Distinguish "no BIB" from "unknown source" before reporting.
        let has_bib = bundle.blocks.iter().any(|b| b.type_code == dtn_bpsec::BIB_TYPE_CODE);
        return Ok(if has_bib { KeyringVerifyOutcome::UnknownSource } else { KeyringVerifyOutcome::NoIntegrityBlock });
    };
    Ok(match dtn_bpsec::verify_bundle(bundle, &key) {
        VerifyOutcome::Valid => KeyringVerifyOutcome::Valid,
        VerifyOutcome::Invalid => KeyringVerifyOutcome::Invalid,
        VerifyOutcome::NoIntegrityBlock => KeyringVerifyOutcome::NoIntegrityBlock,
        VerifyOutcome::MultipleIntegrityBlocks => KeyringVerifyOutcome::MultipleIntegrityBlocks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_bpsec::{sign_bundle, BIB_TYPE_CODE};
    use dtn_bpv7::{Bundle, Eid};
    use dtn_identity::NodeIdentity;

    fn keyring() -> Keyring { Keyring::open_in_memory().unwrap() }

    fn identity_and_bundle(n: u64, signed: bool) -> (NodeIdentity, Bundle) {
        let id = NodeIdentity::generate(n);
        let b = Bundle::new(id.eid.clone(), Eid::dtn("b"), b"trusted message".to_vec(), 3600, 1, 1000);
        let b = if signed { sign_bundle(&b, &id) } else { b };
        (id, b)
    }

    #[test]
    fn put_get_roundtrip() {
        let mut k = keyring();
        let (id, _) = identity_and_bundle(7, false);
        assert!(k.put(&id.eid.as_uri(), &id.public_key()).unwrap());
        let fetched = k.get(&id.eid.as_uri()).unwrap().unwrap();
        assert_eq!(fetched, id.public_key());
        assert_eq!(k.count().unwrap(), 1);
    }

    #[test]
    fn replace_updates_key() {
        let mut k = keyring();
        let (id, _) = identity_and_bundle(7, false);
        let eid = id.eid.as_uri();
        k.put(&eid, &id.public_key()).unwrap();
        let other = NodeIdentity::generate(8);
        assert!(!k.put(&eid, &other.public_key()).unwrap()); // replaced, not inserted
        assert_eq!(k.get(&eid).unwrap().unwrap(), other.public_key());
        assert_eq!(k.count().unwrap(), 1);
    }

    #[test]
    fn unknown_eid_is_none() {
        let k = keyring();
        assert!(k.get("dtn://nobody").unwrap().is_none());
    }

    #[test]
    fn remove_deletes() {
        let mut k = keyring();
        let (id, _) = identity_and_bundle(7, false);
        k.put(&id.eid.as_uri(), &id.public_key()).unwrap();
        assert!(k.remove(&id.eid.as_uri()).unwrap());
        assert!(!k.remove(&id.eid.as_uri()).unwrap());
        assert!(k.get(&id.eid.as_uri()).unwrap().is_none());
    }

    #[test]
    fn list_shows_keys() {
        let mut k = keyring();
        let (id, _) = identity_and_bundle(7, false);
        k.put(&id.eid.as_uri(), &id.public_key()).unwrap();
        let l = k.list().unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].eid, id.eid.as_uri());
        assert_eq!(l[0].pubkey_hex.len(), 64);
    }

    #[test]
    fn verify_valid_signed_bundle() {
        let mut k = keyring();
        let (id, b) = identity_and_bundle(7, true);
        k.put(&id.eid.as_uri(), &id.public_key()).unwrap();
        assert_eq!(verify_signed_bundle(&b, &k).unwrap(), KeyringVerifyOutcome::Valid);
    }

    #[test]
    fn verify_tampered_bundle_invalid() {
        let mut k = keyring();
        let (id, mut b) = identity_and_bundle(7, true);
        k.put(&id.eid.as_uri(), &id.public_key()).unwrap();
        if let Some(p) = b.blocks.iter_mut().find(|x| x.type_code == 1) {
            p.data = b"evil".to_vec();
        }
        assert_eq!(verify_signed_bundle(&b, &k).unwrap(), KeyringVerifyOutcome::Invalid);
    }

    #[test]
    fn verify_unknown_source() {
        let k = keyring();
        let (_, b) = identity_and_bundle(42, true);
        assert_eq!(verify_signed_bundle(&b, &k).unwrap(), KeyringVerifyOutcome::UnknownSource);
        let _ = BIB_TYPE_CODE;
    }

    #[test]
    fn verify_unsigned_bundle() {
        let mut k = keyring();
        let (id, b) = identity_and_bundle(7, false);
        k.put(&id.eid.as_uri(), &id.public_key()).unwrap();
        assert_eq!(verify_signed_bundle(&b, &k).unwrap(), KeyringVerifyOutcome::NoIntegrityBlock);
    }

    #[test]
    fn keyring_persists_to_disk() {
        let dir = std::env::temp_dir().join(format!("dtn-keyring-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.db");
        let (id, _) = identity_and_bundle(7, false);
        {
            let mut k = Keyring::open(&path).unwrap();
            k.put(&id.eid.as_uri(), &id.public_key()).unwrap();
        }
        let k2 = Keyring::open(&path).unwrap();
        assert_eq!(k2.get(&id.eid.as_uri()).unwrap().unwrap(), id.public_key());
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- Phase 17: TOFU classification + signed key rotation ----

    #[test]
    fn tofu_check_classifies_new_match_mismatch() {
        let mut k = keyring();
        let (id, _) = identity_and_bundle(5, false);
        let eid = id.eid.as_uri();
        assert_eq!(k.check(&eid, &id.public_key()).unwrap(), TofuCheck::New);
        k.put(&eid, &id.public_key()).unwrap();
        assert_eq!(k.check(&eid, &id.public_key()).unwrap(), TofuCheck::Match);
        let other = NodeIdentity::generate(6);
        assert_eq!(k.check(&eid, &other.public_key()).unwrap(), TofuCheck::Mismatch);
    }

    #[test]
    fn key_change_sign_and_verify() {
        let old = NodeIdentity::from_seed(5, [9u8; 32]);
        let new = NodeIdentity::from_seed(5, [10u8; 32]); // same EID, new key
        let kc = KeyChange::sign(&old.eid.as_uri(), &old.signing_key(), &new.public_key(), 1700);
        assert!(kc.verify_signature(&old.public_key()));
        assert!(!kc.verify_signature(&new.public_key()), "must verify against the OLD key only");
    }

    #[test]
    fn key_change_wire_roundtrip() {
        let old = NodeIdentity::from_seed(5, [9u8; 32]);
        let new = NodeIdentity::from_seed(5, [10u8; 32]);
        let kc = KeyChange::sign(&old.eid.as_uri(), &old.signing_key(), &new.public_key(), 1750);
        let wire = kc.encode();
        let decoded = KeyChange::decode(&wire).unwrap();
        assert_eq!(decoded, kc);
        assert!(decoded.verify_signature(&old.public_key()));
    }

    #[test]
    fn key_change_decode_rejects_garbage() {
        assert_eq!(KeyChange::decode(b"nope"), Err(KeyChangeError::Malformed));
        let old = NodeIdentity::from_seed(5, [9u8; 32]);
        let new = NodeIdentity::from_seed(5, [10u8; 32]);
        let wire = KeyChange::sign(&old.eid.as_uri(), &old.signing_key(), &new.public_key(), 1).encode();
        // Truncated.
        assert_eq!(KeyChange::decode(&wire[..wire.len() - 1]), Err(KeyChangeError::Malformed));
        // Trailing byte.
        let mut extra = wire.clone();
        extra.push(0);
        assert_eq!(KeyChange::decode(&extra), Err(KeyChangeError::Malformed));
        // Wrong magic.
        let mut bad = wire.clone();
        bad[0] = b'X';
        assert_eq!(KeyChange::decode(&bad), Err(KeyChangeError::Malformed));
    }

    #[test]
    fn rotate_applies_validly_signed_change() {
        let mut k = keyring();
        let old = NodeIdentity::from_seed(5, [9u8; 32]);
        let new = NodeIdentity::from_seed(5, [10u8; 32]);
        let eid = old.eid.as_uri();
        k.put(&eid, &old.public_key()).unwrap();
        let kc = KeyChange::sign(&eid, &old.signing_key(), &new.public_key(), 1800);
        assert_eq!(k.rotate(&kc).unwrap(), KeyRotation::Rotated);
        assert_eq!(k.get(&eid).unwrap().unwrap(), new.public_key());
    }

    #[test]
    fn rotate_rejects_unsigned_and_unknown() {
        let mut k = keyring();
        let old = NodeIdentity::from_seed(5, [9u8; 32]);
        let new = NodeIdentity::from_seed(5, [10u8; 32]);
        let attacker = NodeIdentity::generate(99);
        let eid = old.eid.as_uri();
        k.put(&eid, &old.public_key()).unwrap();

        // Signed by a key that is NOT the currently trusted one.
        let forged = KeyChange::sign(&eid, &attacker.signing_key(), &new.public_key(), 1800);
        assert_eq!(k.rotate(&forged).unwrap(), KeyRotation::InvalidSignature);
        assert_eq!(k.get(&eid).unwrap().unwrap(), old.public_key(), "store must be untouched");

        // Valid rotation, then an unknown EID: nothing to rotate from.
        let kc = KeyChange::sign(&eid, &old.signing_key(), &new.public_key(), 1800);
        assert_eq!(k.rotate(&kc).unwrap(), KeyRotation::Rotated);
        let fresh = KeyChange::sign("dtn://ghost", &old.signing_key(), &new.public_key(), 1800);
        assert_eq!(k.rotate(&fresh).unwrap(), KeyRotation::UnknownKey);
    }
}
