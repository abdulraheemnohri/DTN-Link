//! dtn-keyring — trusted public keys per EID (key distribution).
//!
//! An EID alone is NEVER proof of identity. This crate is the local
//! trust store: it maps an endpoint (EID URI) to the Ed25519 public
//! key that the operator has decided to trust for that endpoint.
//! BPSec verification then answers "is this bundle really signed by
//! the key I trust for this sender?".
//!
//! Honest scope: this is a manual trust-on-first-use (TOFU) store —
//! keys are added by the operator (CLI or future pairing UI). Automatic
//! key exchange in the hello/contact protocol, key rotation with
//! signed key-change messages, and a web-of-trust are future work.

use ed25519_dalek::VerifyingKey;
use rusqlite::{params, Connection};
use std::path::Path;

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
}
