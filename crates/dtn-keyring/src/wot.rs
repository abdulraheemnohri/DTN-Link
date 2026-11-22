//! dtn-keyring::wot — web-of-trust key introductions (Phase 25).
//!
//! A TOFU keyring trusts whatever key first appears for an EID. The
//! web-of-trust layer answers a different question: "which keys can I
//! trust WITHOUT ever having met their owner in a contact myself?"
//!
//! A trusted introducer (a ROOT directly trusted by the operator, or
//! an EID already reachable through previously verified introductions)
//! signs an 'Introduction' announcement vouching for another EID's
//! Ed25519 key:
//!
//!   signed = [u16 intro len][introducer_eid]
//!            [u16 target len][introduced_eid]
//!            [32-byte introduced key][u64 signed_at]
//!   wire   = [DTNWI1][u16 intro len][introducer_eid]
//!            [u16 target len][introduced_eid]
//!            [32-byte introduced key][u64 signed_at]
//!            [64-byte Ed25519 signature by the introducer]
//!
//! 'WebOfTrust' persists roots and verified introduction rows in
//! SQLite and RECOMPUTES the BFS trust distances from the roots on
//! every query — so removing a root or an introduction automatically
//! distrusts every key that was only reachable through it.
//!
//! Integration: the phase 8+ contacts enforce keys from `Keyring`
//! (the operator-managed TOFU store). The web-of-trust bridge
//! `verify_signed_bundle_over_wot` verifies a bundle against the key
//! found for its source EID in the wot graph instead, so
//! wot-introduced keys are usable end to end. `dtn-link keyring wot`
//! exposes the graph to the operator (add-root / list / introduce /
//! record / untrust).
//!
//! Honest scope: trust here is a reachability statement ("a key I
//! trust at depth d vouches for that key"), not identity proof; trust
//! is never overwritten on conflict (the first verified key for an
//! EID wins) and there is no expiry or trust-value decay yet.

use crate::KeyringVerifyOutcome;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;

/// Magic prefix of an encoded `Introduction` announcement.
pub const INTRO_MAGIC: &[u8; 6] = b"DTNWI1";

/// Default reachability limit: a key at trust depth > DEFAULT_MAX_DEPTH
/// from any root is never trusted.
pub const DEFAULT_MAX_DEPTH: u32 = 3;

/// Errors of `Introduction::decode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntroError {
    /// Wrong magic, truncated fields, empty EIDs or trailing bytes.
    Malformed,
}

/// A signed introduction: "EID A vouches that EID B owns `introduced_key`".
#[derive(Debug, Clone, PartialEq)]
pub struct Introduction {
    /// The vouching EID (must hold the signing key).
    pub introducer_eid: String,
    /// The vouched-for EID.
    pub introduced_eid: String,
    /// The vouched-for public key.
    pub introduced_key: VerifyingKey,
    /// Unix seconds when the introduction was signed.
    pub signed_at: u64,
    /// Ed25519 signature by the introducer over `signed_bytes()`.
    pub signature: Signature,
}

impl Introduction {
    /// Bytes covered by the signature.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&(self.introducer_eid.len() as u16).to_be_bytes());
        msg.extend_from_slice(self.introducer_eid.as_bytes());
        msg.extend_from_slice(&(self.introduced_eid.len() as u16).to_be_bytes());
        msg.extend_from_slice(self.introduced_eid.as_bytes());
        msg.extend_from_slice(self.introduced_key.as_bytes());
        msg.extend_from_slice(&self.signed_at.to_be_bytes());
        msg
    }

    /// Create an introduction signed by the introducer's key.
    pub fn sign(
        introducer: &SigningKey,
        introducer_eid: &str,
        introduced_eid: &str,
        introduced_key: &VerifyingKey,
        signed_at: u64,
    ) -> Introduction {
        let mut intro = Introduction {
            introducer_eid: introducer_eid.to_string(),
            introduced_eid: introduced_eid.to_string(),
            introduced_key: *introduced_key,
            signed_at,
            signature: Signature::from_bytes(&[0u8; 64]),
        };
        intro.signature = introducer.sign(&intro.signed_bytes());
        intro
    }

    /// Verify the signature against the claimed introducer's key.
    pub fn verify_signature(&self, introducer_key: &VerifyingKey) -> bool {
        introducer_key.verify(&self.signed_bytes(), &self.signature).is_ok()
    }

    /// Wire encoding:
    /// `[DTNWI1][u16 intro len][introducer][u16 target len][target]
    ///  [32-byte key][u64 signed_at][64-byte sig]`
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            6 + 2 + self.introducer_eid.len() + 2 + self.introduced_eid.len() + 32 + 8 + 64,
        );
        out.extend_from_slice(INTRO_MAGIC);
        out.extend_from_slice(&(self.introducer_eid.len() as u16).to_be_bytes());
        out.extend_from_slice(self.introducer_eid.as_bytes());
        out.extend_from_slice(&(self.introduced_eid.len() as u16).to_be_bytes());
        out.extend_from_slice(self.introduced_eid.as_bytes());
        out.extend_from_slice(self.introduced_key.as_bytes());
        out.extend_from_slice(&self.signed_at.to_be_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    /// Strict decoder: exact field lengths, no trailing bytes,
    /// non-empty EIDs, valid Ed25519 key point.
    pub fn decode(bytes: &[u8]) -> Result<Introduction, IntroError> {
        let header = 6 + 2 + 2 + 32 + 8 + 64;
        if bytes.len() < header + 2 || &bytes[..6] != INTRO_MAGIC {
            return Err(IntroError::Malformed);
        }
        let mut i = 6;
        let intro_len = u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize;
        i += 2;
        if intro_len == 0 {
            return Err(IntroError::Malformed);
        }
        let target_idx = i.checked_add(intro_len)? + 2;
        if bytes.len() < target_idx {
            return Err(IntroError::Malformed);
        }
        let target_len = u16::from_be_bytes([bytes[target_idx - 2], bytes[target_idx - 1]]) as usize;
        if target_len == 0 {
            return Err(IntroError::Malformed);
        }
        if bytes.len() != target_idx + target_len + 32 + 8 + 64 {
            return Err(IntroError::Malformed);
        }
        let introducer_eid = String::from_utf8(bytes[i..i + intro_len].to_vec())
            .map_err(|_| IntroError::Malformed)?;
        let introduced_eid = String::from_utf8(bytes[target_idx..target_idx + target_len].to_vec())
            .map_err(|_| IntroError::Malformed)?;
        let mut i = target_idx + target_len;
        let mut kb = [0u8; 32];
        kb.copy_from_slice(&bytes[i..i + 32]);
        i += 32;
        let introduced_key = VerifyingKey::from_bytes(&kb).map_err(|_| IntroError::Malformed)?;
        let mut tb = [0u8; 8];
        tb.copy_from_slice(&bytes[i..i + 8]);
        i += 8;
        let signed_at = u64::from_be_bytes(tb);
        let mut sb = [0u8; 64];
        sb.copy_from_slice(&bytes[i..i + 64]);
        let signature = Signature::from_bytes(&sb);
        Ok(Introduction {
            introducer_eid,
            introduced_eid,
            introduced_key,
            signed_at,
            signature,
        })
    }
}

/// Outcome of applying an introduction to the web of trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// Trust applied; `depth` is the introduced key's distance from
    /// the nearest root (1 = vouched directly by a root).
    Applied { depth: u32 },
    /// This key for this EID is already known and trusted — no change.
    Duplicate,
    /// The introduction would replace an existing trust entry (root,
    /// closer edge or a different earlier key) — rejected, the store
    /// is untouched.
    Conflict,
    /// The introducer is not trusted within the depth limit.
    UnknownIntroducer,
    /// The signature does not verify under the introducer's trusted
    /// key — rejected.
    InvalidSignature,
    /// The introduction would put the key beyond the depth limit.
    DepthExceeded,
}

/// One trusted identity in the graph (BFS result row).
#[derive(Debug, Clone, PartialEq)]
pub struct WotEntry {
    pub eid: String,
    pub pubkey_hex: String,
    /// Trust depth (0 = operator root).
    pub depth: u32,
}

/// One stored introduction edge.
#[derive(Debug, Clone, PartialEq)]
pub struct IntroRow {
    pub introduced_by: String,
    pub introduced_eid: String,
    pub pubkey_hex: String,
    pub introduced_at: u64,
}

/// SQLite-backed web of trust: operator roots + verified signed
/// introductions, with per-query BFS reachability from the roots.
pub struct WebOfTrust {
    conn: Connection,
}

impl WebOfTrust {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, rusqlite::Error> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS wot_roots (
               eid TEXT PRIMARY KEY,
               pubkey BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS wot_intros (
               introduced_by TEXT NOT NULL,
               introduced_eid TEXT NOT NULL,
               pubkey BLOB NOT NULL,
               introduced_at INTEGER NOT NULL,
               signature BLOB NOT NULL,
               PRIMARY KEY (introduced_by, introduced_eid));")?;
        Ok(WebOfTrust { conn })
    }

    /// Add (or re-point) a directly trusted operator root. Returns
    /// true on insert, false when an existing root was replaced.
    pub fn add_root(&mut self, eid: &str, key: &VerifyingKey) -> Result<bool, rusqlite::Error> {
        let exists = self
            .conn
            .query_row("SELECT 1 FROM wot_roots WHERE eid = ?1", params![eid], |_| Ok(()))
            .is_ok();
        self.conn.execute(
            "INSERT INTO wot_roots (eid, pubkey) VALUES (?1, ?2)
             ON CONFLICT(eid) DO UPDATE SET pubkey = ?2",
            params![eid, key.as_bytes().to_vec()],
        )?;
        Ok(!exists)
    }

    /// Directly trusted roots (depth 0).
    pub fn roots(&self) -> Result<Vec<WotEntry>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT eid, pubkey FROM wot_roots ORDER BY eid")?;
        let rows = stmt
            .query_map([], |r| {
                let bytes: Vec<u8> = r.get(1)?;
                Ok(WotEntry {
                    eid: r.get(0)?,
                    pubkey_hex: to_hex(&bytes),
                    depth: 0,
                })
            })?;
        rows.collect()
    }

    /// Apply a signed introduction under the depth limit. The store
    /// is only mutated on `Applied`.
    pub fn record(
        &mut self,
        intro: &Introduction,
        max_depth: u32,
    ) -> Result<RecordOutcome, rusqlite::Error> {
        let effective = self.effective_set(max_depth)?;
        let Some((introducer_key, introducer_depth)) =
            effective.get(&intro.introducer_eid).cloned()
        else {
            return Ok(RecordOutcome::UnknownIntroducer);
        };
        if intro.signed_at == 0 {
            // The introducer must vouch with a real timestamp; a zero
            // stamp cannot be correlated or audited.
            return Ok(RecordOutcome::InvalidSignature);
        }
        if !intro.verify_signature(&introducer_key) {
            return Ok(RecordOutcome::InvalidSignature);
        }
        let depth = introducer_depth + 1;
        if depth > max_depth {
            return Ok(RecordOutcome::DepthExceeded);
        }
        // Previous introduction of the same target by the SAME
        // introducer (primary key)?
        let existing: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT pubkey FROM wot_intros WHERE introduced_by = ?1 AND introduced_eid = ?2",
                params![intro.introducer_eid, intro.introduced_eid],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        if let Some(bytes) = existing {
            return Ok(if bytes == intro.introduced_key.as_bytes().to_vec() {
                RecordOutcome::Duplicate
            } else {
                RecordOutcome::Conflict
            });
        }
        // Target already reachable through any (better or equal) key?
        if let Some((trusted_key, _)) = effective.get(&intro.introduced_eid) {
            return Ok(if *trusted_key == intro.introduced_key.as_bytes().to_vec() {
                RecordOutcome::Duplicate
            } else {
                RecordOutcome::Conflict
            });
        }
        self.conn.execute(
            "INSERT INTO wot_intros (introduced_by, introduced_eid, pubkey, introduced_at, signature)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                intro.introducer_eid,
                intro.introduced_eid,
                intro.introduced_key.as_bytes().to_vec(),
                intro.signed_at as i64,
                intro.signature.to_bytes().to_vec(),
            ],
        )?;
        Ok(RecordOutcome::Applied { depth })
    }

    /// Full trusted set (roots + everything reachable through verified
    /// introductions within `max_depth`), BFS from the roots, ordered
    /// by depth then EID. Recomputed per call, so any removed root or
    /// edge automatically drops everything behind it.
    pub fn trusted_set(&self, max_depth: u32) -> Result<Vec<WotEntry>, rusqlite::Error> {
        let effective = self.effective_set(max_depth)?;
        let mut out: Vec<WotEntry> = effective
            .into_iter()
            .map(|(eid, (key, depth))| WotEntry {
                eid,
                pubkey_hex: to_hex(&key),
                depth,
            })
            .collect();
        out.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.eid.cmp(&b.eid)));
        Ok(out)
    }

    /// Trust entry for one EID, if reachable within the limit.
    pub fn entry(&self, eid: &str, max_depth: u32) -> Result<Option<WotEntry>, rusqlite::Error> {
        Ok(self
            .trusted_set(max_depth)?
            .into_iter()
            .find(|e| e.eid == eid))
    }

    /// eid -> (key bytes, depth). BFS over roots + verified edges.
    fn effective_set(
        &self,
        max_depth: u32,
    ) -> Result<HashMap<String, (Vec<u8>, u32)>, rusqlite::Error> {
        let mut set: HashMap<String, (Vec<u8>, u32)> = HashMap::new();
        let mut stmt = self.conn.prepare("SELECT eid, pubkey FROM wot_roots")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let eid: String = r.get(0)?;
            let key: Vec<u8> = r.get(1)?;
            if key.len() == 32 {
                set.insert(eid, (key, 0));
            }
        }
        drop(rows);
        drop(stmt);
        // Relax repeatedly; small DTN graphs make fixed-point cheap and
        // deterministic (rows ordered by introduced_at).
        let mut changed = true;
        while changed {
            changed = false;
            let mut stmt = self.conn.prepare(
                "SELECT introduced_by, introduced_eid, pubkey
                 FROM wot_intros ORDER BY introduced_at, introduced_by, introduced_eid")?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let by: String = r.get(0)?;
                let eid: String = r.get(1)?;
                let key: Vec<u8> = r.get(2)?;
                if key.len() != 32 {
                    continue;
                }
                if let Some(&(_, depth)) = set.get(&by) {
                    let next = depth + 1;
                    if next > max_depth {
                        continue;
                    }
                    match set.get(&eid) {
                        None => {
                            set.insert(eid.clone(), (key, next));
                            changed = true;
                        }
                        Some((k, d)) if *d > next && *k == key => {
                            set.insert(eid.clone(), (key, next));
                            changed = true;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(set)
    }

    /// Raw stored introduction edges (audit view).
    pub fn intros(&self) -> Result<Vec<IntroRow>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT introduced_by, introduced_eid, pubkey, introduced_at
             FROM wot_intros ORDER BY introduced_at, introduced_by, introduced_eid")?;
        let rows = stmt.query_map([], |r| {
            let bytes: Vec<u8> = r.get(2)?;
            Ok(IntroRow {
                introduced_by: r.get(0)?,
                introduced_eid: r.get(1)?,
                pubkey_hex: to_hex(&bytes),
                introduced_at: r.get::<_, i64>(3)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Remove one introduction edge. Everything that was only
    /// reachable through it is distrusted by the next query.
    pub fn remove_introduction(
        &mut self,
        introduced_by: &str,
        introduced_eid: &str,
    ) -> Result<bool, rusqlite::Error> {
        let n = self.conn.execute(
            "DELETE FROM wot_intros WHERE introduced_by = ?1 AND introduced_eid = ?2",
            params![introduced_by, introduced_eid],
        )?;
        Ok(n == 1)
    }

    /// Withdraw trust in an EID (root entry, if any). Stored edges
    /// introduced by that EID stay on disk as history, but the BFS
    /// from the roots no longer reaches anything behind it.
    pub fn untrust(&mut self, eid: &str) -> Result<u64, rusqlite::Error> {
        let n = self.conn.execute("DELETE FROM wot_roots WHERE eid = ?1", params![eid])?;
        Ok(n as u64)
    }
}

/// Verify a signed bundle against the key found for its source EID in
/// the web of trust (instead of the TOFU keyring).
pub fn verify_signed_bundle_over_wot(
    bundle: &dtn_bpv7::Bundle,
    wot: &WebOfTrust,
    max_depth: u32,
) -> Result<KeyringVerifyOutcome, rusqlite::Error> {
    let source = bundle.primary.source_node.as_uri();
    let Some((key_hex, _)) = wot.entry(&source, max_depth)?.map(|e| (e.pubkey_hex, e.depth))
    else {
        let has_bib = bundle
            .blocks
            .iter()
            .any(|b| b.type_code == dtn_bpsec::BIB_TYPE_CODE);
        return Ok(if has_bib {
            KeyringVerifyOutcome::UnknownSource
        } else {
            KeyringVerifyOutcome::NoIntegrityBlock
        });
    };
    let mut kb = [0u8; 32];
    for (i, b) in key_hex.as_bytes().chunks(2).enumerate() {
        let hi = (b[0] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (b[1] as char).to_digit(16).unwrap_or(0) as u8;
        kb[i] = hi * 16 + lo;
    }
    let key = match VerifyingKey::from_bytes(&kb) {
        Ok(k) => k,
        Err(_) => return Ok(KeyringVerifyOutcome::UnknownSource),
    };
    Ok(match dtn_bpsec::verify_bundle(bundle, &key) {
        dtn_bpsec::VerifyOutcome::Valid => KeyringVerifyOutcome::Valid,
        dtn_bpsec::VerifyOutcome::Invalid => KeyringVerifyOutcome::Invalid,
        dtn_bpsec::VerifyOutcome::NoIntegrityBlock => KeyringVerifyOutcome::NoIntegrityBlock,
        dtn_bpsec::VerifyOutcome::MultipleIntegrityBlocks => {
            KeyringVerifyOutcome::MultipleIntegrityBlocks
        }
    })
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
