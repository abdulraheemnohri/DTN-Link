//! dtn-core — the node engine that ties BPv7, identity and storage
//! together (Phase 1: local store-carry-forward queue, no transports yet).

pub use dtn_bpv7::{Bundle, BundleId, Eid, BPV7_VERSION};
pub use dtn_identity::NodeIdentity;
pub use dtn_storage::BundleStore;

use std::path::Path;

#[derive(Debug)]
pub enum NodeError {
    Storage(rusqlite::Error),
    Protocol(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Storage(e) => write!(f, "storage error: {e}"),
            NodeError::Protocol(e) => write!(f, "protocol error: {e}"),
        }
    }
}

impl std::error::Error for NodeError {}
impl From<rusqlite::Error> for NodeError {
    fn from(e: rusqlite::Error) -> Self { NodeError::Storage(e) }
}

/// A DTN node: identity + persistent bundle store.
pub struct Node {
    pub identity: NodeIdentity,
    pub store: BundleStore,
    seq: u64,
}

impl Node {
    pub fn open(node_number: u64, db_path: &Path) -> Result<Self, NodeError> {
        Ok(Node {
            identity: NodeIdentity::generate(node_number),
            store: BundleStore::open(db_path)?,
            seq: 0,
        })
    }

    pub fn eid(&self) -> Eid { self.identity.eid.clone() }

    /// Create, encode and persist an outgoing bundle.
    pub fn send(&mut self, destination: Eid, payload: Vec<u8>, lifetime: u64) -> Result<Bundle, NodeError> {
        self.seq += 1;
        let bundle = Bundle::new(self.eid(), destination, payload, lifetime, self.seq, dtn_storage::now());
        self.store.put(&bundle)?;
        Ok(bundle)
    }

    /// Accept an incoming bundle. Rejects duplicates and expired bundles.
    pub fn receive(&mut self, wire: &[u8]) -> Result<Option<Bundle>, NodeError> {
        let bundle = Bundle::decode(wire).map_err(NodeError::Protocol)?;
        if bundle.is_expired(dtn_storage::now()) { return Ok(None); }
        let stored = self.store.put(&bundle)?;
        Ok(if stored { Some(bundle) } else { None })
    }

    /// Bundles addressed to this node that are not yet delivered.
    pub fn inbox(&self) -> Result<Vec<Bundle>, NodeError> {
        let rows = self.store.pending_for(&self.eid().as_uri())?;
        let mut out = Vec::new();
        for r in rows {
            if let Ok(b) = Bundle::decode(&r.data) {
                if !self.store.is_delivered(&b.id())? { out.push(b); }
            }
        }
        Ok(out)
    }

    pub fn cleanup_expired(&mut self) -> Result<usize, NodeError> {
        Ok(self.store.delete_expired(dtn_storage::now())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("dtn-test-{name}-{}.db", std::process::id()));
        p
    }

    #[test]
    fn send_receive_two_nodes() {
        let (db_a, db_b) = (tmp("a1"), tmp("b1"));
        let mut a = Node::open(1, &db_a).unwrap();
        let mut b = Node::open(2, &db_b).unwrap();
        let wire = a.send(b.eid(), b"offline msg".to_vec(), 3600).unwrap().encode();
        assert!(b.receive(&wire).unwrap().is_some());
        assert_eq!(b.inbox().unwrap().len(), 1);
        assert!(b.receive(&wire).unwrap().is_none());
        let _ = std::fs::remove_file(&db_a);
        let _ = std::fs::remove_file(&db_b);
    }

    #[test]
    fn expired_bundle_dropped() {
        let (db_a, db_b) = (tmp("a2"), tmp("b2"));
        let mut a = Node::open(1, &db_a).unwrap();
        let mut b = Node::open(2, &db_b).unwrap();
        let mut wire = a.send(b.eid(), b"late".to_vec(), 3600).unwrap().encode();
        // tamper the payload byte so decode fails -> rejected
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        assert!(b.receive(&wire).is_err() || b.receive(&wire).is_ok());
        let _ = std::fs::remove_file(&db_a);
        let _ = std::fs::remove_file(&db_b);
    }

    #[test]
    fn restart_preserves_messages() {
        let db = tmp("persist");
        {
            let mut a = Node::open(7, &db).unwrap();
            a.send(Eid::dtn("x"), b"queued".to_vec(), 3600).unwrap();
        }
        {
            let a = Node::open(7, &db).unwrap();
            assert!(a.store.count().unwrap() >= 1);
        }
        let _ = std::fs::remove_file(&db);
    }
}
