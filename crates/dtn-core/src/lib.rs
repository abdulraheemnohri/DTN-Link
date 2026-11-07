//! dtn-core — the node engine that ties BPv7, identity, storage and
//! routing together (multi-hop store-carry-forward included).

pub use dtn_bpv7::{Bundle, BundleId, Eid, BPV7_VERSION};
pub use dtn_identity::NodeIdentity;
pub use dtn_routing::{Decision, RoutingEngine, Strategy};
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

/// An outbound bundle selected for forwarding to a peer, with the
/// explainable routing decision that selected it.
#[derive(Debug)]
pub struct Outbound {
    pub bundle: Bundle,
    pub decision: Decision,
}

/// A DTN node: identity + persistent bundle store + routing engine.
pub struct Node {
    pub identity: NodeIdentity,
    pub store: BundleStore,
    pub routing: RoutingEngine,
    seq: u64,
}

impl Node {
    pub fn open(node_number: u64, db_path: &Path, strategy: Strategy) -> Result<Self, NodeError> {
        Ok(Node {
            identity: NodeIdentity::generate(node_number),
            store: BundleStore::open(db_path)?,
            routing: RoutingEngine::new(strategy),
            seq: 0,
        })
    }

    /// Opens the node, persisting the identity seed in a sidecar file
    /// `<db>.identity` (0600 on Unix) so the node keeps the same key pair
    /// across restarts. Generates and persists a new seed on first open.
    pub fn open_persistent(node_number: u64, db_path: &Path, strategy: Strategy) -> Result<Self, NodeError> {
        let mut os = db_path.as_os_str().to_os_string();
        os.push(".identity");
        let seed_path = std::path::PathBuf::from(os);
        let identity = if seed_path.exists() {
            let seed = std::fs::read(&seed_path)
                .map_err(|e| NodeError::Protocol(format!("read identity file: {e}")))?;
            let Ok(seed) = <[u8; 32]>::try_from(seed.as_slice()) else {
                return Err(NodeError::Protocol("identity file corrupt".into()));
            };
            NodeIdentity::from_seed(node_number, seed)
        } else {
            let id = NodeIdentity::generate(node_number);
            std::fs::write(&seed_path, id.seed_bytes())
                .map_err(|e| NodeError::Protocol(format!("write identity file: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &seed_path, std::fs::Permissions::from_mode(0o600));
            }
            id
        };
        Ok(Node {
            identity,
            store: BundleStore::open(db_path)?,
            routing: RoutingEngine::new(strategy),
            seq: 0,
        })
    }

    pub fn eid(&self) -> Eid { self.identity.eid.clone() }

    pub fn send(&mut self, destination: Eid, payload: Vec<u8>, lifetime: u64) -> Result<Bundle, NodeError> {
        self.seq += 1;
        let bundle = Bundle::new(self.eid(), destination, payload, lifetime, self.seq, dtn_storage::now());
        self.store.put(&bundle)?;
        Ok(bundle)
    }

    /// Accept an incoming bundle (any transport). Duplicates and expired
    /// bundles are rejected. Bundles for other nodes stay in the store for
    /// later store-carry-forward (multi-hop).
    pub fn receive(&mut self, wire: &[u8]) -> Result<Option<Bundle>, NodeError> {
        let bundle = Bundle::decode(wire).map_err(NodeError::Protocol)?;
        if bundle.is_expired(dtn_storage::now()) { return Ok(None); }
        let stored = self.store.put(&bundle)?;
        Ok(if stored { Some(bundle) } else { None })
    }

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

    /// Select bundles to forward to `peer` using the hybrid routing engine.
    pub fn select_outbound(&mut self, peer: &Eid) -> Result<Vec<Outbound>, NodeError> {
        self.routing.record_encounter(peer);
        let rows = self.store.all()?;
        let mut out = Vec::new();
        for r in rows {
            let Ok(bundle) = Bundle::decode(&r.data) else { continue };
            if self.store.is_delivered(&bundle.id()).unwrap_or(false) { continue; }
            let is_dest = bundle.primary.destination == *peer;
            let decision = self.routing.decide(&bundle, peer, is_dest);
            if decision.forward {
                out.push(Outbound { bundle, decision });
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
    fn persistent_identity_survives_restart() {
        let db = tmp("persid");
        let key1 = {
            let a = Node::open_persistent(5, &db, Strategy::Epidemic).unwrap();
            a.identity.public_key()
        };
        let key2 = Node::open_persistent(5, &db, Strategy::Epidemic).unwrap().identity.public_key();
        assert_eq!(key1, key2, "identity seed must persist across restarts");
        assert_ne!(
            Node::open_persistent(6, &db, Strategy::Epidemic).unwrap().identity.public_key(),
            key1,
            "different node numbers with same db path get different stored seeds is fine, key uniqueness checked"
        );
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(format!("{}.identity", db.display()));
    }

    #[test]
    fn send_receive_two_nodes() {
        let (db_a, db_b) = (tmp("a1"), tmp("b1"));
        let mut a = Node::open(1, &db_a, Strategy::Epidemic).unwrap();
        let mut b = Node::open(2, &db_b, Strategy::Epidemic).unwrap();
        let wire = a.send(b.eid(), b"offline msg".to_vec(), 3600).unwrap().encode();
        assert!(b.receive(&wire).unwrap().is_some());
        assert_eq!(b.inbox().unwrap().len(), 1);
        assert!(b.receive(&wire).unwrap().is_none());
        let _ = std::fs::remove_file(&db_a);
        let _ = std::fs::remove_file(&db_b);
    }

    #[test]
    fn multi_hop_three_nodes() {
        let (db_a, db_b, db_c) = (tmp("m1"), tmp("m2"), tmp("m3"));
        let mut a = Node::open(1, &db_a, Strategy::Epidemic).unwrap();
        let mut b = Node::open(2, &db_b, Strategy::Epidemic).unwrap();
        let mut c = Node::open(3, &db_c, Strategy::Epidemic).unwrap();
        let wire_a = a.send(c.eid(), b"hop through b".to_vec(), 3600).unwrap().encode();
        assert!(b.receive(&wire_a).unwrap().is_some());
        assert_eq!(b.inbox().unwrap().len(), 0);
        let outbound = b.select_outbound(&c.eid()).unwrap();
        assert_eq!(outbound.len(), 1);
        assert!(outbound[0].decision.forward);
        assert!(c.receive(&outbound[0].bundle.encode()).unwrap().is_some());
        assert_eq!(c.inbox().unwrap().len(), 1);
        let _ = std::fs::remove_file(&db_a);
        let _ = std::fs::remove_file(&db_b);
        let _ = std::fs::remove_file(&db_c);
    }

    #[test]
    fn partition_then_resume() {
        let (db_a, db_b) = (tmp("p1"), tmp("p2"));
        let mut a = Node::open(1, &db_a, Strategy::Epidemic).unwrap();
        let mut b = Node::open(2, &db_b, Strategy::Epidemic).unwrap();
        let wire = a.send(Eid::dtn("far-node"), b"wait for contact".to_vec(), 3600).unwrap().encode();
        b.receive(&wire).unwrap();
        assert_eq!(b.store.all().unwrap().len(), 1);
        let _ = std::fs::remove_file(&db_a);
        let _ = std::fs::remove_file(&db_b);
    }

    #[test]
    fn restart_preserves_messages() {
        let db = tmp("persist");
        {
            let mut a = Node::open(7, &db, Strategy::Epidemic).unwrap();
            a.send(Eid::dtn("x"), b"queued".to_vec(), 3600).unwrap();
        }
        {
            let a = Node::open(7, &db, Strategy::Epidemic).unwrap();
            assert!(a.store.count().unwrap() >= 1);
        }
        let _ = std::fs::remove_file(&db);
    }
}
