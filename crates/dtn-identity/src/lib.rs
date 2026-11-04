//! dtn-identity — cryptographic node identity (Phase 1).
//!
//! Ed25519 key pairs via `ed25519-dalek`. An EID alone is NEVER proof of
//! identity — trust decisions must use signatures.

use dtn_bpv7::Eid;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

#[derive(Clone)]
pub struct NodeIdentity {
    pub eid: Eid,
    signing: SigningKey,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity").field("eid", &self.eid).finish()
    }
}

impl NodeIdentity {
    pub fn generate(node_number: u64) -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        NodeIdentity { eid: Eid::ipn(node_number, 0), signing }
    }

    pub fn from_seed(node_number: u64, seed: [u8; 32]) -> Self {
        NodeIdentity { eid: Eid::ipn(node_number, 0), signing: SigningKey::from_bytes(&seed) }
    }

    pub fn public_key(&self) -> VerifyingKey { self.signing.verifying_key() }

    pub fn sign(&self, msg: &[u8]) -> Signature { self.signing.sign(msg) }

    pub fn verify(peer_key: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
        peer_key.verify(msg, sig).is_ok()
    }

    pub fn seed_bytes(&self) -> [u8; 32] { self.signing.to_bytes() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let a = NodeIdentity::generate(1);
        let b = NodeIdentity::generate(2);
        let msg = b"connect beyond connectivity";
        let sig = a.sign(msg);
        assert!(NodeIdentity::verify(&a.public_key(), msg, &sig));
        assert!(!NodeIdentity::verify(&b.public_key(), msg, &sig));
    }

    #[test]
    fn deterministic_from_seed() {
        let a = NodeIdentity::from_seed(9, [7u8; 32]);
        let b = NodeIdentity::from_seed(9, [7u8; 32]);
        assert_eq!(a.seed_bytes(), b.seed_bytes());
    }
}
