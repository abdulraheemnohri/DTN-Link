//! dtn-routing — hybrid routing engine (Phase 2-3).
//!
//! Three strategies per the DTN-Link master plan:
//! - Epidemic: forward to every encountered peer (resource-bounded).
//! - Spray-and-Wait: forward only while copy budget remains.
//! - Opportunistic: forward based on peer encounter history.
//!
//! Every decision returns an explainable reason; the caller records it.

use dtn_bpv7::{Bundle, Eid};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Epidemic,
    SprayWait,
    Opportunistic,
}

pub const DEFAULT_SPRAY_COPIES: u64 = 8;
pub const OPPORTUNISTIC_MIN_ENCOUNTERS: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub forward: bool,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct RoutingEngine {
    pub strategy: Strategy,
    pub spray_copies: u64,
    encounters: HashMap<String, u32>,
    spray_budget: HashMap<String, u64>,
}

impl RoutingEngine {
    pub fn new(strategy: Strategy) -> Self {
        RoutingEngine { strategy, spray_copies: DEFAULT_SPRAY_COPIES, encounters: HashMap::new(), spray_budget: HashMap::new() }
    }

    pub fn record_encounter(&mut self, peer: &Eid) {
        *self.encounters.entry(peer.as_uri()).or_insert(0) += 1;
    }

    pub fn encounter_count(&self, peer: &Eid) -> u32 {
        self.encounters.get(&peer.as_uri()).copied().unwrap_or(0)
    }

    fn bundle_key(b: &Bundle) -> String {
        let id = b.id();
        format!("{}|{}|{}", id.source.as_uri(), id.creation_ts.0, id.creation_ts.1)
    }

    pub fn decide(&mut self, bundle: &Bundle, peer: &Eid, is_destination: bool) -> Decision {
        if is_destination {
            return Decision { forward: true, reason: "peer is bundle destination".into() };
        }
        if bundle.is_expired(bundle.primary.creation_ts.0.saturating_add(bundle.primary.lifetime)) {
            return Decision { forward: false, reason: "bundle expired".into() };
        }
        match self.strategy {
            Strategy::Epidemic => Decision { forward: true, reason: "epidemic: replicate to encountered peer".into() },
            Strategy::SprayWait => {
                let key = Self::bundle_key(bundle);
                let budget = self.spray_budget.entry(key).or_insert(self.spray_copies);
                if *budget > 0 {
                    *budget -= 1;
                    Decision { forward: true, reason: format!("spray-and-wait: copy sent, {} remaining", *budget) }
                } else {
                    Decision { forward: false, reason: "spray-and-wait: copy budget exhausted".into() }
                }
            }
            Strategy::Opportunistic => {
                let n = self.encounter_count(peer);
                if n >= OPPORTUNISTIC_MIN_ENCOUNTERS {
                    Decision { forward: true, reason: format!("opportunistic: peer encountered {n} times") }
                } else {
                    Decision { forward: false, reason: format!("opportunistic: only {n} encounters with peer") }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_bpv7::Eid;

    fn bundle(src: &str, dst: &str) -> Bundle {
        Bundle::new(Eid::dtn(src), Eid::dtn(dst), b"m".to_vec(), 3600, 1, 1000)
    }

    #[test]
    fn destination_always_forwards() {
        let mut r = RoutingEngine::new(Strategy::SprayWait);
        let b = bundle("a", "b");
        assert!(r.decide(&b, &Eid::dtn("b"), true).forward);
    }

    #[test]
    fn epidemic_replicates_everywhere() {
        let mut r = RoutingEngine::new(Strategy::Epidemic);
        let b = bundle("a", "c");
        assert!(r.decide(&b, &Eid::dtn("b"), false).forward);
        assert!(r.decide(&b, &Eid::dtn("x"), false).forward);
    }

    #[test]
    fn spray_wait_budget_bounded() {
        let mut r = RoutingEngine::new(Strategy::SprayWait);
        r.spray_copies = 3;
        let b = bundle("a", "c");
        assert!(r.decide(&b, &Eid::dtn("p1"), false).forward);
        assert!(r.decide(&b, &Eid::dtn("p2"), false).forward);
        assert!(r.decide(&b, &Eid::dtn("p3"), false).forward);
        assert!(!r.decide(&b, &Eid::dtn("p4"), false).forward);
    }

    #[test]
    fn opportunistic_needs_history() {
        let mut r = RoutingEngine::new(Strategy::Opportunistic);
        let b = bundle("a", "c");
        let peer = Eid::dtn("b");
        assert!(!r.decide(&b, &peer, false).forward);
        r.record_encounter(&peer);
        r.record_encounter(&peer);
        assert!(r.decide(&b, &peer, false).forward);
    }
}
