//! dtn-federation — DTN-Link federation layer.
//!
//! A DTN-Link network may grow beyond one region: a field team, a
//! headquarters network, a satellite ground segment. Federation is
//! the policy that connects them: which EIDs belong to which region
//! (RegionMap), which gateway peer carries traffic to a remote
//! region (the Federation plan), and an explainable routing decision
//! for any destination (route_to).
//!
//! Delivery uses REAL contacts: Federation::sweep scans the store
//! for pending bundles destined to remote regions and performs a
//! full dtn-gateway contact against each responsible gateway — the
//! same TCPCL-lite exchange with the optional security stack that
//! the daemon and every adapter use. A gateway is an ordinary
//! DTN-Link listener; nothing is faked.
//!
//! Security policy (Phase 15): a plan may mark a region
//! `require-signed`, meaning bundles must cross its gateway with the
//! BPSec security stack enabled. A sweep without a SecurityCtx then
//! refuses the contact and reports the region as blocked instead of
//! silently sending plaintext into a region that forbids it.
//!
//! Management (Phase 15): `sweep_logged` records every federation
//! contact — success or failure, with per-contact bundle counters —
//! into a dtn-diagnostics ContactLog tagged `Kind::Federation`, so
//! `dtn-link doctor` shows inter-region traffic.
//!
//! Honest scope: federation is routing policy, not a topology
//! database — the receiving gateway forwards with its own routing
//! engine. Regions are prefix-based; there is no automatic region
//! discovery.

use dtn_bpv7::{Bundle, Eid};
use dtn_core::{Node, NodeError};
use dtn_daemon::SecurityCtx;
use dtn_diagnostics::{ContactLog, Kind};
use dtn_gateway::{contact_counted, ContactReport, GatewayError};
use std::sync::{Arc, Mutex};

/// EID -> region membership by URI prefix.
///
/// Text format, one entry per line (blank lines and # comments are
/// ignored):
///
///     # region  eid-prefix
///     field ipn:1.
///     hq    ipn:9.
///     lab   dtn://lab/
///
/// An EID is in a region when its URI starts with the entry's
/// prefix; the LONGEST matching prefix wins, so a specific entry
/// ("ipn:9.") can override a broad one ("ipn:").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegionMap {
    /// (eid-uri prefix, region) entries in insertion order.
    entries: Vec<(String, String)>,
}

impl RegionMap {
    pub fn new() -> Self {
        RegionMap {
            entries: Vec::new(),
        }
    }

    /// Add a membership entry: EIDs whose URI starts with 'prefix'
    /// belong to 'region'.
    pub fn add(&mut self, prefix: impl Into<String>, region: impl Into<String>) {
        self.entries.push((prefix.into(), region.into()));
    }

    /// Parse a region map from text. Returns the offending line on
    /// error.
    pub fn parse(text: &str) -> Result<RegionMap, String> {
        let mut map = RegionMap::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let region = parts.next().unwrap_or_default().to_string();
            let prefix = parts.next().unwrap_or_default().to_string();
            if region.is_empty() || prefix.is_empty() {
                return Err(format!("line {}: expected 'region eid-prefix'", i + 1));
            }
            if parts.next().is_some() {
                return Err(format!("line {}: unexpected extra field", i + 1));
            }
            map.entries.push((prefix, region));
        }
        Ok(map)
    }

    /// Serialize back to the parseable text format.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for (prefix, region) in &self.entries {
            out.push_str(&format!("{region} {prefix}\n"));
        }
        out
    }

    /// The region of an EID (longest matching prefix wins).
    pub fn region_of(&self, eid: &Eid) -> Option<&str> {
        let uri = eid.as_uri();
        let mut best: Option<(usize, &str)> = None;
        for (prefix, region) in &self.entries {
            if uri.starts_with(prefix.as_str())
                && best.map_or(true, |(len, _)| prefix.len() > len)
            {
                best = Some((prefix.len(), region));
            }
        }
        best.map(|(_, r)| r)
    }
}

/// A gateway peer that carries bundles into a remote region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    /// The remote region this gateway serves.
    pub region: String,
    /// The gateway node's EID (informational; the contact addresses
    /// the listener and learns the peer EID from its hello).
    pub eid: Eid,
    /// 'host:port' of the gateway node's DTN listener.
    pub addr: String,
}

/// Per-region security policy for outgoing federation traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionPolicy {
    /// Any contact may carry this region's traffic (default).
    AllowPlain,
    /// Bundles may only cross this region's gateway with the BPSec
    /// stack enabled (signed outbound + verified inbound). A sweep
    /// without a SecurityCtx blocks the region instead of sending
    /// plaintext.
    RequireSigned,
}

impl RegionPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            RegionPolicy::AllowPlain => "allow-plain",
            RegionPolicy::RequireSigned => "require-signed",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow-plain" => Some(RegionPolicy::AllowPlain),
            "require-signed" => Some(RegionPolicy::RequireSigned),
            _ => None,
        }
    }
}

/// The local region plus the gateway peers for remote regions.
///
/// Text plan format (blank lines and # comments are ignored):
///
///     # our region first
///     local field
///     # region  gateway-eid   gateway-addr
///     hq        ipn:10.0      10.0.0.7:4556
///     lab       dtn://labgw   192.168.1.5:4556
///     # optional per-region security policy
///     policy    hq            require-signed
#[derive(Debug, Clone)]
pub struct Federation {
    /// The region this node belongs to.
    pub local_region: String,
    /// EID membership (not part of the plan text; set separately).
    pub regions: RegionMap,
    /// One gateway per remote region.
    pub gateways: Vec<Gateway>,
    /// Per-region security policies (default AllowPlain).
    pub policies: Vec<(String, RegionPolicy)>,
}

/// Explainable routing decision for one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Destination is in our own region: normal (intra-region)
    /// store-carry-forward handles it.
    Local,
    /// Destination is in a remote region we have a gateway for.
    ViaGateway(Gateway),
    /// Unknown region, or a known region with no configured gateway.
    NoRoute,
}

/// Result of one federation sweep: per-region successes, failures,
/// skipped (pending but gateway-less) and policy-blocked regions.
#[derive(Debug, Default)]
pub struct FedSweepReport {
    /// (region, contact report) for every contacted gateway.
    pub successes: Vec<(String, ContactReport)>,
    /// (region, error) for gateways that failed; one dead gateway
    /// never blocks the others.
    pub failures: Vec<(String, GatewayError)>,
    /// Remote regions that have pending bundles but no configured
    /// gateway.
    pub skipped: Vec<String>,
    /// (region, reason) for regions whose security policy forbade
    /// the contact under the given security context.
    pub blocked: Vec<(String, String)>,
}

impl Federation {
    /// Parse a federation plan from text (see the type docs). The
    /// region map is NOT part of the plan; set it with set_regions
    /// or with_regions.
    pub fn parse(text: &str) -> Result<Federation, String> {
        let mut local: Option<String> = None;
        let mut gateways = Vec::new();
        let mut policies = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let first = parts.next().unwrap_or_default();
            if first == "local" {
                let region = parts.next().unwrap_or_default().to_string();
                if region.is_empty() {
                    return Err(format!("line {}: 'local' needs a region name", i + 1));
                }
                local = Some(region);
            } else if first == "policy" {
                let region = parts.next().unwrap_or_default().to_string();
                let pol_s = parts.next().unwrap_or_default().to_string();
                if region.is_empty() || pol_s.is_empty() {
                    return Err(format!(
                        "line {}: expected 'policy <region> <allow-plain|require-signed>'",
                        i + 1
                    ));
                }
                let policy = RegionPolicy::parse(&pol_s).ok_or_else(|| {
                    format!(
                        "line {}: unknown policy '{pol_s}' (expected allow-plain or require-signed)",
                        i + 1
                    )
                })?;
                if parts.next().is_some() {
                    return Err(format!("line {}: unexpected extra field", i + 1));
                }
                if policies.iter().any(|(r, _)| r == &region) {
                    return Err(format!("line {}: duplicate policy for region '{region}'", i + 1));
                }
                policies.push((region, policy));
            } else {
                let region = first.to_string();
                let eid_s = parts.next().unwrap_or_default().to_string();
                let addr = parts.next().unwrap_or_default().to_string();
                if eid_s.is_empty() || addr.is_empty() {
                    return Err(format!(
                        "line {}: expected 'region gateway-eid gateway-addr'",
                        i + 1
                    ));
                }
                let eid = parse_eid(&eid_s).map_err(|e| format!("line {}: {e}", i + 1))?;
                gateways.push(Gateway { region, eid, addr });
            }
        }
        let local_region = local.ok_or("missing 'local <region>' line")?;
        Ok(Federation {
            local_region,
            regions: RegionMap::new(),
            gateways,
            policies,
        })
    }

    /// Serialize the plan back to the parseable text format.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("local {}\n", self.local_region));
        for g in &self.gateways {
            out.push_str(&format!("{} {} {}\n", g.region, g.eid.as_uri(), g.addr));
        }
        for (region, policy) in &self.policies {
            out.push_str(&format!("policy {region} {}\n", policy.as_str()));
        }
        out
    }

    /// Set the EID region membership.
    pub fn set_regions(&mut self, regions: RegionMap) {
        self.regions = regions;
    }

    /// Builder variant of set_regions.
    pub fn with_regions(mut self, regions: RegionMap) -> Self {
        self.regions = regions;
        self
    }

    /// The security policy for a region (AllowPlain when unset).
    pub fn policy_of(&self, region: &str) -> RegionPolicy {
        self.policies
            .iter()
            .find(|(r, _)| r == region)
            .map(|(_, p)| *p)
            .unwrap_or(RegionPolicy::AllowPlain)
    }

    /// Explainable routing decision for one destination.
    pub fn route_to(&self, dest: &Eid) -> Decision {
        match self.regions.region_of(dest) {
            None => Decision::NoRoute,
            Some(r) if r == self.local_region => Decision::Local,
            Some(r) => match self.gateways.iter().find(|g| g.region == r) {
                Some(g) => Decision::ViaGateway(g.clone()),
                None => Decision::NoRoute,
            },
        }
    }

    /// Remote regions that currently have stored, not-yet-delivered
    /// bundles waiting. Local-region and unknown-region destinations
    /// are excluded: the first is intra-region traffic, the second
    /// has no region to route by.
    pub fn pending_regions(&self, node: &Node) -> Result<Vec<String>, NodeError> {
        let mut regions: Vec<String> = Vec::new();
        for row in node.store.all()? {
            let Ok(bundle) = Bundle::decode(&row.data) else { continue };
            if node.store.is_delivered(&bundle.id()).unwrap_or(false) {
                continue;
            }
            if let Some(r) = self.regions.region_of(&bundle.primary.destination) {
                if r != self.local_region && !regions.iter().any(|x| x == r) {
                    regions.push(r.to_string());
                }
            }
        }
        Ok(regions)
    }

    /// Contact every gateway whose region has pending bundles, with
    /// per-gateway failure isolation. The contact is a full
    /// dtn-gateway contact (the same TCPCL-lite exchange and
    /// security stack the daemon uses), so the receiving gateway is
    /// an ordinary DTN-Link listener.
    pub fn sweep(&self, node: &Arc<Mutex<Node>>, sec: Option<&SecurityCtx>) -> FedSweepReport {
        self.sweep_logged(node, sec, None)
    }

    /// [`sweep`] with contact logging: every federation contact —
    /// success or failure, with per-contact bundle counters — is
    /// recorded into the ContactLog tagged `Kind::Federation`
    /// (best-effort; a logging error never fails a contact).
    pub fn sweep_logged(
        &self,
        node: &Arc<Mutex<Node>>,
        sec: Option<&SecurityCtx>,
        log: Option<&Arc<Mutex<ContactLog>>>,
    ) -> FedSweepReport {
        let pending = {
            let n = node.lock().unwrap();
            self.pending_regions(&n).unwrap_or_default()
        };
        let mut report = FedSweepReport::default();
        for g in &self.gateways {
            if !pending.iter().any(|r| r == &g.region) {
                continue;
            }
            // Per-region security policy: a require-signed region is
            // never contacted without the BPSec stack.
            if self.policy_of(&g.region) == RegionPolicy::RequireSigned && sec.is_none() {
                eprintln!(
                    "[federation] region {} requires signed contacts; refusing plaintext sweep",
                    g.region
                );
                report.blocked.push((
                    g.region.clone(),
                    "region policy require-signed but no security context configured".into(),
                ));
                continue;
            }
            match contact_counted(node, sec, &g.addr, log, Kind::Federation) {
                Ok(r) => report.successes.push((g.region.clone(), r)),
                Err(e) => {
                    eprintln!(
                        "[federation] gateway for region {} unreachable: {e}",
                        g.region
                    );
                    report.failures.push((g.region.clone(), e));
                }
            }
        }
        for region in &pending {
            if !self.gateways.iter().any(|g| &g.region == region) {
                report.skipped.push(region.clone());
            }
        }
        report
    }
}

/// Parse an EID URI ("ipn:9.0" or "dtn://node") for plan files.
fn parse_eid(s: &str) -> Result<Eid, String> {
    if let Some(rest) = s.strip_prefix("ipn:") {
        let (n, svc) = rest
            .split_once('.')
            .ok_or_else(|| format!("ipn EID '{s}' needs node.service numbers"))?;
        let n: u64 = n
            .parse()
            .map_err(|_| format!("ipn node number '{n}' is not numeric"))?;
        let svc: u64 = svc
            .parse()
            .map_err(|_| format!("ipn service number '{svc}' is not numeric"))?;
        Ok(Eid::ipn(n, svc))
    } else if let Some(rest) = s.strip_prefix("dtn://") {
        Ok(Eid::dtn(rest.trim_end_matches('/')))
    } else {
        Ok(Eid::dtn(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_core::Strategy;
    use std::net::TcpListener;
    use std::path::PathBuf;

    fn mem_node(n: u64) -> Arc<Mutex<Node>> {
        Arc::new(Mutex::new(
            Node::open(n, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap(),
        ))
    }

    /// Serve exactly one contact on a fresh listener; return the
    /// serving node and the bound address.
    fn one_shot_listener(n: u64) -> (Arc<Mutex<Node>>, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let node = mem_node(n);
        let srv = node.clone();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = dtn_daemon::exchange(&srv, None, &mut stream);
            }
        });
        (node, addr)
    }

    /// A loopback port with nothing listening (refuses fast).
    fn dead_addr() -> String {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        format!("127.0.0.1:{port}")
    }

    fn test_federation() -> Federation {
        let regions = RegionMap::parse("field ipn:1.\nhq ipn:9.\nlab ipn:7.\n").unwrap();
        let plan = "local field\nhq ipn:10.0 10.0.0.7:4556\n";
        Federation::parse(plan).unwrap().with_regions(regions)
    }

    #[test]
    fn region_map_parse_roundtrip_and_longest_prefix() {
        let text = "# membership\nfield ipn:1.\nhq ipn:9.\nbroad ipn:\n";
        let map = RegionMap::parse(text).unwrap();
        assert_eq!(map.entries.len(), 3);

        // Longest prefix wins over the broad "ipn:" entry.
        assert_eq!(map.region_of(&Eid::ipn(9, 0)), Some("hq"));
        assert_eq!(map.region_of(&Eid::ipn(1, 5)), Some("field"));
        assert_eq!(map.region_of(&Eid::ipn(42, 0)), Some("broad"));
        assert_eq!(map.region_of(&Eid::dtn("outsider")), None);

        // Roundtrip through to_text preserves the map.
        let again = RegionMap::parse(&map.to_text()).unwrap();
        assert_eq!(map, again);
    }

    #[test]
    fn region_map_parse_errors() {
        assert!(RegionMap::parse("hq").is_err(), "missing prefix");
        assert!(RegionMap::parse("hq ipn:9. extra").is_err(), "extra field");
        assert!(RegionMap::parse("").unwrap().entries.is_empty());
    }

    #[test]
    fn federation_plan_parse_roundtrip() {
        let text = "# plan\nlocal field\nhq ipn:10.0 10.0.0.7:4556\nlab dtn://labgw 192.168.1.5:4556\n";
        let fed = Federation::parse(text).unwrap();
        assert_eq!(fed.local_region, "field");
        assert_eq!(
            fed.gateways,
            vec![
                Gateway {
                    region: "hq".into(),
                    eid: Eid::ipn(10, 0),
                    addr: "10.0.0.7:4556".into(),
                },
                Gateway {
                    region: "lab".into(),
                    eid: Eid::dtn("labgw"),
                    addr: "192.168.1.5:4556".into(),
                },
            ]
        );
        assert!(fed.policies.is_empty(), "no policy lines means no policies");

        // Roundtrip through to_text preserves the plan.
        let again = Federation::parse(&fed.to_text()).unwrap();
        assert_eq!(again.local_region, fed.local_region);
        assert_eq!(again.gateways, fed.gateways);
        assert_eq!(again.policies, fed.policies);
    }

    #[test]
    fn federation_plan_parse_errors() {
        assert!(Federation::parse("hq ipn:10.0 10.0.0.7:4556").is_err(), "no local line");
        assert!(Federation::parse("local").is_err(), "local without region");
        assert!(Federation::parse("local field\nhq ipn:10.0").is_err(), "missing addr");
        assert!(
            Federation::parse("local field\nhq ipn:x.0 10.0.0.7:4556").is_err(),
            "bad ipn EID"
        );
    }

    #[test]
    fn region_policy_parse_roundtrip_and_lookup() {
        let text = "local field\n\
                    hq ipn:10.0 10.0.0.7:4556\n\
                    lab dtn://labgw 192.168.1.5:4556\n\
                    policy hq require-signed\n\
                    policy lab allow-plain\n";
        let fed = Federation::parse(text).unwrap();
        assert_eq!(fed.policy_of("hq"), RegionPolicy::RequireSigned);
        assert_eq!(fed.policy_of("lab"), RegionPolicy::AllowPlain);
        assert_eq!(fed.policy_of("unknown"), RegionPolicy::AllowPlain, "unset means allow-plain");

        // Roundtrip through to_text preserves the policies.
        let again = Federation::parse(&fed.to_text()).unwrap();
        assert_eq!(again.policies, fed.policies);

        // Parse errors.
        assert!(Federation::parse("local f\npolicy hq").is_err(), "policy without mode");
        assert!(Federation::parse("local f\npolicy hq encrypted").is_err(), "unknown mode");
        assert!(
            Federation::parse("local f\npolicy hq require-signed extra").is_err(),
            "extra field"
        );
        assert!(
            Federation::parse("local f\npolicy hq require-signed\npolicy hq allow-plain").is_err(),
            "duplicate policy"
        );
    }

    #[test]
    fn route_to_decisions() {
        let fed = test_federation();

        // Same region: local traffic, federation stays out of it.
        assert_eq!(fed.route_to(&Eid::ipn(1, 5)), Decision::Local);

        // Remote region with a gateway.
        match fed.route_to(&Eid::ipn(9, 0)) {
            Decision::ViaGateway(g) => {
                assert_eq!(g.region, "hq");
                assert_eq!(g.addr, "10.0.0.7:4556");
            }
            other => panic!("expected ViaGateway, got {other:?}"),
        }

        // Known region without a configured gateway.
        assert_eq!(fed.route_to(&Eid::ipn(7, 0)), Decision::NoRoute);
        // Unknown region (no membership entry at all).
        assert_eq!(fed.route_to(&Eid::ipn(5, 0)), Decision::NoRoute);
    }

    #[test]
    fn sweep_federates_bundle_to_remote_region() {
        let fed = test_federation();
        let (gateway_node, addr) = one_shot_listener(10);
        let fed = Federation {
            gateways: vec![Gateway {
                region: "hq".into(),
                eid: Eid::ipn(10, 0),
                addr: format!("127.0.0.1:{}", addr.port()),
            }],
            ..fed
        };

        let island = mem_node(1);
        island
            .lock()
            .unwrap()
            .send(Eid::ipn(9, 0), b"to headquarters".to_vec(), 3600)
            .unwrap();

        let report = fed.sweep(&island, None);
        assert_eq!(report.successes.len(), 1, "the hq gateway must be contacted");
        assert_eq!(report.successes[0].0, "hq");
        assert!(report.failures.is_empty());
        assert!(report.skipped.is_empty());
        assert!(report.blocked.is_empty());

        // The gateway node now carries the bundle and its own routing
        // would forward it to the hq destination on the next hop.
        let mut g = gateway_node.lock().unwrap();
        let outbound = g.select_outbound(&Eid::ipn(9, 0)).unwrap();
        assert_eq!(outbound.len(), 1, "gateway must hold the bundle for hq");
        assert!(outbound[0].decision.forward);
    }

    #[test]
    fn sweep_skips_local_and_unknown_destinations() {
        let fed = test_federation();
        // The plan's gateway points at a dead port; if the sweep
        // wrongly tried to contact it, we would see a failure entry.
        let fed = Federation {
            gateways: vec![Gateway {
                region: "hq".into(),
                eid: Eid::ipn(10, 0),
                addr: dead_addr(),
            }],
            ..fed
        };

        let island = mem_node(1);
        island
            .lock()
            .unwrap()
            .send(Eid::ipn(1, 7), b"same-region neighbor".to_vec(), 3600)
            .unwrap();
        island
            .lock()
            .unwrap()
            .send(Eid::ipn(5, 0), b"unknown region".to_vec(), 3600)
            .unwrap();

        let pending = fed.pending_regions(&island.lock().unwrap()).unwrap();
        assert!(pending.is_empty(), "no remote region is pending");

        let report = fed.sweep(&island, None);
        assert!(report.successes.is_empty());
        assert!(report.failures.is_empty(), "no gateway may be dialed");
        assert!(report.skipped.is_empty());
        assert_eq!(
            island.lock().unwrap().store.count().unwrap(),
            2,
            "both bundles stay stored (store-carry-forward)"
        );
    }

    #[test]
    fn sweep_isolates_gateway_failures() {
        let mut fed = test_federation();
        let (lab_node, lab_addr) = one_shot_listener(10);
        fed.gateways = vec![
            Gateway {
                region: "hq".into(),
                eid: Eid::ipn(10, 0),
                addr: dead_addr(),
            },
            Gateway {
                region: "lab".into(),
                eid: Eid::ipn(11, 0),
                addr: format!("127.0.0.1:{}", lab_addr.port()),
            },
        ];

        let island = mem_node(1);
        island
            .lock()
            .unwrap()
            .send(Eid::ipn(9, 0), b"for hq".to_vec(), 3600)
            .unwrap();
        island
            .lock()
            .unwrap()
            .send(Eid::ipn(7, 0), b"for lab".to_vec(), 3600)
            .unwrap();

        let report = fed.sweep(&island, None);
        assert_eq!(report.successes.len(), 1, "the live lab gateway is contacted");
        assert_eq!(report.successes[0].0, "lab");
        assert_eq!(report.failures.len(), 1, "the dead hq gateway is reported");
        assert_eq!(report.failures[0].0, "hq");
        assert!(matches!(report.failures[0].1, GatewayError::Connect(_)));

        // The lab bundle actually crossed the real contact.
        let mut g = lab_node.lock().unwrap();
        let outbound = g.select_outbound(&Eid::ipn(7, 0)).unwrap();
        assert_eq!(outbound.len(), 1, "lab gateway must hold the bundle");
    }

    #[test]
    fn require_signed_policy_blocks_plain_sweep() {
        let mut fed = test_federation();
        let (gateway_node, addr) = one_shot_listener(10);
        fed.policies = vec![("hq".into(), RegionPolicy::RequireSigned)];
        fed.gateways = vec![Gateway {
            region: "hq".into(),
            eid: Eid::ipn(10, 0),
            addr: format!("127.0.0.1:{}", addr.port()),
        }];

        let island = mem_node(1);
        island
            .lock()
            .unwrap()
            .send(Eid::ipn(9, 0), b"must not ride plaintext".to_vec(), 3600)
            .unwrap();

        // No security context: the region is blocked, NOT contacted.
        let report = fed.sweep(&island, None);
        assert!(report.successes.is_empty(), "a require-signed region must not be contacted without security");
        assert!(report.failures.is_empty(), "blocking is a policy decision, not a failure");
        assert_eq!(report.blocked.len(), 1);
        assert_eq!(report.blocked[0].0, "hq");
        assert!(report.blocked[0].1.contains("require-signed"));

        // The one-shot gateway listener must still be unconsumed.
        assert_eq!(
            gateway_node.lock().unwrap().store.count().unwrap(),
            0,
            "no bundle may cross a blocked contact"
        );
    }

    #[test]
    fn allow_plain_policy_still_contacts_without_security() {
        let mut fed = test_federation();
        let (gateway_node, addr) = one_shot_listener(10);
        fed.policies = vec![("hq".into(), RegionPolicy::AllowPlain)];
        fed.gateways = vec![Gateway {
            region: "hq".into(),
            eid: Eid::ipn(10, 0),
            addr: format!("127.0.0.1:{}", addr.port()),
        }];

        let island = mem_node(1);
        island
            .lock()
            .unwrap()
            .send(Eid::ipn(9, 0), b"plain is fine here".to_vec(), 3600)
            .unwrap();

        let report = fed.sweep(&island, None);
        assert_eq!(report.successes.len(), 1, "allow-plain regions contact normally");
        assert!(report.blocked.is_empty());
        assert_eq!(gateway_node.lock().unwrap().store.count().unwrap(), 1);
    }

    #[test]
    fn sweep_logged_records_federation_contacts() {
        let mut fed = test_federation();
        let (gateway_node, addr) = one_shot_listener(10);
        fed.gateways = vec![Gateway {
            region: "hq".into(),
            eid: Eid::ipn(10, 0),
            addr: format!("127.0.0.1:{}", addr.port()),
        }];
        let dead = dead_addr();
        fed.gateways.push(Gateway {
            region: "lab".into(),
            eid: Eid::ipn(11, 0),
            addr: dead.clone(),
        });

        let island = mem_node(1);
        island.lock().unwrap().send(Eid::ipn(9, 0), b"logged federation".to_vec(), 3600).unwrap();
        island.lock().unwrap().send(Eid::ipn(7, 0), b"for dead lab".to_vec(), 3600).unwrap();

        let log = Arc::new(Mutex::new(ContactLog::open_in_memory().unwrap()));
        let report = fed.sweep_logged(&island, None, Some(&log));
        assert_eq!(report.successes.len(), 1);
        assert_eq!(report.failures.len(), 1);

        let recs = log.lock().unwrap().contacts_since(0).unwrap();
        assert_eq!(recs.len(), 2, "success and failure must both be recorded");
        let ok = recs.iter().find(|r| r.ok).unwrap();
        assert!(ok.peer.contains("ipn:10.0"), "success records the gateway hello EID");
        assert_eq!(ok.sent, 1, "the bundle pushed to the hq gateway is counted");
        assert_eq!(ok.kind, Kind::Federation);
        let bad = recs.iter().find(|r| !r.ok).unwrap();
        assert_eq!(bad.peer, dead, "failure records the dial address");
        assert_eq!(bad.kind, Kind::Federation);

        // Kind filtering separates federation traffic from peers.
        let fed_only = log.lock().unwrap().summary_of(Kind::Federation).unwrap();
        assert_eq!(fed_only.len(), 2);
        assert!(log.lock().unwrap().summary_of(Kind::Peer).unwrap().is_empty());

        // The gateway really holds the bundle.
        assert_eq!(gateway_node.lock().unwrap().store.count().unwrap(), 1);
    }
}
