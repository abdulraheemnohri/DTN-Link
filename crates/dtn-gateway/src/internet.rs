//! Internet gateway — always-on peers.
//!
//! Contacts every configured peer on each sweep. Per-peer failures
//! are isolated: a dead relay, a typo'd address or a firewall drop
//! is reported and skipped; the remaining peers are still contacted.
//! This is what a node with continuous connectivity uses to bridge
//! DTN islands onto the internet.

use crate::{contact, ContactPlan, ContactReport, GatewayError};
use dtn_core::Node;
use dtn_daemon::SecurityCtx;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Sweep results: successes and failures in plan order.
#[derive(Debug, Default)]
pub struct SweepReport {
    pub successes: Vec<ContactReport>,
    pub failures: Vec<(String, GatewayError)>,
}

impl SweepReport {
    pub fn contacted(&self) -> usize {
        self.successes.len()
    }
}

/// An internet gateway over an explicit always-open contact plan.
pub struct InternetGateway {
    plan: ContactPlan,
}

impl InternetGateway {
    pub fn new(plan: ContactPlan) -> Self {
        InternetGateway { plan }
    }

    /// Convenience: an always-open plan from a list of peer addresses.
    pub fn peers<I, S>(addrs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        InternetGateway {
            plan: ContactPlan::new(
                addrs.into_iter().map(crate::PlannedContact::always).collect(),
            ),
        }
    }

    pub fn plan(&self) -> &ContactPlan {
        &self.plan
    }

    /// Contact every planned peer once, isolating failures.
    pub fn sweep(
        &self,
        node: &Arc<Mutex<Node>>,
        sec: Option<&SecurityCtx>,
    ) -> SweepReport {
        let mut report = SweepReport::default();
        for pc in &self.plan.contacts {
            match contact(node, sec, &pc.addr) {
                Ok(r) => report.successes.push(r),
                Err(e) => {
                    eprintln!("[gateway] peer {} unreachable: {e}", pc.addr);
                    report.failures.push((pc.addr.clone(), e));
                }
            }
        }
        report
    }

    /// Blocking run loop: sweep every `interval`, forever. Intended to
    /// run on its own thread, exactly like the daemon's sync loop.
    pub fn run(
        self,
        node: Arc<Mutex<Node>>,
        sec: Option<Arc<SecurityCtx>>,
        interval: Duration,
    ) -> ! {
        loop {
            let sec_ref = sec.as_ref().map(|s| s.as_ref());
            let report = self.sweep(&node, sec_ref);
            println!(
                "[gateway] sweep: {}/{} peers contacted",
                report.contacted(),
                self.plan.contacts.len()
            );
            std::thread::sleep(interval);
        }
    }
}

/// A one-shot convenience: contact these internet peers now.
/// Returns how many peers were successfully contacted.
pub fn sweep_peers<I, S>(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    addrs: I,
) -> usize
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let gw = InternetGateway::peers(addrs);
    gw.sweep(node, sec).contacted()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContactPlan;
    use dtn_bpv7::Eid;
    use dtn_core::Node;
    use dtn_routing::Strategy;
    use std::net::TcpListener;
    use std::path::PathBuf;

    fn mem_node(n: u8) -> Arc<Mutex<Node>> {
        Arc::new(Mutex::new(
            Node::open(n, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap(),
        ))
    }

    /// Serve exactly one contact on a fresh listener; return the
    /// serving node and the bound address.
    fn one_shot_listener(n: u8) -> (Arc<Mutex<Node>>, std::net::SocketAddr) {
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

    #[test]
    fn sweep_delivers_bundle_to_internet_peer() {
        let (far, addr) = one_shot_listener(2);
        let gw = InternetGateway::peers([format!("127.0.0.1:{}", addr.port())]);
        let local = mem_node(1);
        local.lock().unwrap().send(Eid::ipn(2, 0), b"to the internet".to_vec(), 3600).unwrap();

        let report = gw.sweep(&local, None);
        assert_eq!(report.contacted(), 1, "peer must be contacted");
        assert!(report.failures.is_empty());
        assert_eq!(far.lock().unwrap().inbox().unwrap().len(), 1,
            "bundle must be delivered through the gateway");
    }

    #[test]
    fn sweep_receives_inbound_and_counts_it() {
        // Far node has a bundle for us and hands it over during its
        // server-side exchange (the contact protocol is two-way).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let far = mem_node(2);
        far.lock().unwrap().send(Eid::ipn(1, 0), b"from the internet".to_vec(), 3600).unwrap();
        let srv = far.clone();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = dtn_daemon::exchange(&srv, None, &mut stream);
            }
        });

        let local = mem_node(1);
        let gw = InternetGateway::peers([format!("127.0.0.1:{}", addr.port())]);
        let report = gw.sweep(&local, None);

        assert_eq!(report.contacted(), 1);
        assert_eq!(report.successes[0].inbound, 1, "inbound bundle must be counted");
        assert_eq!(report.successes[0].addr, format!("127.0.0.1:{}", addr.port()));
        assert_eq!(local.lock().unwrap().inbox().unwrap().len(), 1);
    }

    #[test]
    fn dead_peer_does_not_block_live_peer() {
        let (_far, addr) = one_shot_listener(2);
        // Dead port first: an unbound port on loopback refuses fast.
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let plan = ContactPlan::new(vec![
            crate::PlannedContact::always(format!("127.0.0.1:{dead_port}")),
            crate::PlannedContact::always(format!("127.0.0.1:{}", addr.port())),
        ]);
        let gw = InternetGateway::new(plan);
        let local = mem_node(1);

        let report = gw.sweep(&local, None);
        assert_eq!(report.contacted(), 1, "the live peer must still be contacted");
        assert_eq!(report.failures.len(), 1, "the dead peer must be reported");
        assert!(matches!(report.failures[0].1, crate::GatewayError::Connect(_)));
    }
}
