//! Satellite gateway — contact windows (pass scheduling).
//!
//! A satellite (or any duty-cycled peer) is only reachable during
//! scheduled passes. The satellite gateway sleeps between passes and
//! empties its queue into the peer during every open window — pure
//! store-carry-forward with the OS doing nothing but sleeping.
//!
//! Windows come from the `ContactPlan` text format, so a
//! ground-station pass schedule is just a file:
//!
//! ```text
//! gs.example.net:4556 1762600000 1762600540
//! gs.example.net:4556 1762686400 1762686940
//! ```

use crate::{contact, ContactPlan, ContactReport, PlannedContact};
use dtn_core::Node;
use dtn_daemon::SecurityCtx;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A gateway driven by scheduled contact windows.
pub struct SatelliteGateway {
    plan: ContactPlan,
}

/// Result of one pass: which peers were contacted while their
/// windows were open, and what the gateway is waiting for now.
#[derive(Debug)]
pub struct PassReport {
    pub contacts: Vec<ContactReport>,
    /// Seconds until the earliest future window opens (if any).
    pub next_pass_in: Option<u64>,
}

impl SatelliteGateway {
    pub fn new(plan: ContactPlan) -> Self {
        SatelliteGateway { plan }
    }

    pub fn plan(&self) -> &ContactPlan {
        &self.plan
    }

    /// Contacts currently inside their window at `now` (unix secs).
    pub fn open_contacts(&self, now: u64) -> Vec<&PlannedContact> {
        self.plan.contacts.iter().filter(|c| c.is_open(now)).collect()
    }

    /// Seconds until the next window opens (None if nothing is
    /// scheduled or a window is already open).
    pub fn next_pass_in(&self, now: u64) -> Option<u64> {
        self.plan
            .contacts
            .iter()
            .filter_map(|c| c.opens_in(now))
            .min()
    }

    /// Run one pass at time `now`: contact every peer whose window is
    /// open (failures isolated and reported), and compute how long to
    /// sleep before the next pass. Callers drive the clock explicitly,
    /// which keeps tests deterministic and lets a real deployment use
    /// any time source.
    pub fn run_pass(
        &self,
        node: &Arc<Mutex<Node>>,
        sec: Option<&SecurityCtx>,
        now: u64,
    ) -> PassReport {
        let mut contacts = Vec::new();
        for pc in self.plan.contacts.iter().filter(|c| c.is_open(now)) {
            match contact(node, sec, &pc.addr) {
                Ok(r) => {
                    println!(
                        "[satellite] pass contact with {} ok ({} inbound)",
                        pc.addr, r.inbound
                    );
                    contacts.push(r);
                }
                Err(e) => {
                    // Mid-pass the peer may be briefly down; report
                    // and try again at the next window.
                    eprintln!("[satellite] contact with {} during pass failed: {e}", pc.addr);
                }
            }
        }
        PassReport {
            contacts,
            next_pass_in: self.next_pass_in(now),
        }
    }

    /// Blocking real-time driver: loop { sleep until next pass, run
    /// the pass }. Contacts inside a currently open window first.
    pub fn run(self, node: Arc<Mutex<Node>>, sec: Option<Arc<SecurityCtx>>) -> ! {
        loop {
            let now = crate::now_unix();
            if self.plan.contacts.iter().any(|c| c.is_open(now)) {
                let sec_ref = sec.as_ref().map(|s| s.as_ref());
                let report = self.run_pass(&node, sec_ref, now);
                println!(
                    "[satellite] pass complete: {} contacts",
                    report.contacts.len()
                );
                // A pass may just have finished; sleep a slice before
                // re-checking so we do not spin inside one window.
                std::thread::sleep(Duration::from_secs(1));
            } else {
                let wait = self
                    .next_pass_in(now)
                    .unwrap_or(60)
                    .clamp(1, 60);
                std::thread::sleep(Duration::from_secs(wait));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{now_unix, PlannedContact};
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

    /// A listening far-side ground station that serves exactly one
    /// contact. Returns its node and bound address.
    fn ground_station(n: u8) -> (Arc<Mutex<Node>>, std::net::SocketAddr) {
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
    fn closed_window_contacts_nothing_and_reports_next_pass() {
        let (_gs, addr) = ground_station(2);
        let now = now_unix();
        let gw = SatelliteGateway::new(ContactPlan::new(vec![PlannedContact::windowed(
            format!("127.0.0.1:{}", addr.port()),
            now + 3600,
            now + 4140,
        )]));

        // The ground station IS listening, but the pass has not
        // started: no contact may be attempted.
        let report = gw.run_pass(&mem_node(1), None, now);
        assert!(report.contacts.is_empty(), "closed window must not contact");
        assert_eq!(report.next_pass_in, Some(3600), "must report time to next pass");

        // And run_pass() must not have consumed the station's one
        // accepted connection: the same pass window still works later.
        let local = mem_node(1);
        local
            .lock()
            .unwrap()
            .send(Eid::ipn(2, 0), b"queued for the pass".to_vec(), 3600)
            .unwrap();
        let report = gw.run_pass(&local, None, now + 3600);
        assert_eq!(report.contacts.len(), 1, "open window must contact");
    }

    #[test]
    fn open_pass_empties_the_queue_into_the_ground_station() {
        let (gs, addr) = ground_station(2);
        let now = now_unix();
        let gw = SatelliteGateway::new(ContactPlan::new(vec![PlannedContact::windowed(
            format!("127.0.0.1:{}", addr.port()),
            now - 10,
            now + 600,
        )]));

        let local = mem_node(1);
        local.lock().unwrap().send(Eid::ipn(2, 0), b"payload one".to_vec(), 3600).unwrap();
        local.lock().unwrap().send(Eid::ipn(2, 0), b"payload two".to_vec(), 3600).unwrap();

        let report = gw.run_pass(&local, None, now);
        assert_eq!(report.contacts.len(), 1);
        assert_eq!(
            gs.lock().unwrap().inbox().unwrap().len(),
            2,
            "both queued bundles must ride the pass"
        );
        assert_eq!(report.next_pass_in, None, "window is already open");
    }

    #[test]
    fn expired_window_is_immediately_due_but_not_open() {
        let now = now_unix();
        let gw = SatelliteGateway::new(ContactPlan::new(vec![PlannedContact::windowed(
            "203.0.113.9:4556",
            now - 200,
            now - 100,
        )]));
        assert!(gw.open_contacts(now).is_empty(), "past pass is not open");
        assert_eq!(gw.next_pass_in(now), Some(0), "past window opens 'now'");
    }

    #[test]
    fn multi_pass_plan_picks_earliest_next_pass() {
        let now = now_unix();
        let gw = SatelliteGateway::new(ContactPlan::new(vec![
            PlannedContact::windowed("203.0.113.1:4556", now + 500, now + 540),
            PlannedContact::windowed("203.0.113.2:4556", now + 100, now + 140),
            PlannedContact::always("203.0.113.3:4556"),
        ]));
        assert_eq!(gw.next_pass_in(now), Some(100), "earliest future window wins");
        assert_eq!(gw.open_contacts(now).len(), 1, "always-open contact is open");
    }

    #[test]
    fn pass_failure_is_isolated_and_reported() {
        let now = now_unix();
        // Dead peer inside an open window: reported, not fatal, and
        // run_pass still returns instead of panicking.
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let gw = SatelliteGateway::new(ContactPlan::new(vec![PlannedContact::windowed(
            format!("127.0.0.1:{dead_port}"),
            now - 10,
            now + 600,
        )]));
        let report = gw.run_pass(&mem_node(1), None, now);
        assert!(report.contacts.is_empty());
    }
}
