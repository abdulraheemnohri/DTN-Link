//! dtn-gateway — DTN-Link gateway layer (Phase 11).
//!
//! A gateway turns an intermittently connected island node into part
//! of a larger DTN: it decides WHEN to contact a peer (scheduling)
//! and then performs a full contact (dtn-daemon TCPCL-lite exchange
//! with the existing security stack) against it.
//!
//! Two gateway types are provided:
//!
//! * **Internet gateway** ([`internet`]) — always-on peers: contact
//!   every configured peer on each sweep, tolerate per-peer failures
//!   (one dead host never blocks the others). Use this for a node
//!   with continuous internet connectivity that bridges DTN islands.
//! * **Satellite gateway** ([`satellite`]) — store-carry-forward at
//!   its purest: peers are only contactable inside scheduled contact
//!   windows (pass windows), so the gateway sleeps between passes and
//!   exchanges everything queued when the bird comes overhead.
//!
//! Both run the SAME wire protocol as every other DTN-Link contact
//! (dtn-daemon `exchange`), so a gateway is peer-compatible with any
//! DTN-Link node, daemon or adapter — nothing is faked.
//!
//! Management (Phase 15): `contact_counted` reports per-contact
//! bundle counters and can record every gateway contact (success or
//! failure, with counters) into a dtn-diagnostics ContactLog tagged
//! as `Kind::Gateway`, so `dtn-link doctor` shows gateway traffic.

pub mod internet;
pub mod satellite;

use dtn_bpv7::Eid;
use dtn_core::Node;
use dtn_daemon::SecurityCtx;
use dtn_diagnostics::{ContactLog, Kind};
use std::fmt;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Unix wall-clock seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One planned contact with a peer address and an optional contact
/// window (unix seconds, inclusive start, exclusive end).
/// `None` means "always contactable" (internet gateway semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedContact {
    /// `host:port` of the peer's DTN listener.
    pub addr: String,
    /// Some((start, end)) in unix seconds — contactable when
    /// start <= now < end. None = always open.
    pub window: Option<(u64, u64)>,
}

impl PlannedContact {
    pub fn always(addr: impl Into<String>) -> Self {
        PlannedContact { addr: addr.into(), window: None }
    }

    pub fn windowed(addr: impl Into<String>, start: u64, end: u64) -> Self {
        PlannedContact { addr: addr.into(), window: Some((start, end)) }
    }

    /// Is this contact reachable at `now` (unix seconds)?
    pub fn is_open(&self, now: u64) -> bool {
        match self.window {
            None => true,
            Some((s, e)) => now >= s && now < e,
        }
    }

    /// Seconds until this contact next opens, if it is closed now.
    pub fn opens_in(&self, now: u64) -> Option<u64> {
        match self.window {
            Some((s, e)) if now >= e || now < s => Some(s.saturating_sub(now)),
            _ => None,
        }
    }
}

/// A contact plan: the peers a gateway may talk to.
/// Parseable from a simple text file, one entry per line:
///
/// ```text
/// # internet peers (always open)
/// relay.example.net:4556
/// 10.0.0.7:4556
/// # satellite pass (unix seconds, start end)
/// satellite-gs.example.net:4556 1762600000 1762600540
/// ```
///
/// Lines that are blank or start with `#` are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactPlan {
    pub contacts: Vec<PlannedContact>,
}

impl ContactPlan {
    pub fn new(contacts: Vec<PlannedContact>) -> Self {
        ContactPlan { contacts }
    }

    /// Parse a plan from text. Returns the offending line on error.
    pub fn parse(text: &str) -> Result<ContactPlan, String> {
        let mut contacts = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let addr = parts.next().unwrap_or_default().to_string();
            if addr.is_empty() {
                return Err(format!("line {}: missing peer address", i + 1));
            }
            let window = match (parts.next(), parts.next()) {
                (Some(s), Some(e)) => {
                    let s: u64 = s.parse().map_err(|_| {
                        format!("line {}: window start is not a unix timestamp", i + 1)
                    })?;
                    let e: u64 = e.parse().map_err(|_| {
                        format!("line {}: window end is not a unix timestamp", i + 1)
                    })?;
                    if e <= s {
                        return Err(format!(
                            "line {}: window end ({e}) must be after start ({s})",
                            i + 1
                        ));
                    }
                    Some((s, e))
                }
                (None, None) => None,
                _ => {
                    return Err(format!(
                        "line {}: a window needs both a start and an end timestamp",
                        i + 1
                    ))
                }
            };
            contacts.push(PlannedContact { addr, window });
        }
        Ok(ContactPlan { contacts })
    }

    /// Serialize back to the parseable text format.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for c in &self.contacts {
            match c.window {
                None => out.push_str(&format!("{}\n", c.addr)),
                Some((s, e)) => out.push_str(&format!("{} {} {}\n", c.addr, s, e)),
            }
        }
        out
    }
}

/// Gateway failure modes, reported per peer so one bad peer never
/// poisons a whole sweep.
#[derive(Debug)]
pub enum GatewayError {
    /// TCP connection failed (peer down, wrong address, firewall).
    Connect(String),
    /// The contact started but violated the wire protocol.
    Protocol(String),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayError::Connect(e) => write!(f, "connect failed: {e}"),
            GatewayError::Protocol(e) => write!(f, "contact protocol error: {e}"),
        }
    }
}

/// What one completed contact with a peer accomplished.
#[derive(Debug)]
pub struct ContactReport {
    pub addr: String,
    /// EID the peer announced in its hello.
    pub peer: Eid,
    /// New bundles this node gained from the peer.
    pub inbound: usize,
    /// Bundles this node pushed to the peer (Phase 15).
    pub sent: usize,
}

/// Perform one full TCPCL-lite contact (the same exchange the daemon
/// and every adapter use) against `addr`. Security context is
/// optional and behaves exactly like the daemon: hello key learning,
/// signed outbound, verified inbound.
///
/// Returns a report; the node engine has already stored everything
/// the peer sent us (dedup prevents duplicates on retried contacts).
pub fn contact(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    addr: &str,
) -> Result<ContactReport, GatewayError> {
    contact_counted(node, sec, addr, None, Kind::Gateway)
}

/// [`contact`] with per-contact bundle counters and optional contact
/// logging. When `log` is Some, the outcome (success or failure, with
/// counters) is recorded into the ContactLog tagged `kind` —
/// best-effort: a logging error never fails the contact.
pub fn contact_counted(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    addr: &str,
    log: Option<&Arc<Mutex<ContactLog>>>,
    kind: Kind,
) -> Result<ContactReport, GatewayError> {
    let before = node.lock().unwrap().store.count().unwrap_or(0);
    let mut stream =
        TcpStream::connect(addr).map_err(|e| {
            record_gateway_failure(log, addr, kind);
            GatewayError::Connect(e.to_string())
        })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let (peer, counts) = dtn_daemon::exchange_counted(node, sec, &mut stream)
        .map_err(|e| {
            record_gateway_failure(log, addr, kind);
            GatewayError::Protocol(e.to_string())
        })?;
    let after = node.lock().unwrap().store.count().unwrap_or(0);
    if let Some(log) = log {
        let rec = dtn_diagnostics::ContactRecord {
            peer: peer.as_uri(),
            started_at: now_unix(),
            direction: dtn_diagnostics::Direction::Outgoing,
            sent: counts.sent,
            received: counts.received,
            ok: true,
            kind,
        };
        if let Err(e) = log.lock().unwrap().record(&rec) {
            eprintln!("[gateway] contact log write failed: {e}");
        }
    }
    Ok(ContactReport {
        addr: addr.to_string(),
        peer,
        inbound: after.saturating_sub(before),
        sent: counts.sent,
    })
}

/// Best-effort failure record for a gateway contact that never got
/// far enough to learn the peer EID.
fn record_gateway_failure(
    log: Option<&Arc<Mutex<ContactLog>>>,
    addr: &str,
    kind: Kind,
) {
    let Some(log) = log else { return };
    let rec = dtn_diagnostics::ContactRecord {
        peer: addr.to_string(),
        started_at: now_unix(),
        direction: dtn_diagnostics::Direction::Outgoing,
        sent: 0,
        received: 0,
        ok: false,
        kind,
    };
    if let Err(e) = log.lock().unwrap().record(&rec) {
        eprintln!("[gateway] contact log write failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planned_contact_windows() {
        let c = PlannedContact::windowed("gs:4556", 100, 200);
        assert!(!c.is_open(99));
        assert!(c.is_open(100), "window start is inclusive");
        assert!(c.is_open(199));
        assert!(!c.is_open(200), "window end is exclusive");
        assert_eq!(c.opens_in(50), Some(50));
        assert_eq!(c.opens_in(150), None, "open contacts do not 'open'");
        assert_eq!(c.opens_in(250), Some(0), "a past window is immediately due");

        let a = PlannedContact::always("relay:4556");
        assert!(a.is_open(0));
        assert!(a.is_open(u64::MAX));
        assert_eq!(a.opens_in(0), None);
    }

    #[test]
    fn plan_parse_roundtrip() {
        let text = "# comment\n\
                    relay.example.net:4556\n\
                    10.0.0.7:4556\n\
                    \n\
                    gs.example.net:4556 1762600000 1762600540\n";
        let plan = ContactPlan::parse(text).unwrap();
        assert_eq!(plan.contacts.len(), 3);
        assert_eq!(plan.contacts[0], PlannedContact::always("relay.example.net:4556"));
        assert_eq!(
            plan.contacts[2],
            PlannedContact::windowed("gs.example.net:4556", 1762600000, 1762600540)
        );
        // Roundtrip through to_text preserves the plan.
        let again = ContactPlan::parse(&plan.to_text()).unwrap();
        assert_eq!(plan, again);
    }

    #[test]
    fn plan_parse_errors() {
        assert!(ContactPlan::parse("host:1 100 50").is_err(), "end before start");
        assert!(ContactPlan::parse("host:1 100").is_err(), "half a window");
        assert!(ContactPlan::parse("host:1 abc 200").is_err(), "non-numeric start");
        assert!(ContactPlan::parse("").unwrap().contacts.is_empty());
    }

    #[test]
    fn counted_contact_reports_counters_and_logs() {
        use dtn_routing::Strategy;
        // Real loopback contact with a real contact log.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let far = Arc::new(Mutex::new(
            Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        let srv = far.clone();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = dtn_daemon::exchange(&srv, None, &mut stream);
            }
        });

        let log = Arc::new(Mutex::new(ContactLog::open_in_memory().unwrap()));
        let local = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        local.lock().unwrap().send(Eid::ipn(2, 0), b"counted".to_vec(), 3600).unwrap();

        let report = contact_counted(
            &local, None, &format!("127.0.0.1:{}", addr.port()), Some(&log), Kind::Gateway,
        ).unwrap();

        assert_eq!(report.sent, 1, "the queued bundle must be counted as sent");
        assert!(report.peer.as_uri().contains("ipn:2.0"));
        assert_eq!(far.lock().unwrap().inbox().unwrap().len(), 1);

        let recs = log.lock().unwrap().contacts_since(0).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].kind, Kind::Gateway);
        assert_eq!(recs[0].direction, dtn_diagnostics::Direction::Outgoing);
        assert_eq!(recs[0].sent, 1);
        assert!(recs[0].ok);
        // Gateway-kind filtering sees it; peer-kind filtering does not.
        assert_eq!(log.lock().unwrap().summary_of(Kind::Gateway).unwrap().len(), 1);
        assert!(log.lock().unwrap().summary_of(Kind::Peer).unwrap().is_empty());
    }

    #[test]
    fn failed_gateway_contact_is_logged() {
        use dtn_routing::Strategy;
        // Dead port: connect refuses fast; the failure must be logged.
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);

        let log = Arc::new(Mutex::new(ContactLog::open_in_memory().unwrap()));
        let local = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));

        let res = contact_counted(&local, None, &format!("127.0.0.1:{port}"), Some(&log), Kind::Gateway);
        assert!(matches!(res, Err(GatewayError::Connect(_))));

        let recs = log.lock().unwrap().contacts_since(0).unwrap();
        assert_eq!(recs.len(), 1);
        assert!(!recs[0].ok, "the failed dial must be recorded");
        assert_eq!(recs[0].peer, format!("127.0.0.1:{port}"));
        assert_eq!(recs[0].kind, Kind::Gateway);
    }
}
