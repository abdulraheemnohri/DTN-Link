//! dtn-daemon — a real TCP DTN node with optional BPSec security.
//!
//! Two contact protocols are supported:
//!   * TCPCL-lite (`exchange`, Phase 4): length-prefixed frames.
//!   * RFC 9174 TCPCLv4 (`exchange_v4`, Phase 7): full session
//!     handshake, keepalives, acknowledged transfers, SESS_TERM.
//!
//! Security (Phase 8): when a keyring is configured (`SecurityCtx`),
//! contacts additionally:
//!   * exchange Ed25519 public keys in the TCPCL-lite hello and
//!     trust-on-first-use (TOFU) learn them into the local keyring,
//!   * sign every outbound bundle with the node identity (BIB),
//!   * verify incoming signed bundles against the trusted key for the
//!     source EID and DROP bundles whose signature is Invalid.
//! Unsigned bundles and bundles from unknown sources are accepted
//! (logged); multiple-BIB malformed bundles are dropped.
//!
//! Management (Phase 15): when `DaemonConfig::contact_log` is set,
//! every accepted (TCPCL-lite) connection and every sync attempt is
//! recorded into a dtn-diagnostics ContactLog — peer EID (or address
//! on failure), direction, outcome, per-contact bundle counters and
//! timestamp — for `dtn-link doctor` to report. The counted variants
//! (`exchange_counted`, `exchange_v4_counted`) return how many
//! bundles were sent and newly stored per contact; `exchange` and
//! `exchange_v4` remain the uncounted wrappers.
//!
//! Honest scope: key rotation, signed key-change and TLS (RFC 9174
//! §4.4) remain future work. A mismatch between a learned hello key
//! and a previously trusted key currently logs a warning and does not
//! enforce (MITM hardening is future work).

use dtn_bpv7::{Bundle, Eid};
use dtn_core::Node;
use dtn_diagnostics::{ContactLog, ContactRecord, Direction, Kind};
use dtn_keyring::{Keyring, KeyringVerifyOutcome};
use dtn_routing::Strategy;
use dtn_tcpcl::v4::{Event, Session, SessionError, TERM_OTHER};
use dtn_tcpcl::{read_frame, write_end_of_batch, write_frame, FrameError};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct DaemonConfig {
    pub listen: String,
    pub peers: Vec<String>,
    pub strategy: Strategy,
    pub sync_interval: Duration,
    pub db: PathBuf,
    /// SQLite keyring path. None = security disabled (plain contacts).
    pub keyring: Option<PathBuf>,
    /// SQLite contact-log path (dtn-diagnostics). None = no contact
    /// history recorded.
    pub contact_log: Option<PathBuf>,
}

/// Per-node security context: trusted keys + signing identity.
pub struct SecurityCtx {
    pub keyring: Arc<Mutex<Keyring>>,
    /// Sign outbound bundles with the node identity (BIB).
    pub sign_outbound: bool,
}

/// Per-contact bundle counters, straight from the exchange loop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContactCounts {
    /// Bundles this node pushed to the peer.
    pub sent: usize,
    /// Bundles the peer pushed that this node newly stored
    /// (duplicates and rejects are not counted).
    pub received: usize,
}

/// Best-effort contact-log write; logging must never break a contact.
fn log_contact(
    log: &Option<Arc<Mutex<ContactLog>>>,
    peer: &str,
    direction: Direction,
    ok: bool,
    counts: ContactCounts,
    kind: Kind,
) {
    let Some(log) = log else { return };
    let rec = ContactRecord {
        peer: peer.to_string(),
        started_at: dtn_storage::now(),
        direction,
        sent: counts.sent,
        received: counts.received,
        ok,
        kind,
    };
    if let Err(e) = log.lock().unwrap().record(&rec) {
        eprintln!("[daemon] contact log write failed: {e}");
    }
}

fn parse_eid(bytes: &[u8]) -> Eid {
    let s = String::from_utf8_lossy(bytes);
    Eid::dtn(s.trim().trim_start_matches("dtn://").trim_end_matches('/'))
}

/// TOFU-learn (or check) a peer's public key learned from hello.
fn learn_peer_key(sec: &SecurityCtx, peer_uri: &str, key: &ed25519_dalek::VerifyingKey) {
    let mut kr = sec.keyring.lock().unwrap();
    match kr.get(peer_uri) {
        Ok(Some(existing)) => {
            if existing.as_bytes() != key.as_bytes() {
                eprintln!("[daemon] WARNING: peer {peer_uri} presented a different key than the trusted one (possible rotation or MITM); not enforcing");
            }
        }
        Ok(None) => {
            let _ = kr.put(peer_uri, key);
            eprintln!("[daemon] TOFU: trusted new key for {peer_uri}");
        }
        Err(e) => eprintln!("[daemon] keyring error: {e}"),
    }
}

/// Security-filtered receive: drops bundles whose BIB signature is
/// Invalid under the trusted key for the source EID. Unsigned bundles
/// and unknown-source signed bundles are accepted (logged).
/// Returns Some(bundle) when a new bundle was stored.
fn secured_receive(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    wire: &[u8],
) -> Result<Option<Bundle>, dtn_core::NodeError> {
    let Some(sec) = sec else { return node.lock().unwrap().receive(wire) };
    let Ok(bundle) = Bundle::decode(wire) else {
        // Let Node::receive produce the proper protocol error.
        return node.lock().unwrap().receive(wire);
    };
    match dtn_keyring::verify_signed_bundle(&bundle, &sec.keyring.lock().unwrap()) {
        Ok(KeyringVerifyOutcome::Valid) => node.lock().unwrap().receive(wire),
        Ok(KeyringVerifyOutcome::Invalid) => {
            eprintln!("[daemon] REJECTED: bundle from {} has an invalid signature", bundle.primary.source_node.as_uri());
            Ok(None)
        }
        Ok(KeyringVerifyOutcome::MultipleIntegrityBlocks) => {
            eprintln!("[daemon] REJECTED: malformed bundle from {} (multiple BIBs)", bundle.primary.source_node.as_uri());
            Ok(None)
        }
        Ok(KeyringVerifyOutcome::UnknownSource) => {
            eprintln!("[daemon] note: signed bundle from untrusted source {} accepted (TOFU it later or add a key)", bundle.primary.source_node.as_uri());
            node.lock().unwrap().receive(wire)
        }
        Ok(KeyringVerifyOutcome::NoIntegrityBlock) => node.lock().unwrap().receive(wire),
        Err(e) => {
            eprintln!("[daemon] keyring error during verify: {e}");
            node.lock().unwrap().receive(wire)
        }
    }
}

/// Encode an outbound bundle for the wire, optionally signing it (BIB)
/// with the node identity.
fn outbound_wire(node: &Arc<Mutex<Node>>, sec: Option<&SecurityCtx>, bundle: &Bundle) -> Vec<u8> {
    match sec {
        Some(s) if s.sign_outbound => {
            let n = node.lock().unwrap();
            dtn_bpsec::sign_bundle(bundle, &n.identity).encode()
        }
        _ => bundle.encode(),
    }
}

/// Exchange bundles with a connected peer stream (TCPCL-lite),
/// reporting how many bundles were sent and newly stored.
/// When security is enabled, hello = [EID frame][32-byte pubkey frame]
/// and keys are TOFU-learned into the keyring.
pub fn exchange_counted(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    stream: &mut TcpStream,
) -> Result<(Eid, ContactCounts), FrameError> {
    let our_eid = node.lock().unwrap().eid();
    write_frame(stream, our_eid.as_uri().as_bytes())?;
    if let Some(sec) = sec {
        if sec.sign_outbound {
            let key = node.lock().unwrap().identity.public_key();
            write_frame(stream, key.as_bytes())?;
        }
    }
    let peer_raw = read_frame(stream)?;
    let peer = parse_eid(&peer_raw);
    let peer_uri = String::from_utf8_lossy(&peer_raw).trim().to_string();
    if let Some(sec) = sec {
        if sec.sign_outbound {
            let key_raw = read_frame(stream)?;
            if key_raw.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key_raw);
                if let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                    learn_peer_key(sec, &peer_uri, &key);
                }
            }
        }
    }

    let outbound = {
        let mut n = node.lock().unwrap();
        n.select_outbound(&peer).unwrap_or_default()
    };
    for ob in &outbound {
        write_frame(stream, &outbound_wire(node, sec, &ob.bundle))?;
    }
    write_end_of_batch(stream)?;
    stream.flush()?;

    let mut counts = ContactCounts {
        sent: outbound.len(),
        received: 0,
    };
    loop {
        match read_frame(stream) {
            Ok(bytes) => {
                if secured_receive(node, sec, &bytes)?.is_some() {
                    counts.received += 1;
                }
            }
            Err(FrameError::Closed) => break,
            Err(e) => return Err(e),
        }
    }
    Ok((peer, counts))
}

/// Exchange bundles with a connected peer stream (TCPCL-lite).
/// Compatibility wrapper around [`exchange_counted`].
pub fn exchange(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    stream: &mut TcpStream,
) -> Result<Eid, FrameError> {
    exchange_counted(node, sec, stream).map(|(peer, _)| peer)
}

/// Exchange bundles with a peer over a full RFC 9174 TCPCLv4 session:
/// contact handshake, acknowledged outbound transfers, inbound bundles
/// stored through the node engine, then clean SESS_TERM shutdown.
/// Returns the peer EID URI and per-contact bundle counters.
/// Security: bundles are signed/verified when a SecurityCtx is given,
/// but the v4 session EID carries no pubkey — key learning is
/// TCPCL-lite only (honest limitation).
pub fn exchange_v4_counted(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    stream: TcpStream,
    active: bool,
) -> Result<(String, ContactCounts), SessionError> {
    let local_eid = node.lock().unwrap().eid();
    let local_uri = local_eid.as_uri();
    let mut sess = Session::new(stream, &local_uri, 30);
    sess.handshake(active)?;
    let peer_eid = String::from_utf8_lossy(&sess.peer_eid).into_owned();

    let peer = parse_eid(peer_eid.as_bytes());
    let outbound = {
        let mut n = node.lock().unwrap();
        n.select_outbound(&peer).unwrap_or_default()
    };
    let mut counts = ContactCounts {
        sent: 0,
        received: 0,
    };
    for ob in &outbound {
        let tid = sess.send_bundle(&outbound_wire(node, sec, &ob.bundle))?;
        counts.sent += 1;
        loop {
            match sess.pump()? {
                Some(Event::Bundle(bytes)) => {
                    if secured_receive(node, sec, &bytes)?.is_some() {
                        counts.received += 1;
                    }
                }
                Some(Event::Acked { transfer_id, .. }) if transfer_id == tid => break,
                Some(Event::Terminated { .. }) => break,
                Some(_) => {}
                None => {}
            }
        }
    }
    sess.send_sess_term(0, TERM_OTHER)?;

    loop {
        match sess.pump() {
            Ok(Some(Event::Bundle(bytes))) => {
                if secured_receive(node, sec, &bytes)?.is_some() {
                    counts.received += 1;
                }
            }
            Ok(Some(Event::Terminated { .. })) => break,
            Ok(_) => {}
            Err(SessionError::Closed) => break,
            Err(e) => return Err(e),
        }
    }
    Ok((peer_eid, counts))
}

/// Exchange bundles over TCPCLv4 with optional contact logging
/// (kind Peer). Logging is best-effort and never fails the session.
pub fn exchange_v4_logged(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    stream: TcpStream,
    active: bool,
    log: Option<&Arc<Mutex<ContactLog>>>,
) -> Result<String, SessionError> {
    let res = exchange_v4_counted(node, sec, stream, active);
    if let Some(log) = log {
        let log_opt = Some(log.clone());
        let direction = if active { Direction::Outgoing } else { Direction::Incoming };
        match &res {
            Ok((peer_eid, counts)) => {
                log_contact(&log_opt, peer_eid, direction, true, *counts, Kind::Peer);
            }
            Err(_) => {
                log_contact(&log_opt, "unknown", direction, false, ContactCounts::default(), Kind::Peer);
            }
        }
    }
    res.map(|(peer_eid, _)| peer_eid)
}

/// Exchange bundles with a peer over a full RFC 9174 TCPCLv4 session.
/// Compatibility wrapper around [`exchange_v4_counted`].
pub fn exchange_v4(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    stream: TcpStream,
    active: bool,
) -> Result<String, SessionError> {
    exchange_v4_counted(node, sec, stream, active).map(|(peer_eid, _)| peer_eid)
}

fn serve(
    node: Arc<Mutex<Node>>,
    sec: Option<Arc<SecurityCtx>>,
    listener: TcpListener,
    log: Option<Arc<Mutex<ContactLog>>>,
) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let node = node.clone();
        let sec = sec.clone();
        let log = log.clone();
        std::thread::spawn(move || {
            let res = sec.as_ref().map(|s| s.as_ref());
            match exchange_counted(&node, res, &mut stream) {
                Ok((peer, counts)) => {
                    log_contact(&log, &peer.as_uri(), Direction::Incoming, true, counts, Kind::Peer)
                }
                Err(e) => {
                    eprintln!("[daemon] contact failed: {e}");
                    log_contact(&log, "unknown", Direction::Incoming, false, ContactCounts::default(), Kind::Peer);
                }
            }
        });
    }
}

fn sync_peers(
    node: Arc<Mutex<Node>>,
    sec: Option<Arc<SecurityCtx>>,
    peers: Vec<String>,
    interval: Duration,
    log: Option<Arc<Mutex<ContactLog>>>,
) {
    loop {
        for addr in &peers {
            if let Ok(mut stream) = TcpStream::connect(addr) {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let res = sec.as_ref().map(|s| s.as_ref());
                match exchange_counted(&node, res, &mut stream) {
                    Ok((peer, counts)) => {
                        log_contact(&log, &peer.as_uri(), Direction::Outgoing, true, counts, Kind::Peer)
                    }
                    Err(e) => {
                        eprintln!("[daemon] sync with {addr} failed: {e}");
                        log_contact(&log, addr, Direction::Outgoing, false, ContactCounts::default(), Kind::Peer);
                    }
                }
            } else {
                log_contact(&log, addr, Direction::Outgoing, false, ContactCounts::default(), Kind::Peer);
            }
        }
        std::thread::sleep(interval);
    }
}

pub fn run(cfg: DaemonConfig) -> std::io::Result<()> {
    let node = Node::open_persistent(1, &cfg.db, cfg.strategy)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let sec = match &cfg.keyring {
        Some(path) => {
            let kr = Keyring::open(path)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            Some(Arc::new(SecurityCtx {
                keyring: Arc::new(Mutex::new(kr)),
                sign_outbound: true,
            }))
        }
        None => None,
    };
    let contact_log = match &cfg.contact_log {
        Some(path) => match ContactLog::open(path) {
            Ok(l) => Some(Arc::new(Mutex::new(l))),
            Err(e) => {
                eprintln!("[daemon] contact log disabled ({e})");
                None
            }
        },
        None => None,
    };
    let node = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind(&cfg.listen)?;
    println!("[daemon] listening on {} (security {}, contact log {})", cfg.listen,
        if sec.is_some() { "ON — sign + TOFU key learning + verify" } else { "OFF" },
        if contact_log.is_some() { "ON" } else { "OFF" });

    {
        let sync_node = node.clone();
        let peers = cfg.peers.clone();
        let interval = cfg.sync_interval;
        let sec = sec.clone();
        let log = contact_log.clone();
        std::thread::spawn(move || sync_peers(sync_node, sec, peers, interval, log));
    }

    {
        let cleanup_node = node.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(60));
            if let Ok(mut n) = cleanup_node.lock() {
                let removed = n.cleanup_expired().unwrap_or(0);
                if removed > 0 {
                    println!("[daemon] expired {} bundles", removed);
                }
            }
        });
    }

    serve(node, sec, listener, contact_log);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec_ctx() -> SecurityCtx {
        SecurityCtx {
            keyring: Arc::new(Mutex::new(Keyring::open_in_memory().unwrap())),
            sign_outbound: true,
        }
    }

    #[test]
    fn parse_eid_frames() {
        let e = parse_eid(b"dtn://node42");
        assert_eq!(e.as_uri(), "dtn://node42");
        let e2 = parse_eid(b"node42");
        assert_eq!(e2.as_uri(), "dtn://node42");
    }

    #[test]
    fn contact_logging_records_outcomes() {
        let log = Some(Arc::new(Mutex::new(ContactLog::open_in_memory().unwrap())));
        log_contact(&log, "ipn:7.0", Direction::Incoming, true, ContactCounts { sent: 2, received: 1 }, Kind::Peer);
        log_contact(&log, "127.0.0.1:4556", Direction::Outgoing, false, ContactCounts::default(), Kind::Peer);
        let l = log.as_ref().unwrap().lock().unwrap();
        assert_eq!(l.count().unwrap(), 2);
        let peers = l.summary().unwrap();
        assert_eq!(peers.len(), 2);
        let ok_peer = peers.iter().find(|p| p.peer == "ipn:7.0").unwrap();
        assert_eq!(ok_peer.successful, 1);
        assert_eq!(ok_peer.total_sent, 2);
        assert_eq!(ok_peer.total_received, 1);
        assert!(ok_peer.ever_succeeded());
        let failed = peers.iter().find(|p| p.peer == "127.0.0.1:4556").unwrap();
        assert!(failed.unreachable());
    }

    #[test]
    fn contact_logging_none_is_a_noop() {
        let log: Option<Arc<Mutex<ContactLog>>> = None;
        log_contact(&log, "ipn:7.0", Direction::Incoming, true, ContactCounts::default(), Kind::Peer);
    }

    #[test]
    fn tcp_contact_delivers_bundle() {
        use std::sync::mpsc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            let (mut stream, _) = listener.accept().unwrap();
            exchange(&node, None, &mut stream).unwrap();
            let n = node.lock().unwrap();
            tx.send(n.inbox().unwrap().len()).unwrap();
        });

        let client_node = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        client_node.lock().unwrap().send(Eid::ipn(2, 0), b"over the wire".to_vec(), 3600).unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        exchange(&client_node, None, &mut stream).unwrap();

        let delivered = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(delivered, 1, "bundle must be delivered over TCP");
        server.join().unwrap();
    }

    #[test]
    fn counted_contact_reports_bundle_counters() {
        // One bundle each way over one contact; both sides must report
        // sent=1 / received=1 from the real exchange loop.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            node.lock().unwrap().send(Eid::ipn(1, 0), b"reply payload".to_vec(), 3600).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            exchange_counted(&node, None, &mut stream).unwrap()
        });

        let client_node = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        client_node.lock().unwrap().send(Eid::ipn(2, 0), b"request payload".to_vec(), 3600).unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        let (peer, counts) = exchange_counted(&client_node, None, &mut stream).unwrap();
        assert!(peer.as_uri().contains("ipn:2.0"), "peer EID comes from the hello");
        assert_eq!(counts.sent, 1, "the one queued bundle must be counted as sent");
        assert_eq!(counts.received, 1, "the server's bundle must be counted as received");

        let (_, server_counts) = server.join().unwrap();
        assert_eq!(server_counts.sent, 1);
        assert_eq!(server_counts.received, 1);
    }

    #[test]
    fn counted_contact_logs_to_diagnostics() {
        // A real contact with a real log: the record must carry the
        // bundle counters and the Peer kind.
        let log = Arc::new(Mutex::new(ContactLog::open_in_memory().unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            let (mut stream, _) = listener.accept().unwrap();
            exchange_counted(&node, None, &mut stream).unwrap()
        });

        let client_node = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        client_node.lock().unwrap().send(Eid::ipn(2, 0), b"logged bundle".to_vec(), 3600).unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        let (peer, counts) = exchange_counted(&client_node, None, &mut stream).unwrap();
        let log_ref = Some(log.clone());
        log_contact(&log_ref, &peer.as_uri(), Direction::Outgoing, true, counts, Kind::Peer);
        server.join().unwrap();

        let recs = log.lock().unwrap().contacts_since(0).unwrap();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].peer.contains("ipn:2.0"));
        assert_eq!(recs[0].sent, 1);
        assert_eq!(recs[0].received, 1);
        assert_eq!(recs[0].kind, Kind::Peer);
        assert!(recs[0].ok);
    }

    #[test]
    fn tcp_multi_hop_delivery() {
        use std::sync::mpsc;
        let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        let listener_c = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_c = listener_c.local_addr().unwrap();

        let node_b = Arc::new(Mutex::new(
            Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        let node_c = Arc::new(Mutex::new(
            Node::open(3, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));

        let (tx, rx) = mpsc::channel();
        let c_node = node_c.clone();
        let server_c = std::thread::spawn(move || {
            let (mut stream, _) = listener_c.accept().unwrap();
            exchange(&c_node, None, &mut stream).unwrap();
            let n = c_node.lock().unwrap();
            tx.send(n.inbox().unwrap().len()).unwrap();
        });
        let b_node = node_b.clone();
        let server_b = std::thread::spawn(move || {
            let (mut stream, _) = listener_b.accept().unwrap();
            exchange(&b_node, None, &mut stream).unwrap();
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().send(Eid::ipn(3, 0), b"hop over tcp".to_vec(), 3600).unwrap();
        let mut stream = TcpStream::connect(addr_b).unwrap();
        exchange(&node_a, None, &mut stream).unwrap();
        server_b.join().unwrap();

        let mut stream = TcpStream::connect(addr_c).unwrap();
        exchange(&node_b, None, &mut stream).unwrap();

        let delivered = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(delivered, 1, "multi-hop bundle must reach C over TCP");
        server_c.join().unwrap();
    }

    #[test]
    fn tcpclv4_session_delivers_bundle() {
        use std::sync::mpsc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            let (stream, _) = listener.accept().unwrap();
            exchange_v4(&node, None, stream, false).unwrap();
            let n = node.lock().unwrap();
            tx.send(n.inbox().unwrap().len()).unwrap();
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"tcpclv4 wire".to_vec(), 3600).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        exchange_v4(&node_a, None, stream, true).unwrap();

        let delivered = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(delivered, 1, "bundle must be delivered over TCPCLv4");
        server.join().unwrap();
    }

    #[test]
    fn tcpclv4_session_two_way_exchange() {
        use std::sync::mpsc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            node.lock().unwrap().send(Eid::ipn(1, 0), b"from b over v4".to_vec(), 3600).unwrap();
            let (stream, _) = listener.accept().unwrap();
            exchange_v4(&node, None, stream, false).unwrap();
            let n = node.lock().unwrap();
            tx.send(n.inbox().unwrap().len()).unwrap();
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"from a over v4".to_vec(), 3600).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        exchange_v4(&node_a, None, stream, true).unwrap();

        let delivered = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(delivered, 1, "A's bundle must reach B over TCPCLv4");
        server.join().unwrap();
        assert_eq!(node_a.lock().unwrap().inbox().unwrap().len(), 1,
            "B's bundle must reach A over TCPCLv4");
    }

    #[test]
    fn tcpclv4_counted_session_reports_counters_and_logs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Mutex::new(ContactLog::open_in_memory().unwrap()));

        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            node.lock().unwrap().send(Eid::ipn(1, 0), b"v4 reply".to_vec(), 3600).unwrap();
            let (stream, _) = listener.accept().unwrap();
            exchange_v4_counted(&node, None, stream, false).unwrap()
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"v4 request".to_vec(), 3600).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let (peer_eid, counts) = exchange_v4_counted(&node_a, None, stream, true).unwrap();
        assert_eq!(counts.sent, 1);
        assert_eq!(counts.received, 1, "the server's reply must be counted");

        let (_, server_counts) = server.join().unwrap();
        assert_eq!(server_counts.sent, 1);
        assert_eq!(server_counts.received, 1);

        // The logged variant records the same session into the log.
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            let (stream, _) = listener2.accept().unwrap();
            exchange_v4(&node, None, stream, false).unwrap();
        });
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"v4 logged".to_vec(), 3600).unwrap();
        let stream = TcpStream::connect(addr2).unwrap();
        let logged = Some(log.clone());
        exchange_v4_logged(&node_a, None, stream, true, logged.as_ref()).unwrap();
        srv.join().unwrap();

        let recs = log.lock().unwrap().contacts_since(0).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].peer, peer_eid);
        assert_eq!(recs[0].direction, Direction::Outgoing);
        assert_eq!(recs[0].sent, 1);
        assert_eq!(recs[0].kind, Kind::Peer);
    }

    // ---- Phase 8 security tests ----

    #[test]
    fn secured_contact_learns_keys_and_delivers_signed_bundle() {
        use std::sync::mpsc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let sec_b = Arc::new(sec_ctx());
        let sec_b2 = sec_b.clone();
        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            let (mut stream, _) = listener.accept().unwrap();
            exchange(&node, Some(&sec_b2), &mut stream).unwrap();
            let n = node.lock().unwrap();
            let inbox = n.inbox().unwrap();
            tx.send(inbox).unwrap();
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        let key_a = node_a.lock().unwrap().identity.public_key();
        let sec_a = Arc::new(sec_ctx());
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"signed over tcp".to_vec(), 3600).unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        exchange(&node_a, Some(&sec_a), &mut stream).unwrap();

        let inbox = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(inbox.len(), 1);
        // B must have TOFU-learned A's key during hello.
        let kr_b = sec_b.keyring.lock().unwrap();
        let learned = kr_b.get("ipn:1.0").unwrap().expect("A's key must be learned");
        assert_eq!(learned, key_a);
        // Delivered bundle must carry a valid BIB under A's key.
        assert_eq!(dtn_bpsec::verify_bundle(&inbox[0], &key_a), dtn_bpsec::VerifyOutcome::Valid);
        // And A must have learned B's key too.
        drop(kr_b);
        let kr_a = sec_a.keyring.lock().unwrap();
        assert!(kr_a.get("ipn:2.0").unwrap().is_some(), "B's key must be learned by A");
        server.join().unwrap();
    }

    #[test]
    fn tampered_signed_bundle_rejected_by_secured_receive() {
        let node_b = Arc::new(Mutex::new(
            Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        let key_a = node_a.lock().unwrap().identity.public_key();

        let sec_b = sec_ctx();
        {
            let mut kr = sec_b.keyring.lock().unwrap();
            kr.put("ipn:1.0", &key_a).unwrap();
        }

        let plain = {
            let mut a = node_a.lock().unwrap();
            a.send(Eid::ipn(2, 0), b"authentic".to_vec(), 3600).unwrap()
        };
        let signed = dtn_bpsec::sign_bundle(&plain, &node_a.lock().unwrap().identity);
        let mut tampered = signed.clone();
        if let Some(p) = tampered.blocks.iter_mut().find(|b| b.type_code == 1) {
            p.data = b"forged".to_vec();
        }

        // Tampered wire: rejected, not stored.
        assert!(secured_receive(&node_b, Some(&sec_b), &tampered.encode()).unwrap().is_none());
        assert_eq!(node_b.lock().unwrap().store.count().unwrap(), 0);

        // Untampered signed wire: accepted.
        assert!(secured_receive(&node_b, Some(&sec_b), &signed.encode()).unwrap().is_some());
        assert_eq!(node_b.lock().unwrap().store.count().unwrap(), 1);

        // Unsigned bundle: still accepted (policy).
        assert!(secured_receive(&node_b, Some(&sec_b), &plain.encode()).unwrap().is_some());
    }
}
