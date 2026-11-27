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
//! MITM hardening (Phase 17): `SecurityCtx::enforce_tofu` (default in
//! the daemon and CLI) makes a hello key that DIFFERS from the
//! trusted key fail the contact unless the peer presents a valid
//! SIGNED KEY ROTATION announcement (`dtn_keyring::KeyChange`, signed
//! by the previously trusted key) in the hello. A node that rotated
//! its identity key announces the change via
//! `SecurityCtx::pending_rotation`. In strict mode, signed bundles
//! from sources with no trusted key are also dropped instead of
//! accepted with a log line.
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
//! TLS (Phase 30): with the cargo feature "tls" and a TLS config,
//! incoming contacts are accepted as TLS-wrapped TCPCLv4 sessions
//! (RFC 9174 section 4.4 order: TLS handshake, then contact header)
//! and outgoing contacts dial TLS with a pinned peer certificate;
//! a TLS config on a binary built without the feature fails closed.
//!
//! Honest scope: hello-key TOFU learning is TCPCL-lite only; TLS
//! contacts are authenticated at the transport level by the
//! certificate pin and at the bundle level by BPSec. A rotation
//! announcement is only understood by peers on >= 0.16; announcing a
//! rotation to an older peer degrades that one contact (the frame is
//! not a valid bundle). A web-of-trust is future work.

use dtn_bpv7::{Bundle, Eid};
use dtn_core::Node;
use dtn_diagnostics::{ContactLog, ContactRecord, Direction, Kind};
use dtn_keyring::{KeyChange, Keyring, KeyringVerifyOutcome, TofuCheck};
use dtn_routing::Strategy;
use dtn_tcpcl::v4::{Event, Session, SessionError, TERM_OTHER};
use dtn_tcpcl::{read_frame, write_end_of_batch, write_frame, FrameError};

#[cfg(feature = "tls")]
use dtn_tcpcl::v4_tls::{cert_pin, TlsClientSetup, TlsServerSetup};

/// Accept-side TLS setup, when the cargo feature "tls" is compiled
/// in; an `Option<()>` stub keeps the daemon code feature-agnostic
/// otherwise.
#[cfg(feature = "tls")]
type TlsServerOpt = Option<Arc<TlsServerSetup>>;
#[cfg(not(feature = "tls"))]
type TlsServerOpt = Option<()>;

#[cfg(feature = "tls")]
type TlsClientOpt = Option<Arc<TlsClientSetup>>;
#[cfg(not(feature = "tls"))]
type TlsClientOpt = Option<()>;
use std::io::{Read, Write};
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
    /// Phase 17: reject contacts whose hello key differs from the
    /// trusted key without a valid signed rotation (MITM hardening).
    pub enforce_tofu: bool,
    /// Phase 30: accept-side TLS (RFC 9174 section 4.4). When set,
    /// incoming contacts are TLS-wrapped TCPCLv4 sessions; requires
    /// the cargo feature "tls" (rejected at startup otherwise).
    pub tls_server: Option<TlsServerPem>,
    /// Phase 30: dial-side TLS for outgoing peer contacts — the
    /// pinned peer certificate and the TLS server name. Requires
    /// the cargo feature "tls".
    pub tls_client: Option<TlsPeerPin>,
}

/// Accept-side TLS configuration (RFC 9174 section 4.4): the PEM
/// certificate chain and private key served to incoming contacts.
#[derive(Clone)]
pub struct TlsServerPem {
    pub cert_chain_pem: String,
    pub key_pem: String,
}

/// Dial-side TLS configuration: the pin of the peer certificate —
/// 64 hex characters (SHA-256 of the leaf DER, see
/// [`tls_pin_from_spec`]) or "@path/to/cert.pem" — plus the TLS
/// server name used in the SNI extension.
#[derive(Clone)]
pub struct TlsPeerPin {
    pub pin_spec: String,
    pub server_name: String,
}

/// Per-node security context: trusted keys + signing identity.
pub struct SecurityCtx {
    pub keyring: Arc<Mutex<Keyring>>,
    /// Sign outbound bundles with the node identity (BIB).
    pub sign_outbound: bool,
    /// Phase 17: enforce hello-key mismatch as a contact failure
    /// unless a valid signed rotation is presented.
    pub enforce_tofu: bool,
    /// Phase 17: a signed key-rotation announcement to send during
    /// the hello (set after this node rotated its identity key).
    pub pending_rotation: Option<KeyChange>,
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
/// Returns false when the contact must be rejected (enforced key
/// mismatch without a valid signed rotation).
fn learn_peer_key(
    sec: &SecurityCtx,
    peer_uri: &str,
    key: &ed25519_dalek::VerifyingKey,
    rotation_frame: Option<&[u8]>,
) -> bool {
    let mut kr = sec.keyring.lock().unwrap();
    match kr.check(peer_uri, key) {
        Ok(TofuCheck::New) => {
            let _ = kr.put(peer_uri, key);
            eprintln!("[daemon] TOFU: trusted new key for {peer_uri}");
            true
        }
        Ok(TofuCheck::Match) => true,
        Ok(TofuCheck::Mismatch) => {
            // A signed rotation announcement redeems a key change.
            if let Some(frame) = rotation_frame {
                match KeyChange::decode(frame) {
                    Ok(change)
                        if change.eid == peer_uri
                            && change.new_key.as_bytes() == key.as_bytes() =>
                    {
                        match kr.rotate(&change) {
                            Ok(dtn_keyring::KeyRotation::Rotated) => {
                                eprintln!("[daemon] accepted SIGNED key rotation for {peer_uri}");
                                return true;
                            }
                            Ok(other) => {
                                eprintln!("[daemon] rotation for {peer_uri} not applied: {other:?}");
                            }
                            Err(e) => eprintln!("[daemon] keyring error during rotation: {e}"),
                        }
                    }
                    Ok(_) => eprintln!("[daemon] rotation announcement does not match the presented key/EID"),
                    Err(_) => eprintln!("[daemon] malformed rotation announcement"),
                }
            }
            if sec.enforce_tofu {
                eprintln!(
                    "[daemon] REJECTED: peer {peer_uri} presented a different key than the trusted one and no valid signed rotation was given"
                );
                false
            } else {
                eprintln!(
                    "[daemon] WARNING: peer {peer_uri} presented a different key than the trusted one (possible rotation or MITM); not enforcing"
                );
                true
            }
        }
        Err(e) => {
            eprintln!("[daemon] keyring error: {e}");
            // Fail closed under enforcement, open in legacy mode.
            !sec.enforce_tofu
        }
    }
}

/// Security-filtered receive: drops bundles whose BIB signature is
/// Invalid under the trusted key for the source EID. Unsigned bundles
/// are accepted. Signed bundles from unknown sources are accepted
/// with a log line — unless `enforce_tofu` (Phase 17 strict mode),
/// which drops them.
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
            if sec.enforce_tofu {
                eprintln!("[daemon] REJECTED: signed bundle from unknown source {} (strict TOFU mode)", bundle.primary.source_node.as_uri());
                Ok(None)
            } else {
                eprintln!("[daemon] note: signed bundle from untrusted source {} accepted (TOFU it later or add a key)", bundle.primary.source_node.as_uri());
                node.lock().unwrap().receive(wire)
            }
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
/// (+ an optional signed key-rotation announcement frame), keys are
/// TOFU-learned into the keyring, and an enforced key mismatch fails
/// the contact (Phase 17).
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
            // Phase 17: announce a pending key rotation, if any.
            if let Some(kc) = &sec.pending_rotation {
                write_frame(stream, &kc.encode())?;
            }
        }
    }
    let peer_raw = read_frame(stream)?;
    let peer = parse_eid(&peer_raw);
    let peer_uri = String::from_utf8_lossy(&peer_raw).trim().to_string();

    // Read the peer's hello key (and optional rotation announcement).
    // The frame AFTER the key frame may be (a) a rotation
    // announcement, (b) a first bundle (legacy peer / no rotation), or
    // (c) end-of-batch (peer has nothing to send). KeyChange frames
    // start with the DTNKC1 magic, so (a) and (b) are distinguishable.
    let mut rotation_frame: Option<Vec<u8>> = None;
    let mut preloaded: Option<Vec<u8>> = None;
    if let Some(sec) = sec {
        if sec.sign_outbound {
            let key_raw = read_frame(stream)?;
            if key_raw.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key_raw);
                if let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                    // Peek the next frame to classify it.
                    match read_frame(stream) {
                        Ok(next) => match KeyChange::decode(&next) {
                            Ok(_) => rotation_frame = Some(next),
                            Err(_) => preloaded = Some(next),
                        },
                        Err(FrameError::Closed) => {} // nothing else in the hello
                        Err(e) => return Err(e),
                    }
                    if !learn_peer_key(sec, &peer_uri, &key, rotation_frame.as_deref()) {
                        return Err(FrameError::Protocol("hello key rejected (TOFU enforcement)"));
                    }
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
    if let Some(bytes) = preloaded {
        if secured_receive(node, sec, &bytes)?.is_some() {
            counts.received += 1;
        }
    }
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
pub fn exchange_v4_counted<S: Read + Write>(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    stream: S,
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
pub fn exchange_v4_logged<S: Read + Write>(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    stream: S,
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
pub fn exchange_v4<S: Read + Write>(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    stream: S,
    active: bool,
) -> Result<String, SessionError> {
    exchange_v4_counted(node, sec, stream, active).map(|(peer_eid, _)| peer_eid)
}


/// Phase 30: decode a TLS pin specification — either 64 hex
/// characters (the SHA-256 of the peer's leaf certificate DER) or
/// "@path/cert.pem" (the pin is computed from the PEM file). Used
/// by the CLI `--tls-pin` flag and `DaemonConfig::tls_client`.
#[cfg(feature = "tls")]
pub fn tls_pin_from_spec(spec: &str) -> Result<[u8; 32], String> {
    if let Some(path) = spec.strip_prefix('@') {
        let pem = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read TLS certificate {path}: {e}"))?;
        cert_pin(&pem).map_err(|e| format!("cannot pin certificate: {e}"))
    } else {
        let hex = spec.trim();
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("TLS pin must be 64 hex characters or @cert.pem".to_string());
        }
        let mut pin = [0u8; 32];
        for i in 0..32 {
            pin[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .map_err(|_| "bad hex in TLS pin".to_string())?;
        }
        Ok(pin)
    }
}

/// Phase 30: serve one accepted stream as a TLS-wrapped TCPCLv4
/// contact (accept side). Logging mirrors the plain contact path.
#[cfg(feature = "tls")]
fn serve_tls_contact(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    setup: &TlsServerSetup,
    stream: TcpStream,
    log: &Option<Arc<Mutex<ContactLog>>>,
) {
    match setup.upgrade(stream) {
        Ok(tls) => match exchange_v4_counted(node, sec, tls, false) {
            Ok((peer, counts)) => {
                println!("[daemon] TLS contact from {peer}: sent={} received={}", counts.sent, counts.received);
                log_contact(log, &peer, Direction::Incoming, true, counts, Kind::Peer);
            }
            Err(e) => {
                eprintln!("[daemon] TLS contact failed: {e}");
                log_contact(log, "unknown", Direction::Incoming, false, ContactCounts::default(), Kind::Peer);
            }
        },
        Err(e) => {
            eprintln!("[daemon] TLS handshake failed: {e}");
            log_contact(log, "unknown", Direction::Incoming, false, ContactCounts::default(), Kind::Peer);
        }
    }
}

/// Phase 30: run one outgoing contact over TLS (dial side).
#[cfg(feature = "tls")]
fn tls_sync_one(
    node: &Arc<Mutex<Node>>,
    sec: Option<&SecurityCtx>,
    setup: &TlsClientSetup,
    stream: TcpStream,
    addr: &str,
    log: &Option<Arc<Mutex<ContactLog>>>,
) {
    match setup.upgrade(stream) {
        Ok(tls) => match exchange_v4_counted(node, sec, tls, true) {
            Ok((peer, counts)) => {
                println!("[daemon] TLS sync with {peer}: sent={} received={}", counts.sent, counts.received);
                log_contact(log, &peer, Direction::Outgoing, true, counts, Kind::Peer);
            }
            Err(e) => {
                eprintln!("[daemon] TLS sync failed: {e}");
                log_contact(log, addr, Direction::Outgoing, false, ContactCounts::default(), Kind::Peer);
            }
        },
        Err(e) => {
            eprintln!("[daemon] TLS handshake with {addr} failed: {e}");
            log_contact(log, addr, Direction::Outgoing, false, ContactCounts::default(), Kind::Peer);
        }
    }
}

fn serve(
    node: Arc<Mutex<Node>>,
    sec: Option<Arc<SecurityCtx>>,
    listener: TcpListener,
    log: Option<Arc<Mutex<ContactLog>>>,
    _tls_server: TlsServerOpt,
) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let node = node.clone();
        let sec = sec.clone();
        let log = log.clone();
        std::thread::spawn(move || {
            let res = sec.as_ref().map(|s| s.as_ref());
            #[cfg(feature = "tls")]
            {
                if let Some(setup) = _tls_server.as_ref() {
                    serve_tls_contact(&node, res, setup, stream, &log);
                    return;
                }
            }
            let mut stream = stream;
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
    _tls_client: TlsClientOpt,
) {
    loop {
        for addr in &peers {
            if let Ok(stream) = TcpStream::connect(addr) {
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let res = sec.as_ref().map(|s| s.as_ref());
                #[cfg(feature = "tls")]
                {
                    if let Some(setup) = _tls_client.as_ref() {
                        tls_sync_one(&node, res, setup, stream, addr, &log);
                        continue;
                    }
                }
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
                enforce_tofu: cfg.enforce_tofu,
                pending_rotation: None,
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
    #[cfg(feature = "tls")]
    let tls_server_opt: TlsServerOpt = match &cfg.tls_server {
        Some(pem) => match TlsServerSetup::from_pem(&pem.cert_chain_pem, &pem.key_pem) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("TLS server setup failed: {e}"),
                ));
            }
        },
        None => None,
    };
    #[cfg(feature = "tls")]
    let tls_client_opt: TlsClientOpt = match &cfg.tls_client {
        Some(pin) => match tls_pin_from_spec(&pin.pin_spec) {
            Ok(p) => match TlsClientSetup::from_pin(p, &pin.server_name) {
                Ok(s) => Some(Arc::new(s)),
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("TLS client setup failed: {e}"),
                    ));
                }
            },
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("TLS pin: {e}"),
                ));
            }
        },
        None => None,
    };
    #[cfg(not(feature = "tls"))]
    let tls_server_opt: TlsServerOpt = {
        if cfg.tls_server.is_some() || cfg.tls_client.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS requested but this binary was built without the \"tls\" cargo feature",
            ));
        }
        None
    };
    #[cfg(not(feature = "tls"))]
    let tls_client_opt: TlsClientOpt = None;

    let node = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind(&cfg.listen)?;
    println!("[daemon] listening on {} (security {}, TOFU enforcement {}, contact log {}, tls {})", cfg.listen,
        if sec.is_some() { "ON — sign + TOFU key learning + verify" } else { "OFF" },
        if sec.is_some() && cfg.enforce_tofu { "ON" } else { "OFF" },
        if contact_log.is_some() { "ON" } else { "OFF" },
        if tls_server_opt.is_some() || tls_client_opt.is_some() { "ON" } else { "off" });

    {
        let sync_node = node.clone();
        let peers = cfg.peers.clone();
        let interval = cfg.sync_interval;
        let sec = sec.clone();
        let log = contact_log.clone();
        std::thread::spawn(move || sync_peers(sync_node, sec, peers, interval, log, tls_client_opt));
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

    serve(node, sec, listener, contact_log, tls_server_opt);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec_ctx() -> SecurityCtx {
        SecurityCtx {
            keyring: Arc::new(Mutex::new(Keyring::open_in_memory().unwrap())),
            sign_outbound: true,
            enforce_tofu: true,
            pending_rotation: None,
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

    // ---- Phase 17: MITM enforcement + signed key rotation ----

    /// A peer whose hello key differs from the trusted key (an
    /// impostor reusing the victim's EID) must fail the contact when
    /// enforcement is on, and nothing may be stored.
    #[test]
    fn enforced_mitm_key_switch_fails_the_contact() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // The victim's previously trusted key for ipn:1.0.
        let victim_old = dtn_identity::NodeIdentity::from_seed(1, [42u8; 32]);

        let sec_b = Arc::new(sec_ctx());
        {
            let mut kr = sec_b.keyring.lock().unwrap();
            kr.put("ipn:1.0", &victim_old.public_key()).unwrap();
        }
        let sec_b2 = sec_b.clone();

        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            let (mut stream, _) = listener.accept().unwrap();
            exchange_counted(&node, Some(&sec_b2), &mut stream)
        });

        // The impostor: same EID, DIFFERENT key, no rotation proof.
        let node_imp = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_imp.lock().unwrap().send(Eid::ipn(2, 0), b"i am the real node".to_vec(), 3600).unwrap();
        let sec_imp = sec_ctx();

        let mut stream = TcpStream::connect(addr).unwrap();
        let imp_res = exchange_counted(&node_imp, Some(&sec_imp), &mut stream);
        let b_res = server.join().unwrap();

        assert!(b_res.is_err(), "B must reject the enforced key mismatch");
        // The impostor either errors out or completes an empty contact
        // after B hung up; what matters is that nothing was stored on
        // B and the trusted key is untouched.
        let _ = imp_res;
        // B's keyring must still trust the OLD key.
        let kr_b = sec_b.keyring.lock().unwrap();
        assert_eq!(kr_b.get("ipn:1.0").unwrap().unwrap(), victim_old.public_key());
    }

    /// With enforcement off (legacy behavior) the same mismatch only
    /// warns; the contact completes but the impostor's forged bundle
    /// is still dropped by BIB verification against the OLD key.
    #[test]
    fn unenforced_mismatch_warns_and_still_drops_forgeries() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let victim_old = dtn_identity::NodeIdentity::from_seed(1, [42u8; 32]);
        let sec_b = Arc::new(SecurityCtx {
            keyring: Arc::new(Mutex::new(Keyring::open_in_memory().unwrap())),
            sign_outbound: true,
            enforce_tofu: false,
            pending_rotation: None,
        });
        {
            let mut kr = sec_b.keyring.lock().unwrap();
            kr.put("ipn:1.0", &victim_old.public_key()).unwrap();
        }
        let sec_b2 = sec_b.clone();

        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            let (mut stream, _) = listener.accept().unwrap();
            exchange_counted(&node, Some(&sec_b2), &mut stream)
        });

        let node_imp = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_imp.lock().unwrap().send(Eid::ipn(2, 0), b"forged payload".to_vec(), 3600).unwrap();
        let sec_imp = sec_ctx();

        let mut stream = TcpStream::connect(addr).unwrap();
        let imp_res = exchange_counted(&node_imp, Some(&sec_imp), &mut stream);
        let b_res = server.join().unwrap();

        assert!(imp_res.is_ok(), "legacy (non-enforcing) mode completes the contact");
        let (_, b_counts) = b_res.unwrap();
        assert_eq!(b_counts.received, 0, "the impostor's bundle must be BIB-rejected");
    }

    /// A genuine rotation: the node presents its NEW key plus a
    /// rotation announcement signed by the OLD (trusted) key. The
    /// peer must accept the contact, update its keyring and store
    /// the newly signed bundle.
    #[test]
    fn signed_rotation_is_accepted_and_applied() {
        use ed25519_dalek::SigningKey;
        use std::sync::mpsc;

        let old = dtn_identity::NodeIdentity::from_seed(1, [42u8; 32]);
        let new = dtn_identity::NodeIdentity::from_seed(1, [43u8; 32]);
        assert_eq!(old.eid.as_uri(), new.eid.as_uri(), "same EID, new key");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let sec_b = Arc::new(sec_ctx());
        {
            let mut kr = sec_b.keyring.lock().unwrap();
            kr.put("ipn:1.0", &old.public_key()).unwrap();
        }
        let sec_b2 = sec_b.clone();

        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            let (mut stream, _) = listener.accept().unwrap();
            let res = exchange_counted(&node, Some(&sec_b2), &mut stream);
            let inbox = node.lock().unwrap().inbox().unwrap();
            tx.send((res, inbox)).unwrap();
        });

        // The rotating node: new identity, rotation signed by the old key.
        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().identity = new.clone();
        let rotation = dtn_keyring::KeyChange::sign(
            "ipn:1.0",
            &SigningKey::from_bytes(&old.seed_bytes()),
            &new.public_key(),
            dtn_storage::now(),
        );
        let sec_a = SecurityCtx {
            keyring: Arc::new(Mutex::new(Keyring::open_in_memory().unwrap())),
            sign_outbound: true,
            enforce_tofu: true,
            pending_rotation: Some(rotation),
        };
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"signed by the new key".to_vec(), 3600).unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        let (_, a_counts) = exchange_counted(&node_a, Some(&sec_a), &mut stream).unwrap();
        assert_eq!(a_counts.sent, 1);

        let (b_res, inbox) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(b_res.is_ok(), "a validly signed rotation must not fail the contact");
        assert_eq!(inbox.len(), 1, "the bundle signed by the NEW key must be stored");
        let kr_b = sec_b.keyring.lock().unwrap();
        assert_eq!(kr_b.get("ipn:1.0").unwrap().unwrap(), new.public_key(),
            "the keyring must now trust the new key");
        server.join().ok();
    }

    /// A rotation announcement signed by anything other than the
    /// currently trusted key must fail an enforced contact.
    #[test]
    fn forged_rotation_is_rejected() {
        use ed25519_dalek::SigningKey;

        let old = dtn_identity::NodeIdentity::from_seed(1, [42u8; 32]);
        let new = dtn_identity::NodeIdentity::from_seed(1, [43u8; 32]);
        let attacker = dtn_identity::NodeIdentity::generate(77);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let sec_b = Arc::new(sec_ctx());
        {
            let mut kr = sec_b.keyring.lock().unwrap();
            kr.put("ipn:1.0", &old.public_key()).unwrap();
        }
        let sec_b2 = sec_b.clone();

        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            let (mut stream, _) = listener.accept().unwrap();
            exchange_counted(&node, Some(&sec_b2), &mut stream)
        });

        let node_imp = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_imp.lock().unwrap().identity = new.clone();
        // Signed by the ATTACKER's key, not the trusted old key.
        let forged = dtn_keyring::KeyChange::sign(
            "ipn:1.0",
            &SigningKey::from_bytes(&attacker.seed_bytes()),
            &new.public_key(),
            dtn_storage::now(),
        );
        let sec_imp = SecurityCtx {
            keyring: Arc::new(Mutex::new(Keyring::open_in_memory().unwrap())),
            sign_outbound: true,
            enforce_tofu: true,
            pending_rotation: Some(forged),
        };

        let mut stream = TcpStream::connect(addr).unwrap();
        let _imp_res = exchange_counted(&node_imp, Some(&sec_imp), &mut stream);
        let b_res = server.join().unwrap();

        assert!(b_res.is_err(), "a forged rotation must fail the enforced contact");
        let kr_b = sec_b.keyring.lock().unwrap();
        assert_eq!(kr_b.get("ipn:1.0").unwrap().unwrap(), old.public_key(),
            "the trusted key must be untouched");
    }

    #[test]
    fn strict_mode_drops_unknown_source_bundles() {
        let node_b = Arc::new(Mutex::new(
            Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        let a = dtn_identity::NodeIdentity::generate(51);
        let b = dtn_bpv7::Bundle::new(a.eid.clone(), Eid::ipn(2, 0), b"hi".to_vec(), 3600, 1, 1);
        let signed = dtn_bpsec::sign_bundle(&b, &a);

        // Strict TOFU mode (empty keyring): dropped.
        let sec_strict = sec_ctx();
        assert!(secured_receive(&node_b, Some(&sec_strict), &signed.encode()).unwrap().is_none(),
            "strict mode must drop signed bundles from unknown sources");
        assert_eq!(node_b.lock().unwrap().store.count().unwrap(), 0);

        // Legacy mode still accepts them.
        let sec_lenient = SecurityCtx { enforce_tofu: false, ..sec_ctx() };
        assert!(secured_receive(&node_b, Some(&sec_lenient), &signed.encode()).unwrap().is_some());
    }
}

#[cfg(feature = "tls")]
mod tls_tests {
    use super::*;
    use dtn_tcpcl::v4_tls::cert_pin;

    /// Fresh self-signed certificate for "localhost" (test-only).
    fn test_cert() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn tls_contact_delivers_bundle_and_counts() {
        let (cert_pem, key_pem) = test_cert();
        let server_setup = Arc::new(TlsServerSetup::from_pem(&cert_pem, &key_pem).unwrap());
        let client_setup = TlsClientSetup::pinned(&cert_pem, "localhost").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let node = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            node.lock().unwrap().send(Eid::ipn(1, 0), b"tls reply".to_vec(), 3600).unwrap();
            let (stream, _) = listener.accept().unwrap();
            let tls = server_setup.upgrade(stream).unwrap();
            exchange_v4_counted(&node, None, tls, false).unwrap()
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"tls request".to_vec(), 3600).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let tls = client_setup.upgrade(stream).unwrap();
        let (peer, counts) = exchange_v4_counted(&node_a, None, tls, true).unwrap();
        assert!(peer.contains("ipn:2.0"), "peer EID comes from the TCPCLv4 handshake");
        assert_eq!(counts.sent, 1);
        assert_eq!(counts.received, 1);

        let (_, server_counts) = server.join().unwrap();
        assert_eq!(server_counts.sent, 1);
        assert_eq!(server_counts.received, 1);
    }

    #[test]
    fn tls_contact_with_signed_bundles_and_keyring() {
        let (cert_pem, key_pem) = test_cert();
        let server_setup = Arc::new(TlsServerSetup::from_pem(&cert_pem, &key_pem).unwrap());
        let client_setup =
            TlsClientSetup::from_pin(cert_pin(&cert_pem).unwrap(), "localhost").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ktx, krx) = std::sync::mpsc::channel::<Vec<u8>>();

        let server = std::thread::spawn(move || {
            let node_b = Arc::new(Mutex::new(
                Node::open(2, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
            ktx.send(node_b.lock().unwrap().identity.public_key().as_bytes().to_vec()).unwrap();
            let a_key = krx.recv().unwrap();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&a_key);
            let a_vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).unwrap();
            let sec_b = SecurityCtx {
                keyring: Arc::new(Mutex::new(Keyring::open_in_memory().unwrap())),
                sign_outbound: true,
                enforce_tofu: true,
                pending_rotation: None,
            };
            sec_b.keyring.lock().unwrap().put("ipn:1.0", &a_vk).unwrap();
            node_b.lock().unwrap().send(Eid::ipn(1, 0), b"signed over tls".to_vec(), 3600).unwrap();
            let (stream, _) = listener.accept().unwrap();
            let tls = server_setup.upgrade(stream).unwrap();
            exchange_v4_counted(&node_b, Some(&sec_b), tls, false).unwrap()
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"signed request".to_vec(), 3600).unwrap();
        let b_key = krx.recv().unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b_key);
        let b_vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).unwrap();
        let sec_a = SecurityCtx {
            keyring: Arc::new(Mutex::new(Keyring::open_in_memory().unwrap())),
            sign_outbound: true,
            enforce_tofu: true,
            pending_rotation: None,
        };
        sec_a.keyring.lock().unwrap().put("ipn:2.0", &b_vk).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let tls = client_setup.upgrade(stream).unwrap();
        let (_, counts) = exchange_v4_counted(&node_a, Some(&sec_a), tls, true).unwrap();
        assert_eq!(counts.sent, 1);
        assert_eq!(counts.received, 1);
        server.join().unwrap();
    }

    #[test]
    fn tls_wrong_pin_fails_closed() {
        let (cert_pem, key_pem) = test_cert();
        let (other_pem, _) = test_cert();
        let server_setup = Arc::new(TlsServerSetup::from_pem(&cert_pem, &key_pem).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            assert!(server_setup.upgrade(stream).is_err(),
                "the server must fail the handshake against a wrong pin");
        });
        let client_setup = TlsClientSetup::pinned(&other_pem, "localhost").unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        assert!(client_setup.upgrade(stream).is_err(),
            "the client must fail closed against a certificate it did not pin");
        server.join().unwrap();
    }

    #[test]
    fn tls_pin_spec_roundtrip() {
        let (cert_pem, _) = test_cert();
        let pin = cert_pin(&cert_pem).unwrap();
        let hex: String = pin.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(tls_pin_from_spec(&hex).unwrap(), pin);
        assert!(tls_pin_from_spec("zz").is_err());
        assert!(tls_pin_from_spec("").is_err());
    }
}
