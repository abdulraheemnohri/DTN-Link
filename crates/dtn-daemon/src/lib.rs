//! dtn-daemon — a real TCP DTN node.
//!
//! Two contact protocols are supported:
//!   * TCPCL-lite (`exchange`, Phase 4): length-prefixed frames.
//!   * RFC 9174 TCPCLv4 (`exchange_v4`, Phase 7): full session
//!     handshake, keepalives, acknowledged transfers, SESS_TERM.

use dtn_bpv7::Eid;
use dtn_core::Node;
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
}

fn parse_eid(bytes: &[u8]) -> Eid {
    let s = String::from_utf8_lossy(bytes);
    Eid::dtn(s.trim().trim_start_matches("dtn://").trim_end_matches('/'))
}

/// Exchange bundles with a connected peer stream (TCPCL-lite).
pub fn exchange(node: &Arc<Mutex<Node>>, stream: &mut TcpStream) -> Result<Eid, FrameError> {
    let our_eid = node.lock().unwrap().eid();
    write_frame(stream, our_eid.as_uri().as_bytes())?;
    let peer_raw = read_frame(stream)?;
    let peer = parse_eid(&peer_raw);

    let outbound = {
        let mut n = node.lock().unwrap();
        n.select_outbound(&peer).unwrap_or_default()
    };
    for ob in &outbound {
        write_frame(stream, &ob.bundle.encode())?;
    }
    write_end_of_batch(stream)?;
    stream.flush()?;

    loop {
        match read_frame(stream) {
            Ok(bytes) => {
                let mut n = node.lock().unwrap();
                let _ = n.receive(&bytes);
            }
            Err(FrameError::Closed) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(peer)
}

/// Exchange bundles with a peer over a full RFC 9174 TCPCLv4 session:
/// contact handshake, acknowledged outbound transfers, inbound bundles
/// stored through the node engine, then clean SESS_TERM shutdown.
/// Returns the peer's session EID.
pub fn exchange_v4(node: &Arc<Mutex<Node>>, stream: TcpStream, active: bool) -> Result<String, SessionError> {
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
    for ob in &outbound {
        let tid = sess.send_bundle(&ob.bundle.encode())?;
        loop {
            match sess.pump()? {
                Some(Event::Bundle(bytes)) => {
                    let mut n = node.lock().unwrap();
                    let _ = n.receive(&bytes);
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
                let mut n = node.lock().unwrap();
                let _ = n.receive(&bytes);
            }
            Ok(Some(Event::Terminated { .. })) => break,
            Ok(_) => {}
            Err(SessionError::Closed) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(peer_eid)
}

fn serve(node: Arc<Mutex<Node>>, listener: TcpListener) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let node = node.clone();
        std::thread::spawn(move || {
            if let Err(e) = exchange(&node, &mut stream) {
                eprintln!("[daemon] contact failed: {e}");
            }
        });
    }
}

fn sync_peers(node: Arc<Mutex<Node>>, peers: Vec<String>, interval: Duration) {
    loop {
        for addr in &peers {
            if let Ok(mut stream) = TcpStream::connect(addr) {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                if let Err(e) = exchange(&node, &mut stream) {
                    eprintln!("[daemon] sync with {addr} failed: {e}");
                }
            }
        }
        std::thread::sleep(interval);
    }
}

pub fn run(cfg: DaemonConfig) -> std::io::Result<()> {
    let node = Node::open(1, &cfg.db, cfg.strategy)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let node = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind(&cfg.listen)?;
    println!("[daemon] listening on {}", cfg.listen);

    {
        let sync_node = node.clone();
        let peers = cfg.peers.clone();
        let interval = cfg.sync_interval;
        std::thread::spawn(move || sync_peers(sync_node, peers, interval));
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

    serve(node, listener);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eid_frames() {
        let e = parse_eid(b"dtn://node42");
        assert_eq!(e.as_uri(), "dtn://node42");
        let e2 = parse_eid(b"node42");
        assert_eq!(e2.as_uri(), "dtn://node42");
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
            exchange(&node, &mut stream).unwrap();
            let n = node.lock().unwrap();
            tx.send(n.inbox().unwrap().len()).unwrap();
        });

        let client_node = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        client_node.lock().unwrap().send(Eid::ipn(2, 0), b"over the wire".to_vec(), 3600).unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        exchange(&client_node, &mut stream).unwrap();

        let delivered = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(delivered, 1, "bundle must be delivered over TCP");
        server.join().unwrap();
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
            exchange(&c_node, &mut stream).unwrap();
            let n = c_node.lock().unwrap();
            tx.send(n.inbox().unwrap().len()).unwrap();
        });
        let b_node = node_b.clone();
        let server_b = std::thread::spawn(move || {
            let (mut stream, _) = listener_b.accept().unwrap();
            exchange(&b_node, &mut stream).unwrap();
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().send(Eid::ipn(3, 0), b"hop over tcp".to_vec(), 3600).unwrap();
        let mut stream = TcpStream::connect(addr_b).unwrap();
        exchange(&node_a, &mut stream).unwrap();
        server_b.join().unwrap();

        let mut stream = TcpStream::connect(addr_c).unwrap();
        exchange(&node_b, &mut stream).unwrap();

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
            exchange_v4(&node, stream, false).unwrap();
            let n = node.lock().unwrap();
            tx.send(n.inbox().unwrap().len()).unwrap();
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"tcpclv4 wire".to_vec(), 3600).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        exchange_v4(&node_a, stream, true).unwrap();

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
            exchange_v4(&node, stream, false).unwrap();
            let n = node.lock().unwrap();
            tx.send(n.inbox().unwrap().len()).unwrap();
        });

        let node_a = Arc::new(Mutex::new(
            Node::open(1, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap()));
        node_a.lock().unwrap().send(Eid::ipn(2, 0), b"from a over v4".to_vec(), 3600).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        exchange_v4(&node_a, stream, true).unwrap();

        let delivered = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(delivered, 1, "A's bundle must reach B over TCPCLv4");
        server.join().unwrap();
        assert_eq!(node_a.lock().unwrap().inbox().unwrap().len(), 1,
            "B's bundle must reach A over TCPCLv4");
    }
}
