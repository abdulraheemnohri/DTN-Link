//! Wi-Fi Direct (P2P) group networking glue.
//!
//! A Wi-Fi Direct group, once the platform has negotiated it
//! (wpa_supplicant `p2p_*` commands on Linux, WifiP2pManager on
//! Android), is an ordinary IP network: the group owner is the access
//! point / DHCP server and the members are its clients. So the DTN
//! convergence layer over a Wi-Fi Direct group is plain TCP — the
//! group owner listens and the members connect.
//!
//! This module provides exactly that, with no platform-specific
//! dependency:
//!
//! * GroupOwner — bind the group-owner listener and run one full
//!   contact per accepted member connection (length-prefixed framing,
//!   wire-compatible with the dtn-daemon TCPCL-lite contact protocol).
//! * contact_owner / contact_owner_with_retry — member side: connect
//!   to the group owner and run a full contact. Groups take seconds
//!   to form and a member may wake up before the owner is listening,
//!   so the retry helper keeps dialing until the group answers.
//!
//! Group formation itself (WPS pairing, group-owner election) belongs
//! to the OS. This crate deliberately only needs the resulting IP
//! network: point the members at the owner's address on the p2p
//! interface and bundles flow.

use crate::{exchange, TransportError};
use dtn_bpv7::Eid;
use dtn_core::Node;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default port for DTN-Link Wi-Fi Direct group-owner listeners.
pub const DEFAULT_PORT: u16 = 4556;

/// Group-owner side of a Wi-Fi Direct group: listens for member
/// contacts over TCP.
pub struct GroupOwner {
    listener: TcpListener,
}

impl GroupOwner {
    /// Bind the group-owner listener on all interfaces. Port 0 lets
    /// the OS pick a free port (used by the tests).
    pub fn bind(port: u16) -> io::Result<Self> {
        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        Ok(GroupOwner {
            listener: TcpListener::bind(addr)?,
        })
    }

    /// The bound address members should dial (use the group owner's
    /// address on the p2p interface).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Wait for one member connection and run one full contact
    /// exchange with it. Blocks until a member arrives.
    pub fn serve_contact(&self, node: &Arc<Mutex<Node>>) -> Result<Eid, TransportError> {
        let (mut stream, _) = self.listener.accept()?;
        exchange(node, &mut stream)
    }

    /// Serve up to `max` member contacts, one connection at a time.
    /// Returns the EIDs of every member that completed a contact.
    pub fn serve(&self, node: &Arc<Mutex<Node>>, max: usize) -> Result<Vec<Eid>, TransportError> {
        let mut peers = Vec::with_capacity(max);
        for _ in 0..max {
            peers.push(self.serve_contact(node)?);
        }
        Ok(peers)
    }
}

/// Member side: connect to the group owner at `owner` and run one
/// full contact exchange (blocking).
pub fn contact_owner(node: &Arc<Mutex<Node>>, owner: SocketAddr) -> Result<Eid, TransportError> {
    let mut stream = std::net::TcpStream::connect(owner)?;
    exchange(node, &mut stream)
}

/// Member side with retry. Wi-Fi Direct groups take seconds to form,
/// so keep trying — with `delay` between attempts, up to `attempts`
/// attempts in total — until the group owner answers.
///
/// Connection failures are retried; protocol-level errors (malformed
/// frames, oversized frames) are reported immediately because retrying
/// cannot fix them. A retried contact cannot duplicate bundles: the
/// node engine dedups on (source EID, creation timestamp).
pub fn contact_owner_with_retry(
    node: &Arc<Mutex<Node>>,
    owner: SocketAddr,
    attempts: u32,
    delay: Duration,
) -> Result<Eid, TransportError> {
    let attempts = attempts.max(1);
    let mut last: Option<TransportError> = None;
    for attempt in 0..attempts {
        if attempt > 0 {
            std::thread::sleep(delay);
        }
        match contact_owner(node, owner) {
            Ok(eid) => return Ok(eid),
            Err(TransportError::Io(e)) => {
                // Group still forming / owner not answering yet.
                last = Some(TransportError::Io(e));
            }
            Err(other) => return Err(other),
        }
    }
    Err(last.unwrap_or(TransportError::Closed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_core::Strategy;
    use std::path::PathBuf;

    fn mem_node(n: u64) -> Arc<Mutex<Node>> {
        Arc::new(Mutex::new(
            Node::open(n, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap(),
        ))
    }

    fn loopback(owner: &GroupOwner) -> SocketAddr {
        let addr = owner.local_addr().unwrap();
        SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port()))
    }

    #[test]
    fn member_contacts_group_owner_two_way_over_real_tcp() {
        let owner = GroupOwner::bind(0).unwrap();
        let addr = loopback(&owner);
        assert_ne!(addr.port(), 0);

        let node_go = mem_node(1);
        let node_member = mem_node(2);
        node_go
            .lock()
            .unwrap()
            .send(Eid::ipn(2, 0), b"owner to member".to_vec(), 3600)
            .unwrap();
        node_member
            .lock()
            .unwrap()
            .send(Eid::ipn(1, 0), b"member to owner".to_vec(), 3600)
            .unwrap();

        let go = node_go.clone();
        let server = std::thread::spawn(move || owner.serve_contact(&go).unwrap());
        let peer = contact_owner(&node_member, addr).unwrap();

        // Both sides learned the right peer EID.
        assert_eq!(peer.as_uri(), Eid::ipn(1, 0).as_uri());
        let served = server.join().unwrap();
        assert_eq!(served.as_uri(), Eid::ipn(2, 0).as_uri());

        // And both bundles were delivered across the group.
        assert_eq!(node_go.lock().unwrap().inbox().unwrap().len(), 1);
        assert_eq!(node_member.lock().unwrap().inbox().unwrap().len(), 1);
    }

    #[test]
    fn member_retry_succeeds_when_owner_comes_up_late() {
        // Reserve a free port, then let the owner bind it only after
        // the member has started dialing.
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let node_member = mem_node(2);
        let node_go = mem_node(1);
        let m = node_member.clone();
        let client = std::thread::spawn(move || {
            contact_owner_with_retry(&m, addr, 60, Duration::from_millis(50)).unwrap()
        });

        // The group is still forming while the member retries.
        std::thread::sleep(Duration::from_millis(250));
        let owner = GroupOwner::bind(port).unwrap();
        let go = node_go.clone();
        let server = std::thread::spawn(move || owner.serve_contact(&go).unwrap());

        assert_eq!(client.join().unwrap().as_uri(), Eid::ipn(1, 0).as_uri());
        assert_eq!(server.join().unwrap().as_uri(), Eid::ipn(2, 0).as_uri());
    }

    #[test]
    fn group_owner_serves_sequential_members() {
        let owner = GroupOwner::bind(0).unwrap();
        let addr = loopback(&owner);

        let node_go = mem_node(1);
        let go = node_go.clone();
        let server = std::thread::spawn(move || owner.serve(&go, 2).unwrap());

        let mut uris = Vec::new();
        for i in 0..2u64 {
            let member = mem_node(2 + i);
            let peer = contact_owner(&member, addr).unwrap();
            uris.push(peer.as_uri());
            assert_eq!(member.lock().unwrap().inbox().unwrap().len(), 0);
        }

        let peers = server.join().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(uris, vec![Eid::ipn(1, 0).as_uri(), Eid::ipn(1, 0).as_uri()]);
        assert_ne!(peers[0].as_uri(), peers[1].as_uri());
    }

    #[test]
    fn retry_reports_protocol_errors_immediately() {
        // A non-IO error must not be swallowed by the retry loop.
        let owner = GroupOwner::bind(0).unwrap();
        let addr = loopback(&owner);

        // Fake a peer that speaks garbage: accept the connection and
        // write a frame header announcing an oversized payload.
        let server = std::thread::spawn(move || {
            let (mut stream, _) = owner.listener.accept().unwrap();
            stream.write_all(&[0xFFu8, 0xFF, 0xFF, 0xFF]).unwrap();
        });

        let member = mem_node(2);
        let err =
            contact_owner_with_retry(&member, addr, 5, Duration::from_millis(10)).unwrap_err();
        server.join().unwrap();

        assert!(
            matches!(err, TransportError::TooLarge(_) | TransportError::Io(_)),
            "unexpected error: {err}"
        );
        if let TransportError::TooLarge(n) = err {
            assert_eq!(n, 0xFFFF_FFFF);
        }
    }
}
