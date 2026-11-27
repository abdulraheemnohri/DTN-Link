//! TLS session security for the RFC 9174 TCPCLv4 session
//! (RFC 9174 section 4.4) — Phase 29, behind the cargo feature `tls`.
//!
//! RFC 9174 section 4.4 requires that the TLS handshake completes
//! immediately after the TCP connection is established and BEFORE the
//! TCPCL contact header is exchanged; the whole session then runs
//! inside the TLS channel. This module provides exactly that layer:
//!
//! * [`TlsServerSetup`] — loads a PEM certificate chain + private key
//!   and upgrades an accepted TCP stream to a server-side TLS stream.
//! * [`TlsClientSetup`] — connects with a pinned certificate
//!   fingerprint (SHA-256 of the peer's leaf DER, TOFU-style pinning
//!   matching the project's keyring philosophy) and upgrades an
//!   outgoing TCP stream to a client-side TLS stream. Standard
//!   TLS-level signatures remain fully verified by rustls; only the
//!   web-PKI trust decision is replaced by the pin, so a MITM without
//!   the pinned certificate's private key cannot complete the
//!   handshake.
//! * [`cert_pin`] — computes the pin for a PEM certificate so an
//!   operator can record it out of band (the TOFU fingerprint).
//!
//! The resulting [`TlsServerStream`] / [`TlsClientStream`] implement
//! `Read + Write`, so they plug straight into
//! `crate::v4::Session::new`: the full TCPCLv4 session protocol
//! (handshake, keepalives, acked transfers incl. chunked
//! segmentation, SESS_TERM) runs unchanged inside TLS.
//!
//! Honest scope: RFC 9174 section 4.2 discovery of TLS support over
//! well-known ports and client-certificate authentication (mutual
//! TLS) are future work; the pin is checked per connection; the
//! daemon/CLI wiring lives in dtn-daemon (Phase 30).

use std::io;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::stream::StreamOwned;
use rustls::conn::SideData;
use rustls::{ClientConfig, ClientConnection, CommonState, Error, ServerConfig, ServerConnection};
use sha2::{Digest, Sha256};

/// Server-side TLS stream over TCP (accept side of a TCPCLv4 TLS
/// session).
pub type TlsServerStream = StreamOwned<ServerConnection, TcpStream>;
/// Client-side TLS stream over TCP (dial side of a TCPCLv4 TLS
/// session).
pub type TlsClientStream = StreamOwned<ClientConnection, TcpStream>;

/// Errors produced by the TLS session layer.
#[derive(Debug)]
pub enum TlsError {
    Io(io::Error),
    Tls(Error),
    Config(&'static str),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Io(e) => write!(f, "io error: {e}"),
            TlsError::Tls(e) => write!(f, "tls error: {e}"),
            TlsError::Config(m) => write!(f, "tls config error: {m}"),
        }
    }
}
impl std::error::Error for TlsError {}
impl From<io::Error> for TlsError {
    fn from(e: io::Error) -> Self { TlsError::Io(e) }
}
impl From<Error> for TlsError {
    fn from(e: Error) -> Self { TlsError::Tls(e) }
}

/// SHA-256 fingerprint of a PEM-encoded certificate — the TOFU pin a
/// client pins its peer with. This is the whole leaf certificate DER,
/// so any re-issued certificate changes the pin and fails closed.
pub fn cert_pin(cert_pem: &str) -> Result<[u8; 32], TlsError> {
    let mut pem = cert_pem.as_bytes();
    let cert = rustls_pemfile::certs(&mut pem)
        .next()
        .ok_or(TlsError::Config("no certificate found in PEM"))??;
    Ok(Sha256::digest(cert.as_ref()).into())
}

/// TLS accept-side setup: certificate chain + private key, no client
/// authentication (RFC 9174 does not require it; peer authentication
/// is provided by the bundle-layer BPSec signatures and, on the
/// client side, by the certificate pin).
pub struct TlsServerSetup {
    config: Arc<ServerConfig>,
}

impl TlsServerSetup {
    /// Build the server setup from a PEM certificate chain and PEM
    /// private key (ECDSA or RSA, as parsed by rustls-pemfile).
    pub fn from_pem(cert_chain_pem: &str, key_pem: &str) -> Result<Self, TlsError> {
        let mut pem = cert_chain_pem.as_bytes();
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem)
            .collect::<Result<_, _>>()?;
        if certs.is_empty() {
            return Err(TlsError::Config("no certificates in PEM chain"));
        }
        let mut key_pem_bytes = key_pem.as_bytes();
        let key = rustls_pemfile::private_key(&mut key_pem_bytes)?
            .ok_or(TlsError::Config("no private key found in PEM"))?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        Ok(TlsServerSetup { config: Arc::new(config) })
    }

    /// Wrap an accepted TCP stream in TLS and complete the handshake.
    pub fn upgrade(&self, stream: TcpStream) -> Result<TlsServerStream, TlsError> {
        let conn = ServerConnection::new(self.config.clone())?;
        let mut tls = StreamOwned::new(conn, stream);
        complete_handshake(&mut tls.conn, &mut tls.sock)?;
        Ok(tls)
    }
}

/// TLS dial-side setup: pin the peer's certificate fingerprint
/// (TOFU-style). TLS-level signature verification is unaffected.
pub struct TlsClientSetup {
    config: Arc<ClientConfig>,
    server_name: String,
}

impl TlsClientSetup {
    /// Pin the peer to the certificate whose PEM is given and dial it
    /// as `server_name` (used in the TLS SNI extension; with the pin
    /// verifier the name itself carries no trust decision, but it must
    /// still be a valid DNS name or IP).
    pub fn pinned(cert_pem: &str, server_name: &str) -> Result<Self, TlsError> {
        Self::from_pin(cert_pin(cert_pem)?, server_name)
    }

    /// Pin the peer to a raw SHA-256 leaf-certificate fingerprint
    /// (e.g. the hex pin an operator recorded out of band; see
    /// `dtn_daemon::tls_pin_from_spec` for the hex/@pem decoding).
    pub fn from_pin(pin: [u8; 32], server_name: &str) -> Result<Self, TlsError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinnedVerifier {
            pin,
            provider: provider.clone(),
        });
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(TlsClientSetup {
            config: Arc::new(config),
            server_name: server_name.to_string(),
        })
    }

    /// Wrap an outgoing TCP stream in TLS and complete the handshake.
    pub fn upgrade(&self, stream: TcpStream) -> Result<TlsClientStream, TlsError> {
        let name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| TlsError::Config("invalid server name"))?;
        let conn = ClientConnection::new(self.config.clone(), name)?;
        let mut tls = StreamOwned::new(conn, stream);
        complete_handshake(&mut tls.conn, &mut tls.sock)?;
        Ok(tls)
    }
}

/// Drive the rustls handshake to completion (RFC 9174 section 4.4:
/// TLS finishes before the contact header exchange begins).
fn complete_handshake<Side: SideData>(
    conn: &mut rustls::ConnectionCommon<Side>,
    sock: &mut TcpStream,
) -> Result<(), TlsError> {
    let mut attempts = 0;
    while conn.is_handshaking() {
        conn.complete_io(sock)?;
        attempts += 1;
        if attempts > 64 {
            return Err(TlsError::Config("TLS handshake did not converge"));
        }
    }
    Ok(())
}

/// A `ServerCertVerifier` that accepts exactly one certificate: the
/// one whose DER matches the pinned SHA-256 fingerprint. Signature
/// verification (both TLS 1.2 and TLS 1.3) is delegated to the rustls
/// provider's standard algorithm set, so a tampered handshake still
/// fails; only the web-PKI chain-of-trust decision is replaced by the
/// pin.
#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if digest == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(
                "pinned certificate mismatch (TOFU fingerprint)".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4::{Event, Session};
    use std::net::{TcpListener, TcpStream};

    /// Generate a fresh self-signed certificate for "localhost"
    /// (test-only; the production operator supplies real PEM files).
    fn test_cert() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// A connected loopback TCP socket pair.
    fn channel() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn full_tcpclv4_session_over_tls() {
        let (cert_pem, key_pem) = test_cert();
        let server_setup = TlsServerSetup::from_pem(&cert_pem, &key_pem).unwrap();
        let client_setup = TlsClientSetup::pinned(&cert_pem, "localhost").unwrap();

        let (c_sock, s_sock) = channel();

        let server_thread = std::thread::spawn(move || {
            let tls = server_setup.upgrade(s_sock).unwrap();
            let mut passive = Session::new(tls, "dtn://node-b", 30);
            passive.handshake(false).unwrap();
            assert_eq!(passive.peer_eid.as_slice(), b"dtn://node-a");
            let bundle = loop {
                match passive.pump().unwrap() {
                    Some(Event::Bundle(b)) => break b,
                    _ => continue,
                }
            };
            assert_eq!(bundle, b"secret over tls");
            passive.send_bundle(b"tls reply").unwrap();
            passive.send_sess_term(0, crate::v4::TERM_OTHER).unwrap();
        });

        let tls = client_setup.upgrade(c_sock).unwrap();
        let mut active = Session::new(tls, "dtn://node-a", 30);
        active.handshake(true).unwrap();
        assert_eq!(active.peer_eid.as_slice(), b"dtn://node-b");
        assert_eq!(active.negotiated_keepalive, 30);

        active.send_bundle(b"secret over tls").unwrap();
        let mut acked = false;
        while !acked {
            if let Some(Event::Acked { received, .. }) = active.pump().unwrap() {
                assert_eq!(received, b"secret over tls".len() as u64);
                acked = true;
            }
        }
        let reply = loop {
            match active.pump().unwrap() {
                Some(Event::Bundle(b)) => break b,
                _ => continue,
            }
        };
        assert_eq!(reply, b"tls reply");
        let reason = loop {
            match active.pump().unwrap() {
                Some(Event::Terminated { reason, .. }) => break reason,
                _ => continue,
            }
        };
        assert_eq!(reason, crate::v4::TERM_OTHER);
        server_thread.join().unwrap();
    }

    #[test]
    fn chunked_transfer_over_tls() {
        let (cert_pem, key_pem) = test_cert();
        let server_setup = TlsServerSetup::from_pem(&cert_pem, &key_pem).unwrap();
        let client_setup = TlsClientSetup::pinned(&cert_pem, "localhost").unwrap();

        let (c_sock, s_sock) = channel();
        let data: Vec<u8> = (0..20000u32).map(|i| (i % 253) as u8).collect();
        let expected = data.clone();

        let server_thread = std::thread::spawn(move || {
            let tls = server_setup.upgrade(s_sock).unwrap();
            let mut passive = Session::new(tls, "dtn://node-b", 5);
            passive.handshake(false).unwrap();
            loop {
                match passive.pump().unwrap() {
                    Some(Event::Bundle(b)) => break b,
                    _ => continue,
                }
            }
        });

        let tls = client_setup.upgrade(c_sock).unwrap();
        let mut active = Session::new(tls, "dtn://node-a", 5);
        active.handshake(true).unwrap();
        // 20000 bytes in ~1400-byte segments — the Phase 28 chunked
        // policy must work unchanged inside the TLS channel.
        active.send_bundle_chunked(&data, 1400).unwrap();
        assert_eq!(server_thread.join().unwrap(), expected);
    }

    #[test]
    fn wrong_pin_fails_the_handshake() {
        let (cert_pem, key_pem) = test_cert();
        let (other_pem, _other_key) = test_cert();
        let server_setup = TlsServerSetup::from_pem(&cert_pem, &key_pem).unwrap();
        // Client pins the WRONG certificate.
        let client_setup = TlsClientSetup::pinned(&other_pem, "localhost").unwrap();

        let (c_sock, s_sock) = channel();
        let server_thread =
            std::thread::spawn(move || server_setup.upgrade(s_sock).is_err());

        assert!(client_setup.upgrade(c_sock).is_err());
        assert!(server_thread.join().unwrap());
    }

    #[test]
    fn cert_pin_is_deterministic_and_distinguishes_certificates() {
        let (cert_pem, _) = test_cert();
        let (other_pem, _) = test_cert();
        let a = cert_pin(&cert_pem).unwrap();
        let a2 = cert_pin(&cert_pem).unwrap();
        let b = cert_pin(&other_pem).unwrap();
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_pem_is_rejected() {
        assert!(matches!(
            cert_pin(""),
            Err(TlsError::Config("no certificate found in PEM"))
        ));
        assert!(matches!(
            TlsServerSetup::from_pem("", ""),
            Err(TlsError::Config("no certificates in PEM chain"))
        ));
    }

    #[test]
    fn cert_without_matching_key_is_rejected() {
        let (cert_pem, _) = test_cert();
        let (_other_cert, other_key) = test_cert();
        assert!(TlsServerSetup::from_pem(&cert_pem, &other_key).is_err());
    }

    #[test]
    fn tls_error_renders() {
        assert_eq!(
            TlsError::Config("bad setup").to_string(),
            "tls config error: bad setup"
        );
    }
}
