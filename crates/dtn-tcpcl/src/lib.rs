//! dtn-tcpcl — TCP convergence transport for DTN-Link (Phase 4).
//!
//! Frame protocol (TCPCL-lite): every message is `[u32 BE length][bytes]`.
//! A zero-length frame marks end-of-batch. Full RFC 9174 session
//! negotiation (contact flags, keepalives, acknowledgements) is a later
//! milestone; this is a functional, real TCP transport, not a simulation.

use std::io::{Read, Write};
use std::net::TcpStream;

pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    TooLarge(u32),
    Closed,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "io error: {e}"),
            FrameError::TooLarge(n) => write!(f, "frame too large: {n}"),
            FrameError::Closed => write!(f, "connection closed"),
        }
    }
}
impl std::error::Error for FrameError {}
impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self { FrameError::Io(e) }
}

pub type FrameResult<T> = Result<T, FrameError>;

pub fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> FrameResult<()> {
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

pub fn read_frame(stream: &mut TcpStream) -> FrameResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    let n = stream.read(&mut len_buf)?;
    if n == 0 { return Err(FrameError::Closed); }
    let len = u32::from_be_bytes(len_buf);
    if len == 0 { return Err(FrameError::Closed); }
    if len > MAX_FRAME { return Err(FrameError::TooLarge(len)); }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_end_of_batch(stream: &mut TcpStream) -> FrameResult<()> {
    stream.write_all(&0u32.to_be_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_bpv7::{Bundle, Eid};
    use std::net::TcpListener;

    #[test]
    fn loopback_bundle_transfer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let got = read_frame(&mut sock).unwrap();
            write_end_of_batch(&mut sock).unwrap();
            got
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let bundle = Bundle::new(Eid::dtn("a"), Eid::dtn("b"), b"over tcp".to_vec(), 3600, 1, 1);
        write_frame(&mut client, &bundle.encode()).unwrap();
        write_end_of_batch(&mut client).unwrap();
        let received = server.join().unwrap();
        assert_eq!(Bundle::decode(&received).unwrap(), bundle);
    }

    #[test]
    fn rejects_oversized_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.write_all(&(MAX_FRAME + 1).to_be_bytes()).unwrap();
            read_frame(&mut sock)
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let _ = client.write_all(&[0u8; 8]);
        assert!(server.join().unwrap().is_err());
    }
}
