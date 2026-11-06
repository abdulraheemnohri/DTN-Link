//! In-memory duplex byte streams for adapter tests and examples.
//!
//! pair() returns two connected MemoryStream halves; writing on one
//! side makes the bytes readable on the other, exactly like a socket
//! or serial link. Reads block (channel receive) until data arrives or
//! the peer is dropped.

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};

/// One end of an in-memory byte link.
pub struct MemoryStream {
    outbox: Sender<Vec<u8>>,
    inbox: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

/// Create a connected pair of in-memory byte streams.
pub fn pair() -> (MemoryStream, MemoryStream) {
    let (tx_a, rx_a) = mpsc::channel();
    let (tx_b, rx_b) = mpsc::channel();
    (
        MemoryStream {
            outbox: tx_a,
            inbox: rx_b,
            buf: Vec::new(),
            pos: 0,
        },
        MemoryStream {
            outbox: tx_b,
            inbox: rx_a,
            buf: Vec::new(),
            pos: 0,
        },
    )
}

impl Write for MemoryStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbox
            .send(buf.to_vec())
            .map(|_| buf.len())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer dropped"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for MemoryStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            self.buf = self
                .inbox
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"))?;
            self.pos = 0;
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_transfers_bytes_both_ways() {
        let (mut a, mut b) = pair();
        a.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");

        b.write_all(b"pong").unwrap();
        let mut buf2 = [0u8; 4];
        a.read_exact(&mut buf2).unwrap();
        assert_eq!(&buf2, b"pong");
    }

    #[test]
    fn read_chunking_preserves_all_bytes() {
        let (mut a, mut b) = pair();
        let payload: Vec<u8> = (0..=255u8).cycle().take(700).collect();
        a.write_all(&payload).unwrap();
        let mut got = Vec::new();
        let _ = b.read_to_end(&mut got);
        assert_eq!(got.len(), payload.len());
        assert_eq!(got, payload);
    }
}
