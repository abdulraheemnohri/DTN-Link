//! Bluetooth RFCOMM transport glue.
//!
//! Once the OS pairs a Bluetooth device and exposes its Serial Port
//! Profile (SPP) link as a byte stream — /dev/rfcomm0 on Linux
//! (rfcomm/bluetoothd), the COM port Windows creates for a paired
//! SPP device, /dev/tty.<device>-SerialPort on macOS — RFCOMM is a
//! plain Read + Write link, so the standard DTN-Link contact
//! exchange (contact_stream, TCPCL-lite wire format) runs over it
//! unchanged.
//!
//! Bluetooth links are intermittent: devices drift out of range,
//! sleep and reappear. retry() is a hardware-independent retry
//! helper around any dialing closure: connection-level failures are
//! retried, protocol-level errors (malformed or oversized frames)
//! are reported immediately because retrying cannot fix them. A
//! retried contact cannot duplicate bundles — the node engine dedups
//! on (source EID, creation timestamp).
//!
//! Pairing and RFCOMM socket creation belong to the OS. With cargo
//! feature "serial", open_rfcomm opens the OS-provided SPP serial
//! device directly; a platform-created RFCOMM socket works through
//! contact_stream today.

use crate::TransportError;
use dtn_bpv7::Eid;
use dtn_core::Node;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Conventional baud rate for an OS-provided RFCOMM serial port.
/// The Bluetooth SPP link is virtual, so the value only paces the
/// OS serial driver.
pub const DEFAULT_BAUD: u32 = 115_200;

/// Run one full contact exchange (TCPCL-lite wire format, the same
/// protocol as the daemon and every adapter) over any RFCOMM byte
/// link — an OS-provided SPP serial port or a platform-created
/// RFCOMM socket.
pub fn contact_stream<S: Read + Write>(
    node: &Arc<Mutex<Node>>,
    stream: &mut S,
) -> Result<Eid, TransportError> {
    crate::exchange(node, stream)
}

/// Retry a dialing closure on an intermittent Bluetooth link.
///
/// TransportError::Io (connection refused, link dropped, device
/// asleep) is retried up to 'attempts' times with 'delay' between
/// attempts; protocol-level errors are returned immediately; when
/// the attempts run out, the last connection error is returned.
pub fn retry<F>(attempts: u32, delay: Duration, mut dial: F) -> Result<Eid, TransportError>
where
    F: FnMut() -> Result<Eid, TransportError>,
{
    let attempts = attempts.max(1);
    let mut last: Option<TransportError> = None;
    for attempt in 0..attempts {
        if attempt > 0 {
            std::thread::sleep(delay);
        }
        match dial() {
            Ok(eid) => return Ok(eid),
            Err(TransportError::Io(e)) => {
                // Device out of range / asleep / link dropped: retry.
                last = Some(TransportError::Io(e));
            }
            Err(other) => return Err(other),
        }
    }
    Err(last.unwrap_or(TransportError::Closed))
}

/// Open an OS-provided Bluetooth SPP serial device (cargo feature
/// "serial"), e.g. /dev/rfcomm0 on Linux or the COM port Windows
/// assigns to a paired SPP device.
#[cfg(feature = "serial")]
pub fn open_rfcomm(path: &str, baud: u32) -> std::io::Result<Box<dyn serialport::SerialPort>> {
    serialport::new(path, baud)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("rfcomm {path}: {e}"),
            )
        })
}

/// One contact exchange over an OS-provided RFCOMM serial device.
#[cfg(feature = "serial")]
pub fn contact(
    node: &Arc<Mutex<Node>>,
    path: &str,
    baud: u32,
) -> Result<Eid, TransportError> {
    let mut port = open_rfcomm(path, baud)?;
    crate::exchange(node, &mut port)
}

/// Contact with retry — Bluetooth devices drift in and out of
/// range, so keep dialing until the device answers.
#[cfg(feature = "serial")]
pub fn contact_with_retry(
    node: &Arc<Mutex<Node>>,
    path: &str,
    baud: u32,
    attempts: u32,
    delay: Duration,
) -> Result<Eid, TransportError> {
    retry(attempts, delay, || contact(node, path, baud))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duplex;
    use dtn_core::Strategy;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn mem_node(n: u64) -> Arc<Mutex<Node>> {
        Arc::new(Mutex::new(
            Node::open(n, &PathBuf::from(":memory:"), Strategy::Epidemic).unwrap(),
        ))
    }

    fn io_err() -> TransportError {
        TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "device out of range",
        ))
    }

    #[test]
    fn rfcomm_contact_two_way_over_byte_link() {
        // RFCOMM is a byte stream, so the contact path is proven on
        // an in-memory byte link: the same code runs over a real
        // OS-provided RFCOMM port once one is opened.
        let (mut a_side, mut b_side) = duplex::pair();
        let node_a = mem_node(1);
        let node_b = mem_node(2);
        node_a
            .lock()
            .unwrap()
            .send(Eid::ipn(2, 0), b"a to b over rfcomm".to_vec(), 3600)
            .unwrap();
        node_b
            .lock()
            .unwrap()
            .send(Eid::ipn(1, 0), b"b to a over rfcomm".to_vec(), 3600)
            .unwrap();

        let na = node_a.clone();
        let nb = node_b.clone();
        let sa = std::thread::spawn(move || contact_stream(&na, &mut a_side));
        let sb = std::thread::spawn(move || contact_stream(&nb, &mut b_side));
        sa.join().unwrap().unwrap();
        sb.join().unwrap().unwrap();

        assert_eq!(node_a.lock().unwrap().inbox().unwrap().len(), 1);
        assert_eq!(node_b.lock().unwrap().inbox().unwrap().len(), 1);
    }

    #[test]
    fn retry_succeeds_after_transient_failures() {
        let dial_attempts = AtomicU32::new(0);
        let peer = retry(5, Duration::from_millis(1), || {
            if dial_attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                Err(io_err()) // device asleep twice, then in range
            } else {
                Ok(Eid::ipn(7, 0))
            }
        })
        .unwrap();
        assert_eq!(peer.as_uri(), "ipn:7.0");
        assert_eq!(dial_attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn retry_propagates_protocol_errors_immediately() {
        // A malformed/oversized frame is a peer bug, not a range
        // problem: retrying cannot fix it, so no extra dial happens.
        let dial_attempts = AtomicU32::new(0);
        let err = retry(10, Duration::from_millis(1), || {
            dial_attempts.fetch_add(1, Ordering::SeqCst);
            Err(TransportError::TooLarge(0xFFFF_FFFF))
        })
        .unwrap_err();
        match err {
            TransportError::TooLarge(n) => assert_eq!(n, 0xFFFF_FFFF),
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(dial_attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn retry_exhausts_and_reports_last_io_error() {
        let dial_attempts = AtomicU32::new(0);
        let err = retry(3, Duration::from_millis(1), || {
            dial_attempts.fetch_add(1, Ordering::SeqCst);
            Err(io_err())
        })
        .unwrap_err();
        assert!(
            matches!(err, TransportError::Io(_)),
            "expected the last io error, got {err}"
        );
        assert_eq!(dial_attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn retry_zero_attempts_still_dials_once() {
        let dial_attempts = AtomicU32::new(0);
        let peer = retry(0, Duration::from_millis(1), || {
            dial_attempts.fetch_add(1, Ordering::SeqCst);
            Ok(Eid::ipn(7, 0))
        })
        .unwrap();
        assert_eq!(peer.as_uri(), "ipn:7.0");
        assert_eq!(dial_attempts.load(Ordering::SeqCst), 1);
    }
}
