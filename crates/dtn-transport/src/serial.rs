//! Serial-port hardware glue (cargo feature "serial").
//!
//! Real LoRa TNC / radio-modem / Bluetooth SPP links over a serial
//! port, opened with the serialport crate. A serial port is a plain
//! byte stream, so the generic crate::exchange_framed contact protocol
//! runs over it unchanged: use crate::KissCodec for KISS-capable TNCs
//! and crate::LengthPrefixCodec for raw point-to-point serial cable
//! links.
//!
//! The 200 ms read timeout means a TimedOut io error is returned by
//! the exchange when no peer greeting arrives; callers should retry
//! periodically until the contact succeeds (radios are intermittent
//! by nature — that is what DTN is for).

use crate::{KissCodec, TransportError};
use dtn_bpv7::Eid;
use dtn_core::Node;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Open a serial port at 'baud' for bundle transport.
pub fn open(path: &str, baud: u32) -> std::io::Result<Box<dyn serialport::SerialPort>> {
    serialport::new(path, baud)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("serialport {path}: {e}"),
            )
        })
}

/// Run one KISS-framed contact exchange over a LoRa TNC or serial radio
/// modem. Box<dyn SerialPort> implements Read + Write, so the generic
/// exchange runs over the port directly.
pub fn kiss_exchange(
    node: &Arc<Mutex<Node>>,
    path: &str,
    baud: u32,
) -> Result<Eid, TransportError> {
    let mut port = open(path, baud)?;
    let mut codec = KissCodec::new();
    crate::exchange_framed(node, &mut port, &mut codec)
}
