//! dtn-bpv7 — Bundle Protocol Version 7 (RFC 9171) core primitives.
//!
//! Phase 1 scope: canonical CBOR encoding, primary block, payload block,
//! bundle identification, lifecycle (expiry) rules. BPSec (RFC 9172) and
//! TCPCLv4 (RFC 9174) arrive in later phases.

pub mod cbor;
pub mod bundle;
pub mod eid;

pub use bundle::{Bundle, BundleId, CanonicalBlock, CrcType, PrimaryBlock, BPV7_VERSION};
pub use eid::Eid;
