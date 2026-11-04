//! Endpoint Identifiers (RFC 9171 section 3.1 / 4.3.1).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Eid {
    pub scheme: String,
    pub ssp: String,
}

impl Eid {
    pub fn dtn(node: &str) -> Self {
        Eid { scheme: "dtn".into(), ssp: node.to_string() }
    }

    pub fn dtn_null() -> Self { Eid { scheme: "dtn".into(), ssp: "none".into() } }

    pub fn ipn(node_number: u64, service_number: u64) -> Self {
        Eid { scheme: "ipn".into(), ssp: format!("{node_number}.{service_number}") }
    }

    pub fn as_uri(&self) -> String {
        if self.scheme == "ipn" { format!("{}:{}", self.scheme, self.ssp) }
        else { format!("{}://{}", self.scheme, self.ssp) }
    }

    pub fn is_null(&self) -> bool { self.ssp == "none" }
}

impl fmt::Display for Eid { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.as_uri()) } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dtn_uri() {
        let e = Eid::dtn("node1");
        assert_eq!(e.as_uri(), "dtn://node1");
        assert!(!e.is_null());
        assert!(Eid::dtn_null().is_null());
    }

    #[test]
    fn ipn_uri() {
        let e = Eid::ipn(1, 2);
        assert_eq!(e.as_uri(), "ipn:1.2");
    }
}
