//! dtn-diagnostics — the DTN-Link management layer: node health
//! reports and contact diagnostics.
//!
//! Two surfaces:
//!   * `HealthReport::scan(&Node, now, soon)` — a store-wide health
//!     scan (totals, delivered/pending, expired now, expiring soon,
//!     corrupt rows, store size) with a text rendering for the CLI.
//!   * `ContactLog` — a SQLite-backed log of contacts (peer,
//!     direction, outcome, sent/received counters, timestamp) with
//!     per-peer aggregation (`summary`) and staleness reporting.
//!
//! Honest scope: the daemon records contact outcomes (peer, direction,
//! success) but not per-contact bundle counters yet, and the log is
//! local to one node — there is no network-wide management plane.

use dtn_bpv7::Bundle;
use dtn_core::Node;
use rusqlite::{params, Connection};
use std::path::Path;

// ---------------------------------------------------------------------------
// Health report
// ---------------------------------------------------------------------------

/// Store-wide health of one node, computed at a given instant.
///
/// The expired-now criterion matches the store's cleanup criterion
/// (creation_ts + lifetime < now), so everything counted here is
/// something the daemon's cleanup loop would purge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub node_eid: String,
    pub total_bundles: usize,
    pub delivered: usize,
    pub pending_inbox: usize,
    pub expired_now: usize,
    pub expiring_soon: usize,
    pub corrupt_rows: usize,
    pub store_bytes: usize,
    pub expired_ids: Vec<String>,
    pub expiring_soon_ids: Vec<String>,
}

impl HealthReport {
    /// Scan a node's store. `now` is the current unix time (seconds)
    /// and `soon` the expiring-soon horizon in seconds.
    pub fn scan(node: &Node, now: u64, soon: u64) -> Result<Self, rusqlite::Error> {
        let node_uri = node.eid().as_uri();
        let rows = node.store.all()?;
        let mut report = HealthReport {
            node_eid: node_uri.clone(),
            total_bundles: rows.len(),
            delivered: 0,
            pending_inbox: 0,
            expired_now: 0,
            expiring_soon: 0,
            corrupt_rows: 0,
            store_bytes: 0,
            expired_ids: Vec::new(),
            expiring_soon_ids: Vec::new(),
        };
        for r in rows {
            report.store_bytes += r.data.len();
            let Ok(bundle) = Bundle::decode(&r.data) else {
                report.corrupt_rows += 1;
                continue;
            };
            let expires_at = bundle
                .primary
                .creation_ts
                .0
                .saturating_add(bundle.primary.lifetime);
            if expires_at < now {
                report.expired_now += 1;
                report.expired_ids.push(r.id);
            } else if expires_at <= now.saturating_add(soon) {
                report.expiring_soon += 1;
                report.expiring_soon_ids.push(r.id);
            }
            if node.store.is_delivered(&bundle.id())? {
                report.delivered += 1;
            }
        }
        for r in node.store.pending_for(&node_uri)? {
            if let Ok(b) = Bundle::decode(&r.data) {
                if !node.store.is_delivered(&b.id())? {
                    report.pending_inbox += 1;
                }
            }
        }
        Ok(report)
    }

    /// A node is healthy when no stored bundle is already expired and
    /// no row failed to decode.
    pub fn healthy(&self) -> bool {
        self.expired_now == 0 && self.corrupt_rows == 0
    }

    /// Human-readable rendering (used by `dtn-link doctor`).
    pub fn render_text(&self, now: u64, soon: u64) -> String {
        let mut s = String::new();
        s.push_str("=== DTN-Link health report ===\n");
        s.push_str(&format!("Node:            {}\n", self.node_eid));
        s.push_str(&format!("Scanned at:      {now}\n"));
        s.push_str(&format!("Stored bundles:  {}\n", self.total_bundles));
        s.push_str(&format!("  delivered:     {}\n", self.delivered));
        s.push_str(&format!("  pending inbox: {}\n", self.pending_inbox));
        s.push_str(&format!("  expired now:   {}\n", self.expired_now));
        s.push_str(&format!("  expiring <{soon}s: {}\n", self.expiring_soon));
        s.push_str(&format!("  corrupt rows:  {}\n", self.corrupt_rows));
        s.push_str(&format!("Store size:      {} bytes\n", self.store_bytes));
        s.push_str(&format!(
            "Status:          {}\n",
            if self.healthy() { "HEALTHY" } else { "ATTENTION" }
        ));
        if !self.expired_ids.is_empty() {
            s.push_str("Expired bundles (the daemon cleanup purges these):\n");
            for id in &self.expired_ids {
                s.push_str(&format!("  {id}\n"));
            }
        }
        if !self.expiring_soon_ids.is_empty() {
            s.push_str("Expiring soon:\n");
            for id in &self.expiring_soon_ids {
                s.push_str(&format!("  {id}\n"));
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Contact log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Incoming => "in",
            Direction::Outgoing => "out",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "in" => Some(Direction::Incoming),
            "out" => Some(Direction::Outgoing),
            _ => None,
        }
    }
}

/// One completed (or failed) contact attempt.
#[derive(Debug, Clone)]
pub struct ContactRecord {
    pub peer: String,
    pub started_at: u64,
    pub direction: Direction,
    pub sent: usize,
    pub received: usize,
    pub ok: bool,
}

/// Per-peer aggregate over the contact log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSummary {
    pub peer: String,
    pub contacts: usize,
    pub successful: usize,
    pub last_contact: u64,
    pub total_sent: usize,
    pub total_received: usize,
}

impl PeerSummary {
    /// Seconds since the last contact with this peer.
    pub fn stale_for(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_contact)
    }
    pub fn ever_succeeded(&self) -> bool {
        self.successful > 0
    }
    /// Unreachable = at least one attempt, none successful.
    pub fn unreachable(&self) -> bool {
        self.contacts > 0 && self.successful == 0
    }
}

pub struct ContactLog {
    conn: Connection,
}

impl ContactLog {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS contacts (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               peer TEXT NOT NULL,
               started_at INTEGER NOT NULL,
               direction TEXT NOT NULL,
               sent INTEGER NOT NULL,
               received INTEGER NOT NULL,
               ok INTEGER NOT NULL);",
        )?;
        Ok(ContactLog { conn })
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(Path::new(":memory:"))
    }

    pub fn record(&mut self, r: &ContactRecord) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO contacts (peer, started_at, direction, sent, received, ok)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                r.peer,
                r.started_at as i64,
                r.direction.as_str(),
                r.sent as i64,
                r.received as i64,
                r.ok as i64
            ],
        )?;
        Ok(())
    }

    pub fn count(&self) -> Result<usize, rusqlite::Error> {
        self.conn
            .query_row("SELECT COUNT(*) FROM contacts", [], |r| r.get::<_, i64>(0))
            .map(|c| c as usize)
    }

    pub fn contacts_since(&self, since: u64) -> Result<Vec<ContactRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT peer, started_at, direction, sent, received, ok
             FROM contacts WHERE started_at >= ?1 ORDER BY started_at",
        )?;
        let rows = stmt.query_map(params![since as i64], |r| {
            let dir: String = r.get(2)?;
            Ok(ContactRecord {
                peer: r.get(0)?,
                started_at: r.get::<_, i64>(1)? as u64,
                direction: Direction::parse(&dir).unwrap_or(Direction::Incoming),
                sent: r.get::<_, i64>(3)? as usize,
                received: r.get::<_, i64>(4)? as usize,
                ok: r.get::<_, i64>(5)? != 0,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Per-peer aggregates, most recently contacted first.
    pub fn summary(&self) -> Result<Vec<PeerSummary>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT peer, COUNT(*), SUM(ok), MAX(started_at), SUM(sent), SUM(received)
             FROM contacts GROUP BY peer ORDER BY MAX(started_at) DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(PeerSummary {
                peer: r.get(0)?,
                contacts: r.get::<_, i64>(1)? as usize,
                successful: r.get::<_, Option<i64>>(2)?.unwrap_or(0) as usize,
                last_contact: r.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
                total_sent: r.get::<_, Option<i64>>(4)?.unwrap_or(0) as usize,
                total_received: r.get::<_, Option<i64>>(5)?.unwrap_or(0) as usize,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_bpv7::Eid;
    use dtn_core::Strategy;
    use std::path::PathBuf;

    fn tmp_db(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("dtn-diag-{name}-{}.db", std::process::id()))
    }

    #[test]
    fn health_scan_classifies_bundles() {
        let db = tmp_db("health");
        let mut node = Node::open(1, &db, Strategy::Epidemic).unwrap();
        let now = dtn_storage::now();

        // Pending inbox bundle (for us, undelivered).
        node.send(node.eid(), b"to me".to_vec(), 3600).unwrap();
        // Delivered bundle.
        let d = node.send(node.eid(), b"done".to_vec(), 3600).unwrap();
        node.store.mark_delivered(&d.id()).unwrap();
        // Expired bundle (created long ago with a short lifetime).
        let old = Bundle::new(Eid::dtn("a"), Eid::dtn("other"), b"old".to_vec(), 10, 1, now - 1000);
        node.store.put(&old).unwrap();
        // Expiring within the horizon (lifetime 60s).
        let soon_b = Bundle::new(Eid::dtn("a"), Eid::dtn("other"), b"soon".to_vec(), 60, 2, now);
        node.store.put(&soon_b).unwrap();

        let r = HealthReport::scan(&node, now, 3600).unwrap();
        assert_eq!(r.total_bundles, 4);
        assert_eq!(r.pending_inbox, 1);
        assert_eq!(r.delivered, 1);
        assert_eq!(r.expired_now, 1);
        assert_eq!(r.expiring_soon, 1);
        assert_eq!(r.corrupt_rows, 0);
        assert!(!r.healthy(), "an expired bundle must flag ATTENTION");
        assert_eq!(r.expired_ids.len(), 1);
        assert_eq!(r.expiring_soon_ids.len(), 1);
        let text = r.render_text(now, 3600);
        assert!(text.contains("ATTENTION"));
        assert!(text.contains(&r.node_eid));
        assert!(text.contains("Expiring soon:"));
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn health_scan_healthy_node() {
        let db = tmp_db("healthy");
        let mut node = Node::open(2, &db, Strategy::Epidemic).unwrap();
        node.send(Eid::dtn("far"), b"queued".to_vec(), 3600).unwrap();
        let now = dtn_storage::now();
        let r = HealthReport::scan(&node, now, 60).unwrap();
        assert!(r.healthy());
        assert!(r.render_text(now, 60).contains("HEALTHY"));
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn health_scan_detects_corrupt_row() {
        let db = tmp_db("corrupt");
        let mut node = Node::open(3, &db, Strategy::Epidemic).unwrap();
        node.send(Eid::dtn("far"), b"ok".to_vec(), 3600).unwrap();
        // Corrupt one stored row through a second SQLite connection.
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE bundles SET data = x'00' WHERE id = (SELECT id FROM bundles LIMIT 1)",
            [],
        )
        .unwrap();
        drop(conn);
        let now = dtn_storage::now();
        let r = HealthReport::scan(&node, now, 60).unwrap();
        assert_eq!(r.total_bundles, 1);
        assert_eq!(r.corrupt_rows, 1);
        assert!(!r.healthy(), "a corrupt row must flag ATTENTION");
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn contact_log_records_and_summarizes() {
        let mut log = ContactLog::open_in_memory().unwrap();
        log.record(&ContactRecord {
            peer: "ipn:2.0".into(), started_at: 1000,
            direction: Direction::Outgoing, sent: 3, received: 0, ok: true,
        }).unwrap();
        log.record(&ContactRecord {
            peer: "ipn:2.0".into(), started_at: 2000,
            direction: Direction::Incoming, sent: 0, received: 2, ok: true,
        }).unwrap();
        log.record(&ContactRecord {
            peer: "ipn:9.0".into(), started_at: 3000,
            direction: Direction::Outgoing, sent: 0, received: 0, ok: false,
        }).unwrap();
        assert_eq!(log.count().unwrap(), 3);

        let peers = log.summary().unwrap();
        assert_eq!(peers.len(), 2);
        // Most recently contacted first.
        assert_eq!(peers[0].peer, "ipn:9.0");

        let p2 = peers.iter().find(|p| p.peer == "ipn:2.0").unwrap();
        assert_eq!(p2.contacts, 2);
        assert_eq!(p2.successful, 2);
        assert_eq!(p2.total_sent, 3);
        assert_eq!(p2.total_received, 2);
        assert_eq!(p2.last_contact, 2000);
        assert_eq!(p2.stale_for(2500), 500);
        assert!(p2.ever_succeeded());
        assert!(!p2.unreachable());

        let p9 = peers.iter().find(|p| p.peer == "ipn:9.0").unwrap();
        assert!(p9.unreachable(), "only-failed peer must be unreachable");
        assert!(!p9.ever_succeeded());

        let since = log.contacts_since(2000).unwrap();
        assert_eq!(since.len(), 2);
        assert_eq!(since[0].direction, Direction::Incoming);
        assert_eq!(since[0].received, 2);
        assert_eq!(since[1].direction, Direction::Outgoing);
    }

    #[test]
    fn direction_roundtrips() {
        assert_eq!(Direction::parse(Direction::Incoming.as_str()), Some(Direction::Incoming));
        assert_eq!(Direction::parse(Direction::Outgoing.as_str()), Some(Direction::Outgoing));
        assert_eq!(Direction::parse("bogus"), None);
    }

    #[test]
    fn contact_log_persists_to_disk() {
        let db = tmp_db("persist");
        {
            let mut log = ContactLog::open(&db).unwrap();
            log.record(&ContactRecord {
                peer: "ipn:5.0".into(), started_at: 42,
                direction: Direction::Outgoing, sent: 1, received: 1, ok: true,
            }).unwrap();
        }
        let log = ContactLog::open(&db).unwrap();
        assert_eq!(log.count().unwrap(), 1);
        let s = log.summary().unwrap();
        assert_eq!(s[0].peer, "ipn:5.0");
        assert_eq!(s[0].last_contact, 42);
        assert_eq!(s[0].total_sent, 1);
        assert_eq!(s[0].total_received, 1);
        let _ = std::fs::remove_file(&db);
    }
}
