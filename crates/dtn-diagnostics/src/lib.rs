//! reports and contact diagnostics.
//!
//! Two surfaces:
//!   * `HealthReport::scan(&Node, now, soon)` — a store-wide health
//!     scan (totals, delivered/pending, expired now, expiring soon,
//!     corrupt rows, store size) with a text rendering for the CLI.
//!   * `ContactLog` — a SQLite-backed log of contacts (peer, kind,
//!     direction, outcome, sent/received bundle counters, timestamp)
//!     with per-peer aggregation (`summary`) and staleness reporting.
//!
//! Contact kinds: ordinary daemon peers (`Kind::Peer`), gateway
//! contacts (`Kind::Gateway`) and federation gateway sweeps
//! (`Kind::Federation`) all land in the same log, tagged, so
//! `dtn-link doctor` can show where traffic actually flows.
//!
//! Honest scope: the log is local to one node — there is no
//! network-wide management plane yet.

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

/// What kind of link produced this contact record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An ordinary daemon peer contact (TCPCL-lite or TCPCLv4).
    Peer,
    /// A dtn-gateway contact (internet or satellite pass).
    Gateway,
    /// A federation sweep contact with a remote-region gateway.
    Federation,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Peer => "peer",
            Kind::Gateway => "gateway",
            Kind::Federation => "federation",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "peer" => Some(Kind::Peer),
            "gateway" => Some(Kind::Gateway),
            "federation" => Some(Kind::Federation),
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
    /// Bundles this node pushed to the peer during the contact.
    pub sent: usize,
    /// Bundles this node accepted from the peer during the contact.
    pub received: usize,
    pub ok: bool,
    /// Which layer performed the contact.
    pub kind: Kind,
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
        // Migration: databases created before the kind column existed
        // get it backfilled with the default ('peer').
        let has_kind: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('contacts') WHERE name = 'kind'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !has_kind {
            conn.execute_batch(
                "ALTER TABLE contacts ADD COLUMN kind TEXT NOT NULL DEFAULT 'peer';",
            )?;
        }
        Ok(ContactLog { conn })
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(Path::new(":memory:"))
    }

    pub fn record(&mut self, r: &ContactRecord) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO contacts (peer, started_at, direction, sent, received, ok, kind)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                r.peer,
                r.started_at as i64,
                r.direction.as_str(),
                r.sent as i64,
                r.received as i64,
                r.ok as i64,
                r.kind.as_str(),
            ],
        )?;
        Ok(())
    }

    pub fn count(&self) -> Result<usize, rusqlite::Error> {
        self.conn
            .query_row("SELECT COUNT(*) FROM contacts", [], |r| r.get::<_, i64>(0))
            .map(|c| c as usize)
    }

    fn row_to_record(r: &rusqlite::Row<'_>) -> Result<ContactRecord, rusqlite::Error> {
        let dir: String = r.get(2)?;
        let kind: String = r.get(6)?;
        Ok(ContactRecord {
            peer: r.get(0)?,
            started_at: r.get::<_, i64>(1)? as u64,
            direction: Direction::parse(&dir).unwrap_or(Direction::Incoming),
            sent: r.get::<_, i64>(3)? as usize,
            received: r.get::<_, i64>(4)? as usize,
            ok: r.get::<_, i64>(5)? != 0,
            kind: Kind::parse(&kind).unwrap_or(Kind::Peer),
        })
    }

    pub fn contacts_since(&self, since: u64) -> Result<Vec<ContactRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT peer, started_at, direction, sent, received, ok, kind
             FROM contacts WHERE started_at >= ?1 ORDER BY started_at",
        )?;
        let rows = stmt.query_map(params![since as i64], Self::row_to_record)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Per-peer aggregates, most recently contacted first.
    pub fn summary(&self) -> Result<Vec<PeerSummary>, rusqlite::Error> {
        self.summary_where("")
    }

    /// Per-peer aggregates restricted to one contact kind.
    pub fn summary_of(&self, kind: Kind) -> Result<Vec<PeerSummary>, rusqlite::Error> {
        self.summary_where(&format!(" WHERE kind = '{}'", kind.as_str()))
    }

    fn summary_where(&self, extra_where: &str) -> Result<Vec<PeerSummary>, rusqlite::Error> {
        // extra_where is only ever built from the fixed Kind strings
        // above (as_str), never from user input.
        let sql = format!(
            "SELECT peer, COUNT(*), SUM(ok), MAX(started_at), SUM(sent), SUM(received)
             FROM contacts{extra_where} GROUP BY peer ORDER BY MAX(started_at) DESC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
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
            kind: Kind::Peer,
        }).unwrap();
        log.record(&ContactRecord {
            peer: "ipn:2.0".into(), started_at: 2000,
            direction: Direction::Incoming, sent: 0, received: 2, ok: true,
            kind: Kind::Peer,
        }).unwrap();
        log.record(&ContactRecord {
            peer: "ipn:9.0".into(), started_at: 3000,
            direction: Direction::Outgoing, sent: 0, received: 0, ok: false,
            kind: Kind::Peer,
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
    fn kind_roundtrips_and_filters() {
        assert_eq!(Kind::parse(Kind::Peer.as_str()), Some(Kind::Peer));
        assert_eq!(Kind::parse(Kind::Gateway.as_str()), Some(Kind::Gateway));
        assert_eq!(Kind::parse(Kind::Federation.as_str()), Some(Kind::Federation));
        assert_eq!(Kind::parse("bogus"), None);

        let mut log = ContactLog::open_in_memory().unwrap();
        log.record(&ContactRecord {
            peer: "ipn:2.0".into(), started_at: 1000,
            direction: Direction::Outgoing, sent: 5, received: 1, ok: true,
            kind: Kind::Peer,
        }).unwrap();
        log.record(&ContactRecord {
            peer: "ipn:10.0".into(), started_at: 2000,
            direction: Direction::Outgoing, sent: 2, received: 0, ok: true,
            kind: Kind::Gateway,
        }).unwrap();
        log.record(&ContactRecord {
            peer: "ipn:11.0".into(), started_at: 3000,
            direction: Direction::Outgoing, sent: 1, received: 4, ok: false,
            kind: Kind::Federation,
        }).unwrap();

        let gw = log.summary_of(Kind::Gateway).unwrap();
        assert_eq!(gw.len(), 1);
        assert_eq!(gw[0].peer, "ipn:10.0");
        assert_eq!(gw[0].total_sent, 2);

        let fed = log.summary_of(Kind::Federation).unwrap();
        assert_eq!(fed.len(), 1);
        assert_eq!(fed[0].peer, "ipn:11.0");
        assert_eq!(fed[0].total_received, 4);
        assert!(fed[0].unreachable());

        // summary() still spans all kinds.
        assert_eq!(log.summary().unwrap().len(), 3);
    }

    #[test]
    fn contact_log_persists_to_disk() {
        let db = tmp_db("persist");
        {
            let mut log = ContactLog::open(&db).unwrap();
            log.record(&ContactRecord {
                peer: "ipn:5.0".into(), started_at: 42,
                direction: Direction::Outgoing, sent: 1, received: 1, ok: true,
                kind: Kind::Peer,
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

    #[test]
    fn pre_kind_database_is_migrated() {
        // Simulate a contacts.db written by an older DTN-Link (no kind
        // column, rows default to 'peer').
        let db = tmp_db("migrate");
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE contacts (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   peer TEXT NOT NULL,
                   started_at INTEGER NOT NULL,
                   direction TEXT NOT NULL,
                   sent INTEGER NOT NULL,
                   received INTEGER NOT NULL,
                   ok INTEGER NOT NULL);
                 INSERT INTO contacts (peer, started_at, direction, sent, received, ok)
                 VALUES ('ipn:3.0', 7, 'out', 2, 1, 1);",
            )
            .unwrap();
        }
        let log = ContactLog::open(&db).unwrap();
        assert_eq!(log.count().unwrap(), 1, "old rows must survive the migration");
        let s = log.summary().unwrap();
        assert_eq!(s[0].peer, "ipn:3.0");
        assert_eq!(s[0].total_sent, 2);
        // The migrated row reads back as an ordinary peer contact.
        let recs = log.contacts_since(0).unwrap();
        assert_eq!(recs[0].kind, Kind::Peer);
        // New records with kinds can be added after the migration.
        let mut log = log;
        log.record(&ContactRecord {
            peer: "ipn:10.0".into(), started_at: 9,
            direction: Direction::Outgoing, sent: 1, received: 0, ok: true,
            kind: Kind::Gateway,
        }).unwrap();
        assert_eq!(log.summary_of(Kind::Gateway).unwrap().len(), 1);
        let _ = std::fs::remove_file(&db);
    }
}
