//! dtn-storage — persistent SQLite bundle store.

use dtn_bpv7::{Bundle, BundleId};
use rusqlite::{params, Connection};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn bundle_key(id: &BundleId) -> String {
    format!("{}|{}|{}", id.source.as_uri(), id.creation_ts.0, id.creation_ts.1)
}

#[derive(Debug)]
pub struct StoredBundle {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub lifetime: u64,
    pub received_at: u64,
    pub data: Vec<u8>,
}

pub struct BundleStore {
    conn: Connection,
}

impl BundleStore {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
               version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS bundles (
               id TEXT PRIMARY KEY,
               source TEXT NOT NULL,
               destination TEXT NOT NULL,
               creation_ts_secs INTEGER NOT NULL,
               creation_ts_seq INTEGER NOT NULL,
               lifetime INTEGER NOT NULL,
               received_at INTEGER NOT NULL,
               data BLOB NOT NULL);
             CREATE INDEX IF NOT EXISTS idx_bundles_dest ON bundles(destination);
             CREATE INDEX IF NOT EXISTS idx_bundles_expiry ON bundles(creation_ts_secs, lifetime);
             CREATE TABLE IF NOT EXISTS delivered (
               id TEXT PRIMARY KEY, delivered_at INTEGER NOT NULL);
             INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, strftime('%s','now'));"
        )?;
        Ok(BundleStore { conn })
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(Path::new(":memory:"))
    }

    pub fn put(&mut self, bundle: &Bundle) -> Result<bool, rusqlite::Error> {
        let key = bundle_key(&bundle.id());
        let p = &bundle.primary;
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO bundles (id, source, destination, creation_ts_secs, creation_ts_seq, lifetime, received_at, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![key, p.source_node.as_uri(), p.destination.as_uri(),
                    p.creation_ts.0 as i64, p.creation_ts.1 as i64,
                    p.lifetime as i64, now(), bundle.encode()],
        )?;
        Ok(n == 1)
    }

    pub fn mark_delivered(&mut self, id: &BundleId) -> Result<bool, rusqlite::Error> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO delivered (id, delivered_at) VALUES (?1, ?2)",
            params![bundle_key(id), now()])?;
        Ok(n == 1)
    }

    pub fn is_delivered(&self, id: &BundleId) -> Result<bool, rusqlite::Error> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM delivered WHERE id = ?1",
            params![bundle_key(id)],
            |r| r.get::<_, i64>(0)).map(|c| c > 0)
    }

    pub fn pending_for(&self, destination: &str) -> Result<Vec<StoredBundle>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, source, destination, lifetime, received_at, data
             FROM bundles WHERE destination = ?1 ORDER BY received_at")?;
        let rows = stmt.query_map(params![destination], |r| {
            Ok(StoredBundle {
                id: r.get(0)?,
                source: r.get(1)?,
                destination: r.get(2)?,
                lifetime: r.get::<_, i64>(3)? as u64,
                received_at: r.get::<_, i64>(4)? as u64,
                data: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn all(&self) -> Result<Vec<StoredBundle>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, source, destination, lifetime, received_at, data
             FROM bundles ORDER BY received_at")?;
        let rows = stmt.query_map([], |r| {
            Ok(StoredBundle {
                id: r.get(0)?,
                source: r.get(1)?,
                destination: r.get(2)?,
                lifetime: r.get::<_, i64>(3)? as u64,
                received_at: r.get::<_, i64>(4)? as u64,
                data: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn count(&self) -> Result<i64, rusqlite::Error> {
        self.conn.query_row("SELECT COUNT(*) FROM bundles", [], |r| r.get(0))
    }

    pub fn delete_expired(&mut self, now: u64) -> Result<usize, rusqlite::Error> {
        let n = self.conn.execute(
            "DELETE FROM bundles WHERE creation_ts_secs + lifetime < ?1",
            params![now as i64])?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtn_bpv7::Eid;

    fn bundle(seq: u64, dest: &str) -> Bundle {
        Bundle::new(Eid::dtn("a"), Eid::dtn(dest), b"payload".to_vec(), 3600, seq, now())
    }

    #[test]
    fn store_and_dedup() {
        let mut s = BundleStore::open_in_memory().unwrap();
        assert!(s.put(&bundle(1, "b")).unwrap());
        assert!(!s.put(&bundle(1, "b")).unwrap());
        assert_eq!(s.count().unwrap(), 1);
        assert_eq!(s.pending_for("dtn://b").unwrap().len(), 1);
        assert_eq!(s.all().unwrap().len(), 1);
    }

    #[test]
    fn expiry_cleanup() {
        let mut s = BundleStore::open_in_memory().unwrap();
        let mut b = bundle(1, "b");
        b.primary.lifetime = 10;
        b.primary.creation_ts.0 = 1000;
        s.put(&b).unwrap();
        assert_eq!(s.delete_expired(2000).unwrap(), 1);
        assert_eq!(s.count().unwrap(), 0);
    }

    #[test]
    fn delivery_receipts() {
        let mut s = BundleStore::open_in_memory().unwrap();
        let b = bundle(1, "b");
        s.put(&b).unwrap();
        let id = b.id();
        assert!(!s.is_delivered(&id).unwrap());
        assert!(s.mark_delivered(&id).unwrap());
        assert!(s.is_delivered(&id).unwrap());
        assert!(!s.mark_delivered(&id).unwrap());
    }
}
