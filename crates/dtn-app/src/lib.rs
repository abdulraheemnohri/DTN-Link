//! dtn-app — the platform application layer (Phases 7-9 foundation).
//!
//! This crate is the embeddable messaging-app engine that platform
//! frontends (Android, iOS, Windows, Linux, macOS) build on. It sits on
//! top of the dtn-core node engine and adds the state a real messaging
//! app needs, persisted in its own SQLite database next to the node's
//! bundle store:
//!
//!   * **Contacts** — human aliases mapped to EID URIs
//!     (`chat send alice "hi"` instead of `dtn://alice`).
//!   * **Conversations** — per-peer message threads with direction
//!     (in/out), body, timestamp and read state.
//!   * **Unread tracking** — per-peer and total unread counters plus
//!     mark-read, the data a notification badge needs.
//!   * **Poll-based inbox** — `App::poll_inbox()` drains the node
//!     engine's pending inbox into conversation rows (marking the
//!     bundles delivered in the store), so a GUI can call it on a
//!     timer or after a daemon sync.
//!
//! The node engine keeps doing what it does best (store-carry-forward,
//! dedup, expiry, security); the app layer only adds presentation
//! state. Text bodies are stored lossily-decoded UTF-8: DTN payloads
//! are arbitrary bytes, but a messaging app presents text.
//!
//! Honest scope: this is the shared engine, not the platform UI shells
//! themselves — no FFI bindings, no GUI toolkit, no attachments and no
//! delivery receipts from the remote side (an inbound message is
//! "delivered" locally when it lands in the conversation). Attachments
//! and remote read receipts are future work.

use dtn_bpv7::Eid;
use dtn_core::{Node, NodeError, Strategy};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// Message direction inside a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sent by this node (outbox).
    Out,
    /// Received by this node (inbox).
    In,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Out => "out",
            Direction::In => "in",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "out" => Some(Direction::Out),
            "in" => Some(Direction::In),
            _ => None,
        }
    }
}

/// One chat message, as presented by a platform frontend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: i64,
    /// Peer EID URI this message belongs to (the conversation key).
    pub peer: String,
    pub direction: Direction,
    pub body: String,
    /// Unix seconds the message was created locally.
    pub created_at: u64,
    /// Bundle identity this message was carried in (outbound only),
    /// so a frontend can correlate status back to the bundle store.
    pub bundle_key: Option<String>,
}

/// A contact: a human alias for an EID URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub alias: String,
    pub eid: String,
    pub added_at: u64,
}

/// Per-conversation aggregate for a conversation list screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub peer: String,
    pub last_body: String,
    pub last_at: u64,
    pub unread: usize,
    pub total: usize,
}

#[derive(Debug)]
pub enum AppError {
    Storage(rusqlite::Error),
    Node(NodeError),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Storage(e) => write!(f, "app database error: {e}"),
            AppError::Node(e) => write!(f, "node error: {e}"),
        }
    }
}

impl std::error::Error for AppError {}
impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self { AppError::Storage(e) }
}
impl From<NodeError> for AppError {
    fn from(e: NodeError) -> Self { AppError::Node(e) }
}

// ---------------------------------------------------------------------------
// App database
// ---------------------------------------------------------------------------

/// SQLite-backed application state (contacts + conversations).
pub struct AppDatabase {
    conn: Connection,
}

impl AppDatabase {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS contacts (
               alias TEXT PRIMARY KEY,
               eid TEXT NOT NULL,
               added_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS messages (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               peer TEXT NOT NULL,
               direction TEXT NOT NULL,
               body TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               bundle_key TEXT,
               read INTEGER NOT NULL DEFAULT 0);
             CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer, id);",
        )?;
        Ok(AppDatabase { conn })
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(Path::new(":memory:"))
    }

    // -- contacts ----------------------------------------------------------

    /// Add (or update) an alias for an EID URI. Re-adding an alias
    /// re-points it; returns true when a new row was created.
    pub fn add_contact(&mut self, alias: &str, eid: &str) -> Result<bool, rusqlite::Error> {
        // An UPSERT reports 1 affected row for both insert and update,
        // so existence is checked first to distinguish the two.
        let exists: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM contacts WHERE alias = ?1",
                params![alias],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c > 0)?;
        self.conn.execute(
            "INSERT INTO contacts (alias, eid, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(alias) DO UPDATE SET eid = excluded.eid",
            params![alias, eid, dtn_storage::now() as i64],
        )?;
        Ok(!exists)
    }

    pub fn resolve_alias(&self, alias: &str) -> Result<Option<String>, rusqlite::Error> {
        self.conn
            .query_row(
                "SELECT eid FROM contacts WHERE alias = ?1",
                params![alias],
                |r| r.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
    }

    pub fn list_contacts(&self) -> Result<Vec<Contact>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT alias, eid, added_at FROM contacts ORDER BY alias")?;
        let rows = stmt.query_map([], |r| {
            Ok(Contact {
                alias: r.get(0)?,
                eid: r.get(1)?,
                added_at: r.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect()
    }

    // -- messages ----------------------------------------------------------

    /// Insert one message; returns its row id. Outbound messages are
    /// born read; inbound messages are born unread.
    pub fn insert_message(
        &mut self,
        peer: &str,
        direction: Direction,
        body: &str,
        bundle_key: Option<&str>,
        created_at: u64,
    ) -> Result<i64, rusqlite::Error> {
        let read = matches!(direction, Direction::Out) as i64;
        self.conn.execute(
            "INSERT INTO messages (peer, direction, body, created_at, bundle_key, read)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![peer, direction.as_str(), body, created_at as i64, bundle_key, read],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Full history for one conversation, oldest first.
    pub fn history(&self, peer: &str) -> Result<Vec<Message>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, peer, direction, body, created_at, bundle_key
             FROM messages WHERE peer = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![peer], Self::row_to_message)?;
        rows.collect()
    }

    /// Conversation list: one row per peer with the latest message,
    /// total count and unread count, most recently active first.
    pub fn conversations(&self) -> Result<Vec<Conversation>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT peer,
                    (SELECT body FROM messages m2 WHERE m2.peer = m.peer
                      ORDER BY m2.id DESC LIMIT 1),
                    (SELECT created_at FROM messages m3 WHERE m3.peer = m.peer
                      ORDER BY m3.id DESC LIMIT 1),
                    SUM(CASE WHEN read = 0 THEN 1 ELSE 0 END),
                    COUNT(*)
             FROM messages m GROUP BY peer
             ORDER BY MAX(id) DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Conversation {
                peer: r.get(0)?,
                last_body: r.get(1)?,
                last_at: r.get::<_, i64>(2)? as u64,
                unread: r.get::<_, i64>(3)?.unwrap_or(0) as usize,
                total: r.get::<_, i64>(4)? as usize,
            })
        })?;
        rows.collect()
    }

    /// Total unread messages across all conversations.
    pub fn unread_total(&self) -> Result<usize, rusqlite::Error> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE read = 0 AND direction = 'in'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c as usize)
    }

    /// Mark every inbound message of a conversation read; returns the
    /// number of messages that changed state.
    pub fn mark_read(&mut self, peer: &str) -> Result<usize, rusqlite::Error> {
        let n = self.conn.execute(
            "UPDATE messages SET read = 1 WHERE peer = ?1 AND read = 0",
            params![peer],
        )?;
        Ok(n)
    }

    pub fn message_count(&self) -> Result<usize, rusqlite::Error> {
        self.conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|c| c as usize)
    }

    fn row_to_message(r: &rusqlite::Row<'_>) -> Result<Message, rusqlite::Error> {
        let dir: String = r.get(2)?;
        Ok(Message {
            id: r.get(0)?,
            peer: r.get(1)?,
            direction: Direction::parse(&dir).unwrap_or(Direction::In),
            body: r.get(3)?,
            created_at: r.get::<_, i64>(4)? as u64,
            bundle_key: r.get(5)?,
        })
    }
}

// ---------------------------------------------------------------------------
// App service
// ---------------------------------------------------------------------------

/// The platform application service: node engine + app state.
pub struct App {
    pub node: Node,
    pub db: AppDatabase,
}

impl App {
    /// Opens the node engine at `db_path` and the app database in a
    /// sidecar file `<db>.app`.
    pub fn open(node_number: u64, db_path: &Path, strategy: Strategy) -> Result<Self, AppError> {
        let node = Node::open(node_number, db_path, strategy)?;
        let mut app_path = PathBuf::from(db_path.as_os_str());
        app_path.set_extension("app");
        let db = AppDatabase::open(&app_path)?;
        Ok(App { node, db })
    }

    pub fn eid(&self) -> Eid {
        self.node.eid()
    }

    /// Compose a message and hand it to the node engine as a bundle.
    /// The message is recorded in the conversation immediately; the
    /// bundle sits in the store until a contact (daemon, gateway,
    /// adapter) carries it out — that is DTN, not a bug.
    pub fn send_text(&mut self, peer: &Eid, body: &str, lifetime: u64) -> Result<Message, AppError> {
        let bundle = self
            .node
            .send(peer.clone(), body.as_bytes().to_vec(), lifetime)?;
        let key = bundle_key(&bundle.id());
        let id = self.db.insert_message(
            &peer.as_uri(),
            Direction::Out,
            body,
            Some(&key),
            dtn_storage::now(),
        )?;
        Ok(Message {
            id,
            peer: peer.as_uri(),
            direction: Direction::Out,
            body: body.to_string(),
            created_at: dtn_storage::now(),
            bundle_key: Some(key),
        })
    }

    /// Drain the node engine's pending inbox into conversations.
    /// Returns the newly delivered messages (already marked read =
    /// unread until the frontend calls `mark_read`). Payloads that are
    /// not valid UTF-8 are stored lossily-decoded; empty payloads are
    /// recorded as empty bodies so the bundle is still consumed.
    pub fn poll_inbox(&mut self) -> Result<Vec<Message>, AppError> {
        let inbox = self.node.inbox()?;
        let mut out = Vec::new();
        for bundle in inbox {
            let body = String::from_utf8_lossy(bundle.payload().unwrap_or(&[])).to_string();
            let peer = bundle.primary.source_node.as_uri();
            let key = bundle_key(&bundle.id());
            let id = self.db.insert_message(
                &peer,
                Direction::In,
                &body,
                Some(&key),
                dtn_storage::now(),
            )?;
            self.node.store.mark_delivered(&bundle.id())?;
            out.push(Message {
                id,
                peer,
                direction: Direction::In,
                body,
                created_at: dtn_storage::now(),
                bundle_key: Some(key),
            });
        }
        Ok(out)
    }

    pub fn conversations(&self) -> Result<Vec<Conversation>, AppError> {
        Ok(self.db.conversations()?)
    }

    pub fn history(&self, peer: &str) -> Result<Vec<Message>, AppError> {
        Ok(self.db.history(peer)?)
    }

    pub fn unread_total(&self) -> Result<usize, AppError> {
        Ok(self.db.unread_total()?)
    }

    pub fn mark_read(&mut self, peer: &str) -> Result<usize, AppError> {
        Ok(self.db.mark_read(peer)?)
    }

    /// Conversation-list rendering for text frontends (CLI, TUI).
    pub fn render_conversations(&self) -> Result<String, AppError> {
        let convs = self.conversations()?;
        let mut s = String::from("=== Conversations ===\n");
        if convs.is_empty() {
            s.push_str("(no messages yet)\n");
        }
        for c in convs {
            let badge = if c.unread > 0 {
                format!("  [{} UNREAD]", c.unread)
            } else {
                String::new()
            };
            s.push_str(&format!(
                "{}  msgs={} last={}s-ago{badge}\n    | {}\n",
                c.peer,
                c.total,
                dtn_storage::now().saturating_sub(c.last_at),
                c.last_body,
            ));
        }
        Ok(s)
    }

    /// Conversation-history rendering for text frontends.
    pub fn render_history(&self, peer: &str) -> Result<String, AppError> {
        let msgs = self.history(peer)?;
        let mut s = format!("=== Chat with {peer} ===\n");
        if msgs.is_empty() {
            s.push_str("(no messages yet)\n");
        }
        for m in msgs {
            let who = match m.direction {
                Direction::Out => "you",
                Direction::In => "them",
            };
            s.push_str(&format!("[{who}] {}\n", m.body));
        }
        Ok(s)
    }
}

/// The bundle identity key used for message<->bundle correlation,
/// matching dtn-storage's internal key format.
fn bundle_key(id: &dtn_bpv7::BundleId) -> String {
    format!("{}|{}|{}", id.source.as_uri(), id.creation_ts.0, id.creation_ts.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("dtn-app-{name}-{}.db", std::process::id()))
    }

    fn cleanup(db: &Path) {
        let _ = std::fs::remove_file(db);
        let mut app = db.to_path_buf();
        app.set_extension("app");
        let _ = std::fs::remove_file(app);
    }

    #[test]
    fn send_text_records_outbox_with_bundle_key() {
        let db = tmp_db("outbox");
        {
            let mut app = App::open(1, &db, Strategy::Epidemic).unwrap();
            let m = app
                .send_text(&Eid::dtn("bob"), "hello bob", 3600)
                .unwrap();
            assert_eq!(m.direction, Direction::Out);
            assert_eq!(m.body, "hello bob");
            assert!(m.bundle_key.is_some());
            // The bundle really is in the node store, waiting for a contact.
            assert_eq!(app.node.store.count().unwrap(), 1);
            assert_eq!(app.db.message_count().unwrap(), 1);
        }
        cleanup(&db);
    }

    #[test]
    fn two_node_chat_delivery_and_unread() {
        let (db_a, db_b) = (tmp_db("chat-a"), tmp_db("chat-b"));
        {
            let mut a = App::open(1, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(2, &db_b, Strategy::Epidemic).unwrap();
            a.send_text(&b.eid(), "ping", 3600).unwrap();

            // Carry the bundle over any transport (here: direct wire).
            let wire = a.node.store.all().unwrap()[0].data.clone();
            assert!(b.node.receive(&wire).unwrap().is_some());
            assert_eq!(b.unread_total().unwrap(), 0, "not polled yet");

            let new = b.poll_inbox().unwrap();
            assert_eq!(new.len(), 1);
            assert_eq!(new[0].direction, Direction::In);
            assert_eq!(new[0].body, "ping");
            assert_eq!(new[0].peer, a.eid().as_uri());
            assert_eq!(b.unread_total().unwrap(), 1);

            let convs = b.conversations().unwrap();
            assert_eq!(convs.len(), 1);
            assert_eq!(convs[0].peer, a.eid().as_uri());
            assert_eq!(convs[0].unread, 1);
            assert_eq!(convs[0].total, 1);
            assert_eq!(convs[0].last_body, "ping");

            // The consumed bundle is marked delivered in the store, so a
            // second poll is empty (the node engine dedups anyway).
            assert!(b.poll_inbox().unwrap().is_empty());
            assert_eq!(b.unread_total().unwrap(), 1);
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }

    #[test]
    fn reply_flow_and_mark_read() {
        let (db_a, db_b) = (tmp_db("reply-a"), tmp_db("reply-b"));
        {
            let mut a = App::open(1, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(2, &db_b, Strategy::Epidemic).unwrap();
            a.send_text(&b.eid(), "ping", 3600).unwrap();
            let wire = a.node.store.all().unwrap()[0].data.clone();
            b.node.receive(&wire).unwrap();
            b.poll_inbox().unwrap();

            // b replies; a polls and sees the reply.
            b.send_text(&a.eid(), "pong", 3600).unwrap();
            let wire = b.node.store.all().unwrap()[0].data.clone();
            a.node.receive(&wire).unwrap();
            let new = a.poll_inbox().unwrap();
            assert_eq!(new.len(), 1);
            assert_eq!(new[0].body, "pong");

            assert_eq!(a.unread_total().unwrap(), 1);
            let cleared = a.mark_read(&b.eid().as_uri()).unwrap();
            assert_eq!(cleared, 1);
            assert_eq!(a.unread_total().unwrap(), 0);
            assert_eq!(a.mark_read(&b.eid().as_uri()).unwrap(), 0, "idempotent");

            let hist = a.history(&b.eid().as_uri()).unwrap();
            assert_eq!(hist.len(), 2);
            assert_eq!(hist[0].direction, Direction::Out);
            assert_eq!(hist[1].direction, Direction::In);
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }

    #[test]
    fn contacts_alias_resolution() {
        let db = tmp_db("contacts");
        {
            let mut app = App::open(3, &db, Strategy::Epidemic).unwrap();
            assert!(app.db.add_contact("alice", "dtn://alice-node").unwrap());
            assert!(!app
                .db
                .add_contact("alice", "dtn://alice-node-2")
                .unwrap(), "re-adding updates, not inserts");
            assert_eq!(
                app.db.resolve_alias("alice").unwrap().as_deref(),
                Some("dtn://alice-node-2")
            );
            assert_eq!(app.db.resolve_alias("nobody").unwrap(), None);
            let list = app.db.list_contacts().unwrap();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].alias, "alice");
            assert_eq!(list[0].eid, "dtn://alice-node-2");
        }
        cleanup(&db);
    }

    #[test]
    fn conversation_list_orders_by_activity() {
        let db = tmp_db("order");
        {
            let mut app = App::open(4, &db, Strategy::Epidemic).unwrap();
            app.db
                .insert_message("dtn://x", Direction::In, "old", None, 100)
                .unwrap();
            app.db
                .insert_message("dtn://y", Direction::In, "new", None, 200)
                .unwrap();
            let convs = app.conversations().unwrap();
            assert_eq!(convs.len(), 2);
            assert_eq!(convs[0].peer, "dtn://y", "most recent conversation first");
            assert_eq!(convs[1].peer, "dtn://x");
            assert_eq!(app.unread_total().unwrap(), 2);
        }
        cleanup(&db);
    }

    #[test]
    fn app_state_persists_across_reopen() {
        let db = tmp_db("persist");
        {
            let mut app = App::open(5, &db, Strategy::Epidemic).unwrap();
            app.send_text(&Eid::dtn("bob"), "persist me", 3600).unwrap();
            app.db.add_contact("bob", "dtn://bob").unwrap();
        }
        {
            let app = App::open(5, &db, Strategy::Epidemic).unwrap();
            assert_eq!(app.db.message_count().unwrap(), 1);
            assert_eq!(app.db.resolve_alias("bob").unwrap().as_deref(), Some("dtn://bob"));
            let hist = app.history("dtn://bob").unwrap();
            assert_eq!(hist[0].body, "persist me");
        }
        cleanup(&db);
    }

    #[test]
    fn renderings_mention_peers_and_bodies() {
        let (db_a, db_b) = (tmp_db("render-a"), tmp_db("render-b"));
        {
            let mut a = App::open(6, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(7, &db_b, Strategy::Epidemic).unwrap();
            a.send_text(&b.eid(), "visible body", 3600).unwrap();
            let wire = a.node.store.all().unwrap()[0].data.clone();
            b.node.receive(&wire).unwrap();
            b.poll_inbox().unwrap();

            let conv_text = b.render_conversations().unwrap();
            assert!(conv_text.contains("UNREAD"));
            assert!(conv_text.contains(&a.eid().as_uri()));
            assert!(conv_text.contains("visible body"));

            let hist_text = b.render_history(&a.eid().as_uri()).unwrap();
            assert!(hist_text.contains("[them] visible body"));
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }

    #[test]
    fn direction_roundtrip() {
        assert_eq!(Direction::parse(Direction::Out.as_str()), Some(Direction::Out));
        assert_eq!(Direction::parse(Direction::In.as_str()), Some(Direction::In));
        assert_eq!(Direction::parse("sideways"), None);
    }

    #[test]
    fn non_utf8_payload_is_lossily_recorded() {
        let (db_a, db_b) = (tmp_db("bin-a"), tmp_db("bin-b"));
        {
            let mut a = App::open(8, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(9, &db_b, Strategy::Epidemic).unwrap();
            // Raw bytes through the node engine (not send_text).
            a.node.send(b.eid(), vec![0xff, 0xfe, b'o', b'k'], 3600).unwrap();
            let wire = a.node.store.all().unwrap()[0].data.clone();
            b.node.receive(&wire).unwrap();
            let new = b.poll_inbox().unwrap();
            assert_eq!(new.len(), 1);
            assert!(new[0].body.contains("ok"), "lossy text: {:?}", new[0].body);
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }
}
