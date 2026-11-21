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
//! themselves. File attachments arrived in Phase 23 (`send_file` /
//! `extract_attachment`); remote read receipts arrived in Phase 24
//! (`send_read_receipts` / `poll_inbox_with_receipts`): one receipt
//! bundle acknowledges exactly the bundles that carried a peer's
//! conversations, and `render_history` shows `✓read` on confirmed
//! outbound rows. GUI toolkits and an FFI receipts surface remain
//! future work.

mod attachments;
pub use attachments::{validate_filename, Attachment, AttachmentError};

mod receipts;
pub use receipts::{ReadReceipt, ReceiptError, ReceivedReceipt};

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
    /// Local filesystem I/O (reading an attachment, extracting one).
    Io(std::io::Error),
    /// No attachment is stored for the requested message.
    NoSuchAttachment,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Storage(e) => write!(f, "app database error: {e}"),
            AppError::Node(e) => write!(f, "node error: {e}"),
            AppError::Io(e) => write!(f, "app i/o error: {e}"),
            AppError::NoSuchAttachment => write!(f, "no attachment stored for this message"),
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
impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self { AppError::Io(e) }
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
               read INTEGER NOT NULL DEFAULT 0,
               confirmed_read INTEGER NOT NULL DEFAULT 0);
             CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer, id);
             CREATE TABLE IF NOT EXISTS attachments (
               message_id INTEGER PRIMARY KEY,
               filename TEXT NOT NULL,
               content BLOB NOT NULL);"
        )?;
        // Older databases migrate in place (Phase 24): a fresh schema
        // already carries confirmed_read, so the duplicate-column error
        // here is the expected fresh-database path.
        let _ = conn.execute_batch(
            "ALTER TABLE messages ADD COLUMN confirmed_read INTEGER NOT NULL DEFAULT 0;",
        );
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

    // -- read receipts (Phase 24) -------------------------------------------

    /// Bundle keys of this peer's inbound conversation messages that
    /// have not been acknowledged with a read receipt yet.
    pub fn unacked_inbound_keys(&self, peer: &str) -> Result<Vec<(i64, String)>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, bundle_key FROM messages
             WHERE peer = ?1 AND direction = 'in'
               AND confirmed_read = 0 AND bundle_key IS NOT NULL
             ORDER BY id",
        )?;
        let rows = stmt.query_map(params![peer], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.collect()
    }

    /// Mark the inbound message ids as receipt-acknowledged (local
    /// bookkeeping only; the receipt bundle is the message to the peer).
    pub fn confirm_inbound(&mut self, ids: &[i64]) -> Result<(), rusqlite::Error> {
        for id in ids {
            self.conn.execute(
                "UPDATE messages SET confirmed_read = 1 WHERE id = ?1",
                params![id],
            )?;
        }
        Ok(())
    }

    /// Apply a received read receipt: confirm the out messages whose
    /// bundle_key matches one of the acknowledged keys. Unknown keys
    /// (spoofed or belonging to a foreign conversation) match nothing.
    /// Returns the number of rows confirmed.
    pub fn confirm_out_read(&mut self, keys: &[String]) -> Result<usize, rusqlite::Error> {
        let mut n = 0usize;
        for key in keys {
            n += self.conn.execute(
                "UPDATE messages SET confirmed_read = 1
                 WHERE direction = 'out' AND bundle_key = ?1 AND confirmed_read = 0",
                params![key],
            )?;
        }
        Ok(n)
    }

    /// Whether this outbound message has been confirmed read by its
    /// peer (read-receipt state from Phase 24).
    pub fn message_confirmed(&self, id: i64) -> Result<bool, rusqlite::Error> {
        self.conn
            .query_row(
                "SELECT confirmed_read FROM messages WHERE id = ?1",
                params![id],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v != 0)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                other => Err(other),
            })
    }

    // -- attachments (Phase 23) -------------------------------------------

    /// Store an attachment's bytes next to its conversation message.
    pub fn insert_attachment(
        &mut self,
        message_id: i64,
        filename: &str,
        content: &[u8],
    ) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO attachments (message_id, filename, content)
             VALUES (?1, ?2, ?3)",
            params![message_id, filename, content],
        )?;
        Ok(())
    }

    /// The attachment stored for a conversation message, if any.
    pub fn attachment_for(&self, message_id: i64) -> Result<Option<Attachment>, rusqlite::Error> {
        self.conn
            .query_row(
                "SELECT filename, content FROM attachments WHERE message_id = ?1",
                params![message_id],
                |r| {
                    Ok(Attachment {
                        filename: r.get(0)?,
                        content: r.get(1)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
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

    /// Attach a real file and hand it to the node engine as a bundle
    /// (Phase 23). The message body carries the standard
    /// `[attachment: name (N bytes)]` marker; the bytes are stored in
    /// the app database and can be written back with
    /// `extract_attachment` — before or after delivery, that is DTN.
    pub fn send_file(
        &mut self,
        peer: &Eid,
        path: &Path,
        lifetime: u64,
    ) -> Result<Message, AppError> {
        let content = std::fs::read(path)?;
        let filename = path
            .file_name()
            .ok_or_else(|| {
                AppError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "attachment path has no file name",
                ))
            })?
            .to_string_lossy()
            .into_owned();
        validate_filename(&filename).map_err(|e| {
            AppError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe attachment filename {filename:?}: {e}"),
            ))
        })?;
        if content.len() > attachments::MAX_CONTENT_BYTES {
            return Err(AppError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("attachment too large ({} bytes, max {})", content.len(), attachments::MAX_CONTENT_BYTES),
            )));
        }
        let att = Attachment { filename: filename.clone(), content };
        let body = attachments::marker(&att.filename, att.content.len());
        let bundle = self.node.send(peer.clone(), att.encode(), lifetime)?;
        let key = bundle_key(&bundle.id());
        let id = self.db.insert_message(
            &peer.as_uri(),
            Direction::Out,
            &body,
            Some(&key),
            dtn_storage::now(),
        )?;
        self.db.insert_attachment(id, &att.filename, &att.content)?;
        Ok(Message {
            id,
            peer: peer.as_uri(),
            direction: Direction::Out,
            body,
            created_at: dtn_storage::now(),
            bundle_key: Some(key),
        })
    }

    /// Send read receipts for every inbound message of this peer that
    /// has not been acknowledged yet (Phase 24). Reading itself stays
    /// a separate action (`db.mark_read`); this acknowledges. The
    /// receipt names the exact bundles that carried the messages, so
    /// the remote side confirms precisely those conversation rows.
    /// Returns the number of acknowledged messages; with nothing
    /// pending no bundle is created and Ok(0) is returned.
    pub fn send_read_receipts(&mut self, peer: &Eid, lifetime: u64) -> Result<usize, AppError> {
        let pending = self.db.unacked_inbound_keys(&peer.as_uri())?;
        if pending.is_empty() {
            return Ok(0);
        }
        let keys: Vec<String> = pending.iter().map(|(_, k)| k.clone()).collect();
        let receipt = ReadReceipt::new(keys.clone(), dtn_storage::now())
            .map_err(|e| AppError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())))?;
        self.node.send(peer.clone(), receipt.encode(), lifetime)?;
        self.db.confirm_inbound(&pending.iter().map(|(id, _)| *id).collect::<Vec<_>>())?;
        Ok(keys.len())
    }

    /// Drain the node engine's pending inbox into conversations.
    /// Returns the newly delivered messages (still unread until the
    /// frontend calls `mark_read`). Payloads that are not valid UTF-8
    /// are stored lossily-decoded; empty payloads are recorded as
    /// empty bodies so the bundle is still consumed. DTNA1 attachment
    /// payloads (Phase 23) are decoded: the body becomes the standard
    /// `[attachment: ...]` marker and the bytes are persisted for
    /// `extract_attachment`. DTNR1 read receipts (Phase 24) are
    /// applied and returned, never shown as chat messages.
    pub fn poll_inbox(&mut self) -> Result<Vec<Message>, AppError> {
        Ok(self.poll_inbox_with_receipts()?.0)
    }

    /// As `poll_inbox`, additionally returning the read receipts that
    /// arrived in the same drain (after being applied to the
    /// conversations). Receipts never become conversation rows.
    pub fn poll_inbox_with_receipts(
        &mut self,
    ) -> Result<(Vec<Message>, Vec<ReceivedReceipt>), AppError> {
        let inbox = self.node.inbox()?;
        let mut out = Vec::new();
        let mut receipts = Vec::new();
        for bundle in inbox {
            let payload = bundle.payload().unwrap_or(&[]);
            // Read receipts (DTNR1) are applied, not displayed. A
            // receipt acknowledging bundles this node never sent (or
            // keys from a foreign conversation) confirms nothing.
            if let Ok(r) = ReadReceipt::decode(payload) {
                let from = bundle.primary.source_node.as_uri();
                let confirmed = self.db.confirm_out_read(&r.keys)?;
                self.node.store.mark_delivered(&bundle.id())?;
                receipts.push(ReceivedReceipt {
                    from,
                    acked_at: r.acked_at,
                    confirmed,
                });
                continue;
            }
            // Attachment payloads (DTNA1) are decoded and their bytes
            // persisted; anything else stays lossy text.
            let (body, attachment) = match Attachment::decode(payload) {
                Ok(a) => {
                    let note = attachments::marker(&a.filename, a.content.len());
                    (note, Some(a))
                }
                Err(_) => (String::from_utf8_lossy(payload).to_string(), None),
            };
            let peer = bundle.primary.source_node.as_uri();
            let key = bundle_key(&bundle.id());
            let id = self.db.insert_message(
                &peer,
                Direction::In,
                &body,
                Some(&key),
                dtn_storage::now(),
            )?;
            if let Some(a) = attachment {
                self.db.insert_attachment(id, &a.filename, &a.content)?;
            }
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
        Ok((out, receipts))
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

    /// Whether this outbound message has been confirmed read by its
    /// peer via a received read receipt (Phase 24).
    pub fn message_confirmed(&self, id: i64) -> Result<bool, AppError> {
        Ok(self.db.message_confirmed(id)?)
    }

    /// The attachment stored for a conversation message, if any.
    pub fn attachment_for(&self, message_id: i64) -> Result<Option<Attachment>, AppError> {
        Ok(self.db.attachment_for(message_id)?)
    }

    /// Write the attachment of a conversation message into `dest_dir`
    /// byte-for-byte. The stored filename is re-validated, so nothing
    /// can escape the destination directory no matter what was stored.
    pub fn extract_attachment(
        &self,
        message_id: i64,
        dest_dir: &Path,
    ) -> Result<PathBuf, AppError> {
        let att = self
            .db
            .attachment_for(message_id)?
            .ok_or(AppError::NoSuchAttachment)?;
        validate_filename(&att.filename).map_err(|e| {
            AppError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("stored attachment filename unsafe: {e}"),
            ))
        })?;
        let out = dest_dir.join(&att.filename);
        std::fs::write(&out, &att.content)?;
        Ok(out)
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
            // Phase 24: a confirmed read receipt renders as ✓read on
            // the outbound row the receipt acknowledged.
            let ack = if matches!(m.direction, Direction::Out)
                && self.message_confirmed(m.id).unwrap_or(false)
            {
                " [✓read]"
            } else {
                ""
            };
            s.push_str(&format!("[{who}]{} {}\n", ack, m.body));
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

    /// Find the stored bundle whose payload starts with `magic`; the
    /// store row order is not guaranteed, so [0] is not enough.
    fn find_bundle_with_payload(bytes: Vec<Vec<u8>>, magic: &[u8]) -> Vec<u8> {
        bytes
            .into_iter()
            .find(|d| {
                dtn_bpv7::Bundle::decode(d)
                    .map(|b| b.payload().map(|p| p.starts_with(magic)).unwrap_or(false))
                    .unwrap_or(false)
            })
            .expect("a bundle with the expected payload magic is in the store")
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

    #[test]
    fn attachment_file_delivery_two_nodes() {
        let (db_a, db_b) = (tmp_db("att-a"), tmp_db("att-b"));
        let src = std::env::temp_dir().join(format!("dtn-app-att-src-{}-231.bin", std::process::id()));
        let bytes: Vec<u8> = (0..=u8::MAX).chain([0u8; 64]).collect();
        std::fs::write(&src, &bytes).unwrap();
        {
            let mut a = App::open(21, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(22, &db_b, Strategy::Epidemic).unwrap();
            let m = a.send_file(&b.eid(), &src, 3600).unwrap();
            assert_eq!(m.direction, Direction::Out);
            assert_eq!(bytes.len(), 320);
            assert_eq!(m.body, "[attachment: dtn-app-att-src-".to_owned()
                + &std::process::id().to_string() + "-231.bin (320 bytes)]");
            // The encoded bundle really carries the DTNA1 payload.
            let wire = a.node.store.all().unwrap()[0].data.clone();
            let sent = dtn_bpv7::Bundle::decode(&wire).unwrap();
            assert_eq!(&sent.payload().unwrap()[..5], &b"DTNA1"[..]);

            assert!(b.node.receive(&wire).unwrap().is_some());
            let new = b.poll_inbox().unwrap();
            assert_eq!(new.len(), 1);
            assert_eq!(new[0].body, m.body);
            let att = b.attachment_for(new[0].id).unwrap().unwrap();
            assert_eq!(att.filename, src.file_name().unwrap().to_string_lossy().as_ref());
            assert_eq!(att.content, bytes);

            // Extract writes the exact original bytes into dest_dir.
            let dir = std::env::temp_dir().join(format!("dtn-app-att-out-{}-231", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let out = b.extract_attachment(new[0].id, &dir).unwrap();
            assert_eq!(out.file_name().unwrap(), src.file_name().unwrap());
            assert_eq!(std::fs::read(&out).unwrap(), bytes);
            assert!(b.render_history(&m.peer).unwrap().contains("[attachment: "));
            std::fs::remove_dir_all(&dir).unwrap();
        }
        cleanup(&db_a);
        cleanup(&db_b);
        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn attachment_extract_refuses_unsafe_stored_name_and_missing_rows() {
        let db = tmp_db("att-unsafe");
        {
            let mut app = App::open(23, &db, Strategy::Epidemic).unwrap();
            assert!(
                app.db.insert_attachment(1, "../evil.bin", b"bad").is_ok(),
                "raw db insert is allowed (used to test the extract guard)"
            );
            let dir = std::env::temp_dir().join(format!("dtn-app-att-evil-{}-231", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let err = app.extract_attachment(1, &dir).unwrap_err();
            assert!(matches!(err, AppError::Io(_)), "got: {err:?}");
            assert!(!dir.join("evil.bin").exists(), "nothing may be written outside dest_dir");
            assert!(matches!(
                app.extract_attachment(99, &dir).unwrap_err(),
                AppError::NoSuchAttachment
            ));
            std::fs::remove_dir_all(&dir).unwrap();
        }
        cleanup(&db);
    }

    #[test]
    fn attachment_state_persists_across_reopen() {
        let db = tmp_db("att-persist");
        let src = std::env::temp_dir().join(format!("dtn-app-att-src-{}-232.txt", std::process::id()));
        std::fs::write(&src, b"persist me").unwrap();
        {
            let mut a = App::open(24, &db, Strategy::Epidemic).unwrap();
            a.send_file(&dtn_bpv7::Eid::dtn("bob"), &src, 3600).unwrap();
        }
        {
            let app = App::open(24, &db, Strategy::Epidemic).unwrap();
            let att = app.attachment_for(1).unwrap().unwrap();
            assert_eq!(att.content, b"persist me");
            assert!(app.attachment_for(2).unwrap().is_none());
        }
        cleanup(&db);
        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn plain_text_is_never_misread_as_attachment() {
        let (db_a, db_b) = (tmp_db("plain-a"), tmp_db("plain-b"));
        {
            let mut a = App::open(25, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(26, &db_b, Strategy::Epidemic).unwrap();
            a.send_text(&b.eid(), "DTNA1 neighbour", 3600).unwrap();
            let wire = a.node.store.all().unwrap()[0].data.clone();
            b.node.receive(&wire).unwrap();
            let new = b.poll_inbox().unwrap();
            assert_eq!(new.len(), 1);
            assert_eq!(new[0].body, "DTNA1 neighbour");
            assert!(b.attachment_for(new[0].id).unwrap().is_none());
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }

    // -- Phase 24: remote read receipts --------------------------------------

    #[test]
    fn read_receipt_end_to_end_two_nodes() {
        let (db_a, db_b) = (tmp_db("rr-a"), tmp_db("rr-b"));
        {
            let mut a = App::open(31, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(32, &db_b, Strategy::Epidemic).unwrap();
            a.send_text(&b.eid(), "first", 3600).unwrap();
            a.send_text(&b.eid(), "second", 3600).unwrap();

            // Carry both bundles to b and deliver them.
            for bundle in a.node.store.all().unwrap() {
                assert!(b.node.receive(&bundle.data.clone()).unwrap().is_some());
            }
            let new = b.poll_inbox().unwrap();
            assert_eq!(new.len(), 2);
            assert_eq!(b.unread_total().unwrap(), 2);

            // b acknowledges: one receipt bundle for both messages.
            let store_before = b.node.store.count().unwrap();
            assert_eq!(b.send_read_receipts(&a.eid(), 3600).unwrap(), 2);
            assert_eq!(
                b.node.store.count().unwrap(),
                store_before + 1,
                "exactly one receipt bundle added"
            );
            // The receipt payload really is DTNR1 with both keys.
            let all = b.node.store.all().unwrap();
            let wire = find_bundle_with_payload(
                all.iter().map(|r| r.data.clone()).collect(),
                b"DTNR1",
            );
            let sent = dtn_bpv7::Bundle::decode(&wire).unwrap();
            assert_eq!(&sent.payload().unwrap()[..5], &b"DTNR1"[..]);

            // Idempotent: everything already acknowledged.
            assert_eq!(b.send_read_receipts(&a.eid(), 3600).unwrap(), 0);
            assert_eq!(
                b.node.store.count().unwrap(),
                store_before + 1,
                "no second receipt bundle"
            );

            // Carry the receipt back to a.
            assert!(a.node.receive(&wire).unwrap().is_some());
            let (msgs, receipts) = a.poll_inbox_with_receipts().unwrap();
            assert!(msgs.is_empty(), "a receipt is never a chat message");
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].from, b.eid().as_uri());
            assert_eq!(receipts[0].confirmed, 2, "both out rows confirmed");
            assert_eq!(a.message_count().unwrap(), 2, "no receipt rows");

            // Correlation is by bundle key: exactly the two outs.
            let hist = a.history(&b.eid().as_uri()).unwrap();
            assert!(a.message_confirmed(hist[0].id).unwrap());
            assert!(a.message_confirmed(hist[1].id).unwrap());
            // Unread state of a's own inbound side is untouched (none here).
            assert_eq!(a.unread_total().unwrap(), 0);

            // Rendering shows the ✓read badge.
            let text = a.render_history(&b.eid().as_uri()).unwrap();
            assert_eq!(text.matches("[✓read]").count(), 2, "text: {text}");
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }

    #[test]
    fn receipt_with_one_message_confirms_only_that_row() {
        let (db_a, db_b) = (tmp_db("rr-one"), tmp_db("rr-one-b"));
        {
            let mut a = App::open(33, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(34, &db_b, Strategy::Epidemic).unwrap();
            a.send_text(&b.eid(), "hello", 3600).unwrap();
            let wire = a.node.store.all().unwrap()[0].data.clone();
            b.node.receive(&wire).unwrap();
            b.poll_inbox().unwrap();
            b.send_read_receipts(&a.eid(), 3600).unwrap();
            let wire = find_bundle_with_payload(
                b.node.store.all().unwrap().iter().map(|r| r.data.clone()).collect(),
                b"DTNR1",
            );
            a.node.receive(&wire).unwrap();
            let (_, receipts) = a.poll_inbox_with_receipts().unwrap();
            assert_eq!(receipts[0].confirmed, 1);
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }

    #[test]
    fn spoofed_or_foreign_receipt_keys_confirm_nothing() {
        let (db_a, db_c) = (tmp_db("rr-spoof-a"), tmp_db("rr-spoof-c"));
        {
            let mut a = App::open(35, &db_a, Strategy::Epidemic).unwrap();
            let mut c = App::open(37, &db_c, Strategy::Epidemic).unwrap();
            a.send_text(&c.eid(), "hello", 3600).unwrap();
            let unconfirmed = a.history(&c.eid().as_uri()).unwrap()[0].id;

            // A receipt "from" c names bundles a never sent: nothing
            // may be confirmed.
            let spoof = ReadReceipt {
                keys: vec!["dtn://someone-else|1|1".to_string()],
                acked_at: 42,
            };
            c.node.send(a.eid(), spoof.encode(), 3600).unwrap();
            let wire = c.node.store.all().unwrap()[0].data.clone();
            a.node.receive(&wire).unwrap();
            let (_, receipts) = a.poll_inbox_with_receipts().unwrap();
            assert_eq!(receipts[0].confirmed, 0);
            assert!(!a.message_confirmed(unconfirmed).unwrap());
        }
        cleanup(&db_a);
        cleanup(&db_c);
    }

    #[test]
    fn malformed_receipt_payload_is_recorded_as_plain_text() {
        let (db_a, db_b) = (tmp_db("rr-bad"), tmp_db("rr-bad-b"));
        {
            let mut a = App::open(38, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(39, &db_b, Strategy::Epidemic).unwrap();
            a.send_text(&b.eid(), "real", 3600).unwrap();
            let wire = a.node.store.all().unwrap()[0].data.clone();
            b.node.receive(&wire).unwrap();
            b.poll_inbox().unwrap();

            // Corrupted receipt (bad magic byte) must degrade to lossy
            // text, never crash or silently disappear.
            b.node.send(a.eid(), b"DTNR2garbage".to_vec(), 3600).unwrap();
            let wire = find_bundle_with_payload(
                b.node.store.all().unwrap().iter().map(|r| r.data.clone()).collect(),
                b"DTNR2garbage",
            );
            a.node.receive(&wire).unwrap();
            let (msgs, receipts) = a.poll_inbox_with_receipts().unwrap();
            assert!(receipts.is_empty());
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].direction, Direction::In);
            assert!(msgs[0].body.contains("DTNR2garbage"));
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }

    #[test]
    fn receipts_and_attachments_coexist_in_one_poll() {
        let (db_a, db_b) = (tmp_db("rr-mix"), tmp_db("rr-mix-b"));
        {
            let mut a = App::open(41, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(42, &db_b, Strategy::Epidemic).unwrap();
            a.send_text(&b.eid(), "text", 3600).unwrap();
            let wire = a.node.store.all().unwrap()[0].data.clone();
            b.node.receive(&wire).unwrap();
            b.poll_inbox().unwrap();

            // b's receipt is a DTNR1 bundle whose magic differs from
            // DTNA1: both decoders must route independently.
            b.send_read_receipts(&a.eid(), 3600).unwrap();
            assert!(
                b.db.unacked_inbound_keys(&a.eid().as_uri()).unwrap().is_empty(),
                "b's inbound rows are all acknowledged"
            );
            let wire = find_bundle_with_payload(
                b.node.store.all().unwrap().iter().map(|r| r.data.clone()).collect(),
                b"DTNR1",
            );
            a.node.receive(&wire).unwrap();
            let (_, receipts) = a.poll_inbox_with_receipts().unwrap();
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].confirmed, 1);

            // The plain-text marker never leaks from the receipt path.
            assert!(a.poll_inbox().unwrap().is_empty());
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }

    #[test]
    fn read_receipt_state_persists_across_reopen() {
        let (db_a, db_b) = (tmp_db("rr-persist-a"), tmp_db("rr-persist-b"));
        let peer_uri;
        {
            let mut a = App::open(43, &db_a, Strategy::Epidemic).unwrap();
            let mut b = App::open(44, &db_b, Strategy::Epidemic).unwrap();
            peer_uri = b.eid().as_uri();
            a.send_text(&b.eid(), "persist", 3600).unwrap();
            let wire = a.node.store.all().unwrap()[0].data.clone();
            b.node.receive(&wire).unwrap();
            b.poll_inbox().unwrap();
            b.send_read_receipts(&a.eid(), 3600).unwrap();
            let wire = find_bundle_with_payload(
                b.node.store.all().unwrap().iter().map(|r| r.data.clone()).collect(),
                b"DTNR1",
            );
            a.node.receive(&wire).unwrap();
            a.poll_inbox_with_receipts().unwrap();
        }
        {
            let a = App::open(43, &db_a, Strategy::Epidemic).unwrap();
            let hist = a.history(&peer_uri).unwrap();
            assert!(
                !hist.is_empty() && a.message_confirmed(hist[0].id).unwrap(),
                "confirmed-read state survives reopen"
            );
        }
        cleanup(&db_a);
        cleanup(&db_b);
    }

    #[test]
    fn send_read_receipts_without_unread_creates_nothing() {
        let db = tmp_db("rr-empty");
        {
            let mut app = App::open(45, &db, Strategy::Epidemic).unwrap();
            assert_eq!(app.send_read_receipts(&Eid::dtn("bob"), 3600).unwrap(), 0);
            assert_eq!(app.node.store.count().unwrap(), 0);
        }
        cleanup(&db);
    }
}


