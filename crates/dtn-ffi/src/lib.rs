//! dtn-ffi — the C ABI over the dtn-app engine (Phase 19).
//!
//! This crate is the stable foreign-function boundary that the platform
//! UI shells (Android via JNI, iOS via Swift/C bridging, Windows/Linux/
//! macOS via the C ABI directly) build on. It exports a plain C interface
//! over `dtn_app::App`:
//!
//!   * `dtn_app_open` / `dtn_app_close` — opaque handle lifecycle
//!   * `dtn_app_eid` — the local node's EID URI
//!   * `dtn_app_send` — compose a message into the DTN (bundle queued)
//!   * `dtn_app_poll_inbox` — drain delivered bundles into conversations
//!   * `dtn_app_conversations` / `dtn_app_history` — chat state as JSON
//!   * `dtn_app_unread_total` / `dtn_app_mark_read` — unread badge data
//!   * `dtn_app_add_contact` / `dtn_app_resolve_contact` — alias book
//!   * `dtn_app_last_error` / `dtn_string_free` — error + string protocol
//!
//! Calling convention:
//!   * Every function is safe to call with a NULL handle: it returns the
//!     documented failure value (-1 / NULL) and records a message that
//!     `dtn_app_last_error` retrieves (thread-local, UTF-8, valid until
//!     the next FFI call on the same thread).
//!   * Strings returned to the caller are heap-allocated C strings that
//!     MUST be released with `dtn_string_free`. `dtn_app_last_error` is
//!     the one exception: it is owned by the library, never free it.
//!   * JSON is produced by a small internal escaper (no new
//!     dependencies); all strings inside are escaped, non-UTF-8 payloads
//!     never reach this layer (dtn-app stores them lossily already).
//!
//! The handle is internally a `Mutex<App>`, so a UI may call any entry
//! point from any thread; calls serialize (the engine is single-store
//! SQLite underneath anyway).
//!
//! With cargo feature `jni` (Android builds), the crate additionally
//! exports the JNI entry points the `link.dtn.shell.Native` Kotlin
//! object binds to (see `jni_shim`).

use dtn_app::{App, AppError};
use dtn_bpv7::Eid;
use dtn_core::Strategy;
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_longlong};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

#[cfg(feature = "jni")]
pub mod jni_shim;

// ---------------------------------------------------------------------------
// Opaque handle + error protocol
// ---------------------------------------------------------------------------

/// Opaque handle returned by `dtn_app_open`. The UI keeps the pointer and
/// passes it back to every other entry point.
pub struct AppHandle {
    app: Mutex<App>,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub(crate) fn set_last_error(msg: String) {
    let cs = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(cs));
}

fn clear_last_error() {
    LAST_ERROR.with(|e| *e.borrow_mut() = None);
}

/// Convert a fallible engine call into the FFI convention: `None` on
/// failure after recording the error, `Some(v)` on success after
/// clearing any stale error.
fn ffi<T, E: std::fmt::Display>(r: Result<T, E>) -> Option<T> {
    match r {
        Ok(v) => {
            clear_last_error();
            Some(v)
        }
        Err(e) => {
            set_last_error(e.to_string());
            None
        }
    }
}

/// Borrow the engine out of a (possibly NULL) handle, recording the
/// conventional error on failure.
fn with_app<T>(
    handle: *mut AppHandle,
    f: impl FnOnce(MutexGuard<'_, App>) -> Result<T, AppError>,
) -> Option<T> {
    if handle.is_null() {
        set_last_error("null app handle".into());
        return None;
    }
    // The handle only ever comes from dtn_app_open and is only freed by
    // dtn_app_close, so the pointer is valid while the caller honors the
    // close contract.
    let app = unsafe { &*handle };
    let guard = match app.app.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(guard).map_err(|e| set_last_error(e.to_string())).ok()
}

/// Interpret a caller-provided C string, recording the conventional
/// error when it is NULL or not valid UTF-8.
unsafe fn cstr_opt<'a>(p: *const c_char, what: &str) -> Option<&'a str> {
    if p.is_null() {
        set_last_error(format!("{what} is null"));
        return None;
    }
    match CStr::from_ptr(p).to_str() {
        Ok(s) => Some(s),
        Err(_) => {
            set_last_error(format!("{what} is not valid UTF-8"));
            None
        }
    }
}

/// Release a string returned by this library (everything except the
/// pointer from `dtn_app_last_error`).
#[no_mangle]
pub extern "C" fn dtn_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe { drop(CString::from_raw(s)) };
}

/// Last error message on this thread (UTF-8, owned by the library,
/// valid until the next FFI call on the same thread). NULL when the
/// previous call succeeded. Never free this pointer.
#[no_mangle]
pub extern "C" fn dtn_app_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        e.borrow()
            .as_ref()
            .map(|cs| cs.as_ptr())
            .unwrap_or(std::ptr::null())
    })
}

// ---------------------------------------------------------------------------
// EID parsing (URI form used across the FFI boundary)
// ---------------------------------------------------------------------------

/// Parse an EID URI (`dtn://name`, `dtn:none`, `ipn:n.s`) or a bare node
/// name (treated as `dtn://name`). Returns None for anything else.
pub fn parse_eid(uri: &str) -> Option<Eid> {
    if uri == "dtn:none" {
        return Some(Eid::dtn_null());
    }
    if let Some(rest) = uri.strip_prefix("dtn://") {
        if !rest.is_empty() && !rest.contains('/') {
            return Some(Eid::dtn(rest));
        }
        return None;
    }
    if let Some(rest) = uri.strip_prefix("ipn:") {
        let mut parts = rest.split('.');
        let node = parts.next()?;
        let service = parts.next()?;
        if parts.next().is_some()
            || node.is_empty()
            || service.is_empty()
            || !node.bytes().all(|b| b.is_ascii_digit())
            || !service.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        return Some(Eid::ipn(node.parse().ok()?, service.parse().ok()?));
    }
    if !uri.is_empty() && !uri.contains(':') && !uri.contains('/') {
        return Some(Eid::dtn(uri));
    }
    None
}

// ---------------------------------------------------------------------------
// Minimal JSON emission (no external dependencies)
// ---------------------------------------------------------------------------

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

fn json_opt(s: &Option<String>) -> String {
    match s {
        Some(v) => json_str(v),
        None => "null".to_string(),
    }
}

// ---------------------------------------------------------------------------
// FFI entry points
// ---------------------------------------------------------------------------

/// Routing strategy codes accepted by `dtn_app_open`.
pub const DTN_STRATEGY_EPIDEMIC: u32 = 0;
pub const DTN_STRATEGY_SPRAY_WAIT: u32 = 1;
pub const DTN_STRATEGY_OPPORTUNISTIC: u32 = 2;

/// Open (or create) a node + app state at `db_path`. Returns an opaque
/// handle, or NULL on error (see `dtn_app_last_error`).
///
/// # Safety
/// `db_path` must be a valid NUL-terminated UTF-8 C string, or NULL
/// (NULL is reported as an error, not UB).
#[no_mangle]
pub unsafe extern "C" fn dtn_app_open(
    node_number: u64,
    db_path: *const c_char,
    strategy: u32,
) -> *mut AppHandle {
    let path = match cstr_opt(db_path, "db_path") {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };
    let strat = match strategy {
        DTN_STRATEGY_EPIDEMIC => Strategy::Epidemic,
        DTN_STRATEGY_SPRAY_WAIT => Strategy::SprayWait,
        DTN_STRATEGY_OPPORTUNISTIC => Strategy::Opportunistic,
        _ => Strategy::Epidemic,
    };
    match ffi(App::open(node_number, &PathBuf::from(path), strat)) {
        Some(app) => Box::into_raw(Box::new(AppHandle {
            app: Mutex::new(app),
        })),
        None => std::ptr::null_mut(),
    }
}

/// Close a handle opened by `dtn_app_open`. NULL is a no-op.
///
/// # Safety
/// `handle` must be a handle returned by `dtn_app_open` that has not
/// been closed yet, or NULL. After this call the handle is invalid.
#[no_mangle]
pub unsafe extern "C" fn dtn_app_close(handle: *mut AppHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// The local node's EID URI, or NULL on error.
///
/// # Safety
/// `handle` must be a live handle or NULL.
#[no_mangle]
pub unsafe extern "C" fn dtn_app_eid(handle: *mut AppHandle) -> *mut c_char {
    with_app(handle, |app| Ok(app.eid().as_uri()))
        .map(|uri| match CString::new(uri) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        })
        .unwrap_or(std::ptr::null_mut())
}

/// Compose a text message to `peer_uri` (EID URI or bare node name).
/// The message is recorded in the conversation immediately and the
/// bundle sits in the store until a contact carries it out.
/// Returns the message row id, or -1 on error.
///
/// # Safety
/// `handle`, `peer_uri` and `body` must be valid handles / NUL-terminated
/// UTF-8 C strings, or NULL (NULL is an error, not UB).
#[no_mangle]
pub unsafe extern "C" fn dtn_app_send(
    handle: *mut AppHandle,
    peer_uri: *const c_char,
    body: *const c_char,
    lifetime: u64,
) -> c_longlong {
    let peer = match cstr_opt(peer_uri, "peer_uri") {
        Some(p) => p,
        None => return -1,
    };
    let body = match cstr_opt(body, "body") {
        Some(b) => b,
        None => return -1,
    };
    let eid = match parse_eid(peer) {
        Some(e) => e,
        None => {
            set_last_error(format!("invalid peer EID URI: {peer}"));
            return -1;
        }
    };
    with_app(handle, |mut app| {
        app.send_text(&eid, body, lifetime)
            .map(|m| m.id)
            .map_err(AppError::from)
    })
    .map(|id| id as c_longlong)
    .unwrap_or(-1)
}

/// Drain the node engine's pending inbox into conversations. Returns a
/// JSON array of new messages
/// (`[{"id":..,"peer":"..","direction":"in|out","body":"..",
///   "created_at":..,"bundle_key":..|null}, ..]`), or NULL on error.
/// An empty inbox yields `[]`.
///
/// # Safety
/// `handle` must be a live handle or NULL.
#[no_mangle]
pub unsafe extern "C" fn dtn_app_poll_inbox(handle: *mut AppHandle) -> *mut c_char {
    let msgs = match with_app(handle, |mut app| app.poll_inbox()) {
        Some(m) => m,
        None => return std::ptr::null_mut(),
    };
    let items: Vec<String> = msgs
        .iter()
        .map(|m| {
            format!(
                "{\"id\":{},\"peer\":{},\"direction\":{},\"body\":{},\"created_at\":{},\"bundle_key\":{}}",
                m.id,
                json_str(&m.peer),
                json_str(m.direction.as_str()),
                json_str(&m.body),
                m.created_at,
                json_opt(&m.bundle_key),
            )
        })
        .collect();
    let json = format!("[{}]", items.join(","));
    match CString::new(json) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Conversation list as a JSON array
/// (`[{"peer":"..","last_body":"..","last_at":..,"unread":..,"total":..}, ..]`,
/// most recently active first), or NULL on error.
///
/// # Safety
/// `handle` must be a live handle or NULL.
#[no_mangle]
pub unsafe extern "C" fn dtn_app_conversations(handle: *mut AppHandle) -> *mut c_char {
    let convs = match with_app(handle, |app| app.conversations()) {
        Some(c) => c,
        None => return std::ptr::null_mut(),
    };
    let items: Vec<String> = convs
        .iter()
        .map(|c| {
            format!(
                "{\"peer\":{},\"last_body\":{},\"last_at\":{},\"unread\":{},\"total\":{}}",
                json_str(&c.peer),
                json_str(&c.last_body),
                c.last_at,
                c.unread,
                c.total,
            )
        })
        .collect();
    let json = format!("[{}]", items.join(","));
    match CString::new(json) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Full history of one conversation (peer = EID URI) as a JSON array in
/// the same message shape as `dtn_app_poll_inbox`, oldest first, or
/// NULL on error.
///
/// # Safety
/// `handle` and `peer` must be a live handle / NUL-terminated UTF-8 C
/// string, or NULL.
#[no_mangle]
pub unsafe extern "C" fn dtn_app_history(
    handle: *mut AppHandle,
    peer: *const c_char,
) -> *mut c_char {
    let peer = match cstr_opt(peer, "peer") {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };
    let msgs = match with_app(handle, |app| app.history(peer)) {
        Some(m) => m,
        None => return std::ptr::null_mut(),
    };
    let items: Vec<String> = msgs
        .iter()
        .map(|m| {
            format!(
                "{\"id\":{},\"peer\":{},\"direction\":{},\"body\":{},\"created_at\":{},\"bundle_key\":{}}",
                m.id,
                json_str(&m.peer),
                json_str(m.direction.as_str()),
                json_str(&m.body),
                m.created_at,
                json_opt(&m.bundle_key),
            )
        })
        .collect();
    let json = format!("[{}]", items.join(","));
    match CString::new(json) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Total unread inbound messages across all conversations, or -1 on
/// error.
///
/// # Safety
/// `handle` must be a live handle or NULL.
#[no_mangle]
pub unsafe extern "C" fn dtn_app_unread_total(handle: *mut AppHandle) -> c_longlong {
    with_app(handle, |app| app.unread_total())
        .map(|n| n as c_longlong)
        .unwrap_or(-1)
}

/// Mark every inbound message of one conversation (peer = EID URI)
/// read. Returns the number of messages changed, or -1 on error.
///
/// # Safety
/// `handle` and `peer` must be a live handle / NUL-terminated UTF-8 C
/// string, or NULL.
#[no_mangle]
pub unsafe extern "C" fn dtn_app_mark_read(
    handle: *mut AppHandle,
    peer: *const c_char,
) -> c_longlong {
    let peer = match cstr_opt(peer, "peer") {
        Some(p) => p,
        None => return -1,
    };
    with_app(handle, |mut app| app.mark_read(peer))
        .map(|n| n as c_longlong)
        .unwrap_or(-1)
}

/// Add (or re-point) a contact alias. Returns 1 when a new contact was
/// created, 0 when an existing alias was updated, -1 on error.
///
/// # Safety
/// `handle`, `alias` and `eid` must be a live handle / NUL-terminated
/// UTF-8 C strings, or NULL.
#[no_mangle]
pub unsafe extern "C" fn dtn_app_add_contact(
    handle: *mut AppHandle,
    alias: *const c_char,
    eid: *const c_char,
) -> c_int {
    let alias = match cstr_opt(alias, "alias") {
        Some(a) => a,
        None => return -1,
    };
    let eid = match cstr_opt(eid, "eid") {
        Some(e) => e,
        None => return -1,
    };
    with_app(handle, |mut app| {
        app.db.add_contact(alias, eid).map_err(AppError::from)
    })
    .map(|created| if created { 1 } else { 0 })
    .unwrap_or(-1)
}

/// Resolve a contact alias to its EID URI. Returns a newly allocated
/// string (free with `dtn_string_free`), NULL when the alias is unknown
/// or on error (distinguish via `dtn_app_last_error`).
///
/// # Safety
/// `handle` and `alias` must be a live handle / NUL-terminated UTF-8 C
/// string, or NULL.
#[no_mangle]
pub unsafe extern "C" fn dtn_app_resolve_contact(
    handle: *mut AppHandle,
    alias: *const c_char,
) -> *mut c_char {
    let alias = match cstr_opt(alias, "alias") {
        Some(a) => a,
        None => return std::ptr::null_mut(),
    };
    let eid = match with_app(handle, |app| {
        app.db
            .resolve_alias(alias)
            .map_err(AppError::from)
    }) {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };
    match eid {
        Some(uri) => match CString::new(uri) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => {
            set_last_error(format!("unknown contact alias: {alias}"));
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — the C ABI exercised end-to-end over the real node engine
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn tmp_db(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("dtn-ffi-{name}-{}.db", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.app"));
    }

    fn take_string(p: *mut c_char) -> String {
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        unsafe { dtn_string_free(p) };
        s
    }

    fn last_error() -> String {
        let p = unsafe { dtn_app_last_error() };
        assert!(!p.is_null(), "expected a recorded error");
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    #[test]
    fn eid_parsing() {
        assert_eq!(parse_eid("dtn://bob"), Some(Eid::dtn("bob")));
        assert_eq!(parse_eid("bob"), Some(Eid::dtn("bob")));
        assert_eq!(parse_eid("dtn:none"), Some(Eid::dtn_null()));
        assert_eq!(parse_eid("ipn:12.34"), Some(Eid::ipn(12, 34)));
        assert_eq!(parse_eid(""), None);
        assert_eq!(parse_eid("dtn://"), None);
        assert_eq!(parse_eid("dtn://a/b"), None);
        assert_eq!(parse_eid("ipn:12"), None);
        assert_eq!(parse_eid("ipn:1.2.3"), None);
        assert_eq!(parse_eid("ipn:a.b"), None);
        assert_eq!(parse_eid("http://x"), None);
        assert_eq!(parse_eid("dtn://bo b"), Some(Eid::dtn("bo b")));
    }

    #[test]
    fn json_escape_covers_quotes_and_control_chars() {
        assert_eq!(json_escape("a\"b\\c\nd\te"), "a\\\"b\\\\c\\nd\\te");
        assert_eq!(json_escape("\u{1}"), "\\u0001");
        assert_eq!(json_str("hi"), "\"hi\"");
    }

    #[test]
    fn ffi_two_node_chat_over_the_c_abi() {
        let (dba, dbb) = (tmp_db("chat-a"), tmp_db("chat-b"));
        unsafe {
            let a = dtn_app_open(1, CString::new(dba.as_str()).unwrap().as_ptr(), 0);
            let b = dtn_app_open(2, CString::new(dbb.as_str()).unwrap().as_ptr(), 0);
            assert!(!a.is_null() && !b.is_null());

            let eid_a = take_string(dtn_app_eid(a));
            let eid_b = take_string(dtn_app_eid(b));
            assert!(eid_a.starts_with("dtn://"));
            assert!(eid_b.starts_with("dtn://"));

            // A sends to B through the C ABI; the bundle is queued.
            let body = CString::new("hello from the shell").unwrap();
            let peer = CString::new(eid_b.as_str()).unwrap();
            let msg_id = dtn_app_send(a, peer.as_ptr(), body.as_ptr(), 3600);
            assert!(msg_id >= 0, "send failed: {}", last_error());

            // Carry the bundle over the real node engine (what the
            // daemon / any transport adapter does in production).
            let wire = {
                let handle = &*a;
                let app = handle.app.lock().unwrap();
                app.node.store.all().unwrap()[0].data.clone()
            };
            {
                let handle = &*b;
                let app = handle.app.lock().unwrap();
                assert!(app.node.receive(&wire).unwrap().is_some());
            }

            // B polls through the C ABI and sees the message as JSON.
            let poll = take_string(dtn_app_poll_inbox(b));
            assert!(poll.contains("\"direction\":\"in\""), "poll: {poll}");
            assert!(poll.contains("hello from the shell"));
            assert!(poll.contains(&format!("\"peer\":\"{eid_a}\"")));

            assert_eq!(dtn_app_unread_total(b), 1);

            let convs = take_string(dtn_app_conversations(b));
            assert!(convs.contains(&format!("\"peer\":\"{eid_a}\"")));
            assert!(convs.contains("\"unread\":1"));
            assert!(convs.contains("\"total\":1"));

            let peer_c = CString::new(eid_a.as_str()).unwrap();
            assert_eq!(dtn_app_mark_read(b, peer_c.as_ptr()), 1);
            assert_eq!(dtn_app_mark_read(b, peer_c.as_ptr()), 0, "idempotent");
            assert_eq!(dtn_app_unread_total(b), 0);

            let hist = take_string(dtn_app_history(b, peer_c.as_ptr()));
            assert!(hist.contains("hello from the shell"));

            // Second poll is empty (delivered bundles are consumed).
            assert_eq!(take_string(dtn_app_poll_inbox(b)), "[]");

            dtn_app_close(a);
            dtn_app_close(b);
        }
        cleanup(&dba);
        cleanup(&dbb);
    }

    #[test]
    fn ffi_contacts_add_and_resolve() {
        let db = tmp_db("contacts");
        unsafe {
            let h = dtn_app_open(3, CString::new(db.as_str()).unwrap().as_ptr(), 0);
            assert!(!h.is_null());

            let alias = CString::new("alice").unwrap();
            let eid = CString::new("dtn://alice-node").unwrap();
            assert_eq!(dtn_app_add_contact(h, alias.as_ptr(), eid.as_ptr()), 1);
            assert_eq!(dtn_app_add_contact(h, alias.as_ptr(), eid.as_ptr()), 0);

            let resolved = take_string(dtn_app_resolve_contact(h, alias.as_ptr()));
            assert_eq!(resolved, "dtn://alice-node");

            let unknown = CString::new("nobody").unwrap();
            assert!(dtn_app_resolve_contact(h, unknown.as_ptr()).is_null());
            assert!(last_error().contains("unknown contact alias"));

            dtn_app_close(h);
        }
        cleanup(&db);
    }

    #[test]
    fn ffi_send_accepts_bare_node_names_and_rejects_bad_uris() {
        let db = tmp_db("bare");
        unsafe {
            let h = dtn_app_open(4, CString::new(db.as_str()).unwrap().as_ptr(), 0);
            let body = CString::new("hi").unwrap();
            let bare = CString::new("bob").unwrap();
            assert!(dtn_app_send(h, bare.as_ptr(), body.as_ptr(), 3600) >= 0);

            let bad = CString::new("http://not-an-eid").unwrap();
            assert_eq!(dtn_app_send(h, bad.as_ptr(), body.as_ptr(), 3600), -1);
            assert!(last_error().contains("invalid peer EID URI"));

            dtn_app_close(h);
        }
        cleanup(&db);
    }

    #[test]
    fn ffi_null_handle_and_null_strings_are_errors_not_crashes() {
        unsafe {
            assert!(dtn_app_open(1, std::ptr::null(), 0).is_null());
            assert!(last_error().contains("db_path is null"));

            assert_eq!(dtn_app_send(std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), 60), -1);
            assert!(last_error().contains("null app handle"));

            assert!(dtn_app_eid(std::ptr::null_mut()).is_null());
            assert!(dtn_app_poll_inbox(std::ptr::null_mut()).is_null());
            assert!(dtn_app_conversations(std::ptr::null_mut()).is_null());
            assert!(dtn_app_history(std::ptr::null_mut(), std::ptr::null()).is_null());
            assert_eq!(dtn_app_unread_total(std::ptr::null_mut()), -1);
            assert_eq!(dtn_app_mark_read(std::ptr::null_mut(), std::ptr::null()), -1);
            assert_eq!(dtn_app_add_contact(std::ptr::null_mut(), std::ptr::null(), std::ptr::null()), -1);
            assert!(dtn_app_resolve_contact(std::ptr::null_mut(), std::ptr::null()).is_null());

            // Closing NULL is a documented no-op.
            dtn_app_close(std::ptr::null_mut());
            dtn_string_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn ffi_open_fails_for_a_bad_database_path() {
        unsafe {
            // A directory cannot be opened as a SQLite database.
            let dir = std::env::temp_dir().join(format!("dtn-ffi-dir-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let p = CString::new(dir.to_string_lossy().into_owned()).unwrap();
            assert!(dtn_app_open(5, p.as_ptr(), 0).is_null());
            assert!(last_error().contains("error"));
            let _ = std::fs::remove_dir(&dir);
        }
    }

    #[test]
    fn ffi_unknown_strategy_defaults_to_epidemic() {
        let db = tmp_db("strategy");
        unsafe {
            let h = dtn_app_open(6, CString::new(db.as_str()).unwrap().as_ptr(), 99);
            assert!(!h.is_null(), "unknown strategy code falls back to epidemic");
            dtn_app_close(h);
        }
        cleanup(&db);
    }
}
