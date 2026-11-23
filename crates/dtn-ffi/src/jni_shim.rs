//! dtn-ffi jni_shim — Android JNI bindings over the dtn-ffi C ABI (Phase 21).
//!
//! Compiled only with the cargo feature `jni` (Android builds pass
//! `--features jni`). The Kotlin side lives in `shells/android` and is
//! `package link.dtn.shell`, class `Native` (a Kotlin object), so every
//! exported symbol uses the JNI short name
//! `Java_link_dtn_shell_Native_<method>` (no method is overloaded).
//!
//! The shim contains zero owning logic of its own: it translates
//! Java strings and the handle long into the C ABI arguments and calls
//! the existing `dtn_app_*` functions from the crate root, so the
//! error protocol (`dtn_app_last_error`), NULL handling and memory
//! ownership (`dtn_string_free`) are the exact tested Phase 19/20
//! behaviors. Returning NULL to Java maps "failure" and "not found"
//! to Java null, which the Kotlin wrapper resolves through
//! `Native.lastError()`.
//!
//! Handle convention: a non-null `dtn_app_handle*` is transported to
//! Java as its address; zero means NULL (not open / closed).

#![allow(clippy::missing_safety_doc)]

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Transport a handle back to Java (0 = NULL).
fn handle_to_java(p: *mut crate::AppHandle) -> jlong {
    if p.is_null() {
        0
    } else {
        p as usize as jlong
    }
}

/// Recover a handle from Java (0 -> NULL); the C ABI reports every NULL
/// handle as an error, never dereferences it.
fn handle_from_java(h: jlong) -> *mut crate::AppHandle {
    if h <= 0 {
        std::ptr::null_mut()
    } else {
        h as usize as *mut crate::AppHandle
    }
}

/// Read a Java string into a NUL-terminated C string, recording the
/// conventional last-error on any JNI/conversion failure.
fn cstr_arg(env: &mut JNIEnv, js: &JString, what: &str) -> Option<CString> {
    match env.get_string(js) {
        Ok(j) => match CString::new(j.to_string_lossy().into_owned()) {
            Ok(cs) => Some(cs),
            Err(_) => {
                crate::set_last_error(format!("{what} contains an interior NUL"));
                None
            }
        },
        Err(e) => {
            crate::set_last_error(format!("{what} is not a valid Java string: {e}"));
            None
        }
    }
}

/// Take ownership of a C string returned by the library. Returns None
/// for NULL (which Kotlin observes as Java null).
unsafe fn take_owned(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    crate::dtn_string_free(p);
    Some(s)
}

/// Wrap a Rust string as a Java string; JNI failure surfaces as null so
/// the wrapper reads `Native.lastError()`.
fn to_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(j) => j.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Java `long -> u64` conversion: negative node numbers / lifetimes are
/// caller bugs, clamp to 0 instead of wrapping into huge u64 values.
fn u64_arg(v: jlong) -> u64 {
    if v <= 0 {
        0
    } else {
        v as u64
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_open(
    mut env: JNIEnv,
    _thiz: JClass,
    node_number: jlong,
    db_path: JString,
    strategy: jint,
) -> jlong {
    let Some(path) = cstr_arg(&mut env, &db_path, "db_path") else {
        return 0;
    };
    // Unknown / out-of-range strategy codes are normalized to epidemic
    // by the C ABI (tested in Phase 19); keep the same behavior.
    unsafe {
        handle_to_java(crate::dtn_app_open(
            u64_arg(node_number),
            path.as_ptr(),
            strategy as u32,
        ))
    }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_close(_env: JNIEnv, _thiz: JClass, handle: jlong) {
    unsafe { crate::dtn_app_close(handle_from_java(handle)) };
}

// ---------------------------------------------------------------------------
// Messaging surface
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_eid(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
) -> jstring {
    match unsafe { crate::dtn_app_eid(handle_from_java(handle)) } {
        p if p.is_null() => std::ptr::null_mut(),
        p => {
            let owned = unsafe { take_owned(p) };
            match owned {
                Some(s) => to_jstring(&mut env, &s),
                None => std::ptr::null_mut(),
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_send(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
    peer: JString,
    body: JString,
    lifetime: jlong,
) -> jlong {
    let (Some(peer), Some(body)) = (
        cstr_arg(&mut env, &peer, "peer"),
        cstr_arg(&mut env, &body, "body"),
    ) else {
        return -1;
    };
    unsafe {
        crate::dtn_app_send(
            handle_from_java(handle),
            peer.as_ptr(),
            body.as_ptr(),
            u64_arg(lifetime),
        )
    }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_pollInbox(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
) -> jstring {
    match unsafe { crate::dtn_app_poll_inbox(handle_from_java(handle)) } {
        p if p.is_null() => std::ptr::null_mut(),
        p => {
            let owned = unsafe { take_owned(p) };
            match owned {
                Some(s) => to_jstring(&mut env, &s),
                None => std::ptr::null_mut(),
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_conversations(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
) -> jstring {
    match unsafe { crate::dtn_app_conversations(handle_from_java(handle)) } {
        p if p.is_null() => std::ptr::null_mut(),
        p => {
            let owned = unsafe { take_owned(p) };
            match owned {
                Some(s) => to_jstring(&mut env, &s),
                None => std::ptr::null_mut(),
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_history(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
    peer: JString,
) -> jstring {
    let Some(peer) = cstr_arg(&mut env, &peer, "peer") else {
        return std::ptr::null_mut();
    };
    match unsafe { crate::dtn_app_history(handle_from_java(handle), peer.as_ptr()) } {
        p if p.is_null() => std::ptr::null_mut(),
        p => {
            let owned = unsafe { take_owned(p) };
            match owned {
                Some(s) => to_jstring(&mut env, &s),
                None => std::ptr::null_mut(),
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_unreadTotal(
    _env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
) -> jlong {
    unsafe { crate::dtn_app_unread_total(handle_from_java(handle)) }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_markRead(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
    peer: JString,
) -> jlong {
    let Some(peer) = cstr_arg(&mut env, &peer, "peer") else {
        return -1;
    };
    unsafe { crate::dtn_app_mark_read(handle_from_java(handle), peer.as_ptr()) }
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_addContact(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
    alias: JString,
    eid: JString,
) -> jint {
    let (Some(alias), Some(eid)) = (
        cstr_arg(&mut env, &alias, "alias"),
        cstr_arg(&mut env, &eid, "eid"),
    ) else {
        return -1;
    };
    unsafe { crate::dtn_app_add_contact(handle_from_java(handle), alias.as_ptr(), eid.as_ptr()) }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_resolveContact(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
    alias: JString,
) -> jstring {
    let Some(alias) = cstr_arg(&mut env, &alias, "alias") else {
        return std::ptr::null_mut();
    };
    match unsafe { crate::dtn_app_resolve_contact(handle_from_java(handle), alias.as_ptr()) } {
        p if p.is_null() => std::ptr::null_mut(),
        p => {
            let owned = unsafe { take_owned(p) };
            match owned {
                Some(s) => to_jstring(&mut env, &s),
                None => std::ptr::null_mut(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Receipts + attachments (Phase 26, over the same C ABI entry points)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_sendFile(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
    peer: JString,
    path: JString,
    lifetime: jlong,
) -> jlong {
    let (Some(peer), Some(path)) = (
        cstr_arg(&mut env, &peer, "peer"),
        cstr_arg(&mut env, &path, "path"),
    ) else {
        return -1;
    };
    unsafe {
        crate::dtn_app_send_file(
            handle_from_java(handle),
            peer.as_ptr(),
            path.as_ptr(),
            u64_arg(lifetime),
        )
    }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_extractAttachment(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
    message_id: jlong,
    dest_dir: JString,
) -> jstring {
    let Some(dest_dir) = cstr_arg(&mut env, &dest_dir, "dest_dir") else {
        return std::ptr::null_mut();
    };
    match unsafe {
        crate::dtn_app_extract_attachment(handle_from_java(handle), message_id, dest_dir.as_ptr())
    } {
        p if p.is_null() => std::ptr::null_mut(),
        p => {
            let owned = unsafe { take_owned(p) };
            match owned {
                Some(s) => to_jstring(&mut env, &s),
                None => std::ptr::null_mut(),
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_sendReadReceipts(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
    peer: JString,
    lifetime: jlong,
) -> jlong {
    let Some(peer) = cstr_arg(&mut env, &peer, "peer") else {
        return -1;
    };
    unsafe {
        crate::dtn_app_send_read_receipts(
            handle_from_java(handle),
            peer.as_ptr(),
            u64_arg(lifetime),
        )
    }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_messageConfirmed(
    _env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
    message_id: jlong,
) -> jlong {
    unsafe { crate::dtn_app_message_confirmed(handle_from_java(handle), message_id) }
}

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_pollInboxWithReceipts(
    mut env: JNIEnv,
    _thiz: JClass,
    handle: jlong,
) -> jstring {
    match unsafe { crate::dtn_app_poll_inbox_with_receipts(handle_from_java(handle)) } {
        p if p.is_null() => std::ptr::null_mut(),
        p => {
            let owned = unsafe { take_owned(p) };
            match owned {
                Some(s) => to_jstring(&mut env, &s),
                None => std::ptr::null_mut(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Error protocol
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_link_dtn_shell_Native_lastError(
    mut env: JNIEnv,
    _thiz: JClass,
) -> jstring {
    // The last-error pointer is library-owned and MUST NOT be freed.
    let p = crate::dtn_app_last_error();
    if p.is_null() {
        return std::ptr::null_mut();
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    to_jstring(&mut env, &s)
}
