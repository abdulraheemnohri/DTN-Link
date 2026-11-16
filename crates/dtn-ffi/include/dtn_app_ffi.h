/*
 * dtn_app_ffi.h — C ABI for the DTN-Link platform app engine (dtn-ffi).
 *
 * This is the stable header the platform UI shells (Android/JNI, iOS,
 * Windows, Linux, macOS) compile against. Link with libdtn_ffi
 * (cargo build -p dtn-ffi --release).
 *
 * String protocol:
 *   - Strings returned by dtn_app_eid, dtn_app_poll_inbox,
 *     dtn_app_conversations, dtn_app_history and dtn_app_resolve_contact
 *     are heap-allocated UTF-8 C strings and MUST be released with
 *     dtn_string_free.
 *   - dtn_app_last_error is owned by the library and must NOT be freed.
 *   - NULL return from a string function means failure (or "not found"
 *     for dtn_app_resolve_contact); call dtn_app_last_error for the reason.
 *
 * Error protocol:
 *   - Functions returning -1 / NULL record a message retrievable via
 *     dtn_app_last_error (thread-local, valid until the next FFI call
 *     on the same thread). NULL handle / NULL string arguments are
 *     reported as errors, never dereferenced.
 *
 * JSON shape:
 *   messages:  [{"id":..,"peer":"..","direction":"in|out","body":"..",
 *                "created_at":<unix-seconds>,"bundle_key":".."|null}, ..]
 *   conversations: [{"peer":"..","last_body":"..","last_at":..,
 *                    "unread":..,"total":..}, ..]
 */

#ifndef DTN_APP_FFI_H
#define DTN_APP_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Routing strategy codes for dtn_app_open. */
#define DTN_STRATEGY_EPIDEMIC      0u
#define DTN_STRATEGY_SPRAY_WAIT    1u
#define DTN_STRATEGY_OPPORTUNISTIC 2u

/* Opaque application handle. */
typedef struct dtn_app_handle dtn_app_handle;

/* Lifecycle. */
dtn_app_handle *dtn_app_open(uint64_t node_number, const char *db_path, uint32_t strategy);
void dtn_app_close(dtn_app_handle *handle);

/* Error protocol. Returns the thread-local last error (do NOT free),
 * or NULL when the previous call on this thread succeeded. */
const char *dtn_app_last_error(void);

/* Release a string returned by this library. NULL is a no-op. */
void dtn_string_free(char *s);

/* The local node's EID URI ("dtn://..."), or NULL on error. */
char *dtn_app_eid(dtn_app_handle *handle);

/* Compose a text message. peer_uri accepts "dtn://name", "dtn:none",
 * "ipn:n.s" or a bare node name. Returns the message row id, or -1. */
int64_t dtn_app_send(dtn_app_handle *handle, const char *peer_uri,
                     const char *body, uint64_t lifetime);

/* Drain delivered bundles into conversations. Returns a JSON array of
 * new messages ("[]" when none), or NULL on error. */
char *dtn_app_poll_inbox(dtn_app_handle *handle);

/* Conversation list as a JSON array, most recently active first. */
char *dtn_app_conversations(dtn_app_handle *handle);

/* One conversation's history (peer = EID URI) as a JSON array. */
char *dtn_app_history(dtn_app_handle *handle, const char *peer);

/* Unread badge data. Returns the total unread inbound messages, or -1. */
int64_t dtn_app_unread_total(dtn_app_handle *handle);

/* Mark one conversation read (peer = EID URI). Returns the number of
 * messages changed, or -1. */
int64_t dtn_app_mark_read(dtn_app_handle *handle, const char *peer);

/* Contacts. add returns 1 = created, 0 = updated, -1 = error.
 * resolve returns a newly allocated EID URI, or NULL when the alias is
 * unknown (check dtn_app_last_error) or on error. */
int32_t dtn_app_add_contact(dtn_app_handle *handle, const char *alias, const char *eid);
char *dtn_app_resolve_contact(dtn_app_handle *handle, const char *alias);

#ifdef __cplusplus
}
#endif

#endif /* DTN_APP_FFI_H */
