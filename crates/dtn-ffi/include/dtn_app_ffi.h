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

/* Read receipts (Phase 26). send acknowledges every inbound message of
 * peer_uri not yet receipted (one DTNR1 bundle; 0 = nothing pending,
 * no bundle created) and returns the acknowledged count, or -1.
 * confirmed returns 1 / 0 for one outbound message's confirmed-read
 * state, or -1 on error. */
int64_t dtn_app_send_read_receipts(dtn_app_handle *handle, const char *peer_uri,
                                   uint64_t lifetime);
int64_t dtn_app_message_confirmed(dtn_app_handle *handle, int64_t message_id);

/* Drain delivered bundles AND apply arriving read receipts (Phase 26).
 * Returns a JSON object
 *   {"messages":[...],"receipts":[{"from":"..","acked_at":..,
 *                                 "confirmed":<out-rows-confirmed>}, ..]}
 * or NULL on error. Receipts never become chat rows. */
char *dtn_app_poll_inbox_with_receipts(dtn_app_handle *handle);

/* Attachments (Phase 26). send_file queues a real file as one DTNA1
 * bundle and returns the message row id, or -1. extract_attachment
 * writes the stored bytes of one message byte-for-byte into dest_dir
 * (stored filename re-validated) and returns a newly allocated path
 * (free with dtn_string_free), or NULL on error (unknown message id,
 * no attachment, unsafe stored name). */
int64_t dtn_app_send_file(dtn_app_handle *handle, const char *peer_uri,
                          const char *path, uint64_t lifetime);
char *dtn_app_extract_attachment(dtn_app_handle *handle, int64_t message_id,
                                 const char *dest_dir);

#ifdef __cplusplus
}
#endif

#endif /* DTN_APP_FFI_H */
