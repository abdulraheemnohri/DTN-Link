// dtn_app_ffi.h — kept in sync with crates/dtn-ffi/include/dtn_app_ffi.h.
// Copy here so CDtnFfi builds standalone without a parent-path include.
#ifndef DTN_APP_FFI_H
#define DTN_APP_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DTN_STRATEGY_EPIDEMIC      0u
#define DTN_STRATEGY_SPRAY_WAIT    1u
#define DTN_STRATEGY_OPPORTUNISTIC 2u

typedef struct dtn_app_handle dtn_app_handle;

dtn_app_handle *dtn_app_open(uint64_t node_number, const char *db_path, uint32_t strategy);
void dtn_app_close(dtn_app_handle *handle);
const char *dtn_app_last_error(void);
void dtn_string_free(char *s);
char *dtn_app_eid(dtn_app_handle *handle);
int64_t dtn_app_send(dtn_app_handle *handle, const char *peer_uri,
                     const char *body, uint64_t lifetime);
char *dtn_app_poll_inbox(dtn_app_handle *handle);
char *dtn_app_conversations(dtn_app_handle *handle);
char *dtn_app_history(dtn_app_handle *handle, const char *peer);
int64_t dtn_app_unread_total(dtn_app_handle *handle);
int64_t dtn_app_mark_read(dtn_app_handle *handle, const char *peer);
int32_t dtn_app_add_contact(dtn_app_handle *handle, const char *alias, const char *eid);
char *dtn_app_resolve_contact(dtn_app_handle *handle, const char *alias);

#ifdef __cplusplus
}
#endif

#endif /* DTN_APP_FFI_H */
