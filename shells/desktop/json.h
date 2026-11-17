/*
 * json.h — minimal reader for the flat JSON arrays emitted by dtn-ffi.
 *
 * dtn-ffi returns its chat state as arrays of flat objects whose fields
 * are strings, numbers or null (see crates/dtn-ffi/include/dtn_app_ffi.h
 * and docs/ffi.md). This header exposes just enough of a reader for the
 * desktop shell and the FFI self test — decoding, not validating: the
 * producer is dtn-ffi's own (tested) JSON emitter.
 */

#ifndef DTN_SHELL_JSON_H
#define DTN_SHELL_JSON_H

#include <stddef.h>

/* Number of top-level objects in `arr` ("[]" -> 0, malformed -> 0). */
size_t dtn_json_count(const char *arr);

/* Value of field `field` in top-level item `idx` (0-based). Returns a
 * malloc'd C string — the decoded UTF-8 text for string values, the raw
 * token ("123", "true") for scalars, or the literal "null" — or NULL
 * when the object/field is absent or out of memory. NULL input is OK
 * (returns NULL). The caller frees the result. */
char *dtn_json_get(const char *arr, size_t idx, const char *field);

#endif /* DTN_SHELL_JSON_H */
