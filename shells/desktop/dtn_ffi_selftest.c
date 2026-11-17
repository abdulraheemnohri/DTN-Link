/*
 * dtn_ffi_selftest.c — Phase 20 self test: the desktop shell's entire
 * FFI surface exercised end-to-end against the real libdtn_ffi engine,
 * the same way the shell calls it. Run via `make -C shells/desktop test`.
 *
 * Covers (via the public C ABI only — no Rust internals):
 *   - lifecycle: open / close / eid
 *   - contacts: add (created vs updated), resolve, unknown-alias error
 *   - messaging: send queues bundles (row ids grow), conversations list,
 *     unread badge (outbound is born read), poll idempotency ("[]")
 *   - error protocol: NULL handle / NULL strings / bad EID URI are
 *     reported errors, never crashes
 *   - persistence: reopen the same db keeps contacts + messages
 *
 * Inbound delivery is covered by the Rust-side dtn-ffi tests (which
 * carry a real bundle between two node engines); the ABI alone can't
 * move a bundle between two processes.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtn_app_ffi.h"
#include "json.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        checks++;                                                           \
        if (cond) {                                                         \
            printf("PASS: %s\n", msg);                                      \
        } else {                                                            \
            printf("FAIL: %s\n", msg);                                      \
            failures++;                                                     \
        }                                                                   \
    } while (0)

static char *take(char *p) {
    if (!p) {
        return NULL;
    }
    return p; /* ownership moved; caller frees */
}

static const char *last_error(void) {
    const char *e = dtn_app_last_error();
    return e ? e : "(no error recorded)";
}

static void cleanup_db(const char *path) {
    remove(path);
    char sidecar[512];
    snprintf(sidecar, sizeof sidecar, "%s.app", path);
    remove(sidecar);
    snprintf(sidecar, sizeof sidecar, "%s.key", path);
    remove(sidecar);
}

static void temp_db(char *out, size_t n, const char *tag) {
    snprintf(out, n, "/tmp/dtn-selftest-%s-%d.db", tag, (int)getpid());
    cleanup_db(out);
}

int main(void) {
    char dba[512], dbb[512];
    temp_db(dba, sizeof dba, "a");
    temp_db(dbb, sizeof dbb, "b");

    /* ---- error protocol on open ------------------------------------ */
    CHECK(dtn_app_open(1, NULL, 0) == NULL,
          "open with NULL db_path fails without crashing");

    /* ---- lifecycle -------------------------------------------------- */
    dtn_app_handle *a = dtn_app_open(101, dba, DTN_STRATEGY_EPIDEMIC);
    CHECK(a != NULL, "open node A (epidemic) succeeds");
    dtn_app_handle *b = dtn_app_open(102, dbb, DTN_STRATEGY_SPRAY_WAIT);
    CHECK(b != NULL, "open node B (spray-wait) succeeds");

    char *eid_a = take(dtn_app_eid(a));
    char *eid_b = take(dtn_app_eid(b));
    CHECK(eid_a && strncmp(eid_a, "dtn://", 6) == 0 && strlen(eid_a) > 6,
          "node A EID URI starts with dtn://");
    CHECK(eid_b && strncmp(eid_b, "dtn://", 6) == 0 && strlen(eid_b) > 6,
          "node B EID URI starts with dtn://");
    CHECK(eid_a && eid_b && strcmp(eid_a, eid_b) != 0, "A and B EIDs differ");

    /* ---- contacts --------------------------------------------------- */
    CHECK(dtn_app_add_contact(a, "b", eid_b) == 1, "adding contact 'b' returns created");
    CHECK(dtn_app_add_contact(a, "b", eid_b) == 0, "re-adding contact 'b' returns updated");
    char *resolved = take(dtn_app_resolve_contact(a, "b"));
    CHECK(resolved && eid_b && strcmp(resolved, eid_b) == 0,
          "resolving 'b' yields B's EID URI");
    free(resolved);
    CHECK(dtn_app_resolve_contact(a, "nobody") == NULL &&
              strstr(last_error(), "unknown contact alias") != NULL,
          "unknown alias resolves NULL with a recorded error");

    /* ---- messaging: send queues real bundles ------------------------ */
    long long m1 = dtn_app_send(a, eid_b, "first message from the shell", 3600);
    CHECK(m1 >= 0, "send to B's EID returns a message row id");
    long long m2 = dtn_app_send(a, "b", "second message via alias", 3600);
    CHECK(m2 >= 0 && m2 != m1, "send by alias resolves and returns a new row id");
    CHECK(dtn_app_send(a, "http://not-an-eid", "x", 3600) == -1 &&
              strstr(last_error(), "invalid peer EID URI") != NULL,
          "invalid EID URI is rejected with a recorded error");

    /* ---- conversations / unread / poll ------------------------------ */
    char *convs = take(dtn_app_conversations(a));
    CHECK(convs && dtn_json_count(convs) == 1, "A lists exactly one conversation");
    long long unread = dtn_app_unread_total(a);
    CHECK(unread == 0, "outbound messages are born read (unread == 0)");
    for (size_t i = 0; convs && i < dtn_json_count(convs); i++) {
        char *peer = dtn_json_get(convs, i, "peer");
        char *total = dtn_json_get(convs, i, "total");
        CHECK(peer && eid_b && strcmp(peer, eid_b) == 0,
              "conversation is with B's EID");
        CHECK(total && strcmp(total, "2") == 0, "conversation total == 2");
        char *body = dtn_json_get(convs, i, "last_body");
        CHECK(body && strcmp(body, "second message via alias") == 0,
              "conversation last_body is the latest message");
        free(peer);
        free(total);
        free(body);
    }
    free(convs);

    char *inbox = take(dtn_app_poll_inbox(a));
    CHECK(inbox && strcmp(inbox, "[]") == 0, "poll with no inbound bundles returns []");
    free(inbox);

    /* ---- error protocol --------------------------------------------- */
    CHECK(dtn_app_send(NULL, eid_b, "x", 60) == -1 &&
              strstr(last_error(), "null app handle") != NULL,
          "NULL handle reports an error, never crashes");
    CHECK(dtn_app_send(a, NULL, "x", 60) == -1,
          "NULL peer reports an error, never crashes");
    CHECK(dtn_app_eid(NULL) == NULL, "eid of NULL handle is NULL");
    CHECK(dtn_app_conversations(NULL) == NULL,
          "conversations of NULL handle is NULL");
    CHECK(dtn_app_history(NULL, eid_b) == NULL,
          "history of NULL handle is NULL");
    CHECK(dtn_app_unread_total(NULL) == -1, "unread of NULL handle is -1");
    CHECK(dtn_app_mark_read(NULL, eid_b) == -1, "mark_read of NULL handle is -1");
    CHECK(dtn_app_add_contact(NULL, "x", "y") == -1,
          "add_contact of NULL handle is -1");
    CHECK(dtn_app_resolve_contact(NULL, "b") == NULL,
          "resolve of NULL handle is NULL");
    CHECK(dtn_app_mark_read(a, "dtn://never-talked") == 0,
          "mark_read on an empty conversation changes nothing");
    dtn_app_close(NULL);
    dtn_string_free(NULL);
    CHECK(1, "close(NULL) and dtn_string_free(NULL) are no-ops");

    /* ---- persistence across reopen ---------------------------------- */
    free(eid_a);
    free(eid_b);
    dtn_app_close(a);
    dtn_app_close(b);
    dtn_app_handle *a2 = dtn_app_open(101, dba, DTN_STRATEGY_EPIDEMIC);
    CHECK(a2 != NULL, "reopening A's database succeeds");
    char *convs2 = take(dtn_app_conversations(a2));
    size_t n2 = convs2 ? dtn_json_count(convs2) : 0;
    int persisted = 0;
    if (n2 == 1) {
        char *tot = dtn_json_get(convs2, 0, "total");
        persisted = tot && strcmp(tot, "2") == 0;
        free(tot);
    }
    CHECK(persisted, "reopened A still has the conversation (messages persisted)");
    for (size_t i = 0; i < n2; i++) {
        free(dtn_json_get(convs2, i, "peer"));
    }
    char *resolved2 = take(dtn_app_resolve_contact(a2, "b"));
    CHECK(resolved2 && strlen(resolved2) > 6, "reopened A still resolves contact 'b'");
    free(resolved2);
    free(convs2);
    dtn_app_close(a2);

    cleanup_db(dba);
    cleanup_db(dbb);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    if (failures) {
        printf("dtn-ffi self test FAILED\n");
        return 1;
    }
    printf("dtn-ffi self test OK\n");
    return 0;
}
