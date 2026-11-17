/*
 * dtn_shell.c — DTN-Link desktop shell (Phase 20): an interactive,
 * dependency-free POSIX C terminal chat that embeds the platform app
 * engine through the real C ABI (crates/dtn-ffi, dtn_app_ffi.h).
 *
 * Nothing here is faked: messages are composed through dtn_app_send
 * into the real BPv7 bundle store, delivered through the daemon /
 * gateway / transport-adapter contacts exactly like every other
 * DTN-Link frontend, and read back through dtn_app_poll_inbox,
 * dtn_app_conversations and dtn_app_history.
 *
 * Build (after `cargo build -p dtn-ffi --release`):
 *
 *     make -C shells/desktop
 *
 * Usage:
 *
 *     ./dtn-shell [-n node-number] [-d db-path] [-s strategy]
 *
 * Commands (all start with '/'; a bare line inside a conversation
 * sends a message):
 *
 *     /help                list commands
 *     /me                  local EID + unread badge
 *     /list                conversations with unread badges
 *     /chat <alias|eid>    open a conversation (prints history)
 *     /back                leave the conversation
 *     /msg <alias|eid> <text>
 *     /add <alias> <eid>   add or re-point a contact alias
 *     /read <alias|eid>    mark a conversation read
 *     /unread              total unread
 *     /poll                drain delivered bundles into conversations
 *     /quit
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtn_app_ffi.h"
#include "json.h"

#define DEFAULT_LIFETIME 3600u

static dtn_app_handle *app = NULL;
static char my_eid[512];
static char chat_peer[512];
static int chat_open = 0;

/* ------------------------------------------------------------------ */
/* small string helpers                                               */
/* ------------------------------------------------------------------ */

static void trim(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (unsigned char)s[n - 1] <= ' ') {
        s[--n] = '\0';
    }
    size_t i = 0;
    while (s[i] && (unsigned char)s[i] <= ' ') {
        i++;
    }
    if (i > 0) {
        memmove(s, s + i, n - i + 1);
    }
}

static void print_error(void) {
    const char *e = dtn_app_last_error();
    printf("error: %s\n", e ? e : "(unknown)");
}

static long long ll_of(const char *tok) {
    return tok ? strtoll(tok, NULL, 10) : 0;
}

/* Resolve an alias through the FFI contact book; fall back to the raw
 * argument (a dtn://, ipn: or bare-name EID accepted by dtn_app_send).
 * Returns a malloc'd EID URI or NULL when the argument is empty. */
static char *resolve_peer(const char *arg) {
    if (!arg || !*arg) {
        return NULL;
    }
    char *eid = dtn_app_resolve_contact(app, arg);
    if (eid) {
        return eid; /* malloc'd, must be freed by the caller */
    }
    return strdup(arg); /* last_error may have been set; harmless here */
}

/* ------------------------------------------------------------------ */
/* views over the dtn-ffi JSON shapes                                 */
/* ------------------------------------------------------------------ */

static void render_messages(const char *json) {
    size_t n = dtn_json_count(json);
    for (size_t i = 0; i < n; i++) {
        char *dir = dtn_json_get(json, i, "direction");
        char *body = dtn_json_get(json, i, "body");
        char *peer = dtn_json_get(json, i, "peer");
        int outbound = dir && strcmp(dir, "out") == 0;
        printf("%s %s%s%s\n",
               outbound ? "  you" : "them",
               peer ? peer : "?",
               outbound ? " -> " : "",
               body ? body : "");
        free(dir);
        free(body);
        free(peer);
    }
    if (n == 0) {
        printf("(nothing new)\n");
    }
}

static void cmd_conversations(void) {
    char *json = dtn_app_conversations(app);
    if (!json) {
        print_error();
        return;
    }
    size_t n = dtn_json_count(json);
    if (n == 0) {
        printf("(no conversations yet)\n");
        dtn_string_free(json);
        return;
    }
    printf("%-28s %-12s %s\n", "peer", "unread/total", "last");
    for (size_t i = 0; i < n; i++) {
        char *peer = dtn_json_get(json, i, "peer");
        char *last = dtn_json_get(json, i, "last_body");
        long long unread = ll_of(dtn_json_get(json, i, "unread"));
        long long total = ll_of(dtn_json_get(json, i, "total"));
        char badge[32];
        snprintf(badge, sizeof badge, "%lld/%lld",
                 unread, total);
        printf("%-28s %-12s %s\n",
               peer ? peer : "?", badge, last ? last : "");
        free(peer);
        free(last);
    }
    dtn_string_free(json);
}

static void open_chat(const char *arg) {
    char *eid = resolve_peer(arg);
    if (!eid) {
        printf("chat: peer required (/chat <alias|eid>)\n");
        return;
    }
    snprintf(chat_peer, sizeof chat_peer, "%s", eid);
    chat_open = 1;
    printf("-- conversation with %s (bare lines send; /back leaves) --\n", eid);
    char *json = dtn_app_history(app, eid);
    if (json) {
        render_messages(json);
        dtn_string_free(json);
    } else {
        print_error();
    }
    dtn_app_mark_read(app, eid);
    free(eid);
}

static void send_line(const char *peer_uri, const char *text) {
    if (!text || !*text) {
        return;
    }
    long long id = dtn_app_send(app, peer_uri, text, DEFAULT_LIFETIME);
    if (id < 0) {
        print_error();
    } else {
        printf("queued (bundle row %lld) - carried out on the next contact\n", id);
    }
}

/* ------------------------------------------------------------------ */
/* commands                                                           */
/* ------------------------------------------------------------------ */

static void cmd_help(void) {
    printf("commands:\n"
           "  /me                      local EID + unread badge\n"
           "  /list                    conversations (unread/total, last)\n"
           "  /chat <alias|eid>        open/print a conversation\n"
           "  /back                    leave the open conversation\n"
           "  /msg <alias|eid> <text>  send a message\n"
           "  /add <alias> <eid>       add or re-point a contact alias\n"
           "  /read <alias|eid>        mark a conversation read\n"
           "  /unread                  total unread\n"
           "  /poll                    drain delivered bundles in\n"
           "  /quit                    leave\n"
           "inside a conversation a bare line sends a message.\n");
}

static void handle_command(char *line) {
    char cmd[64];
    const char *rest = "";
    const char *sp = strchr(line, ' ');
    if (sp) {
        size_t n = (size_t)(sp - line);
        if (n >= sizeof cmd) {
            n = sizeof cmd - 1;
        }
        memcpy(cmd, line, n);
        cmd[n] = '\0';
        rest = sp + 1;
        while (*rest == ' ') {
            rest++;
        }
    } else {
        snprintf(cmd, sizeof cmd, "%s", line);
    }

    if (strcmp(cmd, "/help") == 0 || strcmp(cmd, "/?") == 0) {
        cmd_help();
    } else if (strcmp(cmd, "/me") == 0) {
        long long unread = dtn_app_unread_total(app);
        printf("%s | unread: %lld%s\n", my_eid, unread < 0 ? 0 : unread,
               unread < 0 ? " (error)" : "");
    } else if (strcmp(cmd, "/list") == 0) {
        cmd_conversations();
    } else if (strcmp(cmd, "/chat") == 0) {
        open_chat(rest);
    } else if (strcmp(cmd, "/back") == 0) {
        chat_open = 0;
        chat_peer[0] = '\0';
        printf("-- left the conversation --\n");
    } else if (strcmp(cmd, "/msg") == 0) {
        char target[512];
        const char *text = "";
        const char *sp2 = strchr(rest, ' ');
        if (sp2) {
            size_t n = (size_t)(sp2 - rest);
            if (n >= sizeof target) {
                n = sizeof target - 1;
            }
            memcpy(target, rest, n);
            target[n] = '\0';
            text = sp2 + 1;
        } else {
            snprintf(target, sizeof target, "%s", rest);
        }
        char *eid = resolve_peer(target);
        if (!eid) {
            printf("msg: peer required (/msg <alias|eid> <text>)\n");
            return;
        }
        send_line(eid, text);
        free(eid);
    } else if (strcmp(cmd, "/add") == 0) {
        char alias[256];
        const char *eid = "";
        const char *sp2 = strchr(rest, ' ');
        if (sp2) {
            size_t n = (size_t)(sp2 - rest);
            if (n >= sizeof alias) {
                n = sizeof alias - 1;
            }
            memcpy(alias, rest, n);
            alias[n] = '\0';
            eid = sp2 + 1;
        } else {
            snprintf(alias, sizeof alias, "%s", rest);
        }
        if (!alias[0] || !eid[0]) {
            printf("add: /add <alias> <eid>\n");
            return;
        }
        int32_t r = dtn_app_add_contact(app, alias, eid);
        if (r < 0) {
            print_error();
        } else {
            printf("%s: %s -> %s\n", r == 1 ? "added" : "updated", alias, eid);
        }
    } else if (strcmp(cmd, "/read") == 0) {
        char *eid = resolve_peer(rest);
        if (!eid) {
            printf("read: peer required (/read <alias|eid>)\n");
            return;
        }
        long long n = dtn_app_mark_read(app, eid);
        if (n < 0) {
            print_error();
        } else {
            printf("marked %lld message(s) read in %s\n", n, eid);
        }
        free(eid);
    } else if (strcmp(cmd, "/unread") == 0) {
        long long n = dtn_app_unread_total(app);
        if (n < 0) {
            print_error();
        } else {
            printf("unread total: %lld\n", n);
        }
    } else if (strcmp(cmd, "/poll") == 0) {
        char *json = dtn_app_poll_inbox(app);
        if (!json) {
            print_error();
            return;
        }
        render_messages(json);
        dtn_string_free(json);
        long long unread = dtn_app_unread_total(app);
        if (unread > 0) {
            printf("unread total: %lld\n", unread);
        }
    } else if (strcmp(cmd, "/quit") == 0 || strcmp(cmd, "/exit") == 0) {
        chat_open = -1;
    } else {
        printf("unknown command %s — /help lists commands\n", cmd);
    }
}

static void poll_on_start(void) {
    char *json = dtn_app_poll_inbox(app);
    if (json) {
        size_t n = dtn_json_count(json);
        if (n > 0) {
            printf("delivered while offline:\n");
            render_messages(json);
        }
        dtn_string_free(json);
    }
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    uint64_t node_number = 1;
    const char *db_path = "dtn-shell.db";
    uint32_t strategy = DTN_STRATEGY_EPIDEMIC;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            node_number = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            const char *s = argv[++i];
            if (strcmp(s, "epidemic") == 0) {
                strategy = DTN_STRATEGY_EPIDEMIC;
            } else if (strcmp(s, "spray-wait") == 0) {
                strategy = DTN_STRATEGY_SPRAY_WAIT;
            } else if (strcmp(s, "opportunistic") == 0) {
                strategy = DTN_STRATEGY_OPPORTUNISTIC;
            } else {
                fprintf(stderr, "unknown strategy '%s' "
                                "(epidemic|spray-wait|opportunistic)\n", s);
                return 2;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("dtn-shell [-n node-number] [-d db-path] "
                   "[-s epidemic|spray-wait|opportunistic]\n");
            return 0;
        } else {
            db_path = argv[i];
        }
    }

    app = dtn_app_open(node_number, db_path, strategy);
    if (!app) {
        const char *e = dtn_app_last_error();
        fprintf(stderr, "dtn_app_open failed: %s\n", e ? e : "unknown error");
        return 1;
    }

    char *eid = dtn_app_eid(app);
    if (!eid) {
        const char *e = dtn_app_last_error();
        fprintf(stderr, "dtn_app_eid failed: %s\n", e ? e : "unknown error");
        dtn_app_close(app);
        return 1;
    }
    snprintf(my_eid, sizeof my_eid, "%s", eid);
    dtn_string_free(eid);

    printf("DTN-Link shell — node %s (db %s)\n", my_eid, db_path);
    printf("type /help for commands; messages wait in the store until the "
           "next contact (that is DTN, not a bug)\n");
    poll_on_start();

    char *line = NULL;
    size_t cap = 0;
    int interactive = isatty(0);
    if (interactive) {
        printf("dtn> ");
        fflush(stdout);
    }
    ssize_t got;
    while ((got = getline(&line, &cap, stdin)) >= 0) {
        trim(line);
        if (line[0] == '\0') {
            if (interactive) {
                printf(chat_open ? "%s> " : "dtn> ",
                       chat_open ? chat_peer : my_eid);
                fflush(stdout);
            }
            continue;
        }
        if (line[0] == '/') {
            handle_command(line);
            if (chat_open == -1) {
                break;
            }
        } else if (chat_open == 1) {
            send_line(chat_peer, line);
        } else {
            printf("no conversation open — /chat <alias|eid> to start or "
                   "/msg <alias|eid> <text>\n");
        }
        if (interactive) {
            printf(chat_open ? "%s> " : "dtn> ",
                   chat_open ? chat_peer : my_eid);
            fflush(stdout);
        }
    }
    free(line);
    dtn_app_close(app);
    return 0;
}
