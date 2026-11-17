/*
 * json.c — minimal JSON array reader for the dtn-ffi wire shapes.
 *
 * Scope (deliberately small, matching docs/ffi.md):
 *   - input is an array of FLAT objects: [ {"k":"v","n":1,NULLS}, ... ]
 *   - values: JSON strings (full escape decoding incl. \uXXXX with
 *     surrogate pairs), numbers/true/false as raw tokens, null
 *   - the producer is dtn-ffi's own tested emitter; malformed input
 *     fails closed (fewer items / NULL fields), never crashes
 */

#include "json.h"

#include <stdlib.h>
#include <string.h>

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    return p;
}

static char *dup_token(const char *s, size_t n) {
    char *out = malloc(n + 1);
    if (out) {
        memcpy(out, s, n);
        out[n] = '\0';
    }
    return out;
}

/* p points at the opening quote. Returns a pointer just past the
 * closing quote, or NULL on an unterminated/invalid string. */
static const char *skip_string(const char *p) {
    p++; /* opening quote */
    while (*p) {
        if (*p == '\\') {
            if (p[1] == 'u') {
                /* \uXXXX: 4 hex digits (surrogate halves checked by the
                 * decoder, not here — skipping works either way). */
                p += 2;
                int hex = 0;
                while (hex < 4 && *p) {
                    char c = *p;
                    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F')) {
                        p++;
                        hex++;
                    } else {
                        return NULL;
                    }
                }
                if (hex != 4) {
                    return NULL;
                }
            } else if (p[1]) {
                p += 2;
            } else {
                return NULL;
            }
        } else if (*p == '"') {
            return p + 1;
        } else {
            p++;
        }
    }
    return NULL;
}

static int push_byte(char **out, size_t *len, size_t *cap, char c) {
    if (*len + 1 >= *cap) {
        size_t nc = *cap * 2;
        char *g = realloc(*out, nc);
        if (!g) {
            return 0;
        }
        *out = g;
        *cap = nc;
    }
    (*out)[(*len)++] = c;
    return 1;
}

static int push_hex4(const char **p, unsigned *cp) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = (*p)[i];
        v <<= 4;
        if (c >= '0' && c <= '9') {
            v |= (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v |= (unsigned)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v |= (unsigned)(c - 'A' + 10);
        } else {
            return 0;
        }
    }
    *p += 4;
    *cp = v;
    return 1;
}

/* Encode one code point as UTF-8 into out; returns bytes appended. */
static int push_utf8(char **out, size_t *len, size_t *cap, unsigned cp) {
    if (cp <= 0x7F) {
        return push_byte(out, len, cap, (char)cp);
    }
    if (cp <= 0x7FF) {
        if (!push_byte(out, len, cap, (char)(0xC0 | (cp >> 6)))) return 0;
        return push_byte(out, len, cap, (char)(0x80 | (cp & 0x3F)));
    }
    if (cp <= 0xFFFF) {
        if (!push_byte(out, len, cap, (char)(0xE0 | (cp >> 12)))) return 0;
        if (!push_byte(out, len, cap, (char)(0x80 | ((cp >> 6) & 0x3F)))) return 0;
        return push_byte(out, len, cap, (char)(0x80 | (cp & 0x3F)));
    }
    if (!push_byte(out, len, cap, (char)(0xF0 | (cp >> 18)))) return 0;
    if (!push_byte(out, len, cap, (char)(0x80 | ((cp >> 12) & 0x3F)))) return 0;
    if (!push_byte(out, len, cap, (char)(0x80 | ((cp >> 6) & 0x3F)))) return 0;
    return push_byte(out, len, cap, (char)(0x80 | (cp & 0x3F)));
}

/* Decode a JSON string; `*p` points at the opening quote. Returns a
 * fresh malloc'd C string and advances `*p` past the closing quote,
 * or NULL on error. */
static char *decode_string(const char **p) {
    const char *s = *p + 1;
    size_t cap = 64, len = 0;
    char *out = malloc(cap);
    if (!out) {
        return NULL;
    }
    while (*s != '"') {
        unsigned char c = (unsigned char)*s;
        if (c == '\0') {
            goto fail; /* unterminated */
        }
        if (c != '\\') {
            if (!push_byte(&out, &len, &cap, (char)c)) {
                goto fail;
            }
            s++;
            continue;
        }
        /* escape */
        s++;
        switch (*s) {
        case '"': if (!push_byte(&out, &len, &cap, '"')) goto fail; break;
        case '\\': if (!push_byte(&out, &len, &cap, '\\')) goto fail; break;
        case '/': if (!push_byte(&out, &len, &cap, '/')) goto fail; break;
        case 'n': if (!push_byte(&out, &len, &cap, '\n')) goto fail; break;
        case 'r': if (!push_byte(&out, &len, &cap, '\r')) goto fail; break;
        case 't': if (!push_byte(&out, &len, &cap, '\t')) goto fail; break;
        case 'b': if (!push_byte(&out, &len, &cap, '\b')) goto fail; break;
        case 'f': if (!push_byte(&out, &len, &cap, '\f')) goto fail; break;
        case 'u': {
            s++;
            unsigned cp;
            if (!push_hex4(&s, &cp)) {
                goto fail;
            }
            if (cp >= 0xD800 && cp <= 0xDBFF && s[0] == '\\' && s[1] == 'u') {
                const char *la = s + 2;
                unsigned lo;
                if (push_hex4(&la, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    s = la;
                }
            }
            if (!push_utf8(&out, &len, &cap, cp)) {
                goto fail;
            }
            break;
        }
        default:
            goto fail;
        }
        s++;
    }
    *p = s + 1;
    out[len] = '\0';
    return out;
fail:
    free(out);
    return NULL;
}

/* p points at '{'. Returns a pointer just past the matching '}',
 * treating braces inside strings as content. NULL on malformed input. */
static const char *skip_object(const char *p) {
    int depth = 0;
    while (*p) {
        if (*p == '"') {
            p = skip_string(p);
            if (!p) {
                return NULL;
            }
            continue;
        }
        if (*p == '{' || *p == '[') {
            depth++;
        } else if (*p == '}' || *p == ']') {
            depth--;
            if (depth == 0) {
                return p + 1;
            }
            if (depth < 0) {
                return NULL;
            }
        }
        p++;
    }
    return NULL;
}

/* p points at the array opener '['. Finds the start of the idx-th
 * top-level object; NULL when it does not exist. */
static const char *object_start(const char *p, size_t idx) {
    p = skip_ws(p);
    if (*p != '[') {
        return NULL;
    }
    p++;
    size_t seen = 0;
    while (1) {
        p = skip_ws(p);
        if (*p == '\0') {
            return NULL;
        }
        if (*p == ']') {
            return NULL;
        }
        if (*p != '{') {
            return NULL;
        }
        if (seen == idx) {
            return p;
        }
        seen++;
        p = skip_object(p);
        if (!p) {
            return NULL;
        }
        p = skip_ws(p);
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p == ']') {
            return NULL;
        }
        return NULL;
    }
}

size_t dtn_json_count(const char *arr) {
    if (!arr) {
        return 0;
    }
    const char *p = skip_ws(arr);
    if (*p != '[') {
        return 0;
    }
    size_t n = 0;
    p++;
    while (1) {
        p = skip_ws(p);
        if (*p != '{') {
            return n;
        }
        p = skip_object(p);
        if (!p) {
            return n;
        }
        n++;
        p = skip_ws(p);
        if (*p == ',') {
            p++;
            continue;
        }
        return n;
    }
}

char *dtn_json_get(const char *arr, size_t idx, const char *field) {
    if (!arr || !field || !*field) {
        return NULL;
    }
    const char *obj = object_start(arr, idx);
    if (!obj) {
        return NULL;
    }
    const char *end = skip_object(obj);
    if (!end) {
        return NULL;
    }
    size_t flen = strlen(field);
    char *pat = malloc(flen + 3);
    if (!pat) {
        return NULL;
    }
    pat[0] = '"';
    memcpy(pat + 1, field, flen);
    pat[flen + 1] = '"';
    pat[flen + 2] = '\0';

    const char *q = obj + 1;
    while (q < end) {
        const char *hit = strstr(q, pat);
        if (!hit || hit >= end) {
            break;
        }
        const char *v = skip_ws(hit + flen + 2);
        if (*v == ':') {
            v = skip_ws(v + 1);
            free(pat);
            if (*v == '"') {
                return decode_string(&v);
            }
            if (*v == 'n' && strncmp(v, "null", 4) == 0) {
                return dup_token("null", 4);
            }
            /* number / true / false: raw token up to a delimiter */
            const char *t = v;
            while (*t && *t != ',' && *t != '}' && *t != ']' &&
                   *t != ' ' && *t != '\t' && *t != '\n' && *t != '\r') {
                t++;
            }
            if (t == v) {
                return NULL;
            }
            return dup_token(v, (size_t)(t - v));
        }
        q = hit + 1;
    }
    free(pat);
    return NULL;
}
