/* jsdom: QuickJS bindings over the browser DOM tree, see jsdom.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "jsdom.h"

long jsdom_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* ---------------- serializer (innerHTML/outerHTML) ---------------- */

static void ser_esc(const char *s, char **b, size_t *len, size_t *cap) {
    for (; *s; s++) {
        const char *e = NULL;
        if (*s == '&') e = "&amp;";
        else if (*s == '<') e = "&lt;";
        else if (*s == '>') e = "&gt;";
        size_t el = e ? strlen(e) : 1;
        while (*len + el + 1 > *cap) {
            *cap *= 2;
            char *nb = realloc(*b, *cap);
            if (!nb) return;
            *b = nb;
        }
        if (e) {
            memcpy(*b + *len, e, el);
            *len += el;
        } else {
            (*b)[(*len)++] = *s;
        }
    }
}

static void ser_node(struct dom_node *n, char **b, size_t *len, size_t *cap);

static void ser_put(const char *s, size_t n, char **b, size_t *len, size_t *cap) {
    while (*len + n + 1 > *cap) {
        *cap *= 2;
        char *nb = realloc(*b, *cap);
        if (!nb) return;
        *b = nb;
    }
    memcpy(*b + *len, s, n);
    *len += n;
}

static void ser_node(struct dom_node *n, char **b, size_t *len, size_t *cap) {
    if (!n) return;
    if (n->text) {
        ser_esc(n->text, b, len, cap);
        return;
    }
    ser_put("<", 1, b, len, cap);
    ser_put(n->name, strlen(n->name), b, len, cap);
    for (int i = 0; i < n->nattrs; i++) {
        ser_put(" ", 1, b, len, cap);
        ser_put(n->attrs[i].name, strlen(n->attrs[i].name), b, len, cap);
        ser_put("=\"", 2, b, len, cap);
        ser_esc(n->attrs[i].value, b, len, cap);
        ser_put("\"", 1, b, len, cap);
    }
    ser_put(">", 1, b, len, cap);
    for (int i = 0; i < n->nkids; i++) ser_node(n->kids[i], b, len, cap);
    /* Void elements have no close tag. */
    const char *nm = n->name;
    if (!(strcmp(nm, "img") == 0 || strcmp(nm, "br") == 0 || strcmp(nm, "input") == 0 ||
          strcmp(nm, "meta") == 0 || strcmp(nm, "link") == 0 || strcmp(nm, "hr") == 0)) {
        ser_put("</", 2, b, len, cap);
        ser_put(n->name, strlen(n->name), b, len, cap);
        ser_put(">", 1, b, len, cap);
    }
}

static char *serialize_kids(struct dom_node *n) {
    size_t cap = 512, len = 0;
    char *b = malloc(cap);
    if (!b) return NULL;
    for (int i = 0; i < n->nkids; i++) ser_node(n->kids[i], &b, &len, &cap);
    b[len] = '\0';
    return b;
}

/* ---------------- page state ---------------- */

struct js_timer {
    int id;
    long deadline;
    long interval; /* 0 = once */
    JSValue fn;
};

struct js_listener {
    struct dom_node *node; /* NULL = window */
    char type[16];
    JSValue fn;
};

struct jsdom_page {
    JSContext *ctx;
    struct dom_doc *doc;
    char url[512];
    struct js_timer timers[JSDOM_MAX_TIMERS];
    int ntimers;
    int next_id;
    struct js_listener listeners[JSDOM_MAX_LISTENERS];
    int nlisteners;
};

static struct jsdom_page *cur_page(JSContext *ctx) {
    return JS_GetContextOpaque(ctx);
}

/* ---------------- Element class ---------------- */

static JSClassID element_class_id;

static struct dom_node *this_node(JSContext *ctx, JSValueConst v) {
    return JS_GetOpaque(v, element_class_id);
}

static JSValue mk_element(JSContext *ctx, struct dom_node *n) {
    if (!n) return JS_NULL;
    JSValue o = JS_NewObjectClass(ctx, (int)element_class_id);
    if (JS_IsException(o)) return o;
    JS_SetOpaque(o, n);
    return o;
}

static JSValue el_get_id(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    struct dom_node *n = this_node(ctx, self);
    const char *v = n ? dom_attr(n, "id") : NULL;
    return JS_NewString(ctx, v ? v : "");
}

static JSValue el_set_attr(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv);

static JSValue el_set_id(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    if (argc < 1) return JS_UNDEFINED;
    struct dom_node *n = this_node(ctx, self);
    const char *v = JS_ToCString(ctx, argv[0]);
    if (n && v) {
        /* Reuse the attribute setter path. */
        JSValue av[2];
        av[0] = JS_NewString(ctx, "id");
        av[1] = JS_NewString(ctx, v);
        el_set_attr(ctx, self, 2, av);
        JS_FreeValue(ctx, av[0]);
        JS_FreeValue(ctx, av[1]);
    }
    JS_FreeCString(ctx, v);
    return JS_UNDEFINED;
}

static JSValue el_get_tag(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    struct dom_node *n = this_node(ctx, self);
    if (!n || n->text) return JS_NewString(ctx, "");
    char up[32];
    size_t i = 0;
    for (; n->name[i] && i + 1 < sizeof(up); i++)
        up[i] = (char)toupper((unsigned char)n->name[i]);
    up[i] = '\0';
    return JS_NewString(ctx, up);
}

static JSValue el_get_attr(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    if (argc < 1) return JS_NULL;
    struct dom_node *n = this_node(ctx, self);
    const char *an = JS_ToCString(ctx, argv[0]);
    const char *v = (n && an) ? dom_attr(n, an) : NULL;
    JSValue r = v ? JS_NewString(ctx, v) : JS_NULL;
    JS_FreeCString(ctx, an);
    return r;
}

static JSValue el_set_attr(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    if (argc < 2) return JS_UNDEFINED;
    struct dom_node *n = this_node(ctx, self);
    const char *an = JS_ToCString(ctx, argv[0]);
    const char *av = JS_ToCString(ctx, argv[1]);
    if (n && an && av) {
        for (int i = 0; i < n->nattrs; i++) {
            if (strcasecmp(n->attrs[i].name, an) == 0) {
                char *nv = malloc(strlen(av) + 1);
                if (nv) {
                    strcpy(nv, av);
                    free(n->attrs[i].value);
                    n->attrs[i].value = nv;
                }
                JS_FreeCString(ctx, an);
                JS_FreeCString(ctx, av);
                return JS_UNDEFINED;
            }
        }
        struct dom_attr *na = realloc(n->attrs, sizeof(*na) * (size_t)(n->nattrs + 1));
        if (na) {
            n->attrs = na;
            n->attrs[n->nattrs].name = malloc(strlen(an) + 1);
            n->attrs[n->nattrs].value = malloc(strlen(av) + 1);
            if (n->attrs[n->nattrs].name && n->attrs[n->nattrs].value) {
                strcpy(n->attrs[n->nattrs].name, an);
                strcpy(n->attrs[n->nattrs].value, av);
                n->nattrs++;
            } else {
                free(n->attrs[n->nattrs].name);
                free(n->attrs[n->nattrs].value);
            }
        }
    }
    JS_FreeCString(ctx, an);
    JS_FreeCString(ctx, av);
    return JS_UNDEFINED;
}

static JSValue el_inner_html(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    struct dom_node *n = this_node(ctx, self);
    if (!n) return JS_NewString(ctx, "");
    char *s = serialize_kids(n);
    JSValue r = JS_NewString(ctx, s ? s : "");
    free(s);
    return r;
}

static JSValue el_set_inner_html(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    if (argc < 1) return JS_UNDEFINED;
    struct dom_node *n = this_node(ctx, self);
    const char *s = JS_ToCString(ctx, argv[0]);
    if (n && s && !n->text) {
        /* Replacement nodes leak if JS still wraps them; freeing would
         * dangle live wrappers, so detached subtrees are intentionally
         * left for process exit (pages are short-lived). */
        struct dom_doc *frag = dom_parse(s);
        if (frag && frag->root) {
            for (int i = 0; i < n->nkids; i++) {
                /* detach only */
                n->kids[i]->parent = NULL;
            }
            free(n->kids);
            n->kids = frag->root->kids;
            n->nkids = frag->root->nkids;
            for (int i = 0; i < n->nkids; i++)
                if (n->kids[i]) n->kids[i]->parent = n;
            frag->root->kids = NULL;
            frag->root->nkids = 0;
            dom_free(frag);
        }
    }
    JS_FreeCString(ctx, s);
    return JS_UNDEFINED;
}

static JSValue el_text_content(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    struct dom_node *n = this_node(ctx, self);
    if (!n) return JS_NewString(ctx, "");
    char *s = dom_text_content(n);
    JSValue r = JS_NewString(ctx, s ? s : "");
    free(s);
    return r;
}

static JSValue el_set_text_content(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    if (argc < 1) return JS_UNDEFINED;
    struct dom_node *n = this_node(ctx, self);
    const char *s = JS_ToCString(ctx, argv[0]);
    if (n && s && !n->text) {
        for (int i = 0; i < n->nkids; i++) {
            n->kids[i]->parent = NULL; /* leak detached, see above */
        }
        free(n->kids);
        n->kids = NULL;
        n->nkids = 0;
        struct dom_node *t = dom_text(s);
        if (t) dom_append(n, t);
    }
    JS_FreeCString(ctx, s);
    return JS_UNDEFINED;
}

static JSValue el_append_child(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    if (argc < 1) return JS_NULL;
    struct dom_node *parent = this_node(ctx, self);
    struct dom_node *child = this_node(ctx, argv[0]);
    if (!parent || !child || parent->text) return JS_NULL;
    /* Detach from the old parent first. */
    if (child->parent) {
        struct dom_node *op = child->parent;
        for (int i = 0; i < op->nkids; i++) {
            if (op->kids[i] == child) {
                memmove(op->kids + i, op->kids + i + 1,
                        sizeof(*op->kids) * (size_t)(op->nkids - i - 1));
                op->nkids--;
                break;
            }
        }
        child->parent = NULL;
    }
    dom_append(parent, child);
    return JS_DupValue(ctx, argv[0]);
}

static JSValue el_add_listener(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    if (argc < 2) return JS_UNDEFINED;
    struct jsdom_page *pg = cur_page(ctx);
    const char *type = JS_ToCString(ctx, argv[0]);
    if (pg && type && JS_IsFunction(ctx, argv[1]) && pg->nlisteners < JSDOM_MAX_LISTENERS) {
        pg->listeners[pg->nlisteners].node = this_node(ctx, self);
        snprintf(pg->listeners[pg->nlisteners].type,
                 sizeof(pg->listeners[0].type), "%.15s", type);
        pg->listeners[pg->nlisteners].fn = JS_DupValue(ctx, argv[1]);
        pg->nlisteners++;
    }
    JS_FreeCString(ctx, type);
    return JS_UNDEFINED;
}

static void fire_listeners(struct jsdom_page *pg, struct dom_node *node, const char *type) {
    JSContext *ctx = pg->ctx;
    for (int i = 0; i < pg->nlisteners; i++) {
        if (pg->listeners[i].node == node && strcmp(pg->listeners[i].type, type) == 0) {
            JSValue target = node ? mk_element(ctx, node) : JS_GetGlobalObject(ctx);
            JSValue r = JS_Call(ctx, pg->listeners[i].fn, target, 0, NULL);
            JS_FreeValue(ctx, r);
            JS_FreeValue(ctx, target);
            if (JS_HasException(ctx)) {
                JSValue ex = JS_GetException(ctx);
                JS_FreeValue(ctx, ex);
            }
        }
    }
}

static JSValue el_click(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    struct jsdom_page *pg = cur_page(ctx);
    if (pg) fire_listeners(pg, this_node(ctx, self), "click");
    return JS_UNDEFINED;
}

/* ---------------- selectors (#id, .class, tag, tag.class, chains) ---------------- */

static int node_matches(struct dom_node *n, const char *sel) {
    if (!n || n->text) return 0;
    if (sel[0] == '#') {
        const char *v = dom_attr(n, "id");
        return v && strcmp(v, sel + 1) == 0;
    }
    char tag[32] = {0}, cls[32] = {0};
    const char *dot = strchr(sel, '.');
    if (dot) {
        size_t tl = (size_t)(dot - sel);
        if (tl >= sizeof(tag)) return 0;
        memcpy(tag, sel, tl);
        snprintf(cls, sizeof(cls), "%s", dot + 1);
    } else if (sel[0] == '.') {
        snprintf(cls, sizeof(cls), "%s", sel + 1);
    } else {
        snprintf(tag, sizeof(tag), "%s", sel);
    }
    if (tag[0] && strcasecmp(n->name, tag) != 0) return 0;
    if (cls[0]) {
        const char *c = dom_attr(n, "class");
        if (!c) return 0;
        /* Whitespace-separated class list. */
        char buf[128];
        snprintf(buf, sizeof(buf), "%.127s", c);
        for (char *t = strtok(buf, " \t"); t; t = strtok(NULL, " \t"))
            if (strcmp(t, cls) == 0) return 1;
        return 0;
    }
    return 1;
}

/* Rightmost selector must match n; earlier parts match some ancestor chain. */
static int node_matches_chain(struct dom_node *n, const char **parts, int nparts) {
    if (nparts <= 0 || !node_matches(n, parts[nparts - 1])) return 0;
    struct dom_node *a = n->parent;
    for (int i = nparts - 2; i >= 0; i--) {
        while (a && !node_matches(a, parts[i])) a = a->parent;
        if (!a) return 0;
        a = a->parent;
    }
    return 1;
}

static void qs_walk(struct dom_node *n, const char **parts, int nparts,
                    struct dom_node **out, int cap, int *nfound, int first) {
    if (!n || *nfound >= cap) return;
    if (n != NULL && n->parent && node_matches_chain(n, parts, nparts)) {
        out[(*nfound)++] = n;
        if (first) return;
    }
    for (int i = 0; i < n->nkids && *nfound < cap; i++) {
        qs_walk(n->kids[i], parts, nparts, out, cap, nfound, first);
        if (first && *nfound) return;
    }
}

/* Splits on spaces (max 4 parts). Returns part count. */
static int split_sel(const char *sel, const char **parts) {
    static char buf[160];
    snprintf(buf, sizeof(buf), "%.159s", sel);
    int n = 0;
    for (char *t = strtok(buf, " \t"); t && n < 4; t = strtok(NULL, " \t"))
        parts[n++] = t;
    return n;
}

static JSValue doc_query(JSContext *ctx, int all, int argc, JSValueConst *argv, struct dom_node *scope) {
    struct jsdom_page *pg = cur_page(ctx);
    if (argc < 1 || !pg) return all ? JS_NewArray(ctx) : JS_NULL;
    const char *sel = JS_ToCString(ctx, argv[0]);
    JSValue r = all ? JS_NewArray(ctx) : JS_NULL;
    if (sel) {
        const char *parts[4];
        int np = split_sel(sel, (const char **)parts);
        struct dom_node *found[64];
        int nfound = 0;
        if (scope) {
            for (int i = 0; i < scope->nkids; i++)
                qs_walk(scope->kids[i], parts, np, found, 64, &nfound, !all);
        } else {
            qs_walk(pg->doc->root, parts, np, found, 64, &nfound, !all);
        }
        if (all) {
            /* Stores consume (see set_value): do NOT free after. */
            for (int i = 0; i < nfound; i++)
                JS_SetPropertyUint32(ctx, r, (uint32_t)i, mk_element(ctx, found[i]));
        } else if (nfound > 0) {
            r = mk_element(ctx, found[0]);
        }
    }
    JS_FreeCString(ctx, sel);
    return r;
}

static JSValue doc_query_selector(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    return doc_query(ctx, 0, argc, argv, NULL);
}

static JSValue doc_query_all(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    return doc_query(ctx, 1, argc, argv, NULL);
}

static JSValue el_query_selector(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    return doc_query(ctx, 0, argc, argv, this_node(ctx, self));
}

static JSValue el_query_all(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    return doc_query(ctx, 1, argc, argv, this_node(ctx, self));
}

static JSValue doc_by_id(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    struct jsdom_page *pg = cur_page(ctx);
    if (argc < 1 || !pg) return JS_NULL;
    const char *id = JS_ToCString(ctx, argv[0]);
    struct dom_node *n = id ? dom_by_id(pg->doc, id) : NULL;
    JS_FreeCString(ctx, id);
    return mk_element(ctx, n);
}

static JSValue doc_by_tag(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    struct jsdom_page *pg = cur_page(ctx);
    JSValue arr = JS_NewArray(ctx);
    if (argc < 1 || !pg) return arr;
    const char *tag = JS_ToCString(ctx, argv[0]);
    if (tag) {
        struct dom_node *found[64];
        int n = dom_by_tag(pg->doc, tag, found, 64);
        /* dom_by_tag only handles known tags; unknown fall back to walk. */
        if (n == 0) {
            const char *parts[1] = {tag};
            int nfound = 0;
            qs_walk(pg->doc->root, parts, 1, found, 64, &nfound, 0);
            n = nfound;
        }
        for (int i = 0; i < n; i++)
            JS_SetPropertyUint32(ctx, arr, (uint32_t)i, mk_element(ctx, found[i]));
    }
    JS_FreeCString(ctx, tag);
    return arr;
}

static JSValue doc_create(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    if (argc < 1) return JS_NULL;
    const char *tag = JS_ToCString(ctx, argv[0]);
    struct dom_node *n = tag ? dom_element(tag) : NULL;
    JS_FreeCString(ctx, tag);
    /* Unattached nodes leak at page free (see innerHTML note). */
    return mk_element(ctx, n);
}

static struct dom_node *find_body(struct dom_doc *doc) {
    if (!doc) return NULL;
    struct dom_node *found[1] = {0};
    int nfound = 0;
    const char *parts[1] = {"body"};
    qs_walk(doc->root, parts, 1, found, 1, &nfound, 1);
    return nfound ? found[0] : NULL;
}

static JSValue doc_write(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    struct jsdom_page *pg = cur_page(ctx);
    if (!pg) return JS_UNDEFINED;
    struct dom_node *body = find_body(pg->doc);
    if (!body) body = pg->doc->root;
    for (int i = 0; i < argc; i++) {
        const char *s = JS_ToCString(ctx, argv[i]);
        if (s) {
            struct dom_doc *frag = dom_parse(s);
            if (frag && frag->root) {
                for (int k = 0; k < frag->root->nkids; k++)
                    dom_append(body, frag->root->kids[k]);
                /* frag shell keeps no kids now; free wrapper only. */
                free(frag->root->kids);
                frag->root->kids = NULL;
                frag->root->nkids = 0;
                dom_free(frag);
            }
        }
        JS_FreeCString(ctx, s);
    }
    return JS_UNDEFINED;
}

static JSValue doc_title(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    (void)self;
    struct jsdom_page *pg = cur_page(ctx);
    if (!pg) return JS_NewString(ctx, "");
    struct dom_node *found[1] = {0};
    int nfound = 0;
    const char *parts[1] = {"title"};
    qs_walk(pg->doc->root, parts, 1, found, 1, &nfound, 1);
    if (!nfound) return JS_NewString(ctx, "");
    char *t = dom_text_content(found[0]);
    JSValue r = JS_NewString(ctx, t ? t : "");
    free(t);
    return r;
}

/* ---------------- timers ---------------- */

static JSValue win_timeout(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv, int repeat) {
    (void)self;
    struct jsdom_page *pg = cur_page(ctx);
    if (argc < 1 || !pg || !JS_IsFunction(ctx, argv[0])) return JS_NewInt32(ctx, 0);
    int ms = 0;
    if (argc >= 2) JS_ToInt32(ctx, &ms, argv[1]);
    if (ms < 0) ms = 0;
    if (pg->ntimers >= JSDOM_MAX_TIMERS) return JS_NewInt32(ctx, 0);
    /* next_id starts at 1; ids only grow within a page. */
    if (!pg->next_id) pg->next_id = 1;
    int id = pg->next_id++;
    pg->timers[pg->ntimers].id = id;
    pg->timers[pg->ntimers].deadline = jsdom_now_ms() + ms;
    pg->timers[pg->ntimers].interval = repeat ? (ms ? ms : 1) : 0;
    pg->timers[pg->ntimers].fn = JS_DupValue(ctx, argv[0]);
    pg->ntimers++;
    return JS_NewInt32(ctx, id);
}

static JSValue win_set_timeout(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    return win_timeout(ctx, self, argc, argv, 0);
}

static JSValue win_set_interval(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    return win_timeout(ctx, self, argc, argv, 1);
}

static JSValue win_clear(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    struct jsdom_page *pg = cur_page(ctx);
    if (argc < 1 || !pg) return JS_UNDEFINED;
    int id = 0;
    JS_ToInt32(ctx, &id, argv[0]);
    for (int i = 0; i < pg->ntimers; i++) {
        if (pg->timers[i].id == id) {
            JS_FreeValue(ctx, pg->timers[i].fn);
            memmove(pg->timers + i, pg->timers + i + 1,
                    sizeof(*pg->timers) * (size_t)(pg->ntimers - i - 1));
            pg->ntimers--;
            break;
        }
    }
    return JS_UNDEFINED;
}

/* ---------------- synchronous XHR (own socket stack) ---------------- */

#include "resolve.h"
#include "tls.h"

/* Splits scheme://host[:port][/path]. Returns 0 ok. */
static int split_url(const char *url, char *host, size_t hcap, int *port, int *secure,
                     char *path, size_t pcap) {
    const char *p = url;
    *secure = 0;
    if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        *secure = 1;
        *port = 443;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        *port = 80;
    } else {
        return -1;
    }
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t hlen;
    if (colon && (!slash || colon < slash)) {
        hlen = (size_t)(colon - p);
        *port = atoi(colon + 1);
        if (*port <= 0 || *port > 65535) return -1;
    } else {
        hlen = slash ? (size_t)(slash - p) : strlen(p);
    }
    if (hlen == 0 || hlen >= hcap) return -1;
    memcpy(host, p, hlen);
    host[hlen] = '\0';
    snprintf(path, pcap, "%s", slash ? slash : "/");
    return 0;
}

/* Decodes chunked bodies in place; returns decoded length. */
static size_t xh_dechunk(char *b, size_t n) {
    size_t ri = 0, wi = 0;
    while (ri < n) {
        char *e = memchr(b + ri, '\n', n - ri);
        if (!e) break;
        unsigned long sz = strtoul(b + ri, NULL, 16);
        ri = (size_t)(e + 1 - b);
        if (sz == 0) break;
        if (ri + sz > n) break;
        memmove(b + wi, b + ri, sz);
        wi += sz;
        ri += sz;
        if (ri + 2 <= n && b[ri] == '\r' && b[ri + 1] == '\n') ri += 2;
        else if (ri < n && b[ri] == '\n') ri += 1;
    }
    return wi;
}

struct xhr_state {
    char method[8];
    char url[512];
    int status;
    char *text; /* response body, NUL-terminated */
};

static JSClassID xhr_class_id;

static struct xhr_state *xhr_this(JSContext *ctx, JSValueConst v) {
    return JS_GetOpaque(v, xhr_class_id);
}

static JSValue xhr_open(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    struct xhr_state *x = xhr_this(ctx, self);
    if (!x || argc < 2) return JS_UNDEFINED;
    const char *m = JS_ToCString(ctx, argv[0]);
    const char *u = JS_ToCString(ctx, argv[1]);
    if (m) snprintf(x->method, sizeof(x->method), "%.7s", m);
    if (u) snprintf(x->url, sizeof(x->url), "%.511s", u);
    JS_FreeCString(ctx, m);
    JS_FreeCString(ctx, u);
    return JS_UNDEFINED;
}

static void xhr_call_handler(JSContext *ctx, JSValue obj, const char *prop) {
    JSValue fn = JS_GetPropertyStr(ctx, obj, prop);
    if (JS_IsFunction(ctx, fn)) {
        JSValue r = JS_Call(ctx, fn, obj, 0, NULL);
        JS_FreeValue(ctx, r);
        if (JS_HasException(ctx)) {
            JSValue ex = JS_GetException(ctx);
            JS_FreeValue(ctx, ex);
        }
    }
    JS_FreeValue(ctx, fn);
}

static JSValue xhr_send(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    struct xhr_state *x = xhr_this(ctx, self);
    if (!x || !x->url[0]) return JS_UNDEFINED;
    char host[256], path[512];
    int port = 0, secure = 0;
    x->status = 0;
    free(x->text);
    x->text = NULL;
    if (split_url(x->url, host, sizeof(host), &port, &secure, path, sizeof(path)) < 0)
        return JS_UNDEFINED;
    struct in_addr addr;
    if (resolve_host(host, &addr) < 0) {
        fprintf(stderr, "xhr: resolve %s\n", host);
        return JS_UNDEFINED;
    }
    int fd = tcp_connect_timeout(&addr, port, 10000);
    if (fd < 0) {
        fprintf(stderr, "xhr: connect %s:%d: %s\n", host, port, strerror(errno));
        return JS_UNDEFINED;
    }
    struct tls_ctx tls;
    memset(&tls, 0, sizeof(tls));
    char err[128] = {0};
    if (secure && tls_handshake(fd, host, &tls, err, sizeof(err)) < 0) {
        close(fd);
        return JS_UNDEFINED;
    }
    char req[1024];
    snprintf(req, sizeof(req),
             "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: myos-xhr\r\nConnection: close\r\n\r\n",
             x->method[0] ? x->method : "GET", path, host);
    size_t left = strlen(req);
    const char *p = req;
    int ok = 1;
    while (left > 0) {
        ssize_t n = secure ? tls_write(&tls, p, left) : send(fd, p, left, 0);
        if (n <= 0) {
            ok = 0;
            break;
        }
        p += n;
        left -= (size_t)n;
    }
    static char buf[65536];
    size_t got = 0;
    if (ok) {
        for (;;) {
            char tmp[4096];
            ssize_t n = secure ? tls_read(&tls, tmp, sizeof(tmp))
                               : recv(fd, tmp, sizeof(tmp), 0);
            if (n <= 0) break;
            if (got + (size_t)n >= sizeof(buf)) break;
            memcpy(buf + got, tmp, (size_t)n);
            got += (size_t)n;
        }
    }
    tls_free(&tls);
    close(fd);
    if (!ok || got == 0) return JS_UNDEFINED;
    buf[got] = '\0';
    /* Status + body split + chunked decode. */
    {
        int code = 0;
        if (sscanf((char *)buf, "HTTP/%*d.%*d %d", &code) == 1) x->status = code;
        char *sep = strstr(buf, "\r\n\r\n");
        char *bstart = sep ? sep + 4 : buf;
        size_t blen = got - (size_t)(bstart - buf);
        int chunked = 0;
        if (sep) {
            char save = *sep;
            *sep = '\0';
            chunked = strcasestr(buf, "transfer-encoding") && strcasestr(buf, "chunked");
            *sep = save;
        }
        if (chunked) blen = xh_dechunk(bstart, blen);
        x->text = malloc(blen + 1);
        if (x->text) {
            memcpy(x->text, bstart, blen);
            x->text[blen] = '\0';
        }
    }
    JSValue self_rw;
    memcpy(&self_rw, &self, sizeof(self_rw));
    xhr_call_handler(ctx, self_rw, "onreadystatechange");
    xhr_call_handler(ctx, self_rw, "onload");
    /* Drain sync-resolved promise jobs so .then chains observe. */
    {
        JSContext *pctx = NULL;
        while (JS_ExecutePendingJob(JS_GetRuntime(ctx), &pctx) > 0) {}
    }
    return JS_UNDEFINED;
}

static JSValue xhr_ctor(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    (void)argc;
    (void)argv;
    struct xhr_state *x = calloc(1, sizeof(*x));
    if (!x) return JS_EXCEPTION;
    JSValue o = JS_NewObjectClass(ctx, (int)xhr_class_id);
    if (JS_IsException(o)) {
        free(x);
        return o;
    }
    JS_SetOpaque(o, x);
    return o;
}

static void xhr_finalizer(JSRuntime *rt, JSValue v) {
    struct xhr_state *x = JS_GetOpaque(v, xhr_class_id);
    (void)rt;
    if (x) {
        free(x->text);
        free(x);
    }
}

static JSValue xhr_status(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    struct xhr_state *x = xhr_this(ctx, self);
    return JS_NewInt32(ctx, x ? x->status : 0);
}

static JSValue xhr_text(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    struct xhr_state *x = xhr_this(ctx, self);
    return JS_NewString(ctx, (x && x->text) ? x->text : "");
}

static JSValue xhr_state_get(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    (void)self;
    (void)ctx;
    return JS_NewInt32(ctx, 4); /* sync only: always done after send */
}

/* ---------------- install ---------------- */

static void set_fn(JSContext *ctx, JSValue obj, const char *name, JSCFunction *fn, int len) {
    JSValue f = JS_NewCFunction(ctx, fn, name, len);
    JS_SetPropertyStr(ctx, obj, name, f);
}

static void set_getset(JSContext *ctx, JSValue obj, const char *name,
                       JSCFunction *get, JSCFunction *set) {
    JSAtom atom = JS_NewAtom(ctx, name);
    JS_DefinePropertyGetSet(ctx, obj, atom,
                            get ? JS_NewCFunction(ctx, get, name, 0) : JS_UNDEFINED,
                            set ? JS_NewCFunction(ctx, set, name, 1) : JS_UNDEFINED,
                            JS_PROP_CONFIGURABLE);
    JS_FreeAtom(ctx, atom);
}

static JSValue doc_body(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    (void)self;
    struct jsdom_page *pg = cur_page(ctx);
    if (!pg) return JS_NULL;
    return mk_element(ctx, find_body(pg->doc));
}

static JSValue doc_first_tag(JSContext *ctx, const char *tag) {
    struct jsdom_page *pg = cur_page(ctx);
    if (!pg) return JS_NULL;
    struct dom_node *found[1] = {0};
    int nfound = 0;
    const char *parts[1] = {tag};
    qs_walk(pg->doc->root, parts, 1, found, 1, &nfound, 1);
    return nfound ? mk_element(ctx, found[0]) : JS_NULL;
}

static JSValue doc_element(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    (void)self;
    return doc_first_tag(ctx, "html");
}

static JSValue doc_head(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)argc;
    (void)argv;
    (void)self;
    return doc_first_tag(ctx, "head");
}

static JSValue doc_add_listener(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    struct jsdom_page *pg = cur_page(ctx);
    if (argc < 2 || !pg) return JS_UNDEFINED;
    const char *type = JS_ToCString(ctx, argv[0]);
    if (type && JS_IsFunction(ctx, argv[1]) && pg->nlisteners < JSDOM_MAX_LISTENERS) {
        pg->listeners[pg->nlisteners].node = NULL;
        snprintf(pg->listeners[pg->nlisteners].type,
                 sizeof(pg->listeners[0].type), "%.15s", type);
        pg->listeners[pg->nlisteners].fn = JS_DupValue(ctx, argv[1]);
        pg->nlisteners++;
    }
    JS_FreeCString(ctx, type);
    return JS_UNDEFINED;
}

static JSValue js_console_log(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    for (int i = 0; i < argc; i++) {
        const char *s = JS_ToCString(ctx, argv[i]);
        if (i) putchar(' ');
        fputs(s ? s : "null", stdout);
        JS_FreeCString(ctx, s);
    }
    putchar('\n');
    return JS_UNDEFINED;
}

static JSRuntime *shared_rt = NULL;

static void register_classes(JSRuntime *rt) {
    JS_NewClassID(&element_class_id);
    JSClassDef el_def = {
        .class_name = "Element",
    };
    JS_NewClass(rt, element_class_id, &el_def);
    JS_NewClassID(&xhr_class_id);
    JSClassDef xhr_def = {
        .class_name = "XMLHttpRequest",
        .finalizer = xhr_finalizer,
    };
    JS_NewClass(rt, xhr_class_id, &xhr_def);
}

struct jsdom_page *jsdom_run(struct dom_doc *doc, const char *url, char *err, size_t errcap) {
    if (!shared_rt) {
        shared_rt = JS_NewRuntime();
        if (!shared_rt) {
            snprintf(err, errcap, "no runtime");
            return NULL;
        }
        register_classes(shared_rt);
    }
    JSContext *ctx = JS_NewContext(shared_rt);
    if (!ctx) {
        snprintf(err, errcap, "no context");
        return NULL;
    }
    struct jsdom_page *pg = calloc(1, sizeof(*pg));
    if (!pg) {
        JS_FreeContext(ctx);
        snprintf(err, errcap, "oom");
        return NULL;
    }
    pg->ctx = ctx;
    pg->doc = doc;
    snprintf(pg->url, sizeof(pg->url), "%s", url ? url : "");
    JS_SetContextOpaque(ctx, pg);

    JSValue global = JS_GetGlobalObject(ctx);

    /* Element prototype. */
    JSValue el_proto = JS_NewObject(ctx);
    set_getset(ctx, el_proto, "id", el_get_id, el_set_id);
    set_getset(ctx, el_proto, "tagName", el_get_tag, NULL);
    set_getset(ctx, el_proto, "innerHTML", el_inner_html, el_set_inner_html);
    set_getset(ctx, el_proto, "textContent", el_text_content, el_set_text_content);
    set_fn(ctx, el_proto, "getAttribute", el_get_attr, 1);
    set_fn(ctx, el_proto, "setAttribute", el_set_attr, 2);
    set_fn(ctx, el_proto, "appendChild", el_append_child, 1);
    set_fn(ctx, el_proto, "addEventListener", el_add_listener, 2);
    set_fn(ctx, el_proto, "click", el_click, 0);
    set_fn(ctx, el_proto, "querySelector", el_query_selector, 1);
    set_fn(ctx, el_proto, "querySelectorAll", el_query_all, 1);
    /* SetClassProto keeps the object itself: do NOT free (it lives as
     * long as the runtime, which is the process here). */
    JS_SetClassProto(ctx, element_class_id, el_proto);

    /* XHR prototype + constructor. */
    JSValue xhr_proto = JS_NewObject(ctx);
    set_getset(ctx, xhr_proto, "status", xhr_status, NULL);
    set_getset(ctx, xhr_proto, "responseText", xhr_text, NULL);
    set_getset(ctx, xhr_proto, "readyState", xhr_state_get, NULL);
    set_fn(ctx, xhr_proto, "open", xhr_open, 3);
    set_fn(ctx, xhr_proto, "send", xhr_send, 1);
    JS_SetClassProto(ctx, xhr_class_id, xhr_proto);
    JSValue xhr_ctor_fn = JS_NewCFunction2(ctx, (JSCFunction *)xhr_ctor, "XMLHttpRequest",
                                           0, JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, global, "XMLHttpRequest", xhr_ctor_fn);

    /* document. */
    JSValue document = JS_NewObject(ctx);
    set_fn(ctx, document, "getElementById", doc_by_id, 1);
    set_fn(ctx, document, "getElementsByTagName", doc_by_tag, 1);
    set_fn(ctx, document, "querySelector", doc_query_selector, 1);
    set_fn(ctx, document, "querySelectorAll", doc_query_all, 1);
    set_fn(ctx, document, "createElement", doc_create, 1);
    set_fn(ctx, document, "write", doc_write, 1);
    set_fn(ctx, document, "writeln", doc_write, 1);
    set_fn(ctx, document, "addEventListener", doc_add_listener, 2);
    {
        /* String-valued properties pages sniff before use. */
        JSValue c = JS_NewString(ctx, "");
        JS_SetPropertyStr(ctx, document, "cookie", c);
        JSValue rs = JS_NewString(ctx, "complete");
        JS_SetPropertyStr(ctx, document, "readyState", rs);
        JSValue curl = JS_NewString(ctx, pg->url);
        JS_SetPropertyStr(ctx, document, "URL", curl);
        JSValue ref = JS_NewString(ctx, "");
        JS_SetPropertyStr(ctx, document, "referrer", ref);
    }
    set_getset(ctx, document, "title", doc_title, NULL);
    set_getset(ctx, document, "body", doc_body, NULL);
    set_getset(ctx, document, "documentElement", doc_element, NULL);
    set_getset(ctx, document, "head", doc_head, NULL);
    JS_SetPropertyStr(ctx, global, "document", document);

    /* window bits live on the global object. */
    set_fn(ctx, global, "setTimeout", win_set_timeout, 2);
    set_fn(ctx, global, "clearTimeout", win_clear, 1);
    set_fn(ctx, global, "setInterval", win_set_interval, 2);
    set_fn(ctx, global, "clearInterval", win_clear, 1);
    set_fn(ctx, global, "addEventListener", doc_add_listener, 2);
    {
        JSValue loc = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, loc, "href", JS_NewString(ctx, pg->url));
        JS_SetPropertyStr(ctx, global, "location", loc);
        JSValue nav = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, nav, "userAgent",
                          JS_NewString(ctx, "myos-jsdom/1.0"));
        JS_SetPropertyStr(ctx, nav, "language", JS_NewString(ctx, "en-US"));
        JS_SetPropertyStr(ctx, nav, "platform", JS_NewString(ctx, "Linux x86_64"));
        JSValue langs = JS_NewArray(ctx);
        JS_SetPropertyUint32(ctx, langs, 0, JS_NewString(ctx, "en-US"));
        JS_SetPropertyStr(ctx, nav, "languages", langs);
        JS_SetPropertyStr(ctx, global, "navigator", nav);
        JSValue scr = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, scr, "width", JS_NewInt32(ctx, 1280));
        JS_SetPropertyStr(ctx, scr, "height", JS_NewInt32(ctx, 800));
        JS_SetPropertyStr(ctx, global, "screen", scr);
        JS_SetPropertyStr(ctx, global, "innerWidth", JS_NewInt32(ctx, 640));
        JS_SetPropertyStr(ctx, global, "innerHeight", JS_NewInt32(ctx, 480));
        JS_SetPropertyStr(ctx, global, "devicePixelRatio", JS_NewInt32(ctx, 1));
        JSValue console = JS_NewObject(ctx);
        set_fn(ctx, console, "log", js_console_log, 1);
        JS_SetPropertyStr(ctx, global, "console", console);
        JS_SetPropertyStr(ctx, global, "window", JS_DupValue(ctx, global));
    }

    /* Run every script body in order; pump sync-resolved jobs between. */
    {
        const char **ss = NULL;
        int ns = dom_scripts(doc, &ss);
        for (int i = 0; i < ns; i++) {
            JSValue v = JS_Eval(ctx, ss[i], strlen(ss[i]), "<script>", JS_EVAL_TYPE_GLOBAL);
            if (JS_IsException(v)) {
                /* One bad script must not kill the rest: report each
                 * failure (browsers log them all) and carry on. */
                {
                    JSValue ex = JS_GetException(ctx);
                    const char *s = JS_ToCString(ctx, ex);
                    JSValue st = JS_GetPropertyStr(ctx, ex, "stack");
                    const char *stack = NULL;
                    if (!JS_IsUndefined(st)) stack = JS_ToCString(ctx, st);
                    fprintf(stderr, "browser: js script %d: %.80s || %.120s\n", i,
                            s ? s : "script error", stack ? stack : "");
                    if (!err[0])
                        snprintf(err, errcap, "%.100s", s ? s : "script error");
                    JS_FreeCString(ctx, s);
                    if (stack) JS_FreeCString(ctx, stack);
                    JS_FreeValue(ctx, st);
                    JS_FreeValue(ctx, ex);
                }
                JS_FreeValue(ctx, v);
            } else {
                JS_FreeValue(ctx, v);
            }
            free((void *)ss[i]);
            ss[i] = NULL;
            JSContext *pctx = NULL;
            while (JS_ExecutePendingJob(JS_GetRuntime(ctx), &pctx) > 0) {}
        }
        free(ss);
    }
    /* DOMContentLoaded, then load. */
    fire_listeners(pg, NULL, "DOMContentLoaded");
    fire_listeners(pg, NULL, "load");
    {
        JSContext *pctx = NULL;
        while (JS_ExecutePendingJob(JS_GetRuntime(ctx), &pctx) > 0) {}
    }
    JS_FreeValue(ctx, global);
    return pg;
}

int jsdom_poll(struct jsdom_page *pg) {
    if (!pg) return 0;
    int ran = 0;
    long now = jsdom_now_ms();
    for (int i = 0; i < pg->ntimers; i++) {
        if (now >= pg->timers[i].deadline) {
            int fid = pg->timers[i].id;
            JSValue fn = JS_DupValue(pg->ctx, pg->timers[i].fn);
            if (pg->timers[i].interval) {
                pg->timers[i].deadline = now + pg->timers[i].interval;
            } else {
                JS_FreeValue(pg->ctx, pg->timers[i].fn);
                memmove(pg->timers + i, pg->timers + i + 1,
                        sizeof(*pg->timers) * (size_t)(pg->ntimers - i - 1));
                pg->ntimers--;
                i--;
            }
            JSValue r = JS_Call(pg->ctx, fn, JS_UNDEFINED, 0, NULL);
            JS_FreeValue(pg->ctx, r);
            JS_FreeValue(pg->ctx, fn);
            if (JS_HasException(pg->ctx)) {
                JSValue ex = JS_GetException(pg->ctx);
                const char *s = JS_ToCString(pg->ctx, ex);
                fprintf(stderr, "jsdom: timer error: %s\n", s ? s : "?");
                JS_FreeCString(pg->ctx, s);
                JS_FreeValue(pg->ctx, ex);
            }
            ran = 1;
        }
    }
    {
        JSContext *pctx = NULL;
        while (JS_ExecutePendingJob(JS_GetRuntime(pg->ctx), &pctx) > 0) ran = 1;
    }
    return ran;
}

void jsdom_free(struct jsdom_page *pg) {
    if (!pg) return;
    for (int i = 0; i < pg->ntimers; i++) JS_FreeValue(pg->ctx, pg->timers[i].fn);
    for (int i = 0; i < pg->nlisteners; i++) JS_FreeValue(pg->ctx, pg->listeners[i].fn);
    JS_FreeContext(pg->ctx);
    free(pg);
}
