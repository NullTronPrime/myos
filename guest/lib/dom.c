/* dom: tiny HTML tree, see dom.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include "dom.h"

static int tag_id(const char *name) {
    static const char *names[] = {
        "?", "html", "head", "body", "title",
        "div", "p", "span", "a", "img", "br",
        "h1", "h2", "h3", "h4", "h5", "h6",
        "ul", "ol", "li", "table", "tr", "td",
        "form", "input", "button", "script", "style",
        "meta", "link", "hr", "b", "i", "noscript",
        NULL
    };
    for (int i = 1; names[i]; i++)
        if (strcmp(names[i], name) == 0) return i;
    return TAG_UNKNOWN;
}

/* Void elements never have children. */
static int tag_void(const char *name) {
    static const char *voids[] = {
        "img", "br", "input", "meta", "link", "hr", NULL
    };
    for (int i = 0; voids[i]; i++)
        if (strcmp(voids[i], name) == 0) return 1;
    return 0;
}

static char *xstr(const char *s, size_t n) {
    char *o = malloc(n + 1);
    if (!o) return NULL;
    memcpy(o, s, n);
    o[n] = '\0';
    return o;
}

struct dom_node *dom_element(const char *tag) {
    struct dom_node *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    n->name = xstr(tag, strlen(tag));
    if (!n->name) {
        free(n);
        return NULL;
    }
    n->tag = tag_id(tag);
    return n;
}

struct dom_node *dom_text(const char *text) {
    struct dom_node *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    n->name = xstr("#text", 5);
    n->text = xstr(text, strlen(text));
    if (!n->name || !n->text) {
        free(n->name);
        free(n->text);
        free(n);
        return NULL;
    }
    return n;
}

void dom_append(struct dom_node *parent, struct dom_node *child) {
    if (!parent || !child) return;
    struct dom_node **nk = realloc(parent->kids, sizeof(*nk) * (size_t)(parent->nkids + 1));
    if (!nk) return;
    parent->kids = nk;
    parent->kids[parent->nkids++] = child;
    child->parent = parent;
}

static void node_free(struct dom_node *n) {
    if (!n) return;
    for (int i = 0; i < n->nkids; i++) node_free(n->kids[i]);
    free(n->kids);
    for (int i = 0; i < n->nattrs; i++) {
        free(n->attrs[i].name);
        free(n->attrs[i].value);
    }
    free(n->attrs);
    free(n->name);
    free(n->text);
    free(n);
}

void dom_free(struct dom_doc *doc) {
    if (!doc) return;
    node_free(doc->root);
    free(doc);
}

const char *dom_attr(const struct dom_node *n, const char *name) {
    if (!n) return NULL;
    for (int i = 0; i < n->nattrs; i++)
        if (strcasecmp(n->attrs[i].name, name) == 0) return n->attrs[i].value;
    return NULL;
}

static void by_id_walk(struct dom_node *n, const char *id, struct dom_node **hit) {
    if (*hit || !n) return;
    const char *v = dom_attr(n, "id");
    if (v && strcmp(v, id) == 0) {
        *hit = n;
        return;
    }
    for (int i = 0; i < n->nkids; i++) by_id_walk(n->kids[i], id, hit);
}

struct dom_node *dom_by_id(struct dom_doc *doc, const char *id) {
    struct dom_node *hit = NULL;
    if (doc) by_id_walk(doc->root, id, &hit);
    return hit;
}

static void by_tag_walk(struct dom_node *n, int tag, struct dom_node **out, int cap, int *nfound) {
    if (!n || *nfound >= cap) return;
    if (n->tag == tag && tag != TAG_UNKNOWN) out[(*nfound)++] = n;
    for (int i = 0; i < n->nkids && *nfound < cap; i++)
        by_tag_walk(n->kids[i], tag, out, cap, nfound);
}

int dom_by_tag(struct dom_doc *doc, const char *tag, struct dom_node **out, int cap) {
    if (!doc || cap <= 0) return 0;
    char lower[32];
    size_t i = 0;
    for (; tag[i] && i + 1 < sizeof(lower); i++)
        lower[i] = (char)tolower((unsigned char)tag[i]);
    lower[i] = '\0';
    int nfound = 0;
    by_tag_walk(doc->root, tag_id(lower), out, cap, &nfound);
    return nfound;
}

static void text_walk(const struct dom_node *n, char **buf, size_t *len, size_t *cap) {
    if (!n) return;
    if (n->text) {
        size_t tl = strlen(n->text);
        while (*len + tl + 1 > *cap) {
            *cap *= 2;
            char *nb = realloc(*buf, *cap);
            if (!nb) return;
            *buf = nb;
        }
        memcpy(*buf + *len, n->text, tl);
        *len += tl;
    }
    for (int k = 0; k < n->nkids; k++) text_walk(n->kids[k], buf, len, cap);
}

char *dom_text_content(const struct dom_node *n) {
    size_t cap = 256, len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    buf[0] = '\0';
    text_walk(n, &buf, &len, &cap);
    buf[len] = '\0';
    return buf;
}

static void scripts_walk(struct dom_node *n, const char ***out, int *nfound, int *cap) {
    if (!n) return;
    if (n->tag == TAG_SCRIPT) {
        char *t = dom_text_content(n);
        if (t) {
            if (*nfound >= *cap) {
                int nc = *cap ? *cap * 2 : 8;
                const char **nb = realloc(*out, sizeof(*nb) * (size_t)nc);
                if (!nb) {
                    free(t);
                    return;
                }
                *out = nb;
                *cap = nc;
            }
            (*out)[(*nfound)++] = t;
        }
    }
    for (int i = 0; i < n->nkids; i++) scripts_walk(n->kids[i], out, nfound, cap);
}

int dom_scripts(struct dom_doc *doc, const char ***out) {
    *out = NULL;
    if (!doc) return 0;
    int nfound = 0, cap = 0;
    scripts_walk(doc->root, out, &nfound, &cap);
    return nfound;
}

/* Parses one tag's insides: name goes to namebuf (lowercased), attributes
 * appended to n. Returns the tag end (past '>') or NULL on truncation. */
static const char *parse_tag(const char *p, const char *end, char *namebuf, size_t ncap,
                             struct dom_node *n) {
    while (p < end && isspace((unsigned char)*p)) p++;
    size_t ni = 0;
    while (p < end && *p != '>' && !isspace((unsigned char)*p) && *p != '/') {
        if (ni + 1 < ncap) namebuf[ni++] = (char)tolower((unsigned char)*p);
        p++;
    }
    namebuf[ni] = '\0';
    for (;;) {
        while (p < end && isspace((unsigned char)*p)) p++;
        if (p >= end) return NULL;
        if (*p == '>') return p + 1;
        if (*p == '/' && p + 1 < end && p[1] == '>') return p + 2;
        if (*p == '/') {
            p++;
            continue;
        }
        /* Attribute name. */
        char aname[64];
        size_t ai = 0;
        while (p < end && *p != '>' && *p != '=' && !isspace((unsigned char)*p) && *p != '/') {
            if (ai + 1 < sizeof(aname)) aname[ai++] = (char)*p;
            p++;
        }
        aname[ai] = '\0';
        while (p < end && isspace((unsigned char)*p)) p++;
        char *val = xstr("", 0);
        if (p < end && *p == '=') {
            p++;
            while (p < end && isspace((unsigned char)*p)) p++;
            char q = 0;
            if (p < end && (*p == '"' || *p == '\'')) q = *p++;
            const char *vs = p;
            while (p < end && (q ? *p != q : (*p != '>' && !isspace((unsigned char)*p)))) p++;
            free(val);
            val = xstr(vs, (size_t)(p - vs));
            if (q && p < end && *p == q) p++;
        }
        if (ai > 0 && val) {
            struct dom_attr *na = realloc(n->attrs, sizeof(*na) * (size_t)(n->nattrs + 1));
            if (na) {
                n->attrs = na;
                n->attrs[n->nattrs].name = xstr(aname, ai);
                n->attrs[n->nattrs].value = val;
                if (n->attrs[n->nattrs].name) n->nattrs++;
                else free(val);
            } else {
                free(val);
            }
        } else {
            free(val);
        }
    }
}

struct dom_doc *dom_parse(const char *html) {
    struct dom_doc *doc = calloc(1, sizeof(*doc));
    if (!doc) return NULL;
    doc->root = dom_element("doc");
    if (!doc->root) {
        free(doc);
        return NULL;
    }
    struct dom_node *stack[256];
    int depth = 0;
    stack[depth++] = doc->root;
    const char *p = html;
    const char *text_start = p;
    /* Flush text since text_start into the current top. */
    while (*p) {
        if (*p == '<') {
            if (p > text_start) {
                struct dom_node *t = dom_text("");
                if (t) {
                    free(t->text);
                    t->text = xstr(text_start, (size_t)(p - text_start));
                    if (t->text) dom_append(stack[depth - 1], t);
                    else {
                        free(t->name);
                        free(t);
                    }
                }
            }
            if (p[1] == '!' && p[2] == '-' && p[3] == '-') {
                const char *ce = strstr(p + 4, "-->");
                p = ce ? ce + 3 : p + strlen(p);
                text_start = p;
                continue;
            }
            if (p[1] == '!') {
                const char *ge = strchr(p, '>');
                p = ge ? ge + 1 : p + strlen(p);
                text_start = p;
                continue;
            }
            int closing = p[1] == '/';
            const char *tp = p + (closing ? 2 : 1);
            /* Raw-text elements: slurp to the matching close tag. */
            char rawname[32] = {0};
            {
                size_t ri = 0;
                const char *rp = tp;
                while (*rp && *rp != '>' && !isspace((unsigned char)*rp) && *rp != '/' && ri + 1 < sizeof(rawname))
                    rawname[ri++] = (char)tolower((unsigned char)*rp++);
            }
            if (!closing && (strcmp(rawname, "script") == 0 || strcmp(rawname, "style") == 0)) {
                const char *ge = strchr(tp, '>');
                if (!ge) break;
                char close[40];
                snprintf(close, sizeof(close), "</%s>", rawname);
                const char *ce = strcasestr(ge + 1, close);
                size_t rlen = ce ? (size_t)(ce - (ge + 1)) : strlen(ge + 1);
                struct dom_node *el = dom_element(rawname);
                struct dom_node *tx = dom_text("");
                if (el && tx) {
                    free(tx->text);
                    tx->text = xstr(ge + 1, rlen);
                    if (tx->text) {
                        dom_append(el, tx);
                        dom_append(stack[depth - 1], el);
                    } else {
                        node_free(el);
                        node_free(tx);
                    }
                } else {
                    node_free(el);
                    node_free(tx);
                }
                p = ce ? ce + strlen(close) : ge + 1 + rlen;
                text_start = p;
                continue;
            }
            /* Normal tag: find its end (no nesting inside <>). */
            const char *ge = strchr(tp, '>');
            if (!ge) break;
            struct dom_node *el = dom_element("x");
            char tname[32] = {0};
            const char *after = NULL;
            if (el) {
                after = parse_tag(tp, ge, tname, sizeof(tname), el);
                free(el->name);
                el->name = xstr(tname[0] ? tname : "x", strlen(tname[0] ? tname : "x"));
                el->tag = tag_id(tname);
                if (!closing && el->name) {
                    dom_append(stack[depth - 1], el);
                    el = NULL; /* owned by the tree now */
                    if (!tag_void(tname) && depth < (int)(sizeof(stack) / sizeof(stack[0]))) {
                        /* Re-fetch the appended child for the stack. */
                        struct dom_node *top = stack[depth - 1];
                        stack[depth++] = top->kids[top->nkids - 1];
                    }
                } else if (closing && tname[0]) {
                    /* Pop to the matching open (misnesting repair). */
                    for (int d = depth - 1; d > 0; d--) {
                        if (strcasecmp(stack[d]->name, tname) == 0) {
                            depth = d;
                            break;
                        }
                    }
                }
                if (el) node_free(el);
                (void)after;
            }
            p = ge + 1;
            text_start = p;
            continue;
        }
        p++;
    }
    if (p > text_start) {
        struct dom_node *t = dom_text("");
        if (t) {
            free(t->text);
            t->text = xstr(text_start, (size_t)(p - text_start));
            if (t->text) dom_append(stack[depth - 1], t);
            else {
                free(t->name);
                free(t);
            }
        }
    }
    return doc;
}
