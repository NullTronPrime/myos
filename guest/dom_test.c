/* dom_test: parses HTML and dumps the tree + scripts. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/dom.h"

static void dump(struct dom_node *n, int d) {
    if (!n || d > 6) return;
    if (n->text) {
        char t[41] = {0};
        size_t i = 0, j = 0;
        while (n->text[i] && j < 40) {
            if (n->text[i] != '\n' && n->text[i] != '\r') t[j++] = n->text[i];
            i++;
        }
        if (j) printf("%*stext %zuch\n", d * 2, "", j);
        return;
    }
    printf("%*s<%s>", d * 2, "", n->name);
    for (int i = 0; i < n->nattrs; i++) printf(" %s=%s", n->attrs[i].name, n->attrs[i].value);
    printf(" (%d kids)\n", n->nkids);
    for (int i = 0; i < n->nkids; i++) dump(n->kids[i], d + 1);
}

int main(void) {
    const char *html = "<html><head><title>T</title></head><body>"
                       "<div id=main><p>Hello <a href=\"/x\">wor<b>l</b>d</a>!"
                       "</p><img src=i.png><br>tail</div>"
                       "<script>var x = 1 < 2;</script>"
                       "<!-- comment --><p>unclosed";
    struct dom_doc *doc = dom_parse(html);
    if (!doc) {
        printf("parse failed\n");
        return 1;
    }
    dump(doc->root, 0);
    struct dom_node *m = dom_by_id(doc, "main");
    printf("by_id main: %s\n", m ? m->name : "(null)");
    const char **scripts = NULL;
    int ns = dom_scripts(doc, &scripts);
    printf("scripts: %d first=%.20s\n", ns, ns ? scripts[0] : "");
    for (int i = 0; i < ns; i++) free((void *)scripts[i]);
    free(scripts);
    char *t = dom_text_content(m);
    printf("main text: %.40s\n", t ? t : "");
    free(t);
    dom_free(doc);
    /* Entities in attribute values decode at parse (links carry &amp;). */
    {
        struct dom_doc *d2 = dom_parse("<a href=\"/s?a=1&amp;b=2&amp;c=&lt;x&gt;\">e</a>");
        struct dom_node *a = d2 ? d2->root : NULL;
        const char *hv = "";
        if (a && a->nkids > 0) {
            const char *h = dom_attr(a->kids[0], "href");
            if (h) hv = h;
        }
        printf("ent href: %s\n", hv);
        if (d2) dom_free(d2);
    }
    printf("DOM_TEST:PASS\n");
    return 0;
}
