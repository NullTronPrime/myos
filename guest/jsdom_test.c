/* jsdom_test: exercises the DOM bindings headlessly, one snippet each. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lib/dom.h"
#include "lib/jsdom.h"

static const char *html =
    "<html><body><div id=msg>before</div>"
    "<p class=note>alpha</p><p class=note>beta</p>"
    "<div id=timer>waiting</div></body></html>";

static int fails = 0;

static void check(const char *name, const char *script, const char *want, int pump_ms) {
    size_t n = strlen(html) + strlen(script) + 32;
    char *with = malloc(n);
    snprintf(with, n, "%s<script>%s</script>", html, script);
    struct dom_doc *doc = dom_parse(with);
    free(with);
    if (!doc) {
        printf("FAIL %s: parse\n", name);
        fails++;
        return;
    }
    char err[128] = {0};
    struct jsdom_page *pg = jsdom_run(doc, "http://t/", err, sizeof(err));
    if (!pg) {
        printf("FAIL %s: %s\n", name, err);
        fails++;
        dom_free(doc);
        return;
    }
    if (pump_ms > 0) {
        long until = jsdom_now_ms() + pump_ms;
        while (jsdom_now_ms() < until) {
            jsdom_poll(pg);
            usleep(20000);
        }
        jsdom_poll(pg);
    }
    char *out = NULL;
    struct dom_node *o = dom_by_id(doc, "out");
    if (o) out = dom_text_content(o);
    if (want == NULL) {
        /* timeout-style: out may appear late; report only */
        printf("info %s: out=%s\n", name, out ? out : "(null)");
        if (!out) {
            printf("FAIL %s: timer never fired\n", name);
            fails++;
        } else {
            printf("ok %s\n", name);
        }
    } else if (out && strcmp(out, want) == 0) {
        printf("ok %s\n", name);
    } else {
        printf("FAIL %s: got %s want %s\n", name, out ? out : "(null)", want);
        fails++;
    }
    free(out);
    jsdom_free(pg);
    dom_free(doc);
}

int main(void) {
    /* Browser-shaped flow first: full page with timer, pumped like main. */
    {
        const char *page = "<html><body><div id=t>waiting</div><script>setTimeout(function(){console.log(\"TIMER FIRED\");document.getElementById(\"t\").textContent=\"fired\";},300);</script></body></html>";
        struct dom_doc *doc = dom_parse(page);
        char err[128] = {0};
        struct jsdom_page *pg = jsdom_run(doc, "http://t/", err, sizeof(err));
        if (!pg) {
            printf("FAIL pageflow: %s\n", err);
            fails++;
        } else {
            long until = jsdom_now_ms() + 1500;
            while (jsdom_now_ms() < until) {
                jsdom_poll(pg);
                usleep(20000);
            }
            struct dom_node *t = dom_by_id(doc, "t");
            char *tx = t ? dom_text_content(t) : NULL;
            if (tx && strcmp(tx, "fired") == 0) printf("ok pageflow-timer\n");
            else {
                printf("FAIL pageflow-timer: %s\n", tx ? tx : "(null)");
                fails++;
            }
            free(tx);
            jsdom_free(pg);
        }
        dom_free(doc);
    }
    check("by-id-text", "document.getElementById(\"msg\").textContent=\"x\";document.body.innerHTML+=\"<div id=out>\"+document.getElementById(\"msg\").textContent+\"</div>\";", "x", 0);
    check("qs-count", "var ps=document.querySelectorAll(\"p.note\");document.body.innerHTML+=\"<div id=out>n=\"+ps.length+\"</div>\";", "n=2", 0);
    check("create-append", "var d=document.createElement(\"div\");d.textContent=\"hi\";document.body.appendChild(d);var o=document.createElement(\"div\");o.id=\"out\";o.textContent=d.textContent;document.body.appendChild(o);", "hi", 0);
    check("reflect-href", "var a=document.createElement(\"a\");a.id=\"lnk\";a.href=\"/x\";a.textContent=\"t\";document.body.appendChild(a);var o=document.createElement(\"div\");o.id=\"out\";o.textContent=document.getElementById(\"lnk\").getAttribute(\"href\")+\"|\"+document.getElementById(\"lnk\").href;document.body.appendChild(o);", "/x|/x", 0);
    check("reflect-value", "var i=document.createElement(\"input\");i.id=\"f\";i.value=\"typed\";document.body.appendChild(i);var o=document.createElement(\"div\");o.id=\"out\";o.textContent=document.getElementById(\"f\").getAttribute(\"value\");document.body.appendChild(o);", "typed", 0);
    /* Click dispatch: a listener registered by script must run when the
     * browser taps the node (theme toggles, menus). */
    {
        const char *page = "<html><body><div id=b>off</div><script>document.getElementById(\"b\").addEventListener(\"click\",function(){document.getElementById(\"b\").textContent=\"on\";});</script></body></html>";
        struct dom_doc *doc = dom_parse(page);
        char err[128] = {0};
        struct jsdom_page *pg = jsdom_run(doc, "http://t/", err, sizeof(err));
        if (!pg) {
            printf("FAIL clickflow: %s\n", err);
            fails++;
        } else {
            struct dom_node *b = dom_by_id(doc, "b");
            jsdom_click_node(pg, b);
            char *tx = b ? dom_text_content(b) : NULL;
            if (tx && strcmp(tx, "on") == 0) printf("ok clickflow\n");
            else {
                printf("FAIL clickflow: %s\n", tx ? tx : "(null)");
                fails++;
            }
            free(tx);
            jsdom_free(pg);
        }
        dom_free(doc);
    }
    check("timeout", "setTimeout(function(){var o=document.createElement(\"div\");o.id=\"out\";o.textContent=\"fired\";document.body.appendChild(o);},50);", "fired", 500);
    printf(fails ? "JSDOM_TEST:FAIL\n" : "JSDOM_TEST:PASS\n");
    return fails != 0;
}
