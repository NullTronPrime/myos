/* jsdom: QuickJS bindings for the browser's DOM tree (guest/lib/jsdom.c).
 *
 * A page gets one JSContext whose globals expose a working subset:
 * document (getElementById, getElementsByTagName, querySelector(All),
 * createElement, body, title, write), window (setTimeout/clearTimeout,
 * location, navigator), Element (innerHTML/outerHTML/textContent,
 * get/setAttribute, appendChild, addEventListener, click) and a
 * synchronous XMLHttpRequest (sync only; async opens fail like a
 * network error, which is honest for a toy).
 *
 * Timers fire through jsdom_poll(), which the browser calls from its
 * input loop; it returns nonzero when a callback ran (re-render then).
 * Navigation frees the page context, which drops pending timers with it.
 */
#ifndef MYOS_JSDOM_H
#define MYOS_JSDOM_H

#include "../../third_party/quickjs/quickjs.h"
#include "dom.h"

/* Page state owned by the browser (timers live here). Fixed-size tables:
 * pages are short-lived and timers few; static bounds beat allocator
 * interplay bugs. */
#define JSDOM_MAX_TIMERS 16
#define JSDOM_MAX_LISTENERS 32
struct jsdom_page;

/* Installs globals bound to doc and runs every <script> body in order.
 * url is used for location.href. Returns a page for jsdom_poll/jsdom_free,
 * or NULL (no scripts is not an error: returns a page with nothing to run
 * when count==0 too). err describes JS exceptions. */
struct jsdom_page *jsdom_run(struct dom_doc *doc, const char *url, char *err, size_t errcap);

/* Fires due timers (executing callbacks + pending promise jobs).
 * Returns 1 when anything ran (caller should re-render). */
int jsdom_poll(struct jsdom_page *pg);

/* Frees the page (context, timers, callbacks). */
void jsdom_free(struct jsdom_page *pg);

/* Current monotonic milliseconds (shared clock for timers). */
long jsdom_now_ms(void);

#endif /* MYOS_JSDOM_H */
