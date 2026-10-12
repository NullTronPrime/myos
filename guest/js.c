/* js: QuickJS eval guest proving the engine runs under the trap.
 *
 * Usage: js -e 'expression' | js file.js
 * A `print()` global writes to stdout. Exit 0 on success, 1 on a JS
 * exception (printed to stderr), 2 on usage/IO errors.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../third_party/quickjs/quickjs.h"

static JSValue js_print(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    (void)this_val;
    for (int i = 0; i < argc; i++) {
        const char *s = JS_ToCString(ctx, argv[i]);
        if (i) putchar(' ');
        fputs(s ? s : "null", stdout);
        JS_FreeCString(ctx, s);
    }
    putchar('\n');
    return JS_UNDEFINED;
}

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "js: cannot open %s\n", path);
        return NULL;
    }
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n;
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) {
                free(buf);
                fclose(f);
                return NULL;
            }
            buf = nb;
        }
    }
    fclose(f);
    buf[len] = '\0';
    return buf;
}

int main(int argc, char **argv) {
    const char *src = NULL;
    char *owned = NULL;
    if (argc == 3 && strcmp(argv[1], "-e") == 0) {
        src = argv[2];
    } else if (argc == 2) {
        owned = read_file(argv[1]);
        if (!owned) return 2;
        src = owned;
    } else {
        fprintf(stderr, "usage: js -e 'expr' | js file.js\n");
        return 2;
    }

    JSRuntime *rt = JS_NewRuntime();
    if (!rt) {
        fprintf(stderr, "js: no runtime\n");
        free(owned);
        return 2;
    }
    JSContext *ctx = JS_NewContext(rt);
    if (!ctx) {
        fprintf(stderr, "js: no context\n");
        JS_FreeRuntime(rt);
        free(owned);
        return 2;
    }
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, "print",
                      JS_NewCFunction(ctx, js_print, "print", 1));
    JS_FreeValue(ctx, global);

    JSValue v = JS_Eval(ctx, src, strlen(src), "<eval>", JS_EVAL_TYPE_GLOBAL);
    int rc = 0;
    if (JS_IsException(v)) {
        JSValue ex = JS_GetException(ctx);
        const char *s = JS_ToCString(ctx, ex);
        fprintf(stderr, "js: %s\n", s ? s : "exception");
        JS_FreeCString(ctx, s);
        JS_FreeValue(ctx, ex);
        rc = 1;
    } else {
        const char *s = JS_ToCString(ctx, v);
        if (s && strcmp(s, "undefined") != 0) printf("%s\n", s);
        JS_FreeCString(ctx, s);
    }
    JS_FreeValue(ctx, v);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    free(owned);
    return rc;
}
