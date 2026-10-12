/* dom: a tiny HTML node tree for myos guests (guest/lib/dom.c).
 *
 * The browser used to tokenize straight into layout. Scripts need something
 * to manipulate, so parsing now builds a tree first and layout walks it.
 * Toy-grade: no namespaces, no frames, no CSS, misnesting is repaired by
 * popping to the matching open tag, and unknown tags stay in the tree.
 */
#ifndef MYOS_DOM_H
#define MYOS_DOM_H

#include <stddef.h>

/* Tag ids for the common elements; anything else is TAG_UNKNOWN. */
enum {
    TAG_UNKNOWN = 0,
    TAG_HTML, TAG_HEAD, TAG_BODY, TAG_TITLE,
    TAG_DIV, TAG_P, TAG_SPAN, TAG_A, TAG_IMG, TAG_BR,
    TAG_H1, TAG_H2, TAG_H3, TAG_H4, TAG_H5, TAG_H6,
    TAG_UL, TAG_OL, TAG_LI, TAG_TABLE, TAG_TR, TAG_TD,
    TAG_FORM, TAG_INPUT, TAG_BUTTON, TAG_SCRIPT, TAG_STYLE,
    TAG_META, TAG_LINK, TAG_HR, TAG_B, TAG_I, TAG_NOSCRIPT
};

struct dom_attr {
    char *name;
    char *value; /* "" when valueless */
};

struct dom_node {
    int tag;               /* TAG_* or TAG_UNKNOWN */
    char *name;            /* lowercased tag name (unknown tags included) */
    char *text;            /* text nodes only */
    struct dom_attr *attrs;
    int nattrs;
    struct dom_node **kids;
    int nkids;
    struct dom_node *parent;
};

struct dom_doc {
    struct dom_node *root; /* synthetic document node (TAG_UNKNOWN, "doc") */
};

/* Parses html into a document. Scripts and styles are kept as raw-text
 * children of their elements (also collected separately by dom_scripts).
 * Returns NULL on OOM. */
struct dom_doc *dom_parse(const char *html);

/* Frees a whole document. */
void dom_free(struct dom_doc *doc);

/* First element with a matching id attribute, or NULL. */
struct dom_node *dom_by_id(struct dom_doc *doc, const char *id);

/* All elements with a tag name; returns count, fills out (cap). */
int dom_by_tag(struct dom_doc *doc, const char *tag, struct dom_node **out, int cap);

/* Attribute value or NULL. */
const char *dom_attr(const struct dom_node *n, const char *name);

/* Sets (replacing or adding) an attribute. */
void dom_set_attr(struct dom_node *n, const char *name, const char *value);

/* Appends an existing node as a child (reparents). */
void dom_append(struct dom_node *parent, struct dom_node *child);

/* Creates an element node (tag auto-classified). */
struct dom_node *dom_element(const char *tag);

/* Creates a text node. */
struct dom_node *dom_text(const char *text);

/* Concatenated text under a node (caller frees). */
char *dom_text_content(const struct dom_node *n);

/* Script bodies in document order; caller frees the array (not the text,
 * which belongs to the tree). Returns count. */
int dom_scripts(struct dom_doc *doc, const char ***out);

#endif /* MYOS_DOM_H */
