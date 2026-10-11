/* minic as a shared library: the same implementations, but with position-
 * independent code and a dynamic symbol table so it can be loaded as a
 * DT_NEEDED dependency. The guest's own code calls these symbols through
 * the PLT, and the dynamic linker (or our loader) resolves them. */
#include "minic.h"

/* Re-export the key symbols with default visibility. The compiler needs
 * -fPIC and -shared to produce a proper .so. */

/* These are already defined in minic.c; this file exists to document the
 * shared library build. The actual build compiles minic.c with -fPIC -shared
 * and links it as libc.so. */
