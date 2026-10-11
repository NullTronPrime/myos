/* resolve: tiny static-friendly IPv4 resolver for myos guests.
 *
 * glibc's getaddrinfo() needs shared NSS modules that a static guest can
 * neither see (not in the VFS) nor load (no file-backed mmap), so hostname
 * lookup fails even though sockets work. This resolver speaks only syscalls
 * the kernel mediates: numeric addresses inline, /etc/hosts (bridged
 * read-only), then a hand-built DNS A query over UDP to the first
 * nameserver in the bridged /etc/resolv.conf.
 */
#ifndef MYOS_RESOLVE_H
#define MYOS_RESOLVE_H

#include <netinet/in.h>

/* Resolves `name` to an IPv4 address. Returns 0 on success. */
int resolve_host(const char *name, struct in_addr *out);

#endif /* MYOS_RESOLVE_H */
