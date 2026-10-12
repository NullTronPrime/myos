/* resolve: tiny static-friendly IPv4 resolver for parasyteos guests.
 *
 * glibc's getaddrinfo() needs shared NSS modules that a static guest can
 * neither see (not in the VFS) nor load (no file-backed mmap), so hostname
 * lookup fails even though sockets work. This resolver speaks only syscalls
 * the kernel mediates: numeric addresses inline, /etc/hosts (bridged
 * read-only), then a hand-built DNS A query over UDP with a TCP fallback
 * to every nameserver in the bridged /etc/resolv.conf.
 */
#ifndef PARASYTEOS_RESOLVE_H
#define PARASYTEOS_RESOLVE_H

#include <netinet/in.h>

/* Resolves `name` to an IPv4 address. Returns 0 on success. */
int resolve_host(const char *name, struct in_addr *out);

/* Connects a TCP socket with a timeout (a blocking connect hangs for
 * minutes when the network blackholes SYNs). Returns the connected fd
 * or -1 with errno set. `ms` bounds the wait. */
int tcp_connect_timeout(const struct in_addr *addr, int port, int ms);

#endif /* PARASYTEOS_RESOLVE_H */
