/* Probes that a guest mprotect is enforced by the MMU, not merely accepted.
 *
 * Both checks are one-way: each is expected to *fault*, so the process must
 * die with SIGSEGV partway through. Markers are written before the faulting
 * access so the launcher output shows how far the guest got.
 *
 * Built on minic, our self-hosted C library.
 */
#include "minic.h"

int main(void) {
    char *page = (char *)mmap(0, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)page < 0) {
        write(1, "mmap-failed\n", 12);
        _exit(1);
    }
    write(1, "mapped\n", 7);

    /* Negative control: the page is writable right now. */
    *page = 0x41;
    write(1, "wrote-while-rw\n", 14);

    /* Drop write. Read must survive; a store must not. */
    if (mprotect(page, 4096, PROT_READ) != 0) {
        write(1, "mprotect-failed\n", 15);
        _exit(2);
    }
    write(1, "mprotect-ok\n", 12);

    /* Read still works, proving the page is mapped and the change applied. */
    char c = *page;
    write(1, "read-while-r:", 13);
    write(1, &c, 1);
    write(1, "\n", 1);

    /* Provoke the fault. Reaching the next line is a failure. */
    *page = 0x42;
    write(1, "write-not-denied\n", 16);

    void (*fn)(void) = (void (*)(void))page;
    fn();
    write(1, "exec-not-denied\n", 15);

    _exit(3);
}
