/* Does this kernel support seccomp user notifications? A supervisor thread
 * receives the guest's getpid and replies with a synthetic value. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static volatile int listener = -1;

static void *supervisor(void *arg)
{
    (void)arg;
    while (listener < 0) { }
    struct seccomp_notif req;
    memset(&req, 0, sizeof req);
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
        perror("NOTIF_RECV");
        return NULL;
    }
    fprintf(stderr, "notification: nr=%d\n", req.data.nr);
    struct seccomp_notif_resp resp;
    memset(&resp, 0, sizeof resp);
    resp.id = req.id;
    resp.val = 1234;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) perror("NOTIF_SEND");
    return NULL;
}

int main(void)
{
    pthread_t t;
    if (pthread_create(&t, NULL, supervisor, NULL) != 0) { perror("pthread"); return 1; }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("nnp"); return 1; }

    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = 4, .filter = f };
    listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                       SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (listener < 0) { perror("seccomp"); return 1; }
    fprintf(stderr, "listener fd = %d\n", listener);

    long r = syscall(SYS_getpid);
    fprintf(stderr, "getpid returned %ld\n", r);
    return 0;
}
