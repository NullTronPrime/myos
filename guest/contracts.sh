#!/bin/bash
# Contract tests for the seccomp/SIGSYS behaviours myos depends on.
#
# Each probe pins a kernel behaviour that was established empirically while
# fixing the trap layer. They need a Linux kernel with CONFIG_SECCOMP_FILTER
# (WSL2 is fine) and gcc; they do not need root.
#
#   bash guest/contracts.sh
#
set -u

cd "$(dirname "$0")" || exit 1
out=../target/guest
mkdir -p "$out" || exit 1
cc=${CC:-/usr/bin/gcc}

fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
has()  { [[ "$2" == *"$1"* ]]; }

# 1. A seccomp TRAP is reported as si_code == SYS_SECCOMP (1), with the syscall
#    number in si_syscall. This is why the handler must not compare si_code
#    against SECCOMP_RET_TRAP.
"$cc" -O0 -o "$out/probe" probe.c || exit 1
r=$("$out/probe" 2>&1)
has "code=1" "$r" && ok "trap reports SYS_SECCOMP (si_code=1)" || bad "probe si_code: $r"
has "sys=39" "$r" && ok "trap reports the syscall number in si_syscall" || bad "probe si_syscall: $r"

# 2. The handler can set rax and return; the kernel resumes just past the
#    syscall, so the handler must NOT advance rip itself.
"$cc" -O0 -o "$out/probe_return" probe_return.c || exit 1
r=$("$out/probe_return" 2>&1)
has "getpid returned 0" "$r" && ok "handler return resumes cleanly" || bad "probe_return: $r"

# 3. The kernel already steps rip past the syscall for a TRAP; advancing again
#    lands mid-instruction and raises SIGILL.
"$cc" -O0 -o "$out/probe_rip" probe_rip.c || exit 1
r=$("$out/probe_rip" 2>&1)
has "returned 39" "$r" && ok "rip is already past the syscall on entry" || bad "probe_rip: $r"

# 4. execve resets caught signal dispositions, so a guest exec'd under the
#    filter loses the SIGSYS handler and dies on its first trapped syscall.
#    This is why myos loads the guest in-process rather than exec'ing it.
"$cc" -O0 -o "$out/trap_parent" trap_parent.c || exit 1
"$cc" -O0 -o "$out/trap_child" trap_child.c || exit 1
"$out/trap_parent" "$out/trap_child" >/dev/null 2>&1
st=$?
[[ $st -eq 159 ]] && ok "execve discards the SIGSYS handler (status $st)" \
                  || bad "expected SIGSYS death (159), got $st"

# 5. The filter gates on instruction_pointer: a syscall issued from a page
#    mapped below 4 GiB traps, while the same syscall from libc (high) passes.
#    This is what lets the handler use host syscalls without allow-listing them.
"$cc" -O0 -o "$out/ip_probe" ip_probe.c || exit 1
r=$("$out/ip_probe" 2>&1)
has "ip=0x400" "$r" && ok "low-address syscall is trapped" \
    || bad "ip_probe trap: $r"
has "low stub returned 0xabc" "$r" && ok "handler services the low-address call" \
    || bad "ip_probe return: $r"
"$out/ip_probe" >/dev/null 2>&1
[[ $? -eq 0 ]] && ok "high-address (libc) syscalls pass through" \
              || bad "ip_probe rejected a high-address syscall"

# 6. End to end under myos: a static guest's write is trapped and flushed, and
#    openat/read/close are serviced by the in-memory VFS.
MYOS=../target/release/myos
if [[ -x $MYOS ]]; then
    "$cc" -nostdlib -static -no-pie -fno-stack-protector -fno-builtin \
        -Ilib -O2 -o "$out/hello" lib/crt0.S lib/minic.c hello.c || exit 1
    r=$("$MYOS" "$out/hello" 2>/dev/null)
    has "write trapped and serviced by myos" "$r" && ok "guest write is trapped and flushed" \
        || bad "hello write: $r"
    has "parasitic kernel, running inside a process" "$r" \
        && ok "openat/read/close are serviced by the VFS" || bad "hello vfs read: $r"
    has "created through the VFS" "$r" && ok "write through the VFS round-trips" \
        || bad "hello vfs write: $r"

    # 7. mprotect is enforced, not just accepted. The probe writes while the
    #    page is RW, narrows it to PROT_READ, reads back successfully, and then
    #    stores to it. Reaching "write-not-denied" means permissions were only
    #    recorded, so the run must die on SIGSEGV instead.
    "$cc" -nostdlib -static -no-pie -fno-stack-protector -fno-builtin \
        -Ilib -O2 -o "$out/prot_probe" lib/crt0.S lib/minic.c prot_probe.c || exit 1
    r=$("$MYOS" "$out/prot_probe" 2>/dev/null); rc=$?
    # The guest is killed mid-line by SIGSEGV, so the last marker can be cut
    # short; match on prefixes that survive truncation.
    has "wrote-while-rw" "$r" && ok "page is writable before mprotect" \
        || bad "prot_probe pre-write: $r (rc=$rc)"
    has "mprotect-ok" "$r" && ok "guest mprotect is accepted" \
        || bad "prot_probe mprotect: $r (rc=$rc)"
    has "read-while-r:" "$r" && ok "page is still readable after mprotect" \
        || bad "prot_probe read-back: $r (rc=$rc)"
    has "write-not-denied" "$r" && bad "mprotect did not deny a write (rc=$rc)" \
        || ok "write to PROT_READ page faults"
    [ "$rc" -eq 139 ] && ok "guest dies on the write (SIGSEGV)" \
        || bad "expected exit 139 from prot_probe, got $rc"

    # 8. mmap and brk are mediated: the dispatcher decides, the host realises.
    "$cc" -nostdlib -static -no-pie -fno-stack-protector -fno-builtin \
        -Ilib -O2 -o "$out/mem_probe" lib/crt0.S lib/minic.c mem_probe.c || exit 1
    r=$("$MYOS" "$out/mem_probe" 2>/dev/null)
    has "mmap-ok" "$r" && ok "mmap is mediated into a real mapping" \
        || bad "mem_probe mmap: $r"
    has "brk-ok" "$r" && ok "brk growth is realised by the host" \
        || bad "mem_probe brk: $r"

    # 9. A dynamically linked PIE guest. The main image is mapped low, the
    #    interpreter high; ld.so loads libc and the guest runs printf and
    #    returns a distinct status. This exercises PT_INTERP, AT_BASE, the
    #    interpreter's own (host) syscalls, and the initial-stack layout all at
    #    once, so a stack-contiguity or auxv regression shows up here.
    "$cc" -O2 -o "$out/dyn_hello" dyn_hello.c || exit 1
    r=$("$MYOS" "$out/dyn_hello" 2>/dev/null); rc=$?
    has "dyn ok 15" "$r" && ok "dynamic PIE guest runs (ld.so + libc loaded)" \
        || bad "dyn_hello output: $r (rc=$rc)"
    [ "$rc" -eq 42 ] && ok "dynamic guest exit status is propagated" \
        || bad "expected exit 42 from dyn_hello, got $rc"

    # 10. The process model: guest fork (glibc issues a fork-like clone), execve
    #     through the re-exec trampoline, and wait4 all reach the host.
    #     proc_parent forks, execs proc_child, and reaps it; proc_child proves
    #     getpid is real and read(0) is wired to stdin.
    "$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/proc_parent" proc_parent.c || exit 1
    "$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/proc_child"  proc_child.c  || exit 1
    r=$(printf 'hello-stdin\n' | "$MYOS" "$out/proc_child" 2>/dev/null); rc=$?
    has "child read=hello-stdin" "$r" && ok "guest read(0) is wired to stdin" \
        || bad "proc_child stdin: $r (rc=$rc)"
    [ "$rc" -eq 7 ] && ok "proc_child exit status is real" \
        || bad "expected proc_child exit 7, got $rc"
    r=$(printf 'hi\n' | "$MYOS" "$out/proc_parent" "$out/proc_child" 2>/dev/null); rc=$?
    has "parent reaped" "$r" && has "status=7" "$r" && ok "fork + execve + wait4 round-trips" \
        || bad "proc_parent: $r (rc=$rc)"
    [ "$rc" -eq 42 ] && ok "parent exit status is propagated" \
        || bad "expected proc_parent exit 42, got $rc"

    # 11. A real shell guest: fork/exec/wait in a loop, exec errors reported as
    #     errno (exit 127), and child statuses propagated.
    "$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/sh" sh.c || exit 1
    r=$(printf '%s\n%s\n%s\nexit\n' "$out/dyn_hello" "$out/dyn_hello" /no/such/prog \
        | "$MYOS" "$out/sh" 2>&1); rc=$?
    has "dyn ok 15" "$r" && has "exited 42" "$r" && ok "shell runs guests and reports status" \
        || bad "sh dyn_hello: $r (rc=$rc)"
    has "exec: No such file or directory" "$r" && has "exited 127" "$r" \
        && ok "shell reports exec failure as 127" || bad "sh missing exec: $r"
    has "sh: bye" "$r" && [ "$rc" -eq 0 ] && ok "shell exits cleanly on 'exit'" \
        || bad "expected sh exit 0, got $rc ($r)"

    # 12. Rootfs: MYOS_ROOT makes a host directory back the guest's `/`. Files
    #     are pulled into the VFS, and execve resolves guest paths inside it.
    root="$out/rootfs"
    rm -rf "$root"; mkdir -p "$root/bin" "$root/etc"
    cp "$out/dyn_hello" "$root/bin/dyn_hello"
    "$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/catfile" catfile.c || exit 1
    cp "$out/catfile" "$root/bin/catfile"
    printf 'rootfs motd\n' > "$root/etc/motd"
    r=$(MYOS_ROOT="$root" "$MYOS" "$out/catfile" /etc/motd 2>/dev/null); rc=$?
    has "rootfs motd" "$r" && [ "$rc" -eq 0 ] && ok "rootfs file is readable through the VFS" \
        || bad "rootfs read: $r (rc=$rc)"
    r=$(MYOS_ROOT="$root" "$MYOS" "$out/catfile" /etc/none 2>/dev/null); rc=$?
    [ "$rc" -eq 1 ] && ok "missing rootfs file reports ENOENT" \
        || bad "rootfs missing: rc=$rc"
    r=$(printf '/bin/dyn_hello\nexit\n' | MYOS_ROOT="$root" "$MYOS" "$out/sh" 2>/dev/null); rc=$?
    has "dyn ok 15" "$r" && has "exited 42" "$r" && ok "shell execs a program by guest path" \
        || bad "rootfs shell exec: $r (rc=$rc)"

    # 13. Host-backed descriptors: pipe/fork/dup2/write/read/wait, the
    #     foundation of shell pipelines.
    "$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/pipe_test" pipe_test.c || exit 1
    r=$("$MYOS" "$out/pipe_test" 2>/dev/null); rc=$?
    has "parent got: through-the-pipe" "$r" && [ "$rc" -eq 0 ] \
        && ok "pipe + dup2 + fork + wait round-trips" || bad "pipe_test: $r (rc=$rc)"

    # 14. The shell's `|` chains commands through real pipes.
    "$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/catstdin" catstdin.c || exit 1
    cp "$out/catstdin" "$root/bin/catstdin"
    r=$(printf '/bin/dyn_hello | /bin/catstdin\nexit\n' \
        | MYOS_ROOT="$root" "$MYOS" "$out/sh" 2>/dev/null); rc=$?
    has "dyn ok 15" "$r" && [ "$rc" -eq 0 ] \
        && ok "shell pipeline moves bytes through a pipe" || bad "sh pipeline: $r (rc=$rc)"

    # 15. The offscreen display: the guest creates windows, draws pixels into
    #     mapped buffers, and the host composites them to a PPM on present. The
    #     PPM is read back to check layering, raise, and the background.
    "$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/fb_paint" fb_paint.c || exit 1
    px() { od -An -tu1 -j $(( 13 + (($2 * 64) + $1) * 3 )) -N 3 "$3" 2>/dev/null \
        | tr -s ' \n' ' ' | sed 's/^ *//;s/ *$//'; }
    frame="$out/frame_stack.ppm"
    MYOS_DISPLAY=64x48 MYOS_FB_OUT="$frame" "$MYOS" "$out/fb_paint" stack >/dev/null 2>&1; rc=$?
    if [ "$rc" -eq 0 ] && [ "$(head -c 13 "$frame")" = "$(printf 'P6\n64 48\n255')" ] \
        && [ "$(px 5 5 "$frame")" = "255 0 0" ] \
        && [ "$(px 15 15 "$frame")" = "0 255 0" ] \
        && [ "$(px 50 40 "$frame")" = "16 20 24" ]; then
        ok "windows composite to a PPM"
    else
        bad "fb_paint stack rc=$rc p(5,5)=$(px 5 5 "$frame") p(15,15)=$(px 15 15 "$frame")"
    fi
    frame="$out/frame_raise.ppm"
    MYOS_DISPLAY=64x48 MYOS_FB_OUT="$frame" "$MYOS" "$out/fb_paint" raise >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 0 ] && [ "$(px 15 15 "$frame")" = "255 0 0" ] \
        && ok "raise puts a window on top" || bad "fb_paint raise rc=$rc p(15,15)=$(px 15 15 "$frame")"

    # 16. Text: the guest asks the host to render an 8x8 string into a window at
    #     (0,0); the window sits at (2,3) on a black buffer. 'H' row 0 is 0x33,
    #     so its leftmost pixel lights (2,3) white while (4,3) stays black.
    frame="$out/frame_text.ppm"
    MYOS_DISPLAY=64x48 MYOS_FB_OUT="$frame" "$MYOS" "$out/fb_paint" text >/dev/null 2>&1; rc=$?
    if [ "$rc" -eq 0 ] && [ "$(px 2 3 "$frame")" = "255 255 255" ] \
        && [ "$(px 4 3 "$frame")" = "0 0 0" ] \
        && [ "$(px 50 40 "$frame")" = "16 20 24" ]; then
        ok "guest draws 8x8 text through a syscall"
    else
        bad "fb_paint text rc=$rc p(2,3)=$(px 2 3 "$frame") p(4,3)=$(px 4 3 "$frame")"
    fi

    # 17. Self-hosted libc: a guest built with -nostdlib against our own
    #     crt0 + minic runs with no host glibc and no dynamic linker. It
    #     exercises argv, printf formatting, the bump allocator, and exit-status
    #     propagation.
    "$cc" -nostdlib -static -no-pie -fno-stack-protector -fno-builtin \
        -Ilib -O2 -o "$out/selfhost" lib/crt0.S lib/minic.c selfhost.c || exit 1
    r=$("$MYOS" "$out/selfhost" alpha beta 2>/dev/null); rc=$?
    if has "selfhost argc=3" "$r" && has "arg[1]=alpha" "$r" && has "arg[2]=beta" "$r" \
        && has "len=63" "$r" && has "fmt=42/ff/ok" "$r" && [ "$rc" -eq 7 ]; then
        ok "self-hosted libc guest runs without host libc"
    else
        bad "selfhost: rc=$rc out=$r"
    fi
    if command -v readelf >/dev/null 2>&1; then
        if readelf -l "$out/selfhost" 2>/dev/null | grep -q INTERP; then
            bad "selfhost unexpectedly has a PT_INTERP"
        else
            ok "selfhost has no dynamic interpreter"
        fi
    fi

    # 18. Static PIE: an ET_DYN image with no PT_INTERP whose globals hold
    #     absolute addresses. Neither ld.so nor our crt0 relocates it, so the
    #     kernel-side loader must apply the R_X86_64_RELATIVE entries itself.
    "$cc" -nostdlib -static-pie -fno-stack-protector -fno-builtin \
        -Ilib -O2 -o "$out/pie_guest" lib/crt0.S lib/minic.c pie_guest.c || exit 1
    r=$("$MYOS" "$out/pie_guest" hello 2>/dev/null); rc=$?
    if has "name[0]=zero" "$r" && has "name[3]=three" "$r" && has "argc=2" "$r" \
        && [ "$rc" -eq 7 ]; then
        ok "static PIE is relocated by the kernel loader"
    else
        bad "pie_guest: rc=$rc out=$r"
    fi
    if command -v readelf >/dev/null 2>&1; then
        if readelf -l "$out/pie_guest" 2>/dev/null | grep -q INTERP; then
            bad "pie_guest unexpectedly has a PT_INTERP"
        elif readelf -r "$out/pie_guest" 2>/dev/null | grep -q R_X86_64_RELATIVE; then
            ok "static PIE has relative relocations and no interpreter"
        else
            bad "pie_guest has no relative relocations to exercise the loader"
        fi
    fi
else
    echo "skip myos end-to-end checks ($MYOS not built)"
fi

if [[ $fail -eq 0 ]]; then
    echo "all seccomp contract tests passed"
fi
exit $fail
