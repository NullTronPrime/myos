/* minic startup: the process entry point for a self-hosted guest.
 *
 * The kernel enters here with `%rsp` pointing at `argc`, followed by `argv`,
 * `envp`, and the auxiliary vector. We hand `main` its arguments, then exit with
 * its return value. This replaces glibc's `_start` / `__libc_start_main`. */
    .text
    .globl _start
    .type _start, @function
_start:
    xorl %ebp, %ebp
    movq (%rsp), %rdi           /* argc */
    leaq 8(%rsp), %rsi          /* argv */
    leaq 16(%rsp,%rdi,8), %rdx  /* envp = argv + (argc + 1) * 8 */
    andq $-16, %rsp             /* SysV: 16-byte aligned before the call */
    call main
    movl %eax, %edi
    call exit
    hlt
    .size _start, .-_start

/* Signal return trampoline. A handler ends with an ordinary `ret`, which pops
 * the frame's `pretcode` word and jumps here; that word is the `sa_restorer`
 * the kernel recorded for the delivery. It is placed in `.text` rather than in
 * the signal frame itself, because the guest stack is not executable. */
    .globl minic_sigreturn
    .type minic_sigreturn, @function
minic_sigreturn:
    movl $15, %eax             /* SYS_rt_sigreturn */
    syscall
    hlt                        /* rt_sigreturn must not fail to return */
    .size minic_sigreturn, .-minic_sigreturn

    .section .note.GNU-stack,"",@progbits
