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

    .section .note.GNU-stack,"",@progbits
