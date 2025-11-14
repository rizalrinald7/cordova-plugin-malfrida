/**
 * Syscall Wrapper - Assembly Implementation
 *
 * Direct syscall implementations in ARM/ARM64 assembly
 * Bypasses libc to prevent Frida hooks
 *
 * @author Security Team
 * @version 1.0.0
 */

#if defined(__aarch64__)
/* ============================================================================
 * ARM64 (AArch64) Syscall Implementation
 * ============================================================================
 *
 * ARM64 calling convention:
 * - Syscall number: x8
 * - Arguments: x0, x1, x2, x3, x4, x5
 * - Return: x0
 * - Syscall instruction: svc #0
 */

.text
.align 4

/* int syscall_open(const char* pathname, int flags, mode_t mode) */
.global syscall_open
.type syscall_open, @function
syscall_open:
    mov x8, #56             /* __NR_openat */
    mov x3, x2              /* mode */
    mov x2, x1              /* flags */
    mov x1, x0              /* pathname */
    mov x0, #-100           /* AT_FDCWD */
    svc #0
    ret

/* ssize_t syscall_read(int fd, void* buf, size_t count) */
.global syscall_read
.type syscall_read, @function
syscall_read:
    mov x8, #63             /* __NR_read */
    svc #0
    ret

/* int syscall_close(int fd) */
.global syscall_close
.type syscall_close, @function
syscall_close:
    mov x8, #57             /* __NR_close */
    svc #0
    ret

/* ssize_t syscall_readlink(const char* pathname, char* buf, size_t bufsiz) */
.global syscall_readlink
.type syscall_readlink, @function
syscall_readlink:
    mov x8, #78             /* __NR_readlinkat */
    mov x3, x2              /* bufsiz */
    mov x2, x1              /* buf */
    mov x1, x0              /* pathname */
    mov x0, #-100           /* AT_FDCWD */
    svc #0
    ret

/* pid_t syscall_getpid(void) */
.global syscall_getpid
.type syscall_getpid, @function
syscall_getpid:
    mov x8, #172            /* __NR_getpid */
    svc #0
    ret

/* ssize_t syscall_getdents64(int fd, void* dirp, size_t count) */
.global syscall_getdents64
.type syscall_getdents64, @function
syscall_getdents64:
    mov x8, #61             /* __NR_getdents64 */
    svc #0
    ret

#elif defined(__arm__)
/* ============================================================================
 * ARM (32-bit) Syscall Implementation
 * ============================================================================
 *
 * ARM calling convention:
 * - Syscall number: r7
 * - Arguments: r0, r1, r2, r3, r4, r5
 * - Return: r0
 * - Syscall instruction: svc #0 (or swi #0)
 */

.text
.align 4

/* int syscall_open(const char* pathname, int flags, mode_t mode) */
.global syscall_open
.type syscall_open, %function
syscall_open:
    push    {r7}
    mov     r7, #322        /* __NR_openat */
    push    {r0-r2}
    mov     r0, #-100       /* AT_FDCWD */
    pop     {r1-r3}         /* pathname, flags, mode */
    svc     #0
    pop     {r7}
    bx      lr

/* ssize_t syscall_read(int fd, void* buf, size_t count) */
.global syscall_read
.type syscall_read, %function
syscall_read:
    push    {r7}
    mov     r7, #3          /* __NR_read */
    svc     #0
    pop     {r7}
    bx      lr

/* int syscall_close(int fd) */
.global syscall_close
.type syscall_close, %function
syscall_close:
    push    {r7}
    mov     r7, #6          /* __NR_close */
    svc     #0
    pop     {r7}
    bx      lr

/* ssize_t syscall_readlink(const char* pathname, char* buf, size_t bufsiz) */
.global syscall_readlink
.type syscall_readlink, %function
syscall_readlink:
    push    {r7}
    mov     r7, #85         /* __NR_readlink */
    svc     #0
    pop     {r7}
    bx      lr

/* pid_t syscall_getpid(void) */
.global syscall_getpid
.type syscall_getpid, %function
syscall_getpid:
    push    {r7}
    mov     r7, #20         /* __NR_getpid */
    svc     #0
    pop     {r7}
    bx      lr

/* ssize_t syscall_getdents64(int fd, void* dirp, size_t count) */
.global syscall_getdents64
.type syscall_getdents64, %function
syscall_getdents64:
    push    {r7}
    mov     r7, #217        /* __NR_getdents64 */
    svc     #0
    pop     {r7}
    bx      lr

#elif defined(__i386__)
/* ============================================================================
 * x86 (32-bit) Syscall Implementation
 * ============================================================================
 *
 * x86 calling convention:
 * - Syscall number: eax
 * - Arguments: ebx, ecx, edx, esi, edi, ebp
 * - Return: eax
 * - Syscall instruction: int $0x80
 */

.text
.align 4

.global syscall_open
.type syscall_open, @function
syscall_open:
    push    %ebx
    mov     8(%esp), %ebx   /* pathname */
    mov     12(%esp), %ecx  /* flags */
    mov     16(%esp), %edx  /* mode */
    mov     $5, %eax        /* __NR_open */
    int     $0x80
    pop     %ebx
    ret

.global syscall_read
.type syscall_read, @function
syscall_read:
    push    %ebx
    mov     8(%esp), %ebx   /* fd */
    mov     12(%esp), %ecx  /* buf */
    mov     16(%esp), %edx  /* count */
    mov     $3, %eax        /* __NR_read */
    int     $0x80
    pop     %ebx
    ret

.global syscall_close
.type syscall_close, @function
syscall_close:
    push    %ebx
    mov     8(%esp), %ebx   /* fd */
    mov     $6, %eax        /* __NR_close */
    int     $0x80
    pop     %ebx
    ret

.global syscall_readlink
.type syscall_readlink, @function
syscall_readlink:
    push    %ebx
    mov     8(%esp), %ebx   /* pathname */
    mov     12(%esp), %ecx  /* buf */
    mov     16(%esp), %edx  /* bufsiz */
    mov     $85, %eax       /* __NR_readlink */
    int     $0x80
    pop     %ebx
    ret

.global syscall_getpid
.type syscall_getpid, @function
syscall_getpid:
    mov     $20, %eax       /* __NR_getpid */
    int     $0x80
    ret

.global syscall_getdents64
.type syscall_getdents64, @function
syscall_getdents64:
    push    %ebx
    mov     8(%esp), %ebx   /* fd */
    mov     12(%esp), %ecx  /* dirp */
    mov     16(%esp), %edx  /* count */
    mov     $220, %eax      /* __NR_getdents64 */
    int     $0x80
    pop     %ebx
    ret

#elif defined(__x86_64__)
/* ============================================================================
 * x86_64 (64-bit) Syscall Implementation
 * ============================================================================
 *
 * x86_64 calling convention:
 * - Syscall number: rax
 * - Arguments: rdi, rsi, rdx, r10, r8, r9
 * - Return: rax
 * - Syscall instruction: syscall
 */

.text
.align 4

.global syscall_open
.type syscall_open, @function
syscall_open:
    mov     %rdi, %rsi      /* pathname */
    mov     %rsi, %rdx      /* flags */
    mov     %rdx, %r10      /* mode */
    mov     $-100, %rdi     /* AT_FDCWD */
    mov     $257, %rax      /* __NR_openat */
    syscall
    ret

.global syscall_read
.type syscall_read, @function
syscall_read:
    mov     $0, %rax        /* __NR_read */
    syscall
    ret

.global syscall_close
.type syscall_close, @function
syscall_close:
    mov     $3, %rax        /* __NR_close */
    syscall
    ret

.global syscall_readlink
.type syscall_readlink, @function
syscall_readlink:
    mov     %rdi, %rsi      /* pathname */
    mov     %rsi, %rdx      /* buf */
    mov     %rdx, %r10      /* bufsiz */
    mov     $-100, %rdi     /* AT_FDCWD */
    mov     $267, %rax      /* __NR_readlinkat */
    syscall
    ret

.global syscall_getpid
.type syscall_getpid, @function
syscall_getpid:
    mov     $39, %rax       /* __NR_getpid */
    syscall
    ret

.global syscall_getdents64
.type syscall_getdents64, @function
syscall_getdents64:
    mov     $217, %rax      /* __NR_getdents64 */
    syscall
    ret

#else
#error "Unsupported architecture"
#endif

/* Mark stack as non-executable */
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack, "", %progbits
#endif
