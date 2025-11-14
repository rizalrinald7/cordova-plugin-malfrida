/**
 * Syscall Wrapper - Direct System Call Interface
 *
 * Provides direct syscall interface to bypass potential Frida hooks on libc functions.
 * This makes detection more resistant to bypass attempts.
 *
 * @author Security Team
 * @version 1.0.0
 */

#ifndef SYSCALL_WRAPPER_H
#define SYSCALL_WRAPPER_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// DIRECT SYSCALL WRAPPERS
// ============================================================================

/**
 * Direct syscall to open a file
 * Bypasses libc open() which may be hooked by Frida
 *
 * @param pathname Path to file
 * @param flags Open flags (O_RDONLY, etc.)
 * @param mode File permissions
 * @return File descriptor or -1 on error
 */
int syscall_open(const char* pathname, int flags, mode_t mode);

/**
 * Direct syscall to read from file descriptor
 * Bypasses libc read() which may be hooked by Frida
 *
 * @param fd File descriptor
 * @param buf Buffer to read into
 * @param count Number of bytes to read
 * @return Number of bytes read or -1 on error
 */
ssize_t syscall_read(int fd, void* buf, size_t count);

/**
 * Direct syscall to close file descriptor
 * Bypasses libc close() which may be hooked by Frida
 *
 * @param fd File descriptor to close
 * @return 0 on success, -1 on error
 */
int syscall_close(int fd);

/**
 * Direct syscall to read symbolic link
 * Bypasses libc readlink() which may be hooked by Frida
 *
 * @param pathname Path to symbolic link
 * @param buf Buffer to store link target
 * @param bufsiz Size of buffer
 * @return Number of bytes placed in buffer or -1 on error
 */
ssize_t syscall_readlink(const char* pathname, char* buf, size_t bufsiz);

/**
 * Direct syscall to get process ID
 * Bypasses libc getpid() which may be hooked by Frida
 *
 * @return Process ID
 */
pid_t syscall_getpid(void);

// ============================================================================
// SYSCALL NUMBERS (ARM64 / ARM)
// ============================================================================

// These are defined for reference and may be used in assembly implementation

#ifdef __aarch64__
// ARM64 syscall numbers
#define __NR_openat     56
#define __NR_close      57
#define __NR_read       63
#define __NR_readlinkat 78
#define __NR_getpid     172
#else
// ARM (32-bit) syscall numbers
#define __NR_open       5
#define __NR_close      6
#define __NR_read       3
#define __NR_readlink   85
#define __NR_getpid     20
#define __NR_openat     322
#endif

// ============================================================================
// INLINE SYSCALL HELPERS
// ============================================================================

/**
 * Generic syscall wrapper for advanced use
 * Allows making any syscall directly
 *
 * @param number Syscall number
 * @param ... Syscall arguments
 * @return Syscall return value
 */
static inline long syscall_raw(long number, ...) {
    // Implementation will be in assembly or using __asm__
    return syscall(number);
}

#ifdef __cplusplus
}
#endif

#endif // SYSCALL_WRAPPER_H
