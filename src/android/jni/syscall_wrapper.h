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
// STRUCTURES FOR SYSCALL RESULTS
// ============================================================================

/**
 * Directory entry structure for getdents64
 */
struct linux_dirent64 {
    uint64_t        d_ino;      // Inode number
    int64_t         d_off;      // Offset to next dirent
    unsigned short  d_reclen;   // Length of this dirent
    unsigned char   d_type;     // File type
    char            d_name[];   // Filename (null-terminated)
};

// File types for d_type
#define DT_UNKNOWN  0
#define DT_FIFO     1
#define DT_CHR      2
#define DT_DIR      4
#define DT_BLK      6
#define DT_REG      8
#define DT_LNK      10
#define DT_SOCK     12

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

/**
 * Direct syscall to read directory entries
 * Bypasses libc opendir/readdir which may be hooked by Frida
 *
 * @param fd File descriptor of directory (from syscall_open)
 * @param dirp Buffer to store directory entries
 * @param count Size of buffer
 * @return Number of bytes read, 0 on EOF, -1 on error
 */
ssize_t syscall_getdents64(int fd, void* dirp, size_t count);

// ============================================================================
// SYSCALL NUMBERS (ARM64 / ARM)
// ============================================================================

// These are defined for reference and may be used in assembly implementation

#ifdef __aarch64__
// ARM64 syscall numbers
#define __NR_openat     56
#define __NR_close      57
#define __NR_read       63
#define __NR_getdents64 61
#define __NR_readlinkat 78
#define __NR_getpid     172
#else
// ARM (32-bit) syscall numbers
#define __NR_open       5
#define __NR_close      6
#define __NR_read       3
#define __NR_readlink   85
#define __NR_getpid     20
#define __NR_getdents64 217
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
