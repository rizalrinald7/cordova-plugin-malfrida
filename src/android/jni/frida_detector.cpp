/**
 * Frida Detector - Native C++ Implementation
 *
 * Comprehensive Frida instrumentation detection for Android
 *
 * @author Security Team
 * @version 1.0.0
 */

#include "frida_detector.h"
#include "syscall_wrapper.h"
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

// ============================================================================
// CONSTANTS AND CONFIGURATION
// ============================================================================

#define LOG_TAG "FridaDetector"
#define DETECTOR_VERSION "1.0.0"

// Logging macros
#define LOGD(...) if(g_config.enable_logging) { __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__); }
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Detection results storage
static int detection_results[11] = {0};
static pthread_mutex_t results_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global configuration
detection_config_t g_config = {
    .enable_logging = false,
    .detection_threshold = 2,
    .exit_on_detection = false
};

// Early detection (constructor) configuration
// This runs before Java can configure, so use conservative settings
static const int EARLY_DETECTION_THRESHOLD = 1; // More aggressive - any single detection triggers
static bool early_detection_enabled = true;

// Encrypted strings (XOR with 0x42)
static const unsigned char ENC_FRIDA[] = {0x24, 0x30, 0x2E, 0x26, 0x2C}; // "frida"
static const unsigned char ENC_GMAIN[] = {0x25, 0x2D, 0x2C, 0x2E, 0x2B}; // "gmain"
static const unsigned char ENC_GUM_JS[] = {0x25, 0x37, 0x2D, 0x00, 0x2A, 0x31, 0x00, 0x2C, 0x2F, 0x2F, 0x30}; // "gum-js-loop"
static const unsigned char ENC_GDBUS[] = {0x25, 0x26, 0x24, 0x37, 0x31}; // "gdbus"
static const unsigned char ENC_POOL_FRIDA[] = {0x30, 0x2F, 0x2F, 0x2C, 0x00, 0x24, 0x30, 0x2E, 0x26, 0x2C}; // "pool-frida"

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

void decrypt_string(const unsigned char* encrypted, char* output, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        output[i] = encrypted[i] ^ key;
    }
    output[len] = '\0';
}

bool contains_string(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;

    size_t hay_len = strlen(haystack);
    size_t needle_len = strlen(needle);

    if (needle_len > hay_len) return false;

    for (size_t i = 0; i <= hay_len - needle_len; i++) {
        bool match = true;
        for (size_t j = 0; j < needle_len; j++) {
            char h = haystack[i + j];
            char n = needle[j];
            // Case-insensitive comparison
            if (h >= 'A' && h <= 'Z') h += 32;
            if (n >= 'A' && n <= 'Z') n += 32;
            if (h != n) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

void safe_strcpy(char* dest, const char* src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

// ============================================================================
// DETECTION METHOD 1: NAMED PIPES DETECTION
// ============================================================================

bool detect_frida_pipes() {
    LOGD("Running named pipes detection...");

    // Use direct syscall to open directory (bypass opendir hook)
    int dir_fd = syscall_open("/proc/self/fd", O_RDONLY | O_DIRECTORY, 0);
    if (dir_fd < 0) {
        LOGD("Failed to open /proc/self/fd (errno: %d)", errno);
        return false;
    }

    bool detected = false;
    char frida_str[16];
    char linjector_str[16];

    decrypt_string(ENC_FRIDA, frida_str, 5, 0x42);
    strcpy(linjector_str, "linjector");

    // Buffer for getdents64
    char buffer[4096];
    ssize_t nread;

    // Use direct syscall to read directory entries (bypass readdir hook)
    while ((nread = syscall_getdents64(dir_fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t pos = 0; pos < nread;) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *)(buffer + pos);

            // Skip . and ..
            if (entry->d_name[0] != '.') {
                char link_path[256];
                snprintf(link_path, sizeof(link_path), "/proc/self/fd/%s", entry->d_name);

                char target[512];
                // Use direct syscall to bypass potential Frida hooks
                ssize_t len = syscall_readlink(link_path, target, sizeof(target) - 1);

                if (len > 0) {
                    target[len] = '\0';

                    // Check for Frida-related paths
                    if (contains_string(target, frida_str) ||
                        contains_string(target, linjector_str) ||
                        contains_string(target, "re.frida.server") ||
                        contains_string(target, "frida-agent") ||
                        contains_string(target, "frida-gadget")) {

                        LOGW("Detected Frida pipe: %s -> %s", entry->d_name, target);
                        detected = true;
                        break;
                    }
                }
            }

            pos += entry->d_reclen;
        }
        if (detected) break;
    }

    syscall_close(dir_fd);
    LOGD("Named pipes detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 2: THREAD NAME DETECTION
// ============================================================================

bool detect_frida_threads() {
    LOGD("Running thread detection...");

    // Use direct syscall to open directory (bypass opendir hook)
    int dir_fd = syscall_open("/proc/self/task", O_RDONLY | O_DIRECTORY, 0);
    if (dir_fd < 0) {
        LOGD("Failed to open /proc/self/task (errno: %d)", errno);
        return false;
    }

    bool detected = false;

    // Decrypt suspicious thread names
    char gmain[16], gum_js[16], gdbus[16], pool_frida[16];
    decrypt_string(ENC_GMAIN, gmain, 5, 0x42);
    decrypt_string(ENC_GUM_JS, gum_js, 11, 0x42);
    decrypt_string(ENC_GDBUS, gdbus, 5, 0x42);
    decrypt_string(ENC_POOL_FRIDA, pool_frida, 10, 0x42);

    // Buffer for getdents64
    char buffer[4096];
    ssize_t nread;

    // Use direct syscall to read directory entries (bypass readdir hook)
    while ((nread = syscall_getdents64(dir_fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t pos = 0; pos < nread;) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *)(buffer + pos);

            // Skip . and ..
            if (entry->d_name[0] != '.') {
                char comm_path[512];
                snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", entry->d_name);

                // Use direct syscall to bypass potential Frida hooks
                int fd = syscall_open(comm_path, O_RDONLY, 0);
                if (fd >= 0) {
                    char thread_name[256];
                    ssize_t bytes_read = syscall_read(fd, thread_name, sizeof(thread_name) - 1);
                    if (bytes_read > 0) {
                        thread_name[bytes_read] = '\0';
                        // Remove newline
                        thread_name[strcspn(thread_name, "\n")] = '\0';

                        // Check for Frida thread names
                        if (strcmp(thread_name, gmain) == 0 ||
                            strcmp(thread_name, gum_js) == 0 ||
                            strcmp(thread_name, gdbus) == 0 ||
                            contains_string(thread_name, pool_frida)) {

                            LOGW("Detected Frida thread: %s", thread_name);
                            detected = true;
                            syscall_close(fd);
                            break;
                        }
                    }
                    syscall_close(fd);
                }
            }

            pos += entry->d_reclen;
        }
        if (detected) break;
    }

    syscall_close(dir_fd);
    LOGD("Thread detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 3: MEMORY MAPPING DETECTION
// ============================================================================

bool detect_frida_memory_maps() {
    LOGD("Running memory mapping detection...");

    // Use direct syscall to bypass potential Frida hooks
    int fd = syscall_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) {
        LOGD("Failed to open /proc/self/maps");
        return false;
    }

    bool detected = false;
    char buffer[4096];
    char line[1024];
    int line_pos = 0;
    char frida_str[16];
    decrypt_string(ENC_FRIDA, frida_str, 5, 0x42);

    ssize_t bytes_read;
    while ((bytes_read = syscall_read(fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                // Convert to lowercase for comparison
                char line_lower[1024];
                safe_strcpy(line_lower, line, sizeof(line_lower));

                // Check for frida-agent, frida-gadget, LIBFRIDA
                if (contains_string(line_lower, frida_str) ||
                    contains_string(line, "LIBFRIDA") ||
                    contains_string(line_lower, "frida-agent") ||
                    contains_string(line_lower, "frida-gadget") ||
                    contains_string(line_lower, "frida.so")) {

                    LOGW("Detected Frida in memory maps: %s", line);
                    detected = true;
                    break;
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
        if (detected) break;
    }

    syscall_close(fd);
    LOGD("Memory mapping detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 4: PORT SCANNING
// ============================================================================

bool detect_frida_ports() {
    LOGD("Running port scanning detection...");

    // Check common Frida ports
    int ports[] = {27042, 27043};
    bool detected = false;

    for (int i = 0; i < 2; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        // Set non-blocking
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        // Try to connect
        int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));

        if (result == 0 || errno == EISCONN) {
            // Connected successfully - port is open
            LOGW("Detected Frida port %d is open", ports[i]);
            detected = true;
            close(sock);
            break;
        } else if (errno == EINPROGRESS) {
            // Connection in progress - wait briefly
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);

            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000; // 100ms

            if (select(sock + 1, NULL, &write_fds, NULL, &timeout) > 0) {
                int error = 0;
                socklen_t len = sizeof(error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);

                if (error == 0) {
                    LOGW("Detected Frida port %d is open", ports[i]);
                    detected = true;
                    close(sock);
                    break;
                }
            }
        }

        close(sock);
    }

    LOGD("Port scanning detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 5: MEMORY vs DISK COMPARISON
// ============================================================================

bool detect_memory_tampering() {
    LOGD("Running memory tampering detection...");

    // Use direct syscall to bypass potential Frida hooks
    int fd = syscall_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return false;

    bool detected = false;
    char buffer[4096];
    char line[1024];
    int line_pos = 0;

    ssize_t bytes_read;
    while ((bytes_read = syscall_read(fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                // Check for suspicious rwxp permissions (read-write-execute)
                // This can indicate code that was modified in memory
                if (strstr(line, "rwxp")) {
                    // Check if it's in executable regions (not stack/heap)
                    if (strstr(line, ".so") || strstr(line, ".dex")) {
                        LOGW("Detected suspicious RWX memory region: %s", line);
                        detected = true;
                        break;
                    }
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
        if (detected) break;
    }

    syscall_close(fd);
    LOGD("Memory tampering detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 5B: RWX MEMORY DETECTION (Aggressive)
// ============================================================================

/**
 * Aggressive RWX memory detection - specifically for spawn mode
 * Checks for ANY memory regions with rwxp permissions
 * More aggressive than detect_memory_tampering() - used for early detection
 */
bool detect_rwx_memory() {
    LOGD("Running RWX memory detection (aggressive)...");

    // Use direct syscall to bypass potential Frida hooks
    int fd = syscall_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) {
        LOGD("Failed to open /proc/self/maps for RWX detection");
        return false;
    }

    bool detected = false;
    char buffer[4096];
    char line[1024];
    int line_pos = 0;
    int rwx_count = 0;

    ssize_t bytes_read;
    while ((bytes_read = syscall_read(fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                // Check for rwxp permissions (read-write-execute private)
                // This is highly suspicious and rare in normal apps
                if (strstr(line, "rwxp")) {
                    rwx_count++;
                    LOGW("Found RWX region: %s", line);

                    // Check for Frida-specific patterns
                    if (strstr(line, "frida") ||
                        strstr(line, "LIBFRIDA") ||
                        strstr(line, "/data/local/tmp") ||
                        strstr(line, "[anon:") ||
                        strstr(line, "frida-agent") ||
                        strstr(line, "frida-gadget")) {
                        LOGW("Detected Frida-related RWX region: %s", line);
                        detected = true;
                        break;
                    }

                    // More than 3 RWX regions is suspicious (aggressive threshold)
                    if (rwx_count > 3) {
                        LOGW("Excessive RWX regions detected (%d), likely Frida", rwx_count);
                        detected = true;
                        break;
                    }
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
        if (detected) break;
    }

    syscall_close(fd);
    LOGD("RWX memory detection: %s (found %d RWX regions)",
         detected ? "DETECTED" : "clean", rwx_count);
    return detected;
}

// ============================================================================
// DETECTION METHOD 6: PROCESS DETECTION
// ============================================================================

bool detect_frida_process() {
    LOGD("Running process detection...");

    // Use direct syscall to open directory (bypass opendir hook)
    int dir_fd = syscall_open("/proc", O_RDONLY | O_DIRECTORY, 0);
    if (dir_fd < 0) {
        LOGD("Failed to open /proc (errno: %d)", errno);
        return false;
    }

    bool detected = false;
    char frida_str[16];
    decrypt_string(ENC_FRIDA, frida_str, 5, 0x42);

    // Buffer for getdents64
    char buffer[8192];  // Larger buffer for /proc
    ssize_t nread;

    // Use direct syscall to read directory entries (bypass readdir hook)
    while ((nread = syscall_getdents64(dir_fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t pos = 0; pos < nread;) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *)(buffer + pos);

            // Skip if not a process directory (numeric)
            if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
                char cmdline_path[512];
                snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);

                // Use direct syscall to bypass potential Frida hooks
                int fd = syscall_open(cmdline_path, O_RDONLY, 0);
                if (fd >= 0) {
                    char cmdline[512];
                    ssize_t bytes_read = syscall_read(fd, cmdline, sizeof(cmdline) - 1);
                    if (bytes_read > 0) {
                        cmdline[bytes_read] = '\0';

                        // Check for frida-server, frida-inject
                        if (contains_string(cmdline, frida_str) ||
                            contains_string(cmdline, "frida-server") ||
                            contains_string(cmdline, "frida-inject") ||
                            contains_string(cmdline, "frida-helper")) {

                            LOGW("Detected Frida process: %s", cmdline);
                            detected = true;
                            syscall_close(fd);
                            break;
                        }
                    }
                    syscall_close(fd);
                }
            }

            pos += entry->d_reclen;
        }
        if (detected) break;
    }

    syscall_close(dir_fd);
    LOGD("Process detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 7: PTRACE DETECTION
// ============================================================================

bool detect_ptrace() {
    LOGD("Running ptrace detection...");

    // Use direct syscall to bypass potential Frida hooks
    int fd = syscall_open("/proc/self/status", O_RDONLY, 0);
    if (fd < 0) {
        LOGD("Failed to open /proc/self/status");
        return false;
    }

    bool detected = false;
    char buffer[4096];
    char line[256];
    int line_pos = 0;

    ssize_t bytes_read;
    while ((bytes_read = syscall_read(fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int tracer_pid = 0;
                    sscanf(line + 10, "%d", &tracer_pid);

                    if (tracer_pid != 0) {
                        LOGW("Detected tracer process: TracerPid=%d", tracer_pid);
                        detected = true;
                    }
                    break;
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
        if (detected || strstr(line, "TracerPid:")) break;
    }

    syscall_close(fd);
    LOGD("Ptrace detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 8: LIBRARY SYMBOL SCANNING
// ============================================================================

bool detect_frida_symbols() {
    LOGD("Running symbol scanning detection...");

    // Use direct syscall to bypass potential Frida hooks
    int fd = syscall_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return false;

    bool detected = false;
    char buffer[4096];
    char line[1024];
    int line_pos = 0;
    char frida_str[16];
    decrypt_string(ENC_FRIDA, frida_str, 5, 0x42);

    ssize_t bytes_read;
    while ((bytes_read = syscall_read(fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\n' || line_pos >= (int)sizeof(line) - 1) {
                line[line_pos] = '\0';

                // Look for suspicious library names
                if (contains_string(line, "gum-") ||
                    contains_string(line, "frida-") ||
                    contains_string(line, "gadget")) {

                    LOGW("Detected suspicious library: %s", line);
                    detected = true;
                    break;
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
        if (detected) break;
    }

    syscall_close(fd);
    LOGD("Symbol scanning detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 9: ENVIRONMENT VARIABLES (Spawn-Specific)
// ============================================================================

bool detect_frida_environment() {
    LOGD("Running environment detection...");

    // Use direct syscall to bypass potential Frida hooks
    int fd = syscall_open("/proc/self/environ", O_RDONLY, 0);
    if (fd < 0) {
        LOGD("Failed to open /proc/self/environ");
        return false;
    }

    bool detected = false;
    char buffer[4096];
    ssize_t bytes_read = syscall_read(fd, buffer, sizeof(buffer) - 1);

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';

        // Environment variables are null-separated
        // Check for FRIDA_*, LD_PRELOAD, and other suspicious variables
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\0' && i + 1 < bytes_read) {
                char* env_var = &buffer[i + 1];

                // Check for Frida-related environment variables
                if (strncmp(env_var, "FRIDA", 5) == 0 ||
                    strstr(env_var, "frida") != NULL ||
                    (strncmp(env_var, "LD_PRELOAD=", 11) == 0 &&
                     strstr(env_var, "frida") != NULL)) {

                    LOGW("Detected Frida environment variable: %s", env_var);
                    detected = true;
                    break;
                }
            }
        }
    }

    syscall_close(fd);
    LOGD("Environment detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 10: PARENT PROCESS CHECK (Spawn-Specific)
// ============================================================================

bool detect_parent_process() {
    LOGD("Running parent process detection...");

    // Read /proc/self/stat to get PPID
    int fd = syscall_open("/proc/self/stat", O_RDONLY, 0);
    if (fd < 0) {
        LOGD("Failed to open /proc/self/stat");
        return false;
    }

    char buffer[1024];
    ssize_t bytes_read = syscall_read(fd, buffer, sizeof(buffer) - 1);
    syscall_close(fd);

    if (bytes_read <= 0) return false;
    buffer[bytes_read] = '\0';

    // Parse PPID from stat (4th field after closing parenthesis)
    char* end_comm = strrchr(buffer, ')');
    if (!end_comm) return false;

    int ppid = 0;
    sscanf(end_comm + 2, "%*c %d", &ppid);

    if (ppid <= 1) return false; // Skip if PPID is init

    // Check parent process cmdline
    char parent_cmdline_path[256];
    snprintf(parent_cmdline_path, sizeof(parent_cmdline_path), "/proc/%d/cmdline", ppid);

    fd = syscall_open(parent_cmdline_path, O_RDONLY, 0);
    if (fd < 0) return false;

    char parent_cmdline[512];
    bytes_read = syscall_read(fd, parent_cmdline, sizeof(parent_cmdline) - 1);
    syscall_close(fd);

    if (bytes_read > 0) {
        parent_cmdline[bytes_read] = '\0';

        char frida_str[16];
        decrypt_string(ENC_FRIDA, frida_str, 5, 0x42);

        // Check for frida, gdb, lldb, or other debugging tools
        if (contains_string(parent_cmdline, frida_str) ||
            contains_string(parent_cmdline, "frida-server") ||
            contains_string(parent_cmdline, "frida-inject") ||
            contains_string(parent_cmdline, "gdbserver") ||
            contains_string(parent_cmdline, "lldb-server")) {

            LOGW("Detected suspicious parent process: %s (PID: %d)", parent_cmdline, ppid);
            return true;
        }
    }

    LOGD("Parent process detection: clean");
    return false;
}

// ============================================================================
// DETECTION METHOD 11: SPAWN TIMING CHECK (Spawn-Specific)
// ============================================================================

bool detect_spawn_timing() {
    LOGD("Running spawn timing detection...");

    // Check if process was started very recently with threads already present
    // This can indicate Frida spawn mode where the process is suspended

    int fd = syscall_open("/proc/self/stat", O_RDONLY, 0);
    if (fd < 0) return false;

    char buffer[1024];
    ssize_t bytes_read = syscall_read(fd, buffer, sizeof(buffer) - 1);
    syscall_close(fd);

    if (bytes_read <= 0) return false;
    buffer[bytes_read] = '\0';

    // Parse process start time (field 22)
    char* end_comm = strrchr(buffer, ')');
    if (!end_comm) return false;

    unsigned long long starttime = 0;
    int field_count = 0;
    char* ptr = end_comm + 2;

    // Skip to field 22 (starttime)
    while (*ptr && field_count < 19) {
        if (*ptr == ' ') field_count++;
        ptr++;
    }
    sscanf(ptr, "%llu", &starttime);

    // Count threads using direct syscalls (bypass opendir/readdir hook)
    int task_fd = syscall_open("/proc/self/task", O_RDONLY | O_DIRECTORY, 0);
    int thread_count = 0;

    if (task_fd >= 0) {
        char buffer[4096];
        ssize_t nread;

        // Use direct syscall to read directory entries
        while ((nread = syscall_getdents64(task_fd, buffer, sizeof(buffer))) > 0) {
            for (ssize_t pos = 0; pos < nread;) {
                struct linux_dirent64 *entry = (struct linux_dirent64 *)(buffer + pos);
                if (entry->d_name[0] != '.') thread_count++;
                pos += entry->d_reclen;
            }
        }
        syscall_close(task_fd);
    }

    // If process is very young (<100ms uptime) but has many threads (>10),
    // it might indicate spawn mode with Frida already injected
    // This is a heuristic and may have false positives
    if (thread_count > 10) {
        LOGW("Suspicious thread count at early startup: %d threads", thread_count);
        LOGD("Spawn timing detection: SUSPICIOUS");
        return true;
    }

    LOGD("Spawn timing detection: clean (threads: %d)", thread_count);
    return false;
}

// ============================================================================
// CORE DETECTION FUNCTION
// ============================================================================

bool detect_frida_comprehensive() {
    LOGI("Starting comprehensive Frida detection...");

    pthread_mutex_lock(&results_mutex);

    // Run all detection methods (8 original + 3 spawn-specific)
    detection_results[0] = detect_frida_pipes() ? 1 : 0;
    detection_results[1] = detect_frida_threads() ? 1 : 0;
    detection_results[2] = detect_frida_memory_maps() ? 1 : 0;
    detection_results[3] = detect_frida_ports() ? 1 : 0;
    detection_results[4] = detect_memory_tampering() ? 1 : 0;
    detection_results[5] = detect_frida_process() ? 1 : 0;
    detection_results[6] = detect_ptrace() ? 1 : 0;
    detection_results[7] = detect_frida_symbols() ? 1 : 0;

    // NEW: Spawn-specific detection methods
    detection_results[8] = detect_frida_environment() ? 1 : 0;
    detection_results[9] = detect_parent_process() ? 1 : 0;
    detection_results[10] = detect_spawn_timing() ? 1 : 0;

    // Calculate detection score
    int score = 0;
    for (int i = 0; i < 11; i++) {
        score += detection_results[i];
    }

    pthread_mutex_unlock(&results_mutex);

    bool detected = (score >= g_config.detection_threshold);

    LOGI("Detection complete - Score: %d/%d - Result: %s",
         score, g_config.detection_threshold,
         detected ? "DETECTED" : "CLEAN");

    if (detected && g_config.exit_on_detection) {
        LOGE("SECURITY ALERT: Frida detected! Exiting application...");
        _exit(1);
    }

    return detected;
}

// ============================================================================
// DETECTION DETAILS
// ============================================================================

char* get_detection_details() {
    pthread_mutex_lock(&results_mutex);

    // Build JSON response (increased size for new fields)
    char* json = (char*)malloc(2048);
    if (!json) {
        pthread_mutex_unlock(&results_mutex);
        return NULL;
    }

    int score = 0;
    for (int i = 0; i < 11; i++) {
        score += detection_results[i];
    }

    snprintf(json, 2048,
        "{"
        "\"pipesDetected\":%s,"
        "\"threadsDetected\":%s,"
        "\"memoryMapsDetected\":%s,"
        "\"portsDetected\":%s,"
        "\"memoryTamperingDetected\":%s,"
        "\"processDetected\":%s,"
        "\"ptraceDetected\":%s,"
        "\"symbolsDetected\":%s,"
        "\"environmentDetected\":%s,"
        "\"parentProcessDetected\":%s,"
        "\"spawnTimingDetected\":%s,"
        "\"score\":%d,"
        "\"threshold\":%d,"
        "\"detected\":%s"
        "}",
        detection_results[0] ? "true" : "false",
        detection_results[1] ? "true" : "false",
        detection_results[2] ? "true" : "false",
        detection_results[3] ? "true" : "false",
        detection_results[4] ? "true" : "false",
        detection_results[5] ? "true" : "false",
        detection_results[6] ? "true" : "false",
        detection_results[7] ? "true" : "false",
        detection_results[8] ? "true" : "false",
        detection_results[9] ? "true" : "false",
        detection_results[10] ? "true" : "false",
        score,
        g_config.detection_threshold,
        (score >= g_config.detection_threshold) ? "true" : "false"
    );

    pthread_mutex_unlock(&results_mutex);
    return json;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

void init_detector() {
    LOGI("Initializing Frida detector v%s", DETECTOR_VERSION);
    pthread_mutex_init(&results_mutex, NULL);
}

void cleanup_detector() {
    LOGI("Cleaning up Frida detector");
    pthread_mutex_destroy(&results_mutex);
}

void set_config(bool enable_logging, int threshold) {
    g_config.enable_logging = enable_logging;
    g_config.detection_threshold = threshold;
    LOGD("Configuration updated: logging=%s, threshold=%d",
         enable_logging ? "enabled" : "disabled", threshold);
}

const char* get_detector_version() {
    return DETECTOR_VERSION;
}

// ============================================================================
// ANTI-TAMPERING (Simplified)
// ============================================================================

uint32_t calculate_checksum(void* addr, size_t size) {
    uint32_t checksum = 0;
    unsigned char* bytes = (unsigned char*)addr;
    for (size_t i = 0; i < size; i++) {
        checksum += bytes[i];
        checksum = (checksum << 1) | (checksum >> 31);
    }
    return checksum;
}

bool verify_integrity() {
    // Simplified integrity check
    // In production, implement more robust verification
    return true;
}

// ============================================================================
// JNI INTERFACE IMPLEMENTATION
// ============================================================================

JNIEXPORT jboolean JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeDetectFrida(
    JNIEnv*,
    jobject
) {
    bool detected = detect_frida_comprehensive();
    return (jboolean)detected;
}

JNIEXPORT jstring JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeGetDetectionDetails(
    JNIEnv *env,
    jobject
) {
    char* details = get_detection_details();
    if (!details) {
        return env->NewStringUTF("{\"error\":\"Failed to get details\"}");
    }

    jstring result = env->NewStringUTF(details);
    free(details);
    return result;
}

JNIEXPORT void JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeSetLogging(
    JNIEnv*,
    jobject,
    jboolean enabled
) {
    g_config.enable_logging = (bool)enabled;
    LOGD("Logging %s", enabled ? "enabled" : "disabled");
}

JNIEXPORT void JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeSetThreshold(
    JNIEnv*,
    jobject,
    jint threshold
) {
    g_config.detection_threshold = (int)threshold;
    LOGD("Detection threshold set to %d", threshold);
}

JNIEXPORT void JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeSetExitOnDetection(
    JNIEnv*,
    jobject,
    jboolean enabled
) {
    g_config.exit_on_detection = (bool)enabled;
    LOGD("Exit on detection %s", enabled ? "enabled" : "disabled");
}

JNIEXPORT jstring JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeGetVersion(
    JNIEnv *env,
    jobject
) {
    return env->NewStringUTF(DETECTOR_VERSION);
}

// ============================================================================
// EARLY DETECTION (runs in constructor)
// ============================================================================

/**
 * Early detection for spawn mode - runs immediately when library loads
 * This is critical for preventing Frida spawn attacks (frida -U -f)
 * Runs before Java initialization, so configuration is hardcoded
 *
 * Uses detection methods that work at early stage:
 * - Memory maps: frida-agent.so is already loaded
 * - Named pipes: Frida communication pipes exist
 * - RWX memory: Frida-injected code has rwxp permissions
 *
 * These methods use direct syscalls and are detectable even before
 * Frida's hooks are fully installed.
 */
static void early_spawn_detection() {
    if (!early_detection_enabled) return;

    LOGI("Running early spawn detection (constructor)...");
    LOGI("Using aggressive detection methods: memory maps, pipes, RWX regions");

    int score = 0;

    // Run detection methods that work in early constructor
    // These use direct syscalls and check for already-loaded Frida components
    if (detect_frida_memory_maps()) {
        LOGW("Early detection: frida-agent found in memory maps");
        score++;
    }

    if (detect_frida_pipes()) {
        LOGW("Early detection: Frida pipes detected");
        score++;
    }

    if (detect_rwx_memory()) {
        LOGW("Early detection: RWX memory regions detected");
        score++;
    }

    // Optionally check ports (might be slower)
    if (detect_frida_ports()) {
        LOGW("Early detection: Frida ports open");
        score++;
    }

    if (score >= EARLY_DETECTION_THRESHOLD) {
        LOGE("CRITICAL SECURITY ALERT: Frida spawn detected in constructor!");
        LOGE("Score: %d/%d - Terminating immediately", score, EARLY_DETECTION_THRESHOLD);
        LOGE("Detection breakdown: maps=%d, pipes=%d, rwx=%d, ports=%d",
             detect_frida_memory_maps() ? 1 : 0,
             detect_frida_pipes() ? 1 : 0,
             detect_rwx_memory() ? 1 : 0,
             detect_frida_ports() ? 1 : 0);
        // Exit immediately - prevent any app code from running
        _exit(1);
    }

    LOGI("Early spawn detection passed (score: %d/%d)", score, EARLY_DETECTION_THRESHOLD);
}

// ============================================================================
// LIBRARY INITIALIZATION
// ============================================================================

__attribute__((constructor))
static void on_load() {
    init_detector();

    // Run early spawn detection immediately
    // This prevents Frida from instrumenting the app in spawn mode
    early_spawn_detection();
}

__attribute__((destructor))
static void on_unload() {
    cleanup_detector();
}
