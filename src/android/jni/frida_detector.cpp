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
static int detection_results[8] = {0};
static pthread_mutex_t results_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global configuration
detection_config_t g_config = {
    .enable_logging = false,
    .detection_threshold = 2,
    .exit_on_detection = false
};

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

    char fd_dir[] = "/proc/self/fd";
    DIR* dir = opendir(fd_dir);
    if (!dir) {
        LOGD("Failed to open /proc/self/fd");
        return false;
    }

    bool detected = false;
    struct dirent* entry;
    char frida_str[16];
    char linjector_str[16];

    decrypt_string(ENC_FRIDA, frida_str, 5, 0x42);
    strcpy(linjector_str, "linjector");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char link_path[256];
        snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir, entry->d_name);

        char target[512];
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);

        if (len > 0) {
            target[len] = '\0';

            // Check for Frida-related paths
            if (contains_string(target, frida_str) ||
                contains_string(target, linjector_str) ||
                contains_string(target, "re.frida.server")) {

                LOGW("Detected Frida pipe: %s -> %s", entry->d_name, target);
                detected = true;
                break;
            }
        }
    }

    closedir(dir);
    LOGD("Named pipes detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 2: THREAD NAME DETECTION
// ============================================================================

bool detect_frida_threads() {
    LOGD("Running thread detection...");

    char task_dir[] = "/proc/self/task";
    DIR* dir = opendir(task_dir);
    if (!dir) {
        LOGD("Failed to open /proc/self/task");
        return false;
    }

    bool detected = false;
    struct dirent* entry;

    // Decrypt suspicious thread names
    char gmain[16], gum_js[16], gdbus[16], pool_frida[16];
    decrypt_string(ENC_GMAIN, gmain, 5, 0x42);
    decrypt_string(ENC_GUM_JS, gum_js, 11, 0x42);
    decrypt_string(ENC_GDBUS, gdbus, 5, 0x42);
    decrypt_string(ENC_POOL_FRIDA, pool_frida, 10, 0x42);

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char comm_path[512];
        snprintf(comm_path, sizeof(comm_path), "%s/%s/comm", task_dir, entry->d_name);

        FILE* fp = fopen(comm_path, "r");
        if (fp) {
            char thread_name[256];
            if (fgets(thread_name, sizeof(thread_name), fp)) {
                // Remove newline
                thread_name[strcspn(thread_name, "\n")] = '\0';

                // Check for Frida thread names
                if (strcmp(thread_name, gmain) == 0 ||
                    strcmp(thread_name, gum_js) == 0 ||
                    strcmp(thread_name, gdbus) == 0 ||
                    contains_string(thread_name, pool_frida)) {

                    LOGW("Detected Frida thread: %s", thread_name);
                    detected = true;
                    fclose(fp);
                    break;
                }
            }
            fclose(fp);
        }
    }

    closedir(dir);
    LOGD("Thread detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 3: MEMORY MAPPING DETECTION
// ============================================================================

bool detect_frida_memory_maps() {
    LOGD("Running memory mapping detection...");

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGD("Failed to open /proc/self/maps");
        return false;
    }

    bool detected = false;
    char line[1024];
    char frida_str[16];
    decrypt_string(ENC_FRIDA, frida_str, 5, 0x42);

    while (fgets(line, sizeof(line), fp)) {
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
    }

    fclose(fp);
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

    // This is a simplified version
    // In production, you would compare actual executable sections
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;

    bool detected = false;
    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
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
    }

    fclose(fp);
    LOGD("Memory tampering detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 6: PROCESS DETECTION
// ============================================================================

bool detect_frida_process() {
    LOGD("Running process detection...");

    DIR* dir = opendir("/proc");
    if (!dir) {
        LOGD("Failed to open /proc");
        return false;
    }

    bool detected = false;
    struct dirent* entry;
    char frida_str[16];
    decrypt_string(ENC_FRIDA, frida_str, 5, 0x42);

    while ((entry = readdir(dir)) != NULL) {
        // Skip if not a process directory (numeric)
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        char cmdline_path[512];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);

        FILE* fp = fopen(cmdline_path, "r");
        if (fp) {
            char cmdline[512];
            if (fgets(cmdline, sizeof(cmdline), fp)) {
                // Check for frida-server, frida-inject
                if (contains_string(cmdline, frida_str) ||
                    contains_string(cmdline, "frida-server") ||
                    contains_string(cmdline, "frida-inject")) {

                    LOGW("Detected Frida process: %s", cmdline);
                    detected = true;
                    fclose(fp);
                    break;
                }
            }
            fclose(fp);
        }
    }

    closedir(dir);
    LOGD("Process detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 7: PTRACE DETECTION
// ============================================================================

bool detect_ptrace() {
    LOGD("Running ptrace detection...");

    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) {
        LOGD("Failed to open /proc/self/status");
        return false;
    }

    bool detected = false;
    char line[256];

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = 0;
            sscanf(line + 10, "%d", &tracer_pid);

            if (tracer_pid != 0) {
                LOGW("Detected tracer process: TracerPid=%d", tracer_pid);
                detected = true;
            }
            break;
        }
    }

    fclose(fp);
    LOGD("Ptrace detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// DETECTION METHOD 8: LIBRARY SYMBOL SCANNING
// ============================================================================

bool detect_frida_symbols() {
    LOGD("Running symbol scanning detection...");

    // This is a simplified implementation
    // Full implementation would parse ELF symbols from loaded libraries
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;

    bool detected = false;
    char line[1024];
    char frida_str[16];
    decrypt_string(ENC_FRIDA, frida_str, 5, 0x42);

    // Look for suspicious library names
    while (fgets(line, sizeof(line), fp)) {
        if (contains_string(line, "gum-") ||
            contains_string(line, "frida-") ||
            contains_string(line, "gadget")) {

            LOGW("Detected suspicious library: %s", line);
            detected = true;
            break;
        }
    }

    fclose(fp);
    LOGD("Symbol scanning detection: %s", detected ? "DETECTED" : "clean");
    return detected;
}

// ============================================================================
// CORE DETECTION FUNCTION
// ============================================================================

bool detect_frida_comprehensive() {
    LOGI("Starting comprehensive Frida detection...");

    pthread_mutex_lock(&results_mutex);

    // Run all detection methods
    detection_results[0] = detect_frida_pipes() ? 1 : 0;
    detection_results[1] = detect_frida_threads() ? 1 : 0;
    detection_results[2] = detect_frida_memory_maps() ? 1 : 0;
    detection_results[3] = detect_frida_ports() ? 1 : 0;
    detection_results[4] = detect_memory_tampering() ? 1 : 0;
    detection_results[5] = detect_frida_process() ? 1 : 0;
    detection_results[6] = detect_ptrace() ? 1 : 0;
    detection_results[7] = detect_frida_symbols() ? 1 : 0;

    // Calculate detection score
    int score = 0;
    for (int i = 0; i < 8; i++) {
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

    // Build JSON response
    char* json = (char*)malloc(1024);
    if (!json) {
        pthread_mutex_unlock(&results_mutex);
        return NULL;
    }

    int score = 0;
    for (int i = 0; i < 8; i++) {
        score += detection_results[i];
    }

    snprintf(json, 1024,
        "{"
        "\"pipesDetected\":%s,"
        "\"threadsDetected\":%s,"
        "\"memoryMapsDetected\":%s,"
        "\"portsDetected\":%s,"
        "\"memoryTamperingDetected\":%s,"
        "\"processDetected\":%s,"
        "\"ptraceDetected\":%s,"
        "\"symbolsDetected\":%s,"
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

JNIEXPORT jstring JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeGetVersion(
    JNIEnv *env,
    jobject
) {
    return env->NewStringUTF(DETECTOR_VERSION);
}

// ============================================================================
// LIBRARY INITIALIZATION
// ============================================================================

__attribute__((constructor))
static void on_load() {
    init_detector();
}

__attribute__((destructor))
static void on_unload() {
    cleanup_detector();
}
