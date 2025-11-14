/**
 * Frida Detector - Native C++ Detection Engine
 *
 * Comprehensive Frida instrumentation detection for Android
 * Implements multiple detection vectors to identify Frida at runtime
 *
 * Detection Methods:
 * 1. Named Pipes Detection - Scan /proc/self/fd for Frida FIFOs
 * 2. Thread Name Detection - Check for Frida-specific thread names
 * 3. Memory Mapping Scan - Scan /proc/self/maps for frida-agent libraries
 * 4. Port Scanning - Check for Frida default ports (27042, 27043)
 * 5. Memory vs Disk Comparison - Compare executable sections
 * 6. Process Detection - Scan /proc for frida-server process
 * 7. Ptrace Detection - Check if being traced/debugged
 * 8. Library Symbol Scanning - Check for Frida symbols in memory
 *
 * @author Security Team
 * @version 1.0.0
 */

#ifndef FRIDA_DETECTOR_H
#define FRIDA_DETECTOR_H

#include <jni.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * Detection configuration structure
 */
typedef struct {
    bool enable_logging;        // Enable debug logging
    int detection_threshold;    // Minimum score to trigger detection (1-8)
    bool exit_on_detection;     // Exit immediately if detected
} detection_config_t;

// Global configuration
extern detection_config_t g_config;

// ============================================================================
// CORE DETECTION FUNCTIONS
// ============================================================================

/**
 * Comprehensive Frida detection
 * Runs all detection methods and returns true if threshold is met
 *
 * @return true if Frida detected, false otherwise
 */
bool detect_frida_comprehensive();

/**
 * Get detailed detection results from all methods
 * Returns JSON string with individual method results
 *
 * @return JSON string (caller must free)
 */
char* get_detection_details();

// ============================================================================
// INDIVIDUAL DETECTION METHODS
// ============================================================================

/**
 * Method 1: Named Pipes Detection
 * Scans /proc/self/fd for Frida-related named pipes (FIFOs)
 * This is one of the most reliable detection methods
 *
 * @return true if Frida pipes detected
 */
bool detect_frida_pipes();

/**
 * Method 2: Thread Name Detection
 * Checks for Frida-specific thread names:
 * - gmain
 * - gum-js-loop
 * - gdbus
 * - pool-frida
 *
 * @return true if Frida threads detected
 */
bool detect_frida_threads();

/**
 * Method 3: Memory Mapping Detection
 * Scans /proc/self/maps for frida-agent and frida-gadget libraries
 *
 * @return true if Frida libraries detected in memory
 */
bool detect_frida_memory_maps();

/**
 * Method 4: Port Scanning
 * Checks if Frida default ports are listening:
 * - 27042 (primary)
 * - 27043 (secondary)
 *
 * @return true if Frida ports detected
 */
bool detect_frida_ports();

/**
 * Method 5: Memory vs Disk Comparison
 * Compares executable text sections in memory vs disk
 * Frida modifies code in memory when hooking
 *
 * @return true if memory modifications detected
 */
bool detect_memory_tampering();

/**
 * Method 6: Process Detection
 * Scans /proc for frida-server process
 *
 * @return true if frida-server process detected
 */
bool detect_frida_process();

/**
 * Method 7: Ptrace Detection
 * Checks if process is being traced/debugged
 *
 * @return true if tracer detected
 */
bool detect_ptrace();

/**
 * Method 8: Library Symbol Scanning
 * Scans loaded libraries for Frida-specific symbols
 *
 * @return true if Frida symbols detected
 */
bool detect_frida_symbols();

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Initialize detection system
 */
void init_detector();

/**
 * Cleanup detection system
 */
void cleanup_detector();

/**
 * Set configuration
 */
void set_config(bool enable_logging, int threshold);

/**
 * Get detector version
 */
const char* get_detector_version();

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * String encryption/decryption for obfuscation
 */
void decrypt_string(const unsigned char* encrypted, char* output, size_t len, unsigned char key);

/**
 * Check if string contains substring (case-insensitive)
 */
bool contains_string(const char* haystack, const char* needle);

/**
 * Safe string copy
 */
void safe_strcpy(char* dest, const char* src, size_t dest_size);

// ============================================================================
// JNI INTERFACE
// ============================================================================

/**
 * JNI: Detect Frida
 */
JNIEXPORT jboolean JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeDetectFrida(
    JNIEnv *env,
    jobject thiz
);

/**
 * JNI: Get detection details
 */
JNIEXPORT jstring JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeGetDetectionDetails(
    JNIEnv *env,
    jobject thiz
);

/**
 * JNI: Set logging
 */
JNIEXPORT void JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeSetLogging(
    JNIEnv *env,
    jobject thiz,
    jboolean enabled
);

/**
 * JNI: Set detection threshold
 */
JNIEXPORT void JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeSetThreshold(
    JNIEnv *env,
    jobject thiz,
    jint threshold
);

/**
 * JNI: Get version
 */
JNIEXPORT jstring JNICALL
Java_cordova_plugin_malfrida_MalfridaPlugin_nativeGetVersion(
    JNIEnv *env,
    jobject thiz
);

// ============================================================================
// ANTI-TAMPERING
// ============================================================================

/**
 * Verify detection function integrity
 * Checks that detection functions haven't been patched
 */
bool verify_integrity();

/**
 * Calculate checksum of function
 */
uint32_t calculate_checksum(void* addr, size_t size);

#ifdef __cplusplus
}
#endif

#endif // FRIDA_DETECTOR_H
