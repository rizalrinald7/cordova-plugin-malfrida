# Android.mk - NDK Build Configuration for Frida Detector
#
# Builds the native C++ detection engine with security hardening
#
# @author Security Team
# @version 1.0.0

LOCAL_PATH := $(call my-dir)

# ============================================================================
# Frida Detector Native Library
# ============================================================================

include $(CLEAR_VARS)

# Module name
LOCAL_MODULE := frida_detector

# Source files
LOCAL_SRC_FILES := \
    frida_detector.cpp \
    syscall_wrapper.S

# Header search paths
LOCAL_C_INCLUDES := $(LOCAL_PATH)

# ============================================================================
# Compiler Flags - Security and Optimization
# ============================================================================

# C++ flags
LOCAL_CPPFLAGS := \
    -std=c++14 \
    -O3 \
    -fvisibility=hidden \
    -ffunction-sections \
    -fdata-sections \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -fPIE \
    -fPIC \
    -fno-rtti \
    -fno-exceptions \
    -fno-strict-aliasing \
    -Wall \
    -Wextra

# C flags (for assembly and any C code)
LOCAL_CFLAGS := \
    -std=c11 \
    -O3 \
    -fvisibility=hidden \
    -ffunction-sections \
    -fdata-sections \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -fPIE \
    -fPIC \
    -Wall

# Assembly flags
LOCAL_ASMFLAGS := \
    -D__ASSEMBLY__

# ============================================================================
# Linker Flags - Security and Size Optimization
# ============================================================================

LOCAL_LDFLAGS := \
    -Wl,--gc-sections \
    -Wl,--strip-all \
    -Wl,--as-needed \
    -Wl,-z,relro \
    -Wl,-z,now \
    -Wl,-z,noexecstack

# ============================================================================
# System Libraries
# ============================================================================

LOCAL_LDLIBS := \
    -llog \
    -landroid

# ============================================================================
# Build Configuration
# ============================================================================

# Build as shared library
include $(BUILD_SHARED_LIBRARY)
