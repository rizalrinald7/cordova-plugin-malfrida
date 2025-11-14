# Application.mk - NDK Application Configuration for Frida Detector
#
# App-level build settings for all architectures
#
# @author Security Team
# @version 1.0.0

# ============================================================================
# Target ABIs (Architectures)
# ============================================================================

# Build for all major Android architectures
# ARM64 is required for Google Play (64-bit requirement)
APP_ABI := armeabi-v7a arm64-v8a x86 x86_64

# Alternative: Build for all supported ABIs
# APP_ABI := all

# ============================================================================
# Platform and API Level
# ============================================================================

# Minimum Android API level (Android 5.0 Lollipop)
APP_PLATFORM := android-21

# ============================================================================
# C++ Standard Library
# ============================================================================

# Use static C++ library (no runtime dependency)
APP_STL := c++_static

# ============================================================================
# Build Configuration
# ============================================================================

# Build in release mode with optimizations
APP_OPTIM := release

# Enable C++ exceptions (disabled in Android.mk for size)
# APP_CPPFLAGS += -fexceptions

# Short commands for better build output readability
APP_SHORT_COMMANDS := true

# ============================================================================
# Security and Optimization
# ============================================================================

# Enable all available CPU features for optimization
APP_CFLAGS += -O3

# Position Independent Executable (PIE) - required for Android 5.0+
APP_CFLAGS += -fPIE -fPIC

# Stack protection
APP_CFLAGS += -fstack-protector-strong

# Fortify source (buffer overflow protection)
APP_CFLAGS += -D_FORTIFY_SOURCE=2

# ============================================================================
# Build Output
# ============================================================================

# Strip debug symbols in release builds
ifeq ($(APP_OPTIM),release)
    APP_CFLAGS += -g0
    LOCAL_LDFLAGS += -Wl,--strip-all
endif

# ============================================================================
# Project Information
# ============================================================================

# Project name (optional)
APP_PROJECT_PATH := $(LOCAL_PATH)

# Module name
APP_MODULES := frida_detector
