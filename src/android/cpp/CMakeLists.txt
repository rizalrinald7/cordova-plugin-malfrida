# CMake build configuration for Frida Detector Native Library
#
# Builds the native C++ detection engine with security hardening
#
# @author Security Team
# @version 1.0.0

cmake_minimum_required(VERSION 3.10.2)

project(frida_detector)

# ============================================================================
# Compiler Settings
# ============================================================================

# C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# C standard
set(CMAKE_C_STANDARD 11)

# ============================================================================
# Source Files
# ============================================================================

# Main native library
add_library(
    frida_detector
    SHARED
    frida_detector.cpp
    syscall_wrapper.S
)

# ============================================================================
# Include Directories
# ============================================================================

target_include_directories(
    frida_detector
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ============================================================================
# Link Libraries
# ============================================================================

target_link_libraries(
    frida_detector
    log           # Android logging
    android       # Android NDK
)

# ============================================================================
# Compiler Flags - Security and Optimization
# ============================================================================

# Common flags for all architectures
set(COMMON_FLAGS
    -O3                          # Maximum optimization
    -fvisibility=hidden          # Hide symbols by default
    -ffunction-sections          # Place each function in its own section
    -fdata-sections              # Place each data item in its own section
    -fstack-protector-strong     # Stack protection
    -fno-strict-aliasing         # Avoid strict aliasing issues
    -Wall                        # Enable all warnings
    -Wextra                      # Enable extra warnings
)

# Security hardening flags
set(SECURITY_FLAGS
    -D_FORTIFY_SOURCE=2          # Buffer overflow detection
    -fPIE                        # Position independent executable
    -fPIC                        # Position independent code
)

# Apply flags to C++ compilation
target_compile_options(
    frida_detector
    PRIVATE
    ${COMMON_FLAGS}
    ${SECURITY_FLAGS}
    -fno-rtti                    # Disable RTTI (runtime type info)
    -fno-exceptions              # Disable C++ exceptions
)

# ============================================================================
# Linker Flags - Security and Size Optimization
# ============================================================================

set(LINKER_FLAGS
    -Wl,--gc-sections            # Remove unused sections
    -Wl,--strip-all              # Strip all symbols
    -Wl,--as-needed              # Only link needed libraries
    -Wl,-z,relro                 # Read-only relocations
    -Wl,-z,now                   # Resolve all symbols at load time
    -Wl,-z,noexecstack           # Non-executable stack
)

target_link_options(
    frida_detector
    PRIVATE
    ${LINKER_FLAGS}
)

# ============================================================================
# Architecture-Specific Settings
# ============================================================================

# ARM64 (aarch64)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    message(STATUS "Building for ARM64 (arm64-v8a)")
    target_compile_definitions(frida_detector PRIVATE __aarch64__)
endif()

# ARM (32-bit)
if(ANDROID_ABI STREQUAL "armeabi-v7a")
    message(STATUS "Building for ARM (armeabi-v7a)")
    target_compile_definitions(frida_detector PRIVATE __arm__)
endif()

# x86
if(ANDROID_ABI STREQUAL "x86")
    message(STATUS "Building for x86")
    target_compile_definitions(frida_detector PRIVATE __i386__)
endif()

# x86_64
if(ANDROID_ABI STREQUAL "x86_64")
    message(STATUS "Building for x86_64")
    target_compile_definitions(frida_detector PRIVATE __x86_64__)
endif()

# ============================================================================
# Build Type Configuration
# ============================================================================

# Release build - maximum security and optimization
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Release build - applying maximum security hardening")

    # Additional optimization flags for release
    target_compile_options(
        frida_detector
        PRIVATE
        -Os                      # Optimize for size
        -flto                    # Link-time optimization
    )

    # LTO linker flags
    target_link_options(
        frida_detector
        PRIVATE
        -flto
    )
endif()

# Debug build - enable debugging symbols and logging
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Debug build - enabling debug symbols")

    target_compile_options(
        frida_detector
        PRIVATE
        -g                       # Debug symbols
        -O0                      # No optimization
    )

    target_compile_definitions(
        frida_detector
        PRIVATE
        DEBUG=1
    )
endif()

# ============================================================================
# Obfuscation (Optional - requires O-LLVM)
# ============================================================================

# To enable obfuscation with O-LLVM, uncomment the following:
# Note: Requires O-LLVM to be installed and configured
#
# target_compile_options(
#     frida_detector
#     PRIVATE
#     -mllvm -fla              # Control flow flattening
#     -mllvm -sub              # Instruction substitution
#     -mllvm -bcf              # Bogus control flow
# )

# ============================================================================
# Build Information
# ============================================================================

message(STATUS "")
message(STATUS "==================================================")
message(STATUS "Frida Detector Native Library Build Configuration")
message(STATUS "==================================================")
message(STATUS "CMake Version:        ${CMAKE_VERSION}")
message(STATUS "Build Type:           ${CMAKE_BUILD_TYPE}")
message(STATUS "Android ABI:          ${ANDROID_ABI}")
message(STATUS "Android Platform:     ${ANDROID_PLATFORM}")
message(STATUS "Compiler:             ${CMAKE_CXX_COMPILER}")
message(STATUS "C++ Standard:         ${CMAKE_CXX_STANDARD}")
message(STATUS "==================================================")
message(STATUS "")

# ============================================================================
# Installation
# ============================================================================

# Install the library to the appropriate location
install(
    TARGETS frida_detector
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# ============================================================================
# Custom Targets
# ============================================================================

# Clean target
add_custom_target(
    clean-all
    COMMAND ${CMAKE_BUILD_TOOL} clean
    COMMENT "Cleaning all build artifacts"
)
