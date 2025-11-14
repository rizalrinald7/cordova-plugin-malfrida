# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**cordova-plugin-malfrida** is a Cordova plugin for detecting Frida instrumentation on Android devices. This is a security plugin that implements 11 detection vectors in native C++ code to identify runtime manipulation attempts, including specialized spawn mode prevention.

**Key Features**:
- **11 detection methods** (8 standard + 3 spawn-specific)
- **Direct syscalls** to bypass libc hooks
- **Early detection** in native constructor (prevents `frida -U -f` spawn mode)
- **Aggressive exit mode** to terminate app immediately on detection

**Important**: This plugin is designed for legitimate security purposes (protecting applications from reverse engineering, tampering, and instrumentation). It should only be used in authorized contexts.

## Build Commands

### Building the Plugin

```bash
# Install the plugin in a Cordova project
cordova plugin add .

# Build Android app with the plugin
cordova build android

# Build release version
cordova build android --release
```

### Testing

```bash
# Run on device/emulator
cordova run android

# View logs (filter for plugin output)
adb logcat | grep -E "FridaDetector|MalfridaPlugin"
```

### NDK Build (Manual)

The native library is built automatically by Gradle using NDK, but for manual builds:

```bash
# Navigate to JNI directory
cd platforms/android/app/src/main/jni

# Build with ndk-build
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk
```

## Architecture

### Three-Layer Architecture

1. **JavaScript Layer** (`www/malfrida.js`)
   - Cordova JavaScript API exposed as `cordova.plugins.malfrida`
   - Handles callbacks and monitoring state
   - Provides developer-friendly interface

2. **Java Bridge Layer** (`src/android/MalfridaPlugin.java`)
   - Extends `CordovaPlugin` to bridge JavaScript and native code
   - Manages threading, lifecycle events, and monitoring threads
   - Handles JNI calls to native detection engine
   - Auto-starts monitoring on plugin initialization (NO delay - immediate start for spawn prevention)
   - Configurable aggressive mode (`exitOnDetection`)

3. **Native Detection Engine** (`src/android/jni/`)
   - C++ implementation of **11 detection methods** (8 standard + 3 spawn-specific)
   - **Uses direct syscalls** via assembly (`syscall_wrapper.S`) to bypass potential Frida hooks on all file operations
   - **Early spawn detection** runs in `__attribute__((constructor))` before app code executes
   - Implements scoring system (each detection method adds 1 point)
   - Default threshold: 2 points to trigger detection (max: 11)
   - Early constructor threshold: 1 point (aggressive)

### Detection Methods (11 Total)

#### Standard Detection Methods (1-8)

1. **Named Pipes** - Scans `/proc/self/fd` for Frida FIFOs using `syscall_readlink()`
2. **Thread Names** - Detects `gmain`, `gum-js-loop`, `gdbus`, `pool-frida` using `syscall_read()`
3. **Memory Mapping** - Scans `/proc/self/maps` for `frida-agent`, `frida-gadget` using `syscall_read()`
4. **Port Scanning** - Checks ports 27042, 27043
5. **Memory Tampering** - Detects RWX memory regions in executables using `syscall_read()`
6. **Process Detection** - Scans `/proc` for `frida-server` using `syscall_read()`
7. **Ptrace Detection** - Checks `/proc/self/status` for TracerPid using `syscall_read()`
8. **Symbol Scanning** - Looks for Frida symbols in loaded libraries using `syscall_read()`

#### Spawn-Specific Detection Methods (9-11)

9. **Environment Variables** - Checks `/proc/self/environ` for `FRIDA_*` and `LD_PRELOAD` using `syscall_read()`
10. **Parent Process Check** - Verifies parent process isn't Frida/gdbserver using `syscall_read()`
11. **Spawn Timing Check** - Detects suspicious thread counts at early startup

### Build System

- **plugin.xml** - Cordova plugin manifest, defines platform configs and file mappings
- **malfrida.gradle** - Android build configuration with NDK integration
- **Android.mk** - NDK makefile for building native library with security flags
- **Application.mk** - NDK app-level configuration (ABIs, platform, STL)

### Key Components

**MalfridaPlugin.java**:
- Native library loading via `System.loadLibrary("frida_detector")` (triggers constructor)
- JNI method declarations: `nativeDetectFrida()`, `nativeGetDetectionDetails()`, `nativeSetExitOnDetection()`, etc.
- Monitoring thread management with `AtomicBoolean` for thread safety
- Auto-monitoring starts in `pluginInitialize()` immediately (NO delay)
- NOTE: Early detection already completed in native constructor before Java loads

**frida_detector.h/cpp**:
- Core detection logic with configurable threshold
- **Early spawn detection** in `on_load()` constructor using `__attribute__((constructor))`
- JSON result generation for detailed detection info (11 detection methods)
- **All file I/O uses direct syscalls** - `syscall_open()`, `syscall_read()`, `syscall_readlink()`, `syscall_close()`
- Early detection runs 3 critical checks: environment, parent process, threads
- Early detection threshold: 1 (any detection triggers immediate `_exit(1)`)

**syscall_wrapper.S**:
- Assembly implementations for direct syscalls
- Architecture-specific syscall numbers (ARM, ARM64, x86, x86_64)
- **ACTIVELY USED** to bypass Frida hooks on `open()`, `read()`, `readlink()`, `close()`
- Critical for spawn mode prevention

## Native Library Details

### Compiler Flags (Security Hardening)

- `-O3` - Maximum optimization
- `-fvisibility=hidden` - Hide symbols by default
- `-fstack-protector-strong` - Stack canary protection
- `-D_FORTIFY_SOURCE=2` - Buffer overflow protection
- `-fPIE -fPIC` - Position independent code (required for Android 5.0+)
- `-fno-rtti -fno-exceptions` - Reduce binary size

### Linker Flags

- `-Wl,--gc-sections` - Remove unused sections
- `-Wl,--strip-all` - Strip all symbols in release
- `-Wl,-z,relro -Wl,-z,now` - Full RELRO (security hardening)
- `-Wl,-z,noexecstack` - Non-executable stack

### Supported ABIs

All major Android architectures: `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`

## Configuration

### Detection Threshold

Default: 2 points (any 2 detection methods must trigger)
Range: 1-11 (11 total detection methods available)

Configure via JavaScript:
```javascript
cordova.plugins.malfrida.configure({ detectionThreshold: 3 });
```

### Aggressive Mode (Exit on Detection)

**NEW**: Exit app immediately when Frida is detected (in runtime monitoring only - early constructor detection always exits)

```javascript
// Aggressive mode - exit immediately on detection
cordova.plugins.malfrida.configure({
  detectionThreshold: 1,  // Lower threshold
  exitOnDetection: true   // Exit immediately
});
```

**Note**: Early detection in native constructor ALWAYS exits on detection (hardcoded threshold: 1). This configuration only affects runtime monitoring via `detect_frida_comprehensive()`.

### Debug Logging

Disabled by default. Enable via:
```javascript
cordova.plugins.malfrida.configure({ enableLogging: true });
```

### Complete Configuration Example

```javascript
cordova.plugins.malfrida.configure({
  enableLogging: true,         // Show debug logs
  detectionThreshold: 2,       // Require 2+ detections
  exitOnDetection: false       // Just report, don't exit
},
function() { console.log('Configured'); },
function(err) { console.error(err); }
);
```

## Development Notes

### Spawn Mode Prevention

**Critical**: This plugin now prevents Frida spawn mode attacks (`frida -U -f com.package`):

1. **Early Detection in Constructor** - Runs in `on_load()` with `__attribute__((constructor))`
   - Executes BEFORE `JNI_OnLoad()`, BEFORE Java initialization
   - Runs 3 critical checks: environment vars, parent process, thread names
   - Threshold: 1 (any single detection triggers immediate `_exit(1)`)
   - Cannot be bypassed by configuration (hardcoded for security)

2. **Direct Syscalls** - All `/proc` file I/O uses `syscall_wrapper.S`
   - `syscall_open()`, `syscall_read()`, `syscall_close()`, `syscall_readlink()`
   - Bypasses libc hooks that Frida might install
   - Makes detection significantly harder to bypass

3. **Timeline**:
   ```
   App Launch (frida -U -f)
     ↓
   [T+0ms] System.loadLibrary() loads native library
     ↓
   [T+1ms] __attribute__((constructor)) on_load() runs
     ↓
   [T+2ms] Early spawn detection (3 checks, direct syscalls)
     ↓
   [IF DETECTED] _exit(1) - app terminates immediately
     ↓
   [IF CLEAN] Constructor completes, Java initialization continues
     ↓
   [T+100ms] pluginInitialize() called
     ↓
   [T+101ms] Auto-monitoring starts (all 11 checks, continuous)
   ```

### Auto-Start Behavior

The plugin automatically starts monitoring when initialized:
- **NO delay** (starts immediately for spawn prevention)
- 5-second monitoring interval (configurable)
- Runs in background thread
- Runs ALL 11 detection methods every interval
- To modify: edit `pluginInitialize()` and `startAutoMonitoring()` in `MalfridaPlugin.java`

### Thread Safety

- Uses `AtomicBoolean` for monitoring state
- Monitoring runs in separate thread via `cordova.getThreadPool()`
- Callback context kept alive with `PluginResult.setKeepCallback(true)`

### JNI Method Naming

JNI method names must follow exact convention:
`Java_<package>_<class>_<method>` where package uses underscores instead of dots.

Example: `Java_cordova_plugin_malfrida_MalfridaPlugin_nativeDetectFrida`

### ProGuard Configuration

Release builds enable ProGuard obfuscation. Keep rules are defined inline in `malfrida.gradle`:
- Keeps plugin class and native methods
- Keeps Cordova interfaces
- Aggressive obfuscation with `-repackageclasses`

## OutSystems Compatibility

Plugin is designed to be wrapped as OutSystems mobile plugin:
1. Package as `.zip` with all source files
2. Create OutSystems module with resource pointing to zip
3. Create client actions that call `cordova.plugins.malfrida` methods
4. Define structures for detection results

See README.md sections "OutSystems Integration" for detailed wrapper implementation.

## File Structure Key Points

```
src/android/
  ├── MalfridaPlugin.java        # Java bridge (CordovaPlugin)
  ├── malfrida.gradle             # Gradle build config
  └── jni/
      ├── frida_detector.h        # Detection engine header
      ├── frida_detector.cpp      # Detection implementation
      ├── syscall_wrapper.h       # Syscall wrapper declarations
      ├── syscall_wrapper.S       # Assembly syscalls (ARM/x86)
      ├── Android.mk              # NDK build config
      └── Application.mk          # NDK app config

www/
  └── malfrida.js                 # JavaScript API

plugin.xml                        # Cordova plugin manifest
```

## Common Modifications

### Adjusting Monitoring Interval

Edit `MalfridaPlugin.java` line 45:
```java
private int monitoringInterval = 5000; // Default interval (milliseconds)
```

**Note**: The 2-second startup delay was removed for spawn mode prevention.

### Disabling Early Spawn Detection

**WARNING**: This reduces security against spawn mode attacks!

Edit `frida_detector.cpp` line 54:
```cpp
static bool early_detection_enabled = false;  // Disable early detection
```

### Adding New Detection Method

1. Add function declaration in `frida_detector.h`
2. Implement detection function in `frida_detector.cpp`
3. Add to `detect_frida_comprehensive()` - increment array size and call your method
4. Update `detection_results` array size (currently 11)
5. Add field to JSON in `get_detection_details()`
6. **Important**: Use direct syscalls (`syscall_open`, `syscall_read`, etc.) for all file I/O

Example:
```cpp
bool detect_my_new_method() {
    int fd = syscall_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return false;

    char buffer[1024];
    ssize_t bytes = syscall_read(fd, buffer, sizeof(buffer));
    syscall_close(fd);

    // Your detection logic here
    return false;
}
```

### Disabling Auto-Start Monitoring

Edit `MalfridaPlugin.java` - comment out lines 77-82 in `pluginInitialize()`:
```java
// cordova.getThreadPool().execute(new Runnable() {
//     @Override
//     public void run() {
//         startAutoMonitoring();
//     }
// });
```

## Security Considerations

### Strengths

- **Spawn Mode Prevention**: Early detection in constructor prevents `frida -U -f` attacks
- **Direct Syscalls**: All file I/O bypasses libc, making hooks harder to install
- **11 Detection Methods**: Multiple vectors increase detection probability
- **String Obfuscation**: XOR encryption (key: 0x42) hides suspicious strings
- **Early Execution**: Detection runs before app code, before most Frida hooks can activate

### Limitations & Bypass Considerations

- **Detection is not foolproof**: This is a cat-and-mouse game - determined attackers can bypass any protection
- **Recommended use**: One layer in defense-in-depth strategy, not sole protection
- **False positives possible**: May trigger on rooted devices or with legitimate debugging tools
- **Syscalls can be hooked**: Advanced attackers can hook syscall instruction itself
- **Constructor timing**: Very sophisticated Frida scripts might execute before constructor
- **Custom Frida builds**: Modified Frida with different signatures may evade detection

### Best Practices

1. **Combine with other protections**: Root detection, SSL pinning, code obfuscation
2. **Monitor logs**: Watch for detection patterns in production
3. **Tune threshold**: Adjust `detectionThreshold` based on false positive rate
4. **Update regularly**: Frida evolves, detection methods should too
5. **Test thoroughly**: Verify on real devices, not just emulators

## Known Limitations

- **Android-only**: No iOS support
- **Cannot detect all Frida variants**: Custom builds with modified signatures may evade
- **Performance impact**: Continuous monitoring consumes CPU (mitigated by reasonable intervals)
- **ROM compatibility**: Some detection methods may not work on heavily modified Android ROMs
- **Root access**: Attackers with root can disable detection entirely
- **Syscall hooking**: Kernel-level hooks can intercept even direct syscalls
