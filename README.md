# cordova-plugin-malfrida

> Advanced Frida detection plugin for Cordova Android applications

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Android-green.svg)](https://www.android.com/)
[![Cordova](https://img.shields.io/badge/cordova-%3E%3D10.0.0-orange.svg)](https://cordova.apache.org/)

## Overview

**Malfrida** is a comprehensive security plugin that detects and prevents Frida instrumentation attacks on Cordova Android applications. It implements multiple detection vectors in native C++ code to provide robust protection against runtime manipulation.

### Key Features

- **8 Detection Methods**: Comprehensive multi-layered detection approach
- **Native C++ Implementation**: Maximum performance and security
- **Direct Syscalls**: Bypass potential Frida hooks on libc functions
- **Auto-Start Monitoring**: Automatic protection on app launch
- **Flexible API**: Callback-based detection with detailed results
- **OutSystems Compatible**: Ready for OutSystems mobile plugin wrapping
- **Production Ready**: Optimized, obfuscated, and hardened for release builds

## Detection Methods

Malfrida implements the following detection techniques:

1. **Named Pipes Detection** - Scans `/proc/self/fd` for Frida communication pipes
2. **Thread Name Detection** - Identifies Frida-specific threads (`gmain`, `gum-js-loop`, etc.)
3. **Memory Mapping Scan** - Detects `frida-agent` and `frida-gadget` libraries
4. **Port Scanning** - Checks for Frida default ports (27042, 27043)
5. **Memory vs Disk Comparison** - Identifies runtime code modifications
6. **Process Detection** - Scans for `frida-server` process
7. **Ptrace Detection** - Detects if app is being traced/debugged
8. **Symbol Scanning** - Identifies Frida-related symbols in memory

## Installation

### Cordova Installation

```bash
cordova plugin add cordova-plugin-malfrida
```

### Manual Installation

```bash
git clone https://github.com/rizalrinald7/cordova-plugin-malfrida.git
cd cordova-plugin-malfrida
cordova plugin add .
```

### Requirements

- **Cordova**: >= 10.0.0
- **Cordova Android**: >= 10.0.0
- **Android SDK**: API Level 21+ (Android 5.0+)
- **NDK**: CMake 3.10.2+

## Usage

### Basic Detection

Perform a one-time Frida detection check:

```javascript
document.addEventListener('deviceready', function() {
    cordova.plugins.malfrida.detectFrida(
        function(result) {
            if (result.detected) {
                console.warn('Security Alert: Frida detected!');
                // Handle detection (e.g., show warning, exit app)
                alert('Security threat detected. App will exit.');
                navigator.app.exitApp();
            } else {
                console.log('No threats detected');
            }
        },
        function(error) {
            console.error('Detection error:', error);
        }
    );
}, false);
```

### Continuous Monitoring

Start continuous monitoring with custom interval:

```javascript
// Monitor every 5 seconds
cordova.plugins.malfrida.startMonitoring(
    5000,  // Check interval in milliseconds
    function(result) {
        // Called when Frida is detected during monitoring
        console.warn('Frida detected during monitoring:', result);

        // Take action
        alert('Security threat detected!');
        navigator.app.exitApp();
    },
    function(error) {
        console.error('Monitoring error:', error);
    }
);

// Stop monitoring when needed
cordova.plugins.malfrida.stopMonitoring(
    function() {
        console.log('Monitoring stopped');
    },
    function(error) {
        console.error('Error stopping monitoring:', error);
    }
);
```

### Detailed Detection Results

Get detailed information about which detection methods triggered:

```javascript
cordova.plugins.malfrida.getDetectionDetails(
    function(details) {
        console.log('Detection Details:');
        console.log('- Pipes detected:', details.pipesDetected);
        console.log('- Threads detected:', details.threadsDetected);
        console.log('- Memory maps detected:', details.memoryMapsDetected);
        console.log('- Ports detected:', details.portsDetected);
        console.log('- Memory tampering:', details.memoryTamperingDetected);
        console.log('- Process detected:', details.processDetected);
        console.log('- Ptrace detected:', details.ptraceDetected);
        console.log('- Symbols detected:', details.symbolsDetected);
        console.log('- Total score:', details.score);
        console.log('- Threshold:', details.threshold);
        console.log('- Overall detected:', details.detected);
    },
    function(error) {
        console.error('Error:', error);
    }
);
```

### Configuration

Configure plugin behavior (optional):

```javascript
cordova.plugins.malfrida.configure(
    {
        enableLogging: true,        // Enable debug logging (default: false)
        detectionThreshold: 2        // Minimum score to trigger (default: 2)
    },
    function() {
        console.log('Configuration updated');
    },
    function(error) {
        console.error('Configuration error:', error);
    }
);
```

### Check Monitoring Status

```javascript
if (cordova.plugins.malfrida.isMonitoring()) {
    console.log('Monitoring is active');
} else {
    console.log('Monitoring is not active');
}
```

### Get Version Information

```javascript
cordova.plugins.malfrida.getVersion(
    function(info) {
        console.log('Plugin version:', info.version);
        console.log('Native library version:', info.nativeVersion);
        console.log('Platform:', info.platform);
    },
    function(error) {
        console.error('Error:', error);
    }
);
```

## Auto-Start Monitoring

By default, the plugin automatically starts monitoring when the app launches with a 5-second interval. This provides immediate protection without requiring explicit initialization code.

To customize or disable auto-start behavior, modify the `pluginInitialize()` method in `MalfridaPlugin.java`.

## API Reference

### Methods

#### `detectFrida(successCallback, errorCallback)`

Performs a one-time Frida detection check.

- **successCallback**: `function(result)` - Called with detection result
  - `result.detected`: `boolean` - True if Frida detected
  - `result.timestamp`: `number` - Detection timestamp
  - `result.message`: `string` - Human-readable message
- **errorCallback**: `function(error)` - Called on error

#### `startMonitoring(intervalMs, detectionCallback, errorCallback)`

Starts continuous background monitoring.

- **intervalMs**: `number` - Check interval in milliseconds (minimum 1000)
- **detectionCallback**: `function(result)` - Called when detection occurs
- **errorCallback**: `function(error)` - Called on error

#### `stopMonitoring(successCallback, errorCallback)`

Stops continuous monitoring.

- **successCallback**: `function()` - Called when stopped
- **errorCallback**: `function(error)` - Called on error

#### `getDetectionDetails(successCallback, errorCallback)`

Gets detailed results from all detection methods.

- **successCallback**: `function(details)` - Called with detailed results
  - `details.pipesDetected`: `boolean`
  - `details.threadsDetected`: `boolean`
  - `details.memoryMapsDetected`: `boolean`
  - `details.portsDetected`: `boolean`
  - `details.memoryTamperingDetected`: `boolean`
  - `details.processDetected`: `boolean`
  - `details.ptraceDetected`: `boolean`
  - `details.symbolsDetected`: `boolean`
  - `details.score`: `number` - Total detection score (0-8)
  - `details.threshold`: `number` - Current threshold
  - `details.detected`: `boolean` - Overall detection result
- **errorCallback**: `function(error)` - Called on error

#### `configure(config, successCallback, errorCallback)`

Configures plugin behavior.

- **config**: `object` - Configuration options
  - `enableLogging`: `boolean` - Enable debug logging
  - `detectionThreshold`: `number` - Minimum score to trigger (1-8)
- **successCallback**: `function()` - Called on success
- **errorCallback**: `function(error)` - Called on error

#### `isMonitoring()`

Returns whether monitoring is currently active.

- **Returns**: `boolean` - True if monitoring is active

#### `getVersion(successCallback, errorCallback)`

Gets plugin version information.

- **successCallback**: `function(info)` - Called with version info
  - `info.version`: `string` - Plugin version
  - `info.nativeVersion`: `string` - Native library version
  - `info.platform`: `string` - Platform ("android")
- **errorCallback**: `function(error)` - Called on error

## OutSystems Integration

### Creating an OutSystems Mobile Plugin

1. **Create New Module** in OutSystems Service Studio
2. **Add Resource**: Upload `cordova-plugin-malfrida.zip`
3. **Configure Extensibility**:

```json
{
    "plugin": {
        "url": "cordova-plugin-malfrida.zip"
    }
}
```

### OutSystems Client Actions

Create the following client actions in your module:

#### DetectFrida

```javascript
// Output: DetectionResult structure
return new Promise(function(resolve, reject) {
    cordova.plugins.malfrida.detectFrida(
        function(result) {
            resolve({
                Detected: result.detected,
                Timestamp: new Date(result.timestamp),
                Message: result.message
            });
        },
        function(error) {
            reject({ Message: error });
        }
    );
});
```

#### StartMonitoring

```javascript
// Input: IntervalMs (Integer)
// Output: Success message
return new Promise(function(resolve, reject) {
    cordova.plugins.malfrida.startMonitoring(
        $parameters.IntervalMs,
        function(result) {
            // Detection callback
            console.log('Frida detected:', result);
        },
        function(error) {
            reject({ Message: error });
        }
    );
    resolve({ Message: "Monitoring started" });
});
```

### OutSystems Structures

**DetectionResult**:
- Detected: Boolean
- Timestamp: DateTime
- Message: Text

**DetectionDetails**:
- PipesDetected: Boolean
- ThreadsDetected: Boolean
- MemoryMapsDetected: Boolean
- PortsDetected: Boolean
- MemoryTamperingDetected: Boolean
- ProcessDetected: Boolean
- PtraceDetected: Boolean
- SymbolsDetected: Boolean
- Score: Integer
- Threshold: Integer
- Detected: Boolean

## Testing

### Prerequisites

- Physical Android device (emulator may not accurately represent Frida behavior)
- ADB installed and configured
- Frida tools installed (for testing detection)

### Testing Without Frida

1. Build and install the app:
```bash
cordova build android
cordova run android
```

2. Check logs:
```bash
adb logcat | grep FridaDetector
```

3. Expected result: No detection

### Testing With Frida

1. Install Frida server on device:
```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

2. Run the app and check detection

3. Expected result: Frida should be detected

### Testing Detection Methods

Test individual detection methods by observing logs:

```bash
adb logcat | grep "FridaDetector"
```

Look for messages like:
- `Named pipes detection: DETECTED`
- `Thread detection: DETECTED`
- `Memory mapping detection: DETECTED`
- etc.

## Security Considerations

### Detection Threshold

The plugin uses a **scoring system**:
- Each detection method adds 1 point if it detects Frida
- Default threshold is **2 points**
- You can adjust the threshold based on your security requirements:
  - Lower threshold (1): More sensitive, possible false positives
  - Higher threshold (3-4): Less sensitive, fewer false positives

### Known Limitations

1. **No Detection is Perfect**: Determined attackers can bypass any protection
2. **False Positives**: Legitimate debugging tools may trigger detection
3. **Custom Frida Builds**: Modified Frida versions may evade signature-based checks
4. **Rooted Devices**: More difficult to detect on heavily modified systems
5. **Performance**: Continuous monitoring uses CPU/battery (mitigated by reasonable intervals)

### Recommendations

1. **Combine with Other Security Measures**:
   - Certificate pinning
   - Code obfuscation
   - Root detection
   - Tamper detection

2. **Use Reasonable Monitoring Intervals**: 3-10 seconds balances security and performance

3. **Handle Detection Gracefully**: Don't just exit - consider:
   - Showing user-friendly message
   - Logging to server
   - Restricting sensitive features
   - Allowing user to proceed with warning

4. **Keep Updated**: Frida and bypass techniques evolve - update the plugin regularly

5. **Test Thoroughly**: Test on multiple devices and Android versions

## Advanced Configuration

### Adjusting Detection Sensitivity

```javascript
// More sensitive (trigger on any single detection)
cordova.plugins.malfrida.configure({ detectionThreshold: 1 });

// Less sensitive (require multiple detections)
cordova.plugins.malfrida.configure({ detectionThreshold: 3 });
```

### Custom Response Actions

```javascript
cordova.plugins.malfrida.detectFrida(function(result) {
    if (result.detected) {
        // Option 1: Exit immediately
        navigator.app.exitApp();

        // Option 2: Warn user
        navigator.notification.alert(
            'Security threat detected',
            function() { navigator.app.exitApp(); },
            'Security Warning',
            'Exit'
        );

        // Option 3: Restricted mode
        enableRestrictedMode();

        // Option 4: Log to server
        logSecurityEvent('frida_detected', result);
    }
});
```

## Troubleshooting

### Plugin Not Working

1. Verify installation:
```bash
cordova plugin ls
```

2. Check native library was built:
```bash
# Look for libfrida_detector.so in build output
ls platforms/android/app/build/intermediates/cmake/
```

3. Check logs for errors:
```bash
adb logcat | grep -E "FridaDetector|MalfridaPlugin"
```

### Build Errors

**CMake not found**:
```bash
# Install CMake via Android SDK Manager
sdkmanager "cmake;3.10.2.4988404"
```

**NDK not found**:
```bash
# Install NDK
sdkmanager "ndk;21.4.7075529"
```

**ABI errors**:
- Ensure NDK is properly configured in `local.properties`
- Check that `abiFilters` in `malfrida.gradle` matches your needs

### False Positives

If you're getting false positives:

1. Increase detection threshold:
```javascript
cordova.plugins.malfrida.configure({ detectionThreshold: 3 });
```

2. Check which methods are triggering:
```javascript
cordova.plugins.malfrida.getDetectionDetails(function(details) {
    console.log(details);
});
```

3. Disable sensitive checks if needed (requires modifying native code)

## Project Structure

```
cordova-plugin-malfrida/
   plugin.xml                          # Plugin configuration
   package.json                        # NPM package metadata
   README.md                           # This file
   www/
      malfrida.js                    # JavaScript API
   src/
       android/
           MalfridaPlugin.java        # Java bridge
           malfrida.gradle            # Gradle configuration
           cpp/                       # Native C++ code
               CMakeLists.txt         # CMake build config
               frida_detector.h       # Detection engine header
               frida_detector.cpp     # Detection implementation
               syscall_wrapper.h      # Syscall wrapper header
               syscall_wrapper.S      # Assembly syscalls
```

## Building for Production

### Release Build Checklist

1. **Disable Debug Logging**:
```javascript
cordova.plugins.malfrida.configure({ enableLogging: false });
```

2. **Build Release APK**:
```bash
cordova build android --release
```

3. **ProGuard Enabled**: Automatically enabled in release builds

4. **Symbol Stripping**: Native symbols automatically stripped

5. **Sign APK**: Sign with your release keystore

### Optimization Tips

- Adjust monitoring interval based on threat model (longer = better battery)
- Use callback-based detection to avoid blocking UI
- Consider disabling monitoring when app is in background

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup

```bash
git clone https://github.com/rizalrinald7/cordova-plugin-malfrida.git
cd cordova-plugin-malfrida
```

## License

Apache 2.0 License. See [LICENSE](LICENSE) file for details.

## Acknowledgments

- Research based on published Frida detection techniques
- Inspired by security research from the mobile security community
- Built with Cordova and Android NDK

## Support

- **Issues**: [GitHub Issues](https://github.com/rizalrinald7/cordova-plugin-malfrida/issues)
- **Questions**: Open a GitHub Discussion or Issue

## Changelog

### Version 1.0.0 (2025-01-14)

- Initial release
- 8 comprehensive detection methods
- Auto-start monitoring
- OutSystems compatible
- Native C++ implementation with syscalls
- ProGuard obfuscation support
- Production-ready security hardening

---

**Made with security in mind** =
