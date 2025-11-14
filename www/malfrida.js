/**
 * Malfrida - Frida Detection Plugin for Cordova
 *
 * Provides comprehensive Frida instrumentation detection for Android applications.
 * Implements 11 detection vectors including:
 * - Named pipe detection
 * - Thread name detection
 * - Memory mapping scanning
 * - Port scanning
 * - Memory tampering detection
 * - Process detection
 * - Ptrace detection
 * - Library symbol scanning
 * - Environment variables (spawn-specific)
 * - Parent process check (spawn-specific)
 * - Spawn timing detection (spawn-specific)
 *
 * Features direct syscalls to bypass libc hooks and early detection in native
 * constructor to prevent Frida spawn mode attacks (frida -U -f).
 *
 * @module cordova-plugin-malfrida
 */

var exec = require('cordova/exec');

/**
 * Detection callback
 * @callback DetectionCallback
 * @param {Object} result - Detection result
 * @param {boolean} result.detected - Whether Frida was detected
 * @param {number} result.timestamp - Unix timestamp of detection
 * @param {Object} result.details - Detailed detection information
 */

/**
 * Error callback
 * @callback ErrorCallback
 * @param {string} error - Error message
 */

var Malfrida = {
    /**
     * Internal monitoring callback storage
     * @private
     */
    _monitoringCallback: null,
    _isMonitoring: false,

    /**
     * Perform a one-time Frida detection check
     *
     * @param {Function} successCallback - Called with detection result
     * @param {Function} errorCallback - Called on error
     *
     * @example
     * cordova.plugins.malfrida.detectFrida(
     *   function(result) {
     *     if (result.detected) {
     *       console.log('Frida detected!', result);
     *       // Handle detection (e.g., exit app, show warning)
     *     }
     *   },
     *   function(error) {
     *     console.error('Detection error:', error);
     *   }
     * );
     */
    detectFrida: function(successCallback, errorCallback) {
        exec(successCallback, errorCallback, 'Malfrida', 'detectFrida', []);
    },

    /**
     * Start continuous monitoring for Frida
     * Monitoring will run in background and trigger callback when Frida is detected
     *
     * @param {number} intervalMs - Check interval in milliseconds (recommended: 3000-10000)
     * @param {DetectionCallback} detectionCallback - Called when Frida is detected during monitoring
     * @param {ErrorCallback} errorCallback - Called on error
     *
     * @example
     * // Monitor every 5 seconds
     * cordova.plugins.malfrida.startMonitoring(
     *   5000,
     *   function(result) {
     *     console.log('Monitoring detected Frida:', result);
     *     // Handle detection
     *   },
     *   function(error) {
     *     console.error('Monitoring error:', error);
     *   }
     * );
     */
    startMonitoring: function(intervalMs, detectionCallback, errorCallback) {
        var self = this;

        // Validate interval
        if (typeof intervalMs !== 'number' || intervalMs < 1000) {
            if (errorCallback) {
                errorCallback('Invalid interval. Must be a number >= 1000ms');
            }
            return;
        }

        // Store callback for detection events
        self._monitoringCallback = detectionCallback;
        self._isMonitoring = true;

        // Start native monitoring
        exec(
            function(result) {
                // Monitoring started successfully
                if (result.status === 'started') {
                    // Success - monitoring is now active
                    console.log('[Malfrida] Monitoring started');
                } else if (result.status === 'detected' && self._monitoringCallback) {
                    // Detection event during monitoring
                    self._monitoringCallback(result);
                }
            },
            function(error) {
                self._isMonitoring = false;
                if (errorCallback) {
                    errorCallback(error);
                }
            },
            'Malfrida',
            'startMonitoring',
            [intervalMs]
        );
    },

    /**
     * Stop continuous monitoring
     *
     * @param {Function} successCallback - Called when monitoring stopped
     * @param {Function} errorCallback - Called on error
     *
     * @example
     * cordova.plugins.malfrida.stopMonitoring(
     *   function() {
     *     console.log('Monitoring stopped');
     *   },
     *   function(error) {
     *     console.error('Error stopping monitoring:', error);
     *   }
     * );
     */
    stopMonitoring: function(successCallback, errorCallback) {
        this._isMonitoring = false;
        this._monitoringCallback = null;

        exec(
            successCallback,
            errorCallback,
            'Malfrida',
            'stopMonitoring',
            []
        );
    },

    /**
     * Get detailed detection results from all detection methods
     *
     * @param {Function} successCallback - Called with detailed results
     * @param {Function} errorCallback - Called on error
     *
     * @example
     * cordova.plugins.malfrida.getDetectionDetails(
     *   function(details) {
     *     console.log('Thread detection:', details.threadsDetected);
     *     console.log('Pipes detection:', details.pipesDetected);
     *     console.log('Memory detection:', details.memoryDetected);
     *     console.log('Ports detection:', details.portsDetected);
     *     console.log('Detection score:', details.score);
     *   },
     *   function(error) {
     *     console.error('Error:', error);
     *   }
     * );
     */
    getDetectionDetails: function(successCallback, errorCallback) {
        exec(
            successCallback,
            errorCallback,
            'Malfrida',
            'getDetectionDetails',
            []
        );
    },

    /**
     * Check if monitoring is currently active
     *
     * @returns {boolean} True if monitoring is active
     *
     * @example
     * if (cordova.plugins.malfrida.isMonitoring()) {
     *   console.log('Monitoring is active');
     * }
     */
    isMonitoring: function() {
        return this._isMonitoring;
    },

    /**
     * Configure plugin behavior (optional)
     * Note: Configuration must be set before first detection call
     *
     * @param {Object} config - Configuration options
     * @param {boolean} config.enableLogging - Enable debug logging (default: false)
     * @param {number} config.detectionThreshold - Minimum detection score to trigger (default: 2, max: 11)
     * @param {boolean} config.exitOnDetection - Exit app immediately if Frida detected (default: false)
     * @param {Function} successCallback - Called on success
     * @param {Function} errorCallback - Called on error
     *
     * @example
     * cordova.plugins.malfrida.configure(
     *   {
     *     enableLogging: true,
     *     detectionThreshold: 2,
     *     exitOnDetection: false
     *   },
     *   function() { console.log('Configured'); },
     *   function(err) { console.error(err); }
     * );
     *
     * @example
     * // Aggressive mode - exit immediately on any detection
     * cordova.plugins.malfrida.configure(
     *   {
     *     detectionThreshold: 1,
     *     exitOnDetection: true
     *   },
     *   function() { console.log('Aggressive mode enabled'); },
     *   function(err) { console.error(err); }
     * );
     */
    configure: function(config, successCallback, errorCallback) {
        if (!config || typeof config !== 'object') {
            if (errorCallback) {
                errorCallback('Invalid configuration object');
            }
            return;
        }

        exec(
            successCallback,
            errorCallback,
            'Malfrida',
            'configure',
            [config]
        );
    },

    /**
     * Get plugin version information
     *
     * @param {Function} successCallback - Called with version info
     * @param {Function} errorCallback - Called on error
     *
     * @example
     * cordova.plugins.malfrida.getVersion(
     *   function(info) {
     *     console.log('Plugin version:', info.version);
     *     console.log('Native library version:', info.nativeVersion);
     *   }
     * );
     */
    getVersion: function(successCallback, errorCallback) {
        exec(
            successCallback,
            errorCallback,
            'Malfrida',
            'getVersion',
            []
        );
    }
};

// Export the module
module.exports = Malfrida;
