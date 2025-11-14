package cordova.plugin.malfrida;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import android.util.Log;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Malfrida Cordova Plugin
 *
 * Provides comprehensive Frida instrumentation detection for Android applications.
 * This plugin implements multiple detection vectors in native C++ code and provides
 * a Java bridge for Cordova integration.
 *
 * Detection methods include:
 * - Named pipe detection (Frida communication channels)
 * - Thread name detection (Frida-specific thread names)
 * - Memory mapping scanning (frida-agent libraries)
 * - Port scanning (default Frida ports 27042, 27043)
 * - Memory vs disk comparison
 * - Process detection (frida-server)
 * - Ptrace detection
 * - Library symbol scanning
 *
 * @author Security Team
 * @version 1.0.0
 */
public class MalfridaPlugin extends CordovaPlugin {

    private static final String TAG = "MalfridaPlugin";
    private static final String PLUGIN_VERSION = "1.0.0";

    // Configuration
    private boolean enableLogging = false;
    private int detectionThreshold = 2;

    // Monitoring state
    private AtomicBoolean isMonitoring = new AtomicBoolean(false);
    private Thread monitoringThread = null;
    private CallbackContext monitoringCallback = null;
    private int monitoringInterval = 5000; // Default 5 seconds

    // Load native library
    static {
        try {
            System.loadLibrary("frida_detector");
            Log.d(TAG, "Native library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library: " + e.getMessage());
        }
    }

    // Native method declarations (JNI)
    private native boolean nativeDetectFrida();
    private native String nativeGetDetectionDetails();
    private native void nativeSetLogging(boolean enabled);
    private native void nativeSetThreshold(int threshold);
    private native void nativeSetExitOnDetection(boolean enabled);
    private native String nativeGetVersion();

    /**
     * Plugin initialization - called when plugin loads
     * Starts auto-monitoring immediately (no delay for spawn mode prevention)
     */
    @Override
    public void pluginInitialize() {
        super.pluginInitialize();
        logDebug("Plugin initialized - version " + PLUGIN_VERSION);

        // Auto-start monitoring immediately
        // Default interval: 5 seconds
        // NOTE: Early detection already ran in native constructor
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                startAutoMonitoring();
            }
        });
    }

    /**
     * Execute plugin actions from JavaScript
     */
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext)
            throws JSONException {

        logDebug("Execute action: " + action);

        switch (action) {
            case "detectFrida":
                return detectFrida(callbackContext);

            case "startMonitoring":
                int intervalMs = args.getInt(0);
                return startMonitoring(intervalMs, callbackContext);

            case "stopMonitoring":
                return stopMonitoring(callbackContext);

            case "getDetectionDetails":
                return getDetectionDetails(callbackContext);

            case "configure":
                JSONObject config = args.getJSONObject(0);
                return configure(config, callbackContext);

            case "getVersion":
                return getVersion(callbackContext);

            default:
                callbackContext.error("Invalid action: " + action);
                return false;
        }
    }

    /**
     * Perform one-time Frida detection
     */
    private boolean detectFrida(final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                try {
                    logDebug("Running Frida detection...");

                    boolean detected = nativeDetectFrida();

                    JSONObject result = new JSONObject();
                    result.put("detected", detected);
                    result.put("timestamp", System.currentTimeMillis());
                    result.put("message", detected ? "Frida detected" : "No detection");

                    if (detected) {
                        Log.w(TAG, "SECURITY WARNING: Frida instrumentation detected!");
                    }

                    callbackContext.success(result);

                } catch (Exception e) {
                    Log.e(TAG, "Detection error: " + e.getMessage(), e);
                    callbackContext.error("Detection failed: " + e.getMessage());
                }
            }
        });
        return true;
    }

    /**
     * Start continuous monitoring for Frida
     */
    private boolean startMonitoring(final int intervalMs, final CallbackContext callbackContext) {
        logDebug("Starting monitoring with interval: " + intervalMs + "ms");

        if (isMonitoring.get()) {
            logDebug("Monitoring already active");
            callbackContext.error("Monitoring already active");
            return false;
        }

        if (intervalMs < 1000) {
            callbackContext.error("Interval must be at least 1000ms");
            return false;
        }

        monitoringInterval = intervalMs;
        monitoringCallback = callbackContext;
        isMonitoring.set(true);

        // Send initial success response
        PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
        result.setKeepCallback(true);
        callbackContext.sendPluginResult(result);

        // Start monitoring thread
        monitoringThread = new Thread(new Runnable() {
            @Override
            public void run() {
                logDebug("Monitoring thread started");

                while (isMonitoring.get() && !Thread.currentThread().isInterrupted()) {
                    try {
                        // Perform detection
                        boolean detected = nativeDetectFrida();

                        if (detected) {
                            Log.w(TAG, "SECURITY ALERT: Frida detected during monitoring!");

                            // Prepare detection result
                            JSONObject detectionResult = new JSONObject();
                            detectionResult.put("status", "detected");
                            detectionResult.put("detected", true);
                            detectionResult.put("timestamp", System.currentTimeMillis());
                            detectionResult.put("message", "Frida detected during monitoring");

                            // Send callback to JavaScript
                            PluginResult pluginResult = new PluginResult(
                                PluginResult.Status.OK,
                                detectionResult
                            );
                            pluginResult.setKeepCallback(true);

                            if (monitoringCallback != null) {
                                monitoringCallback.sendPluginResult(pluginResult);
                            }
                        }

                        // Sleep until next check
                        Thread.sleep(monitoringInterval);

                    } catch (InterruptedException e) {
                        logDebug("Monitoring interrupted");
                        break;
                    } catch (Exception e) {
                        Log.e(TAG, "Monitoring error: " + e.getMessage(), e);
                    }
                }

                logDebug("Monitoring thread stopped");
                isMonitoring.set(false);
            }
        });

        monitoringThread.start();
        return true;
    }

    /**
     * Stop continuous monitoring
     */
    private boolean stopMonitoring(CallbackContext callbackContext) {
        logDebug("Stopping monitoring");

        if (!isMonitoring.get()) {
            callbackContext.success("Monitoring not active");
            return true;
        }

        isMonitoring.set(false);

        if (monitoringThread != null && monitoringThread.isAlive()) {
            monitoringThread.interrupt();
            try {
                monitoringThread.join(2000); // Wait up to 2 seconds
            } catch (InterruptedException e) {
                logDebug("Error waiting for monitoring thread: " + e.getMessage());
            }
        }

        monitoringCallback = null;
        callbackContext.success("Monitoring stopped");
        return true;
    }

    /**
     * Get detailed detection results
     */
    private boolean getDetectionDetails(final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                try {
                    logDebug("Getting detection details...");

                    String detailsJson = nativeGetDetectionDetails();
                    JSONObject details = new JSONObject(detailsJson);

                    callbackContext.success(details);

                } catch (Exception e) {
                    Log.e(TAG, "Error getting details: " + e.getMessage(), e);
                    callbackContext.error("Failed to get details: " + e.getMessage());
                }
            }
        });
        return true;
    }

    /**
     * Configure plugin settings
     */
    private boolean configure(JSONObject config, CallbackContext callbackContext) {
        try {
            logDebug("Configuring plugin: " + config.toString());

            if (config.has("enableLogging")) {
                enableLogging = config.getBoolean("enableLogging");
                nativeSetLogging(enableLogging);
                logDebug("Logging enabled: " + enableLogging);
            }

            if (config.has("detectionThreshold")) {
                detectionThreshold = config.getInt("detectionThreshold");
                nativeSetThreshold(detectionThreshold);
                logDebug("Detection threshold set: " + detectionThreshold);
            }

            if (config.has("exitOnDetection")) {
                boolean exitOnDetection = config.getBoolean("exitOnDetection");
                nativeSetExitOnDetection(exitOnDetection);
                logDebug("Exit on detection: " + exitOnDetection);
            }

            callbackContext.success("Configuration updated");
            return true;

        } catch (JSONException e) {
            Log.e(TAG, "Configuration error: " + e.getMessage(), e);
            callbackContext.error("Configuration failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get plugin version information
     */
    private boolean getVersion(CallbackContext callbackContext) {
        try {
            String nativeVersion = nativeGetVersion();

            JSONObject versionInfo = new JSONObject();
            versionInfo.put("version", PLUGIN_VERSION);
            versionInfo.put("nativeVersion", nativeVersion);
            versionInfo.put("platform", "android");

            callbackContext.success(versionInfo);
            return true;

        } catch (JSONException e) {
            callbackContext.error("Failed to get version: " + e.getMessage());
            return false;
        }
    }

    /**
     * Auto-start monitoring (called during initialization)
     */
    private void startAutoMonitoring() {
        logDebug("Auto-starting monitoring...");

        if (!isMonitoring.get()) {
            isMonitoring.set(true);

            monitoringThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    logDebug("Auto-monitoring thread started");

                    while (isMonitoring.get() && !Thread.currentThread().isInterrupted()) {
                        try {
                            boolean detected = nativeDetectFrida();

                            if (detected) {
                                Log.w(TAG, "SECURITY ALERT: Frida detected during auto-monitoring!");
                                // Since this is auto-monitoring, we just log
                                // The app can call getDetectionDetails() to get specifics
                            }

                            Thread.sleep(monitoringInterval);

                        } catch (InterruptedException e) {
                            logDebug("Auto-monitoring interrupted");
                            break;
                        } catch (Exception e) {
                            Log.e(TAG, "Auto-monitoring error: " + e.getMessage());
                        }
                    }

                    logDebug("Auto-monitoring thread stopped");
                }
            });

            monitoringThread.start();
        }
    }

    /**
     * Cleanup when plugin is destroyed
     */
    @Override
    public void onDestroy() {
        logDebug("Plugin destroyed - cleaning up");

        isMonitoring.set(false);

        if (monitoringThread != null && monitoringThread.isAlive()) {
            monitoringThread.interrupt();
            try {
                monitoringThread.join(1000);
            } catch (InterruptedException e) {
                // Ignore
            }
        }

        super.onDestroy();
    }

    /**
     * Handle app pause
     */
    @Override
    public void onPause(boolean multitasking) {
        logDebug("App paused");
        super.onPause(multitasking);
    }

    /**
     * Handle app resume
     */
    @Override
    public void onResume(boolean multitasking) {
        logDebug("App resumed");
        super.onResume(multitasking);
    }

    /**
     * Handle app reset
     */
    @Override
    public void onReset() {
        logDebug("App reset");

        // Stop monitoring on reset
        isMonitoring.set(false);
        if (monitoringThread != null && monitoringThread.isAlive()) {
            monitoringThread.interrupt();
        }

        super.onReset();
    }

    /**
     * Debug logging helper
     */
    private void logDebug(String message) {
        if (enableLogging) {
            Log.d(TAG, message);
        }
    }
}
