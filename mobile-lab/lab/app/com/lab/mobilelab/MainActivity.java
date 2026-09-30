package com.lab.mobilelab;

import android.content.Context;
import android.os.Build;
import android.util.Log;

/**
 * Self-authored sample activity for the mobile-lab static analysis lane.
 *
 * This is deliberately NOT a hardened app. It is an ordinary app that happens to contain
 * every artefact the analyser is built to find, so the analyser can be scored against a
 * ground truth we wrote down rather than against a third-party APK:
 *
 *   - a JNI boundary (System.loadLibrary + native methods)          -> JNI tracing
 *   - OkHttp CertificatePinner pinning                              -> pinning class 1
 *   - a hand-rolled X509TrustManager with a hostname allowlist     -> pinning class 3
 *   - network_security_config.xml with <pin-set>                    -> pinning class 2
 *   - hardcoded endpoints and an API key-shaped constant            -> string/endpoint extraction
 *   - anti-debug / anti-frida *detection* in our own code           -> detector scoring
 *
 * The protection code here is DETECTION (it reports and refuses), never evasion, and it is
 * our own sample. See README.md "Stop lines".
 */
public class MainActivity {

    private static final String TAG = "MobileLab";

    /** The library name the JNI layer is loaded from. The analyser must map this to lib/<abi>/mobilelab.so. */
    private static final String NATIVE_LIB = "mobilelab";

    static {
        // JNI boundary #1: the static initialiser. This is the loadLibrary the tracer keys on.
        System.loadLibrary(NATIVE_LIB);
    }

    private final Context context;
    private final ApiClient apiClient;
    private final IntegrityGuard integrityGuard;

    public MainActivity(Context context) {
        this.context = context;
        this.apiClient = new ApiClient();
        this.integrityGuard = new IntegrityGuard();
    }

    /**
     * JNI boundary #2: the declaration side. The analyser must pair every `native`
     * method here with a `Java_com_lab_mobilelab_*` symbol in lib/<abi>/mobilelab.so.
     */
    public native byte[] nativeDeriveKey(byte[] salt, int rounds);

    /** JNI: returns a device-bound token. Throws if the native integrity check fails. */
    public native String nativeAttest(String challenge);

    /** JNI: reads a value out of native memory — the target of the memory-read Frida helper. */
    public native int nativeReadFlag(int index);

    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("sdk=").append(Build.VERSION.SDK_INT);
        sb.append(" abi=").append(Build.CPU_ABI.ABI);
        sb.append(" pkg=").append(context.getPackageName());
        sb.append(" lib=").append(NATIVE_LIB);
        return sb.toString();
    }

    /**
     * The happy path. Ordered so that every interesting subsystem is actually reached.
     */
    public void onCreate() {
        Log.i(TAG, describe());

        // Anti-tamper / anti-instrumentation DETECTION, on our own sample.
        if (integrityGuard.isBeingDebugged()) {
            Log.w(TAG, "debugger attached: refusing to serve secrets");
        }
        if (integrityGuard.hasFridaServer()) {
            Log.w(TAG, "frida-server reachable on 27042");
        }

        // JNI round-trip.
        byte[] salt = Endpoints.SALT.getBytes();
        byte[] key = nativeDeriveKey(salt, 4096);
        Log.i(TAG, "derived key bytes=" + key.length);

        String attestation = nativeAttest("challenge-1");
        Log.i(TAG, "attestation=" + attestation);

        // Network path: two independent pinning mechanisms are in play.
        Log.i(TAG, "endpoint " + Endpoints.API_BASE + Endpoints.PATH_SESSION);
        apiClient.fetchSession();
    }

    /** Reads a flag out of the native array. Exists to give the memory-read helper a target. */
    public int featureFlag(int index) {
        return nativeReadFlag(index);
    }
}
