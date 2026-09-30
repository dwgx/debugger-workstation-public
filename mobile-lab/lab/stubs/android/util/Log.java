package android.util;

/**
 * COMPILE-TIME STUB. Part of the self-authored sample lab, not the Android platform.
 *
 * There is no android.jar on this box (no Android SDK platform is installed), so the lab
 * declares the handful of framework types it references. These stubs are passed to
 * javac and to d8's --lib, and are NOT packaged into the APK: on a real device the
 * platform supplies the real classes. The APK therefore contains only com.lab.* code,
 * which is what a real app would ship.
 *
 * Method bodies here are never executed — they exist so javac can typecheck. Returning
 * 0 is the conventional "success" answer and keeps the stubs honest about being inert.
 */
public final class Log {
    private Log() {}
    public static int v(String tag, String msg) { return 0; }
    public static int d(String tag, String msg) { return 0; }
    public static int i(String tag, String msg) { return 0; }
    public static int w(String tag, String msg) { return 0; }
    public static int e(String tag, String msg) { return 0; }
}
