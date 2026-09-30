package android.os;

/**
 * COMPILE-TIME STUB — see android/util/Log.java. Not packaged into the APK.
 *
 * The lab's IntegrityGuard calls these, so the stub exists to let javac typecheck. The
 * implementation the APK actually runs against on a device is the platform's.
 */
public class Debug {
    public static boolean isDebuggerConnected() { return false; }
    public static boolean waitingForDebugger() { return false; }
    public static void waitForDebugger() { }
}
