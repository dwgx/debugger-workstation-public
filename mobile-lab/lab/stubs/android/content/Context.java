package android.content;

import android.content.pm.PackageManager;

/** COMPILE-TIME STUB — see android/util/Log.java. Not packaged into the APK. */
public abstract class Context {
    public static final String TELEPHONY_SERVICE = "phone";
    public abstract PackageManager getPackageManager();
    public abstract String getPackageName();
    public abstract Object getSystemService(String name);
}
