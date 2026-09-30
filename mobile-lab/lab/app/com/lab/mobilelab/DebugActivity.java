package com.lab.mobilelab;

import android.util.Log;

/**
 * A non-exported activity. Exists so the manifest extractor has a second `<activity>` with
 * exported=false and no intent-filter, so a report that only looks at the launcher cannot
 * pass by accident.
 */
public class DebugActivity {
    private static final String TAG = "MobileLab";

    public void onCreate() {
        Log.d(TAG, "debug screen (not exported)");
    }
}
