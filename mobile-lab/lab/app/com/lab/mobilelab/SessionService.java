package com.lab.mobilelab;

import android.util.Log;

/**
 * A non-exported service. Exists so the manifest extractor has a `<service>` that is NOT
 * exported, and the report has to distinguish it from the exported receiver.
 */
public class SessionService {

    private static final String TAG = "MobileLab";

    public int onCreate() {
        Log.i(TAG, "session service up");
        return 0;
    }
}
