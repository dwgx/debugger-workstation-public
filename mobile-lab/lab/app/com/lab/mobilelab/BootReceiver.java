package com.lab.mobilelab;

/**
 * An exported receiver with a BOOT_COMPLETED filter. Exists so the extractor has an
 * exported=true component that is not the launcher activity — the case where "exported"
 * is the security-relevant bit.
 */
public class BootReceiver {
    public void onReceive(Object context, Object intent) {
        /* self-authored fixture: deliberately does nothing on boot */
    }
}
