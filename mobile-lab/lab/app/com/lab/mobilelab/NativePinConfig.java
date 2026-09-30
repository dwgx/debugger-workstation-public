package com.lab.mobilelab;

/**
 * Pinning mechanism #3 of 3: a NATIVE pin table.
 *
 * The pin digests live in the .so, not in the DEX, and the DEX only names the table. A
 * DEX-only static pass therefore sees a bare "pin" concept with no digests; the digests
 * require reading lib/&lt;abi&gt;/mobilelab.so. The analyser's JNI section has to notice that
 * this class's constants are passed to a native method and follow the boundary.
 *
 * The strings below are duplicated into the .so by the native build, which is exactly the
 * arrangement a real app uses to keep pins out of the Java layer.
 */
public class NativePinConfig {

    /** Index into the native pin table. 0 = current, 1 = backup. */
    public static final int TABLE_INDEX_CURRENT = 0;
    public static final int TABLE_INDEX_BACKUP = 1;

    /** Table id passed straight through to native code. */
    public static final int TABLE_ID = 0x4D4C4231; /* "MLB1" */

    public static String describeTable() {
        return "native pin table id=0x" + Integer.toHexString(TABLE_ID)
                + " slots=" + (TABLE_INDEX_BACKUP + 1);
    }

    /** Hands the table id to the JNI layer, which does the actual pin comparison. */
    public native int verifyNativePin(int tableId, byte[] leafCertificateDer);

    /** Declared so the JNI tracer has a second native edge to resolve. */
    public native byte[] nativeLeafCertificate();
}
