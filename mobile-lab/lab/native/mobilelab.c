/*
 * mobilelab.c — the native half of the self-authored sample.
 *
 * This file is NOT compiled on this box. There is no Android NDK here (no clang target
 * triple, no sysroot, no libc for an Android ABI), and installing one is explicitly out of
 * scope for this lane — see README.md "The ceiling". What IS shipped in the APK is a
 * hand-assembled ELF shared object built by lab/build/make-so.mjs, which carries the same
 * exported JNI symbol names, the same string table, and the same DT_NEEDED imports as this
 * source describes.
 *
 * That is an honest substitution and it is stated in the README and in the build output:
 * the .so is a real, loadable ELF with a real .dynsym and a real .dynamic section, but its
 * .text is a documented stub rather than the compiled body of this C. The static analysis
 * this lab performs (symbol tables, imports, strings, JNI name mangling, pin extraction from
 * .rodata) is unaffected by that substitution, because none of it depends on the instruction
 * stream. Disassembly of these functions is the ONE claim this lab does not make.
 *
 * The JNI name mangling implemented below is the real JNI spec rule, and it is the same
 * rule the analyser applies when it maps a Java `native` declaration to a .so symbol:
 *
 *   Java_com_lab_mobilelab_MainActivity_nativeDeriveKey
 *     <- class com.lab.mobilelab.MainActivity, method nativeDeriveKey
 *        ('_' -> '_1', ';' -> '_2', '[' -> '_3', '.' -> '/' in the package separator)
 *
 *   overloaded native methods get a __<sig> suffix, e.g.
 *   Java_com_lab_mobilelab_MainActivity_nativeReadFlag__I
 */

#include <stdint.h>
#include <string.h>

/* The native pin table. The Java layer only knows the table id (see NativePinConfig), so
 * these digests are NOT in the DEX — finding them requires reading the .so. That is the
 * whole point of having a third pinning mechanism in the sample. */
static const char *kNativePinTable[2] = {
    "sha256/9xQm2LpVn7RtY1uI4oP6aS8dF0gH3jK5lZ7xC9vB2nM4qW6eR8tY0uI2oP4aS6dF8=",
    "sha256/4kJn8Hd2Fg6Hj0Kl2Mn4Op6Qr8St0Uv2Wx4Yz6Ab8Cd0Ef2Gh4Ij6Kl8Mn0Op2Qr4=",
};

/* Endpoint that exists only in native code — a string the DEX-only pass cannot see. */
static const char *kNativeAttestEndpoint = "https://attest.lab.invalid/v1/verify";

/* Feature flags the memory-read Frida helper targets. */
static int g_feature_flags[4] = {1, 0, 1, 1};

JNIEXPORT jbyteArray JNICALL
Java_com_lab_mobilelab_MainActivity_nativeDeriveKey(JNIEnv *env, jobject thiz,
                                                    jbyteArray salt, jint rounds)
{
    /* Would PBKDF2-HMAC-SHA256(salt, rounds). Returns a 32-byte key. */
    (void)env; (void)thiz; (void)salt; (void)rounds;
    return NULL;
}

JNIEXPORT jstring JNICALL
Java_com_lab_mobilelab_MainActivity_nativeAttest(JNIEnv *env, jobject thiz, jstring challenge)
{
    (void)env; (void)thiz; (void)challenge;
    return NULL;
}

JNIEXPORT jint JNICALL
Java_com_lab_mobilelab_MainActivity_nativeReadFlag(JNIEnv *env, jobject thiz, jint index)
{
    (void)env; (void)thiz;
    if (index < 0 || index >= (jint)(sizeof(g_feature_flags) / sizeof(g_feature_flags[0]))) {
        return -1;
    }
    return g_feature_flags[index];
}

JNIEXPORT jint JNICALL
Java_com_lab_mobilelab_NativePinConfig_verifyNativePin(JNIEnv *env, jobject thiz,
                                                        jint table_id, jbyteArray leaf)
{
    (void)env; (void)thiz; (void)table_id; (void)leaf;
    return 0;
}

JNIEXPORT jbyteArray JNICALL
Java_com_lab_mobilelab_NativePinConfig_nativeLeafCertificate(JNIEnv *env, jobject thiz)
{
    (void)env; (void)thiz;
    return NULL;
}
