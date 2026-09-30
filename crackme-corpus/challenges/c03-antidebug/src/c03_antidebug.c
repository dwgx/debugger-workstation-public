/*
 * c03_antidebug.c -- crackme #3: naive anti-debug plus a self-integrity check.
 *
 * Authored for the debugger-workstation crackme corpus (D15). Self-authored
 * teaching sample: a program we own, checking whether *it* is being observed.
 * It is not a bypass for anybody else's software.
 *
 * Technique taught: recognising anti-analysis in a sample and knowing that a
 * result produced under a debugger can be a fabrication.
 *
 * Three guards, weakest first:
 *   1. IsDebuggerPresent()                 -- the naive API check.
 *   2. a direct read of PEB->BeingDebugged -- no import, nothing for a hook to
 *      catch; the classic step up from (1).
 *   3. a QueryPerformanceCounter window    -- catches single-stepping/tracing.
 *   Plus an FNV-1a checksum over the sealed key table, so patching the data to
 *   "make it say ACCEPTED" produces INTEGRITY FAILURE instead.
 *
 * The trap: if any guard fires, the program prints ACCEPTED and a *decoy* flag
 * for any password at all. Run it in a debugger, believe the flag, be wrong.
 * The real password and flag are sealed with a rolling XOR (seed + i*step) and
 * are not present in the file in plaintext.
 *
 * Build: see ../README.md. Known answer: see ../README.md.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Rolling-XOR sealed "C03-ROLLING-KEY-7D" (seed 0x77, step 0x0D). */
static const unsigned char kSealedKey[18] = {
    0x34, 0xB4, 0xA2, 0xB3, 0xF9, 0xF7, 0x89, 0x9E, 0x96, 0xA2, 0xBE, 0x2B,
    0x58, 0x65, 0x74, 0x17, 0x70, 0x10,
};

/* Rolling-XOR sealed "FLAG{c03_rolling_key_behind_guard}" (seed 0x2C, step 0x11). */
static const unsigned char kSealedFlag[34] = {
    0x6A, 0x71, 0x0F, 0x18, 0x0B, 0xE2, 0xA2, 0x90, 0xEB, 0xB7, 0xB9, 0x8B,
    0x94, 0x60, 0x74, 0x4C, 0x63, 0x26, 0x3B, 0x16, 0xDF, 0xF3, 0xC7, 0xDB,
    0xAD, 0xBB, 0x82, 0xA8, 0x6F, 0x6C, 0x4B, 0x49, 0x28, 0x20,
};

/* The lie, in plaintext. `strings` finds this one first. */
static const char kDecoyFlag[] = "FLAG{c03_debugger_present_decoy}";

#define KEY_SEED 0x77u
#define KEY_STEP 0x0Du
#define FLAG_SEED 0x2Cu
#define FLAG_STEP 0x11u

#define KEY_FNV1A 0x2EE8BA30u

static void unseal(const unsigned char *src, int n, unsigned char seed, unsigned char step, char *dst)
{
    unsigned char k = seed;
    int i;
    for (i = 0; i < n; ++i) {
        dst[i] = (char)(src[i] ^ k);
        k = (unsigned char)(k + step);
    }
    dst[n] = '\0';
}

static int integrity_ok(void)
{
    unsigned int h = 0x811C9DC5u;
    int i;
    for (i = 0; i < (int)sizeof kSealedKey; ++i) {
        h ^= kSealedKey[i];
        h *= 0x01000193u;
    }
    return h == KEY_FNV1A;
}

static int peb_being_debugged(void)
{
    unsigned char flag = 0;
#ifdef _M_X64
    flag = *(volatile unsigned char *)(__readgsqword(0x60) + 2);
#else
    __asm { mov eax, fs:[0x30] ; movzx eax, byte ptr [eax+2] ; mov flag, al }
#endif
    return flag != 0;
}

static int timing_says_traced(void)
{
    LARGE_INTEGER freq, a, b;
    volatile unsigned long sink = 0;
    unsigned long i;
    double ms;

    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0) {
        return 0;
    }
    QueryPerformanceCounter(&a);
    for (i = 0; i < 2000000ul; ++i) {
        sink += i;
    }
    QueryPerformanceCounter(&b);
    ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)freq.QuadPart;
    return ms > 250.0; /* ~2 ms clean; single-stepping blows straight past this */
}

static int traced(void)
{
    if (IsDebuggerPresent()) {
        return 1;
    }
    if (peb_being_debugged()) {
        return 1;
    }
    return timing_says_traced();
}

int main(int argc, char **argv)
{
    char key[32];
    char flag[48];

    if (argc != 2) {
        printf("usage: %s <password>\n", argv[0]);
        return 2;
    }

    if (!integrity_ok()) {
        puts("INTEGRITY FAILURE");
        return 3;
    }

    if (traced()) {
        /* The trap: any input "passes" here, and the flag is a lie. */
        puts("ACCEPTED");
        puts(kDecoyFlag);
        return 0;
    }

    unseal(kSealedKey, (int)sizeof kSealedKey, KEY_SEED, KEY_STEP, key);
    unseal(kSealedFlag, (int)sizeof kSealedFlag, FLAG_SEED, FLAG_STEP, flag);

    if (strcmp(argv[1], key) == 0) {
        puts("ACCEPTED");
        puts(flag);
        return 0;
    }

    puts("REJECTED");
    return 1;
}
