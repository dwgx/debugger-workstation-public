/* labnative.c -- the native half of m05.
 *
 * Two exports, both C calling convention:
 *
 *   LabTransform(buf, len, seed)   in-place transform, returns len or -1
 *   LabCheck(key, len)             1 when key is the accepted secret
 *
 * The accepted secret is not in the binary as a string. `kWanted` is stored
 * XOR-masked with kMaskKey, and it is not the secret itself but the secret after
 * LabTransform with seed 0x2A. Recovering the key therefore takes two inverse
 * steps, in the opposite order from the forward transform, and getting the order
 * wrong yields a 14-byte answer that is simply wrong.
 *
 * Build: cl /nologo /LD labnative.c /Fe:labnative.dll
 */

#include <string.h>

#define EXPORT __declspec(dllexport)

static const unsigned char kMasked[14] = {
    0xBA, 0xC0, 0xB9, 0xA2, 0xCC, 0xD3, 0xDC, 0xD2, 0xA7, 0xA2, 0xA7, 0xC2,
    0xAF, 0xAC
};

static const unsigned char kMaskKey = 0xA7;

static const int kSeed = 0x2A;

static void Unmask(unsigned char out[14])
{
    int i;
    for (i = 0; i < 14; i++) {
        out[i] = (unsigned char)(kMasked[i] ^ kMaskKey);
    }
}

EXPORT int LabTransform(unsigned char *buf, int len, unsigned char seed)
{
    int i;
    unsigned char t;

    if (buf == 0 || len <= 0) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        buf[i] = (unsigned char)(buf[i] ^ (unsigned char)(seed + i * 3));
    }

    for (i = len - 1; i > 0; i -= 2) {
        t = buf[i - 1];
        buf[i - 1] = buf[i];
        buf[i] = t;
    }

    return len;
}

EXPORT int LabCheck(const unsigned char *key, int len)
{
    unsigned char wanted[14];
    int i;

    if (key == 0 || len != 14) {
        return 0;
    }

    Unmask(wanted);

    for (i = 0; i < 14; i++) {
        if (key[i] != wanted[i]) {
            return 0;
        }
    }

    return 1;
}
