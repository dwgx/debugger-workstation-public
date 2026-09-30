/* core.c -- the native half of the headless lab.
 *
 * Two exports, deliberately shaped so that the headless capabilities have
 * something real to chew on:
 *
 *   checksum(buf, len)  a loop with an XOR and an IMUL: dense in P-code, and the
 *                       body hash changes when a single constant changes
 *   classify(a, b)      four basic blocks including a loop with an early exit --
 *                       a CFG with a real edge that is not fallthrough
 *
 * Build two variants from this one file with -DLAB_MASK=0xA7 and
 * -DLAB_MASK=0x3C. `classify` is byte-identical between them; `checksum` is not.
 * That difference is the ground truth the cross-binary diff has to reproduce.
 *
 * Build: cl /nologo /LD /O1 core.c /Fe:core_v1.dll
 *        cl /nologo /LD /O1 /DLAB_MASK=0x3C core.c /Fe:core_v2.dll
 */

#include <stdint.h>

#define EXPORT __declspec(dllexport)

#ifndef LAB_MASK
#define LAB_MASK 0xA7
#endif

/* A struct the analyst is expected to author in Ghidra from the field map, and
 * a function that reads it, so /create_struct has a real consumer. */
struct header {
    uint32_t magic;
    uint16_t version;
    uint16_t count;
    uint32_t checksum;
};

EXPORT uint32_t checksum(const unsigned char *buf, int len)
{
    uint32_t h = 0x811c9dc5u ^ LAB_MASK;
    int i;

    if (buf == 0 || len <= 0) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        h ^= buf[i];
        h *= 16777619u;
    }

    return h & 0x7fffffffu;
}

EXPORT int classify(int a, int b)
{
    if (a < 0) {
        return -1;
    }

    if (b == 0) {
        return 0;
    }

    while (a > b) {
        a -= b;
        if (a == 1) {
            return 3;
        }
    }

    return a % b;
}

EXPORT uint32_t header_magic(const struct header *h)
{
    if (h == 0) {
        return 0;
    }
    return h->magic ^ ((uint32_t)h->version << 16) ^ h->count;
}
