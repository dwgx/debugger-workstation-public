/*
 * c05_blob.c -- crackme #5: recover a packed record layout from a data blob.
 *
 * Authored for the debugger-workstation crackme corpus (D15). Self-authored
 * teaching sample. The blob and its layout were written by hand for this
 * exercise; no third-party file format is reproduced or parsed.
 *
 * Technique taught: data-format reversing, the discipline you need the moment
 * the interesting part of a program is not its code but its data. You are given
 * a byte blob whose header says almost nothing and whose body is a run of
 * records. The only way in is to reconstruct the record layout the program
 * expects, then read the records with it.
 *
 * The exercise has four parts, and each one is load-bearing:
 *
 *   1. The magic and the version. The first two bytes are a magic; byte 2 is a
 *      version that selects the record size. Get the version wrong and every
 *      offset after it is wrong too. The header is a contract, not decoration.
 *   2. The struct. Records are NOT stored in declaration order. read_record()
 *      pulls each field out of an explicit offset, and those offsets are the
 *      on-disk order -- which is not the order anyone would declare them in.
 *      There is no struct definition in the file to read; the mapping has to be
 *      derived from the field-width evidence the code leaves behind.
 *   3. The decoys. Records with the decoy flag set are structurally perfect and
 *      must be excluded. Including them is the most common way to get a
 *      plausible-looking but wrong answer here, because the records still parse.
 *   4. The hashed byte range. The per-record checksum covers one byte range and
 *      the key material covers a different, overlapping-but-unequal one. Getting
 *      either range wrong yields a well-formed answer that is simply not the
 *      right one -- and the per-record checksum is what tells you which records
 *      you misread.
 *
 * The per-record checksums are genuine, so a partially-recovered layout gets
 * rejected record by record. That feedback loop is what this technique gives
 * you and string-scraping does not: you find out exactly which records are
 * wrong instead of guessing.
 *
 * Strictly benign: a synthetic format, a synthetic blob, a password. No real
 * file format is parsed, nothing is unpacked, no third-party software is
 * involved, and the program touches no file, network, or registry.
 *
 * Build: see ../README.md (MSVC cl.exe through vcvars64).
 * Known answer: see ../README.md.
 */
#include <stdio.h>
#include <string.h>

#define MAGIC        0xC0DEu
#define VERSION      3u
#define REC_SIZE_V3  20u
#define REC_SIZE_V2  16u   /* older, shorter records -- a different layout */
#define RECORDS_OFF  8u    /* header: magic, version, count, header-flags */
#define LIVE_MIN     4     /* below this the blob is judged malformed */

#define HASH_OFF     0u    /* record_hash covers offsets 0..13  */
#define HASH_LEN     14u
#define KEY_OFF      4u    /* the key material covers offsets 4..17 */
#define KEY_LEN      14u

/* The on-disk record, version 3, 20 bytes, in storage order:
 *
 *   off  size  field        note
 *   0    2     u16 magic     0xC0DE, little-endian
 *   2    1     u8  version   3
 *   3    1     u8  flags     bit0 = "live", bit1 = decoy
 *   4    4     u32 tag       per-record nonce
 *   8    2     i16 weight    signed
 *   10   4     u32 stamp     seconds since the lab epoch
 *   14   4     u32 digest    FNV-1a over offsets 0..13, stored here
 *   18   2     u16 salt      per-record salt; in neither hashed range
 */

static const unsigned char kBlob[8 + 12 * 20] = {
    0xDE, 0xC0, 0x03, 0x0C, 0xA5, 0x00, 0x00, 0x00,          /* header */
    /*  0 */ 0xDE, 0xC0, 0x03, 0x01, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0xA6, 0xBD, 0x3A, 0x0F, 0x00, 0x2C,
    /*  1 */ 0xDE, 0xC0, 0x03, 0x01, 0x11, 0x20, 0x00, 0x00, 0xE0, 0xFF, 0x28, 0x03, 0x00, 0x00, 0xDE, 0xA0, 0xBC, 0x33, 0x3D, 0x2C,
    /*  2 */ 0xDE, 0xC0, 0x03, 0x01, 0x22, 0x30, 0x00, 0x00, 0x30, 0x00, 0x50, 0x03, 0x00, 0x00, 0xF8, 0x92, 0xBB, 0x0D, 0x7A, 0x2C,
    /*  3 */ 0xDE, 0xC0, 0x03, 0x01, 0x33, 0x40, 0x00, 0x00, 0xC0, 0xFF, 0x78, 0x03, 0x00, 0x00, 0x54, 0xCB, 0x76, 0xDC, 0xB7, 0x2C,
    /*  4 */ 0xDE, 0xC0, 0x03, 0x02, 0x44, 0x50, 0x00, 0x00, 0x50, 0x00, 0xA0, 0x03, 0x00, 0x00, 0x77, 0x55, 0x69, 0x4C, 0xF4, 0x2C, /* decoy */
    /*  5 */ 0xDE, 0xC0, 0x03, 0x01, 0x55, 0x60, 0x00, 0x00, 0xA0, 0xFF, 0xC8, 0x03, 0x00, 0x00, 0xEA, 0x93, 0x73, 0x15, 0x31, 0x2D,
    /*  6 */ 0xDE, 0xC0, 0x03, 0x01, 0x66, 0x70, 0x00, 0x00, 0x70, 0x00, 0xF0, 0x03, 0x00, 0x00, 0x3C, 0x45, 0x95, 0xCA, 0x6E, 0x2D,
    /*  7 */ 0xDE, 0xC0, 0x03, 0x02, 0x77, 0x80, 0x00, 0x00, 0x80, 0xFF, 0x18, 0x04, 0x00, 0x00, 0x80, 0x12, 0x98, 0x47, 0xAB, 0x2D, /* decoy */
    /*  8 */ 0xDE, 0xC0, 0x03, 0x01, 0x88, 0x90, 0x00, 0x00, 0x90, 0x00, 0x40, 0x04, 0x00, 0x00, 0x0F, 0xCF, 0x97, 0x4F, 0xE8, 0x2D,
    /*  9 */ 0xDE, 0xC0, 0x03, 0x01, 0x99, 0xA0, 0x00, 0x00, 0x60, 0xFF, 0x68, 0x04, 0x00, 0x00, 0x87, 0x94, 0x18, 0xB5, 0x25, 0x2E,
    /* 10 */ 0xDE, 0xC0, 0x03, 0x01, 0xAA, 0xB0, 0x00, 0x00, 0xB0, 0x00, 0x90, 0x04, 0x00, 0x00, 0x8D, 0xA1, 0x46, 0x43, 0x62, 0x2E,
    /* 11 */ 0xDE, 0xC0, 0x03, 0x01, 0xBB, 0xC0, 0x00, 0x00, 0x40, 0xFF, 0xB8, 0x04, 0x00, 0x00, 0x11, 0xF6, 0x30, 0x0A, 0x9F, 0x2E,
};

/* Deliberate decoy, sealed exactly like a real credential. It is never
 * accepted, because the expected password is not stored anywhere: it is
 * *derived* from the record layout at run time. `strings | grep C05` and any
 * solver that assumes a sealed table is the credential both land here. */
static const unsigned char kSealedDecoy[21] = {
    0x10, 0x6C, 0x50, 0x43, 0x33, 0xC5, 0xCA, 0xDD, 0xC2, 0x89, 0xEF,
    0xFA, 0xF0, 0x8A, 0xFC, 0x96, 0xA2, 0xB5, 0xBA, 0xAB, 0x53,
};

#define PW_SEED 0x53u
#define PW_STEP 0x09u

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

static unsigned int rd16(const unsigned char *p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8);
}

static unsigned int rd32(const unsigned char *p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static unsigned int fnv1a(const unsigned char *p, unsigned int n, unsigned int h)
{
    unsigned int i;
    for (i = 0; i < n; ++i) {
        h ^= (unsigned int)p[i];
        h *= 0x01000193u;
    }
    return h;
}

/* ---------------------------------------------------------------------------
 * read_record -- the puzzle.
 *
 * Deliberately not a struct cast. Each field is pulled out of an explicit
 * offset, and those offsets are the on-disk order, which is not the order
 * anyone would declare them in. An analyst recovers this mapping from the
 * field widths and the byte ranges the checks consume, not by reading a
 * definition -- there is no definition in the binary to read.
 * ------------------------------------------------------------------------- */
typedef struct {
    unsigned int  magic;
    unsigned char version;
    unsigned char flags;
    unsigned int  tag;
    int           weight;
    unsigned int  stamp;
    unsigned int  digest;
    unsigned int  salt;
} record;

static int read_record(const unsigned char *p, unsigned int size, record *r)
{
    if (size < REC_SIZE_V3) {
        return 0;
    }
    r->magic   = rd16(p + 0);
    r->version = p[2];
    r->flags   = p[3];
    r->tag     = rd32(p + 4);
    r->weight  = (int)(short)rd16(p + 8);   /* signed 16-bit at offset 8 */
    r->stamp   = rd32(p + 10);
    r->digest  = rd32(p + 14);
    r->salt    = rd16(p + 18);
    return 1;
}

static unsigned int record_hash(const unsigned char *p)
{
    return fnv1a(p + HASH_OFF, HASH_LEN, 0x811C9DC5u);
}

static int record_ok(const unsigned char *p, record *r)
{
    if (r->magic != MAGIC || r->version != VERSION) {
        return 0;
    }
    /* bit1 marks a decoy: structurally perfect, excluded from the key material */
    if (r->flags & 0x02u) {
        return 0;
    }
    return record_hash(p) == r->digest;
}

int main(int argc, char **argv)
{
    char pw[40];
    unsigned int h = 0x811C9DC5u;
    unsigned int i, off, size, count;
    const unsigned char *body;
    int live = 0;

    if (argc != 2) {
        printf("usage: %s <password>\n", argv[0]);
        return 2;
    }

    if (rd16(kBlob) != MAGIC) {
        puts("BAD BLOB (magic)");
        return 3;
    }

    size = (kBlob[2] == 2u) ? REC_SIZE_V2 : REC_SIZE_V3;
    count = kBlob[3];
    body = kBlob + RECORDS_OFF;

    for (i = 0; i < count; ++i) {
        record r;
        off = i * size;
        if (!read_record(body + off, size, &r)) {
            puts("BAD BLOB (short record)");
            return 3;
        }
        if (!record_ok(body + off, &r)) {
            continue;
        }
        live++;
        h = fnv1a(body + off + KEY_OFF, KEY_LEN, h);
    }

    /* A blob whose records do not parse at all is malformed, not merely wrong.
     * The threshold is what separates "you have the wrong layout" from "this
     * file is not what you think it is". */
    if (live == 0) {
        puts("BAD BLOB (no record passed its own digest)");
        return 3;
    }

    /* The credential is not stored. It is the printable rendering of the hash
     * over the correctly-parsed live records, so a wrong layout produces a
     * well-formed password that is simply the wrong one. */
    sprintf_s(pw, sizeof pw, "C05-%08X", h);

    if (strcmp(argv[1], pw) == 0) {
        puts("ACCEPTED");
        puts(pw);
        printf("records: %u declared, %d live, key=fnv1a:%08x "
               "(offsets %u..%u of each record)\n",
               count, live, h, KEY_OFF, KEY_OFF + KEY_LEN - 1);
        return 0;
    }

    /* Say how close the parse got. This is the feedback loop: a wrong record
     * size or a wrong digest offset shows up as too few live records. */
    if (live < LIVE_MIN) {
        printf("BAD BLOB (only %d live records)\n", live);
        return 3;
    }

    unseal(kSealedDecoy, (int)sizeof kSealedDecoy, PW_SEED, PW_STEP, pw);
    puts("REJECTED");
    printf("expected the hash of the live records (%d of %u parsed); "
           "the sealed string in .rdata is a decoy\n", live, count);
    return 1;
}

