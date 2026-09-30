/*
 * c01_stringobf.c -- crackme #1: string-table obfuscation.
 *
 * Authored for the debugger-workstation crackme corpus (D15). Self-authored
 * teaching sample; nothing here is copied from a third party.
 *
 * Technique taught: `strings` -> DiE -> capa -> Ghidra decompile.
 * The acceptance password and the real flag are stored byte-rotated and
 * XOR-masked in .rdata, so no plaintext appears in the file. A decoy flag IS
 * plaintext, so a `strings | grep FLAG` shortcut returns a wrong answer.
 *
 * Build: see ../README.md (MSVC cl.exe through vcvars64).
 * Known answer: see ../README.md.
 */
#include <stdio.h>
#include <string.h>

/* Rotated (11 bytes) and XOR-masked (0x5A) "C01-TABLE-XOR-9F2A". */
static const unsigned char kBlobPw[18] = {
    0x16, 0x1F, 0x77, 0x02, 0x15, 0x08, 0x77, 0x63, 0x1C, 0x68, 0x1B, 0x19,
    0x6A, 0x6B, 0x77, 0x0E, 0x1B, 0x18,
};

/* Rotated (5 bytes) and XOR-masked (0x33) "FLAG{c01_string_table_xor}". */
static const unsigned char kBlobFlag[26] = {
    0x6C, 0x4B, 0x5C, 0x41, 0x4E, 0x75, 0x7F, 0x72, 0x74, 0x48, 0x50, 0x03,
    0x02, 0x6C, 0x40, 0x47, 0x41, 0x5A, 0x5D, 0x54, 0x6C, 0x47, 0x52, 0x51,
    0x5F, 0x56,
};

static const int kRotPw = 11;
static const int kRotFlag = 5;
static const unsigned char kMaskPw = 0x5A;
static const unsigned char kMaskFlag = 0x33;

/* Deliberate decoy: plaintext, never accepted. Punishes `strings | grep FLAG`. */
static const char kDecoy[] = "FLAG{c01_strings_gave_you_this_decoy}";

static void unscramble(const unsigned char *src, int n, int rot, unsigned char mask, char *dst)
{
    int i;
    for (i = 0; i < n; ++i) {
        dst[i] = (char)(src[(i + rot) % n] ^ mask);
    }
    dst[n] = '\0';
}

int main(int argc, char **argv)
{
    char pw[32];
    char flag[40];

    if (argc != 2) {
        printf("usage: %s <password>\n", argv[0]);
        return 2;
    }

    unscramble(kBlobPw, (int)sizeof kBlobPw, kRotPw, kMaskPw, pw);
    unscramble(kBlobFlag, (int)sizeof kBlobFlag, kRotFlag, kMaskFlag, flag);

    if ((strlen(argv[1]) == strlen(kDecoy)) && (strcmp(argv[1], kDecoy) == 0)) {
        puts("REJECTED (that is the decoy)");
        return 1;
    }

    if (strcmp(argv[1], pw) == 0) {
        puts("ACCEPTED");
        puts(flag);
        return 0;
    }

    puts("REJECTED");
    return 1;
}
