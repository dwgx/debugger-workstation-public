/*
 * c02_cff.c -- crackme #2: control-flow flattening.
 *
 * Authored for the debugger-workstation crackme corpus (D15). Self-authored
 * teaching sample.
 *
 * Technique taught: reading decompiled output and reconstructing the real
 * logic. The acceptance test is not written as a loop over a string; it is
 * chopped into one basic block per character and glued back together by a
 * dispatcher switch on a state variable. Nothing about the password is
 * contiguous anywhere in the file, so `strings` and data-scanning fail: the
 * only way in is to read the dispatcher and walk the state graph.
 *
 * State graph (recovered form):
 *   state 0 -> 4 -> 7 -> 11 -> 13 -> 16 -> 19 -> 22 -> 26 -> 30 -> 33 -> 35
 *   -> 37 -> 100 (accept);  any mismatch -> 99 (reject).
 *
 * Build: see ../README.md. Known answer: see ../README.md.
 */
#include <stdio.h>
#include <string.h>

#define ST_ACCEPT 100u
#define ST_REJECT 99u

/* Opaque predicate: always true, but not folded at /Od, so a decompile reader
 * has to evaluate it instead of assuming it away. */
static int opaque(void)
{
    volatile unsigned int a = 0x5A5Au;
    volatile unsigned int b = 0x5A5Au;
    return (a ^ b) == 0u;
}

static int run_machine(const char *s)
{
    unsigned int i = 0;
    volatile unsigned int state = 0;
    unsigned int guard = 0;

    if (!opaque()) {
        return 0;
    }

    for (;;) {
        if (++guard > 512u) {
            return 0;
        }
        switch (state) {
        case 0:
            if (s[i] == 'F') { ++i; state = 4; } else { state = ST_REJECT; }
            break;
        case 4:
            if (s[i] == 'L') { ++i; state = 7; } else { state = ST_REJECT; }
            break;
        case 7:
            if (s[i] == '4') { ++i; state = 11; } else { state = ST_REJECT; }
            break;
        case 11:
            if (s[i] == 'T') { ++i; state = 13; } else { state = ST_REJECT; }
            break;
        case 13:
            if (s[i] == '-') { ++i; state = 16; } else { state = ST_REJECT; }
            break;
        case 16:
            if (s[i] == 'S') { ++i; state = 19; } else { state = ST_REJECT; }
            break;
        case 19:
            if (s[i] == 'T') { ++i; state = 22; } else { state = ST_REJECT; }
            break;
        case 22:
            if (s[i] == 'A') { ++i; state = 26; } else { state = ST_REJECT; }
            break;
        case 26:
            if (s[i] == 'T') { ++i; state = 30; } else { state = ST_REJECT; }
            break;
        case 30:
            if (s[i] == 'E') { ++i; state = 33; } else { state = ST_REJECT; }
            break;
        case 33:
            if (s[i] == '-') { ++i; state = 35; } else { state = ST_REJECT; }
            break;
        case 35:
            if (s[i] == '7') { ++i; state = 37; } else { state = ST_REJECT; }
            break;
        case 37:
            if (s[i] == 'B') { ++i; state = ST_ACCEPT; } else { state = ST_REJECT; }
            break;
        case ST_REJECT:
            return 0;
        case ST_ACCEPT:
            return 1;
        default:
            return 0;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: %s <password>\n", argv[0]);
        return 2;
    }
    if (run_machine(argv[1]) == 1) {
        puts("ACCEPTED");
        puts("FLAG{c02_flattened_state_machine}");
        return 0;
    }
    puts("REJECTED");
    return 1;
}
