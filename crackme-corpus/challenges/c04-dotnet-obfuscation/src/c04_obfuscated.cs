/*
 * c04_obfuscated.cs -- crackme #4: .NET string encryption + a control-flow VM.
 *
 * Authored for the debugger-workstation crackme corpus (D15). Self-authored
 * teaching sample. Nothing here is copied from a third-party obfuscator; the
 * patterns are the two that show up most often in real .NET obfuscation and
 * that a decompiler can be walked back through.
 *
 * Technique taught: managed-code reversing. A native PE gives you assembly and
 * you fight the compiler. A .NET assembly gives you IL, and IL is close enough
 * to the source that a good decompiler hands the program back nearly intact. So
 * the question is never "can I decompile it" -- it is "what did the obfuscator
 * do to the decompiled output, and how do I undo it".
 *
 * Three things a beginner gets wrong here, on purpose:
 *
 *   1. No string literal survives. Every interesting string is XOR-masked with
 *      a per-string key and only materialised at the point of use, through a
 *      ldtoken field access. `strings` on the assembly, and grepping the
 *      decompiled source for FLAG, both come up empty.
 *   2. The comparison is not a comparison. Verify() runs a tiny VM over an
 *      encrypted program, so the password is never an operand of a string
 *      compare. Reading the decompiled C for == or .Equals finds nothing to
 *      read. You have to recover the VM program instead.
 *   3. The VM's opcodes are not in source order. Each instruction word packs a
 *      *table slot* in the high half, not an opcode, and kOpcodeMap says which
 *      slot belongs to which opcode. Inverting that permutation is the actual
 *      exercise; the VM interpreter body itself is ordinary C#.
 *
 * There is also a decoy instruction in the program that the JMP skips. A
 * solver that walks the words linearly instead of honouring control flow will
 * recover a wrong answer and be rejected by the binary.
 *
 * This is a program we wrote, teaching a technique. It is not a bypass for
 * anyone's product, and it contains no anti-debug, no VM protection of a
 * commercial product, and no third-party code.
 *
 * Build: see ../README.md (dotnet build). Known answer: see ../README.md.
 */
using System;

namespace Crackme.C04
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("usage: c04 <password>");
                Environment.Exit(2);
                return;
            }

            if (Verify(args[0]))
            {
                Console.WriteLine("ACCEPTED");
                Console.WriteLine(Str(0x0A11));
                Environment.Exit(0);
            }

            Console.WriteLine("REJECTED");
            Environment.Exit(1);
        }

        /* ------------------------------------------------------------------
         * String encryption.
         *
         * kStrings holds the masked bytes; kKeys[i] is the single-byte XOR key
         * for kStrings[i]. Str() is the only way to get text out, and it is
         * NoInlining so it stays a real call in the IL -- an analyst needs the
         * call to be visible in order to recognise the pattern at its use site.
         * ------------------------------------------------------------------ */
        private static readonly byte[][] kStrings =
        {
            // slot 0 -- the password (index 0x4F21); the target of CMP_IDX
            new byte[] { 0x0E, 0x7D, 0x79, 0x60, 0x09, 0x02, 0x19, 0x03, 0x08, 0x19, 0x60, 0x1B, 0x00, 0x60, 0x7E, 0x08, 0x74, 0x7C },
            // slot 1 -- the flag (index 0x0A11), printed on ACCEPT
            new byte[] { 0x0B, 0x01, 0x0C, 0x0A, 0x36, 0x2E, 0x7D, 0x79, 0x12, 0x20, 0x2C, 0x23, 0x2C, 0x2A, 0x28, 0x29, 0x12, 0x3B, 0x20, 0x12, 0x3E, 0x39, 0x3F, 0x24, 0x23, 0x2A, 0x12, 0x26, 0x28, 0x34, 0x3E, 0x30 },
            // slot 2 -- printed on a VM fault; a hint, not a credential
            new byte[] { 0x08, 0x13, 0x64, 0x7E, 0x31, 0x2E, 0x3D, 0x31, 0x3A, 0x3B, 0x7E, 0x2A, 0x3F, 0x3C, 0x32, 0x3B, 0x7E, 0x3A, 0x3B, 0x2D, 0x27, 0x30, 0x3D, 0x3B, 0x3A },
            // slot 3 -- the decoy, never accepted
            new byte[] { 0x3E, 0x3F, 0x36, 0x33, 0x38, 0x3F, 0x28, 0x3B, 0x2E, 0x3F, 0x7A, 0x3E, 0x3F, 0x39, 0x35, 0x23, 0x76, 0x7A, 0x34, 0x3F, 0x2C, 0x3F, 0x28, 0x7A, 0x3B, 0x39, 0x39, 0x3F, 0x2A, 0x2E, 0x3F, 0x3E },
        };

        private static readonly byte[] kKeys = { 0x4D, 0x4D, 0x5E, 0x5A };

        private static readonly int[] kIndices = { 0x4F21, 0x0A11, 0x2C03, 0x1F0D };

        [System.Runtime.CompilerServices.MethodImpl(
            System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        private static string Str(int index)
        {
            int slot = Array.IndexOf(kIndices, index);
            if (slot < 0)
            {
                return "<no such string>";
            }

            byte[] masked = kStrings[slot];
            byte key = kKeys[slot];
            char[] outBuf = new char[masked.Length];
            for (int i = 0; i < masked.Length; i++)
            {
                outBuf[i] = (char)(masked[i] ^ key);
            }
            return new string(outBuf);
        }

        /* ------------------------------------------------------------------
         * The VM.
         *
         * An instruction word is (slot << 16) | arg. The slot is NOT an opcode:
         * kOpcodeMap[opcode] gives the slot that opcode lives in, so the
         * interpreter has to invert that table before it can dispatch. The
         * opcode numbers themselves are never written down in the assembly --
         * only the permutation is. That inversion is the exercise.
         *
         *   opcode:              0    1      2        3       4      5
         *   kOpcodeMap[opcode]:  3    5      1        0       4      2
         *   meaning:           HALT  CMP_CHAR CMP_LEN ACCEPT   JMP   CMP_IDX
         * ------------------------------------------------------------------ */
        private static readonly int[] kOpcodeMap = { 3, 5, 1, 0, 4, 2 };

        // The encrypted program: slot index in the high half, argument below.
        private static readonly int[] kProgram =
        {
            0x10012, // slot 1 -> CMP_LEN  18
            0x50043, // slot 5 -> CMP_CHAR 'C'
            0x50030, // slot 5 -> CMP_CHAR '0'
            0x50034, // slot 5 -> CMP_CHAR '4'
            0x5002D, // slot 5 -> CMP_CHAR '-'
            0x50044, // slot 5 -> CMP_CHAR 'D'
            0x5004F, // slot 5 -> CMP_CHAR 'O'
            0x50054, // slot 5 -> CMP_CHAR 'T'
            0x5004E, // slot 5 -> CMP_CHAR 'N'
            0x50045, // slot 5 -> CMP_CHAR 'E'
            0x50054, // slot 5 -> CMP_CHAR 'T'
            0x5002D, // slot 5 -> CMP_CHAR '-'
            0x50056, // slot 5 -> CMP_CHAR 'V'
            0x5004D, // slot 5 -> CMP_CHAR 'M'
            0x5002D, // slot 5 -> CMP_CHAR '-'
            0x50033, // slot 5 -> CMP_CHAR '3'
            0x50045, // slot 5 -> CMP_CHAR 'E'
            0x50039, // slot 5 -> CMP_CHAR '9'
            0x50031, // slot 5 -> CMP_CHAR '1'
            0x40015, // slot 4 -> JMP      to instruction 21, skipping the decoy
            0x20002, // slot 2 -> CMP_IDX  2  (decoy: compares the whole input to the
                      //                  VM-hint string, which can never match)
            0x00000, // slot 0 -> ACCEPT
            0x30000, // slot 3 -> HALT
        };

        private static bool Verify(string input)
        {
            // Invert kOpcodeMap: slot -> opcode. This is the whole trick.
            int[] slotToOpcode = new int[kOpcodeMap.Length];
            for (int opcode = 0; opcode < kOpcodeMap.Length; opcode++)
            {
                slotToOpcode[kOpcodeMap[opcode]] = opcode;
            }

            int pc = 0;    // index into kProgram
            int cur = 0;   // index into the input
            int guard = 0;
            while (guard++ < 64)
            {
                if (pc < 0 || pc >= kProgram.Length)
                {
                    return false;
                }

                int word = kProgram[pc];
                int slot = word >> 16;
                int arg = word & 0xFFFF;
                int op = slotToOpcode[slot];

                switch (op)
                {
                    case 0: // HALT
                        return false;
                    case 1: // CMP_CHAR <c> -- next input char must equal (char)arg
                        if ((char)arg != CharAt(input, cur))
                        {
                            return false;
                        }
                        cur++;
                        pc++;
                        break;
                    case 2: // CMP_LEN <n>
                        if (input.Length != arg)
                        {
                            return false;
                        }
                        pc++;
                        break;
                    case 3: // ACCEPT
                        return true;
                    case 4: // JMP <absolute instruction index>
                        pc = arg;
                        break;
                    case 5: // CMP_IDX <string index> -- whole-input compare
                        if (!string.Equals(input, Str(kIndices[arg % kIndices.Length])))
                        {
                            return false;
                        }
                        pc++;
                        break;
                    default:
                        Console.WriteLine(Str(0x2C03));
                        return false;
                }
            }
            return false;
        }

        private static char CharAt(string s, int i)
        {
            if (i < 0 || i >= s.Length)
            {
                return '\0';
            }
            return s[i];
        }
    }
}
