// m01 -- string encryption.
//
// WHAT IT IS: three strings that exist nowhere in the assembly as literals. The
// ciphertext is base64 in a `const string`; the plaintext only exists inside the
// routine below, which reconstructs it on every call.
//
// WHY IT IS HERE: this is the smallest useful managed-RE skill. `strings` on the
// DLL finds three base64 blobs and nothing else; the answer is in the code. The
// skill is reading a decompilation and re-implementing the transform -- not
// guessing, and not running the program to see what it prints.
//
// THE TRAP: a plausible-looking single-layer XOR is NOT enough. Layer 1 is a
// position-dependent keystream, layer 2 is an in-place byte swap on the odd
// indices. A solver that applies only layer 1 produces printable-looking garbage
// and will happily report it. The runner in tools/loop.mjs asserts the exact
// plaintext, so a half-solved answer is a failure, not a near miss.

using System;
using System.Text;

namespace M01
{
    internal static class Program
    {
        // base64 of the raw cipher bytes -- layer 1 (keystream XOR) then layer 2 (swap)
        private const string C0 = "NwYAEBHiG/igwf2IiuCDrruuu4mJltQ7MjAxU1NfXCNTNmwBNAkbCwjh77X7";
        private const string C1 = "Lg0JBlDvC//uwbzd2K7OqeimuYbFloF5cncxQlYWXCxJcykDNgkTG1jp6Q==";
        private const string C2 = "KhoAWgTxCrnixfPGh6XRq+W9s5WXj4RuZ2g8XkFZQiBc";

        // seed 0x5A -- the only literal that is not itself ciphertext
        private const byte Seed = 0x5A;

        private static int KeyStream(int index, byte seed)
        {
            return seed + (index * 7) + (index / 3);
        }

        private static byte[] Reveal(string blob)
        {
            byte[] raw = Convert.FromBase64String(blob);

            // layer 2 -- undo the odd-index swap first
            for (int i = 1; i + 1 < raw.Length; i += 2)
            {
                byte t = raw[i];
                raw[i] = raw[i + 1];
                raw[i + 1] = t;
            }

            // layer 1 -- undo the position-dependent XOR
            for (int i = 0; i < raw.Length; i++)
            {
                raw[i] = (byte)(raw[i] ^ KeyStream(i, Seed));
            }

            return raw;
        }

        private static string Text(int which)
        {
            switch (which)
            {
                case 0: return Encoding.UTF8.GetString(Reveal(C0));
                case 1: return Encoding.UTF8.GetString(Reveal(C1));
                default: return Encoding.UTF8.GetString(Reveal(C2));
            }
        }

        private static int Main(string[] args)
        {
            // `--ids` prints the recovered ids only, so a solver can diff ids
            // without re-parsing the banner text.
            if (args.Length > 0 && args[0] == "--ids")
            {
                Console.WriteLine(string.Join(",", Text(0), Text(2)));
                return 0;
            }

            Console.WriteLine(Text(0));
            Console.WriteLine(Text(1));
            Console.WriteLine(Text(2));
            return 0;
        }
    }
}
