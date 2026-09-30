// m02 -- control-flow flattening with opaque predicates.
//
// WHAT IT IS: the straight-line computation of m01 is rewritten as a state machine.
// Every basic block became a `case`, a single `state` variable became the only
// control transfer, and two of the cases are guarded by a predicate that can
// never be true. The source reads top-to-bottom as a dispatcher, so "what does
// this program do" is not answerable by reading it in order -- it is answerable
// only by building the successor graph and walking it.
//
// WHY IT IS HERE: this is the skill that separates "can decompile C#" from "can
// read a decompiled program". Static recovery of the true order is a graph walk
// plus a little constant folding, and it produces a result you can check without
// ever running the binary.
//
// THE TRAP, part 1 -- the dead guards. `Opaque1`/`Opaque2` are opaque predicates:
// for the ids they are called with they always evaluate to false, so the branch
// is dead. A parser that harvests every `state = ...` assignment in a case body
// picks up the dead one too and follows the wrong edge.
//
// THE TRAP, part 2 -- the decoy. `case 0x2B` is a real, reachable-looking block
// that nothing reaches. Recovering the order by walking backwards from the exit,
// or by assuming blocks appear in execution order, both land on it.
//
// THE TRAP, part 3 -- the entry point is `Boot[1]`, not `Boot[0]` and not a
// literal. Resolve the array before you start the walk.
//
// KNOWN ANSWER (see README.md): acc = dbb9c662, order 0x1C -> 0x07 -> 0x4A ->
// 0x35 -> 0x11 -> 0x2E -> 0x59 -> 0x41.

using System;
using System.Collections.Generic;

namespace M02
{
    internal static class Program
    {
        private const long Mod = 4294967295L;

        // entry state is Boot[1], not Boot[0]
        private static readonly int[] Boot = { 0x4A, 0x1C, 0x07 };

        // opaque predicate #1: never true for the id it is called with
        private static bool Opaque1(int id, int bias)
        {
            return (id * id + bias) % 3 == 0;
        }

        // opaque predicate #2: never true for the id it is called with
        private static bool Opaque2(int id)
        {
            return (id & 0x20) == 0x20 && (id % 2) == 0;
        }

        private static long Step(long acc, int k)
        {
            return (acc * 31L + k) % Mod;
        }

        private static int Main(string[] args)
        {
            bool trace = args.Length > 0 && args[0] == "--trace";

            int state = Boot[1];
            long acc = 1L;
            List<string> order = new List<string>();

            while (state != -1)
            {
                order.Add("0x" + state.ToString("X2"));

                switch (state)
                {
                    case 0x1C:
                        acc = Step(acc, 0xA3);
                        state = 0x07;
                        break;

                    case 0x07:
                        if (Opaque2(0x07)) { acc = 0L; state = 0x2B; break; }
                        acc = Step(acc, 0x11);
                        state = 0x4A;
                        break;

                    case 0x4A:
                        if (Opaque1(0x4A, 1)) { acc = 0L; state = 0x59; break; }
                        acc = Step(acc, 0x5C);
                        state = 0x35;
                        break;

                    case 0x35:
                        if (Opaque1(0x35, 1)) { acc = 0L; state = 0x11; break; }
                        acc = Step(acc, 0x2E);
                        state = 0x11;
                        break;

                    case 0x11:
                        if (Opaque1(0x11, 1)) { acc = 0L; state = 0x2E; break; }
                        acc = Step(acc, 0x99);
                        state = 0x2E;
                        break;

                    case 0x2E:
                        if (Opaque1(0x2E, 1)) { acc = 0L; state = 0x59; break; }
                        acc = Step(acc, 0x07);
                        state = 0x59;
                        break;

                    case 0x59:
                        acc = Step(acc, 0xC3);
                        state = 0x41;
                        break;

                    case 0x41:
                        if (Opaque1(0x41, 1)) { acc = 0L; state = 0x07; break; }
                        acc = Step(acc, 0x38);
                        state = -1;
                        break;

                    case 0x2B:
                        // decoy: real code, reachable from nothing
                        acc = Step(acc, 0xEE);
                        state = 0x41;
                        break;

                    case -1:
                        break;

                    default:
                        throw new InvalidOperationException("bad state " + state);
                }
            }

            if (trace)
            {
                Console.WriteLine(string.Join(" -> ", order));
            }

            Console.WriteLine(acc.ToString("x8"));
            return 0;
        }
    }
}
