// m05 -- the managed/native boundary.
//
// WHAT IT IS: a managed program whose entire security decision is made in a DLL
// it does not contain. The managed side marshals a byte array across, calls
// LabTransform, then LabCheck. The key is not anywhere in the managed assembly.
//
// WHY IT IS HERE: this is the phase that breaks naive tooling. A managed
// decompiler gives you a perfect, complete, boring view of everything the
// managed code does -- and the answer is in the other binary. An analyst who
// stops at the P/Invoke declaration has narrowed the problem to a single 14-byte
// comparison in a DLL, which is a much easier problem, but has not solved it.
//
// THE TRAP: the DllImport name is not the export name you will find in the DLL's
// export table, and it is not the only thing the loader looks at. The calling
// convention, the marshalling of `byte[]` (LPArray, in/out, length passed
// separately as a second argument) and the DLL search path are all part of the
// contract and all of them are visible only if you read both halves.
//
// KNOWN ANSWER (see README.md): the 14-byte key, plus the recovered body of
// LabTransform, plus the export names in labnative.dll.

using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace M05
{
    internal static class Program
    {
        private const string Lib = "labnative";
        private const byte Seed = 0x2A;
        private const int KeyLen = 14;

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int LabTransform(byte[] buf, int len, byte seed);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int LabCheck(byte[] key, int len);

        // The DLL ships beside the executable, not on PATH and not next to the
        // source. Without this resolver the program would only start by accident.
        static Program()
        {
            NativeLibrary.SetDllImportResolver(typeof(Program).Assembly, Resolve);
        }

        private static IntPtr Resolve(string name, Assembly asm, DllImportSearchPath? path)
        {
            if (!string.Equals(name, Lib, StringComparison.Ordinal)) return IntPtr.Zero;

            string dir = Path.GetDirectoryName(asm.Location) ?? AppContext.BaseDirectory;
            foreach (string probe in new[] { "labnative.dll", Path.Combine(dir, "labnative.dll") })
            {
                if (File.Exists(probe) && NativeLibrary.TryLoad(probe, out IntPtr h)) return h;
            }

            return IntPtr.Zero;
        }

        private static string Hex(byte[] b)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        private static int Main(string[] args)
        {
            if (args.Length >= 1 && args[0] == "--selftest")
            {
                // Transform a caller-supplied probe with the built-in seed. This
                // lets a static recovery of LabTransform be checked against the
                // real function without touching the key at all.
                byte[] probe = Encoding.ASCII.GetBytes(args.Length > 1 ? args[1] : "probe-bytes");
                int rc = LabTransform(probe, probe.Length, Seed);
                Console.WriteLine("rc      " + rc);
                Console.WriteLine("out     " + Hex(probe));
                return 0;
            }

            if (args.Length < 1)
            {
                Console.Error.WriteLine("usage: m05_bridge <key> | --selftest <probe>");
                return 2;
            }

            byte[] key = Encoding.UTF8.GetBytes(args[0]);
            Console.WriteLine("keylen  " + key.Length);
            if (key.Length != KeyLen)
            {
                Console.WriteLine("verdict REJECT (length)");
                return 1;
            }

            int n = LabTransform(key, key.Length, Seed);
            Console.WriteLine("xform   rc=" + n + " " + Hex(key));

            int ok = LabCheck(key, key.Length);
            Console.WriteLine("verdict " + (ok != 0 ? "ACCEPT" : "REJECT"));
            return ok != 0 ? 0 : 1;
        }
    }
}
