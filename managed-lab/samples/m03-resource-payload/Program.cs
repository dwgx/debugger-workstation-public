// m03 -- resource-embedded payload.
//
// WHAT IT IS: a blob that is base64 inside a file that is itself an embedded
// resource inside the assembly, with one position-dependent XOR on top. Nothing
// in the metadata or the user strings names the payload's contents; the only way
// to the bytes is to read the loader and re-implement it.
//
// WHY IT IS HERE: this is the .NET equivalent of unpacking a section, and it is
// the single most common shape in real managed malware loaders and in real
// resource-driven plugin systems. It also teaches the two ILSpy/ilspycmd
// operations that have no C# equivalent at all: listing and extracting a
// resource (`--list-resources`, `--resource`), which is how you get the raw bytes
// out *without* re-implementing the loader at all.
//
// KNOWN ANSWER (see README.md): the decoded blob begins with the ASCII magic
// M03P, version 0x02, and is 117 bytes long.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace M03.ResourcePayload
{
    internal static class Program
    {
        private const string ResourceSuffix = ".b64";
        private const string Magic = "M03P";

        private static string FindPayload(Assembly asm)
        {
            List<string> names = asm.GetManifestResourceNames()
                .Where(n => n.EndsWith(ResourceSuffix, StringComparison.Ordinal))
                .ToList();

            if (names.Count != 1)
            {
                throw new InvalidOperationException(
                    "expected exactly one .b64 resource, found " + names.Count);
            }

            return names[0];
        }

        private static byte[] Unmask(string resourceName, byte[] raw)
        {
            // the seed is derived from the resource name, so the name has to be
            // resolved before the bytes mean anything
            int seed = 0x5A ^ (resourceName.Length & 0x3F);

            byte[] outp = new byte[raw.Length];
            for (int i = 0; i < raw.Length; i++)
            {
                outp[i] = (byte)(raw[i] ^ (seed + i));
            }

            return outp;
        }

        private static byte[] LoadPayload(Assembly asm)
        {
            string name = FindPayload(asm);
            string b64;
            using (Stream s = asm.GetManifestResourceStream(name))
            using (StreamReader r = new StreamReader(s, Encoding.ASCII))
            {
                b64 = r.ReadToEnd().Trim();
            }

            return Unmask(name, Convert.FromBase64String(b64));
        }

        private static string Sha256Hex(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
            }
        }

        private static int Main(string[] args)
        {
            Assembly asm = typeof(Program).Assembly;

            if (args.Length > 0 && args[0] == "--list")
            {
                foreach (string n in FindPayloads(asm)) Console.WriteLine(n);
                return 0;
            }

            byte[] plain = LoadPayload(asm);
            string head = Encoding.ASCII.GetString(plain, 0, Math.Min(4, plain.Length));

            Console.WriteLine("resource  " + FindPayload(asm));
            Console.WriteLine("length    " + plain.Length);
            Console.WriteLine("magic     " + head);
            Console.WriteLine("sha256    " + Sha256Hex(plain));
            Console.WriteLine("version   0x" + plain[4].ToString("x2"));
            Console.WriteLine("body      " + Encoding.UTF8.GetString(plain, 5, plain.Length - 5));
            return 0;
        }

        private static IEnumerable<string> FindPayloads(Assembly asm)
        {
            foreach (string n in asm.GetManifestResourceNames())
            {
                if (n.EndsWith(ResourceSuffix, StringComparison.Ordinal)) yield return n;
            }
        }
}
}
