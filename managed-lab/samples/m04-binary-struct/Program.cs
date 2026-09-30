// m04 -- hand-rolled binary struct.
//
// WHAT IT IS: a 16-byte header plus a chain of length-prefixed records, each with
// its own integrity word, all little-endian, all 4-byte aligned. The file format
// has no self-description: the only description is `WriteRecord` below.
//
// WHY IT IS HERE: recovering a structure from a binary is a native-RE skill
// (ReClass.NET, ImHex, Ghidra datatypes), and this is the managed column of the
// same skill. The information you need is not in the file -- it is in the code
// that wrote it. The exercise is: take the writer apart, derive the field map,
// then parse an artifact you were handed with nothing but that map.
//
// THE TRAP: the integrity word looks like a CRC and is not one. It is FNV-1a/32
// -- 0x811C9DC5 and the prime 16777619, in that order, XOR-then-multiply. A
// solver that assumes CRC32 computes a "valid" checksum for a file it has
// mis-parsed, and never notices.
//
// THE SECOND TRAP: alignment padding is part of the layout, not slack. Record
// offsets are only derivable if you know where the next record starts.
//
// KNOWN ANSWER (see README.md): the exact record table, with file offsets, of
// `managed-lab/out/m04/m04_records.dat`.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace M04
{
    internal static class Program
    {
        // ---- layout constants, all recoverable from this file ---------------
        private const int HeaderSize = 16;
        private const int RecordHeaderSize = 8;
        private const int RecordAlign = 4;
        private const ushort Version = 3;

        private static readonly byte[] Magic = { (byte)'M', (byte)'S', (byte)'T', (byte)'R' };

        /// <summary>FNV-1a/32. Not CRC32 -- see the header comment.</summary>
        private static uint Fnv(byte[] d, int off, int len)
        {
            uint h = 0x811C9DC5u;
            for (int i = 0; i < len; i++)
            {
                h ^= d[off + i];
                h = unchecked(h * 16777619u);
            }

            return h;
        }

        private static int AlignUp(int n)
        {
            return (n + RecordAlign - 1) / RecordAlign * RecordAlign;
        }

        // ---- writer: this is the format specification ----------------------

        private static void WriteHeader(MemoryStream ms, ushort recordCount, int totalSize)
        {
            ms.Write(Magic, 0, 4);                                  // 0x00 magic[4]
            ms.Write(BitConverter.GetBytes(Version), 0, 2);         // 0x04 u16 version
            ms.Write(BitConverter.GetBytes(recordCount), 0, 2);     // 0x06 u16 count
            byte[] sofar = ms.ToArray();
            ms.Write(BitConverter.GetBytes(Fnv(sofar, 0, 8)), 0, 4);  // 0x08 u32 headerCheck
            ms.Write(BitConverter.GetBytes((uint)totalSize), 0, 4);    // 0x0C u32 totalSize
        }

        private static void WriteRecord(MemoryStream ms, byte kind, byte flags, ushort id, byte[] value)
        {
            int start = (int)ms.Position;
            ms.WriteByte(kind);                                     // +0 u8
            ms.WriteByte(flags);                                    // +1 u8
            ms.Write(BitConverter.GetBytes(id), 0, 2);              // +2 u16
            ms.Write(BitConverter.GetBytes((uint)value.Length), 0, 4); // +4 u32 valueLen
            ms.Write(value, 0, value.Length);                       // +8 value[valueLen]
            byte[] sofar = ms.ToArray();
            ms.Write(BitConverter.GetBytes(Fnv(sofar, start, RecordHeaderSize + value.Length)), 0, 4);
            int pad = AlignUp((int)ms.Position) - (int)ms.Position;
            for (int i = 0; i < pad; i++) ms.WriteByte(0);
        }

        // ---- reader: what an analyst has to reproduce ------------------------

        private sealed class Record
        {
            public int Offset;
            public byte Kind;
            public byte Flags;
            public ushort Id;
            public byte[] Value;
            public uint Check;
        }

        private static byte[] Load(string path, List<Record> outRecords)
        {
            byte[] all = File.ReadAllBytes(path);
            if (all.Length < HeaderSize) throw new InvalidDataException("short header");

            for (int i = 0; i < 4; i++)
            {
                if (all[i] != Magic[i]) throw new InvalidDataException("bad magic");
            }

            ushort ver = BitConverter.ToUInt16(all, 4);
            if (ver != Version) throw new InvalidDataException("version " + ver);

            ushort count = BitConverter.ToUInt16(all, 6);
            uint hdrCheck = BitConverter.ToUInt32(all, 8);
            if (hdrCheck != Fnv(all, 0, 8)) throw new InvalidDataException("header check failed");

            uint total = BitConverter.ToUInt32(all, 12);
            if (total != all.Length) throw new InvalidDataException("total size mismatch");

            int off = HeaderSize;
            for (int i = 0; i < count; i++)
            {
                if (off + RecordHeaderSize + 4 > all.Length) throw new InvalidDataException("truncated record");

                Record r = new Record();
                r.Offset = off;
                r.Kind = all[off];
                r.Flags = all[off + 1];
                r.Id = BitConverter.ToUInt16(all, off + 2);
                uint len = BitConverter.ToUInt32(all, off + 4);
                if (off + RecordHeaderSize + (int)len + 4 > all.Length) throw new InvalidDataException("value overruns file");
                r.Value = new byte[len];
                Array.Copy(all, off + RecordHeaderSize, r.Value, 0, (int)len);
                r.Check = BitConverter.ToUInt32(all, off + RecordHeaderSize + (int)len);

                uint want = Fnv(all, off, RecordHeaderSize + (int)len);
                if (r.Check != want)
                {
                    throw new InvalidDataException(string.Format(CultureInfo.InvariantCulture,
                        "record {0} check {1:x8} != {2:x8}", i, r.Check, want));
                }

                outRecords.Add(r);
                off = AlignUp(off + RecordHeaderSize + (int)len + 4);
            }

            return all;
        }

        // ---- the built-in record set -----------------------------------------

        private static List<byte[]> BuiltIn()
        {
            return new List<byte[]>
            {
                Rec(1, 0x01, 0x0001, Encoding.ASCII.GetBytes("license-check: fails closed")),
                Rec(2, 0x00, 0x0002, BitConverter.GetBytes((uint)1234)),
                Rec(3, 0x02, 0x0003, new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }),
                Rec(1, 0x00, 0x0100, Encoding.ASCII.GetBytes("stage=2")),
                Rec(2, 0x03, 0x0200, BitConverter.GetBytes(0xDEADBEEFu)),
            };
        }

        private static byte[] Rec(byte kind, byte flags, ushort id, byte[] value)
        {
            byte[] head = { kind, flags, 0, 0, 0, 0, 0, 0 };
            BitConverter.GetBytes(id).CopyTo(head, 2);
            BitConverter.GetBytes((uint)value.Length).CopyTo(head, 4);
            byte[] all = new byte[RecordHeaderSize + value.Length];
            head.CopyTo(all, 0);
            value.CopyTo(all, RecordHeaderSize);
            return all;
        }

        private static void Save(string path)
        {
            List<byte[]> recs = BuiltIn();
            int body = 0;
            foreach (byte[] r in recs) body += AlignUp(r.Length + 4);

            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(new byte[HeaderSize], 0, HeaderSize);
                ms.Position = 0;
                WriteHeader(ms, (ushort)recs.Count, HeaderSize + body);

                foreach (byte[] r in recs)
                {
                    byte[] value = new byte[r.Length - RecordHeaderSize];
                    Array.Copy(r, RecordHeaderSize, value, 0, value.Length);
                    WriteRecord(ms, r[0], r[1], BitConverter.ToUInt16(r, 2), value);
                }

                File.WriteAllBytes(path, ms.ToArray());
            }
        }

        // ---- canonical listing: the known answer, printed by the artifact ----

        private static string Canonical(byte[] all, List<Record> recs)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat(CultureInfo.InvariantCulture,
                "MSTR v{0} records={1} total=0x{2:x8} hdrcheck=0x{3:x8}",
                BitConverter.ToUInt16(all, 4), BitConverter.ToUInt16(all, 6),
                BitConverter.ToUInt32(all, 12), Fnv(all, 0, 8));
            sb.Append('\n');

            for (int i = 0; i < recs.Count; i++)
            {
                Record r = recs[i];
                sb.AppendFormat(CultureInfo.InvariantCulture,
                    "[{0}] @0x{1:x4} kind={2} flags=0x{3:x2} id=0x{4:x4} len={5} check=0x{6:x8} ",
                    i, r.Offset, r.Kind, r.Flags, r.Id, r.Value.Length, r.Check);

                if (r.Kind == 1)
                {
                    sb.Append("ascii=\"").Append(Encoding.ASCII.GetString(r.Value)).Append('"');
                }
                else if (r.Kind == 2 && r.Value.Length == 4)
                {
                    sb.AppendFormat(CultureInfo.InvariantCulture, "u32=0x{0:x8}", BitConverter.ToUInt32(r.Value, 0));
                }
                else
                {
                    sb.Append("hex=");
                    foreach (byte b in r.Value) sb.AppendFormat(CultureInfo.InvariantCulture, "{0:x2}", b);
                }

                sb.Append('\n');
            }

            return sb.ToString();
        }

        private static int Main(string[] args)
        {
            bool write = true;
            string path = null;
            foreach (string a in args)
            {
                if (a == "--no-write") write = false;
                else path = a;
            }

            if (path == null) path = Path.Combine(AppContext.BaseDirectory, "m04_records.dat");
            if (write) Save(path);

            List<Record> recs = new List<Record>();
            byte[] all = Load(path, recs);
            Console.Write(Canonical(all, recs));
            return 0;
        }
    }
}
