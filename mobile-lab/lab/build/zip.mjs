/*
 * zip.mjs — a minimal, correct ZIP reader/writer with zero dependencies.
 *
 * WHY HAND-ROLLED
 * ---------------
 * The APK build has to (a) read the ZIP that aapt2 produced, (b) add classes.dex and
 * lib/<abi>/*.so, and (c) preserve every existing entry's compression method and raw bytes.
 * The station rule is that third-party code does not go into this tree, and the whole job is
 * about 200 lines of the ZIP spec. Node's zlib supplies raw deflate; everything else here is
 * the container format.
 *
 * The one behaviour that actually matters for an APK: resources.arsc MUST be STORED
 * (uncompressed) and 4-byte aligned, because the runtime mmaps it directly. Preserving each
 * entry's original method verbatim is what keeps that true, so this reader exposes the raw
 * method and the writer replays it rather than recompressing.
 *
 * EOCD64 is not supported: no APK or APK-producing tool emits it, and a ZIP that needs it is
 * >4 GiB, which is not a case this lab has. That is stated rather than silently mishandled.
 */

import zlib from 'node:zlib';

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;

const METHOD_STORE = 0;
const METHOD_DEFLATE = 8;

const FLAG_DATA_DESCRIPTOR = 0x0008;
const FLAG_UTF8 = 0x0800;

/* CRC-32, table-driven. ZIP needs our own; zlib does not expose one. */
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

export function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function findEocd(buf) {
  const min = Math.max(0, buf.length - 0xffff - 22);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  throw new Error('not a ZIP: no end-of-central-directory record');
}

/**
 * Read a ZIP. Returns entries in central-directory order with:
 *   name, method, rawCompressed, dataSize, crc, localOffset, flags, modTime, modDate
 * `rawCompressed` is the still-compressed bytes, so a write pass can replay them untouched.
 */
export function readZip(buf) {
  const eocd = findEocd(buf);
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(off) !== SIG_CENTRAL) throw new Error(`bad central header at entry ${i}`);
    const flags = buf.readUInt16LE(off + 8);
    const method = buf.readUInt16LE(off + 10);
    const modTime = buf.readUInt16LE(off + 12);
    const modDate = buf.readUInt16LE(off + 14);
    const crc = buf.readUInt32LE(off + 16);
    const compSize = buf.readUInt32LE(off + 20);
    const dataSize = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOffset = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nameLen);

    /* Walk to the local header to find where the data actually starts. The local header's
       own name/extra lengths can differ from the central ones — that is legal and is why
       we cannot just add a constant. */
    if (buf.readUInt32LE(localOffset) !== SIG_LOCAL) throw new Error(`bad local header for ${name}`);
    const lNameLen = buf.readUInt16LE(localOffset + 26);
    const lExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataOff = localOffset + 30 + lNameLen + lExtraLen;
    entries.push({
      name, method, flags, modTime, modDate, crc, compSize, dataSize, localOffset,
      rawCompressed: buf.subarray(dataOff, dataOff + compSize),
    });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** Inflate an entry to its plain bytes. */
export function entryData(entry) {
  if (entry.method === METHOD_STORE) return Buffer.from(entry.rawCompressed);
  if (entry.method === METHOD_DEFLATE) return zlib.inflateRawSync(entry.rawCompressed);
  throw new Error(`unsupported compression method ${entry.method} for ${entry.name}`);
}

function dosTime(d = new Date()) {
  const time = ((d.getHours() & 31) << 11) | ((d.getMinutes() & 63) << 5) | ((d.getSeconds() / 2) & 31);
  const date = (((d.getFullYear() - 1980) & 127) << 9) | (((d.getMonth() + 1) & 15) << 5) | (d.getDate() & 31);
  return { time, date };
}

/**
 * Write a ZIP.
 * @param entries  [{ name, data?, rawCompressed?, method?, flags?, modTime?, modDate?, crc? }]
 *   Pass `rawCompressed` to replay bytes verbatim; pass `data` to (de)compress.
 * @param opts.comment  optional archive comment
 */
export function writeZip(entries, { comment = '' } = {}) {
  const { time: defTime, date: defDate } = dosTime();
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, 'utf8');
    const method = e.method ?? (e.rawCompressed ? e.method : METHOD_DEFLATE);
    let raw = e.rawCompressed;
    let crc = e.crc;
    let dataSize = e.dataSize;

    if (!raw) {
      const data = e.data;
      dataSize = data.length;
      crc = crc32(data);
      if (method === METHOD_STORE) {
        raw = data;
      } else {
        raw = zlib.deflateRawSync(data, { level: 9 });
        /* Never let "compression" make an entry bigger. */
        if (raw.length >= data.length) { raw = data; method = METHOD_STORE; }
      }
    }

    const flags = (e.flags ?? (FLAG_UTF8 | FLAG_DATA_DESCRIPTOR)) & ~FLAG_DATA_DESCRIPTOR;
    const modTime = e.modTime ?? defTime;
    const modDate = e.modDate ?? defDate;

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(SIG_LOCAL, 0);
    lh.writeUInt16LE(20, 4);                    /* version needed */
    lh.writeUInt16LE(flags, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(modTime, 10);
    lh.writeUInt16LE(modDate, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(raw.length, 18);
    lh.writeUInt32LE(dataSize, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, nameBuf, raw);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(SIG_CENTRAL, 0);
    ch.writeUInt16LE(20, 4);                    /* version made by */
    ch.writeUInt16LE(20, 6);                    /* version needed */
    ch.writeUInt16LE(flags, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt16LE(modTime, 12);
    ch.writeUInt16LE(modDate, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(raw.length, 20);
    ch.writeUInt32LE(dataSize, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30);                    /* extra length */
    ch.writeUInt16LE(0, 32);                    /* comment length */
    ch.writeUInt16LE(0, 34);                    /* disk number start */
    ch.writeUInt16LE(0, 36);                    /* internal attributes */
    /* The Unix mode lives in the high half of external_attr. JavaScript's << is a signed
       32-bit operation, so 0o100644 << 16 comes out negative and writeUInt32LE rejects it;
       >>> 0 converts it back to unsigned. */
    ch.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, nameBuf);

    offset += lh.length + nameBuf.length + raw.length;
  }

  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(Buffer.byteLength(comment), 20);
  const commentBuf = Buffer.from(comment, 'utf8');

  return Buffer.concat([...locals, centralBuf, eocd, commentBuf]);
}
