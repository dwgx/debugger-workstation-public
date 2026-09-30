/* pcap-reader.mjs — a libpcap reader, written for this lab because the station had a
 * writer and no reader.
 *
 * WHY THIS FILE EXISTS. `net-reverse/lab/pcap-writer.mjs` writes pcaps. Nothing in the
 * tree reads them in JavaScript: net-reverse shells out to tshark, and a third-party
 * dissector is not a fuzz target this lab is entitled to claim -- it is not
 * self-authored, and a finding in tshark is not a finding about this repository.
 *
 * A pcap file is a 24-byte global header followed by a sequence of 16-byte record
 * headers, each declaring the captured length of the frame that follows. The entire
 * parser surface is those declared lengths: every one of them is attacker-controlled
 * and every one of them is a chance to read past the end of the file. That makes it the
 * right first target, and it is why this reader is here rather than in net-reverse: it
 * is an artifact of the fuzzer, and the README says so.
 *
 * WHAT "ROBUST" MEANS HERE, concretely. For each field the reader consults, it asks
 * first whether the file is long enough to contain it, and it caps anything that would
 * otherwise turn a declared count into unbounded work. It reports refusal as a typed
 * PcapFormatError, because a parser that dies with a RangeError on a malformed file is
 * not a parser an analyst can point at evidence with.
 */

export class PcapFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PcapFormatError';
  }
}

const GLOBAL_HEADER = 24;
const RECORD_HEADER = 16;

/** The four magics libpcap and libpcap-ng writers emit, and the byte order each implies. */
const MAGICS = new Map([
  [0xa1b2c3d4, { le: true, nanos: false }],   // usec, same endianness as reader
  [0xd4c3b2a1, { le: false, nanos: false }],  // usec, swapped
  [0xa1b23c4d, { le: true, nanos: true }],    // nsec
  [0x4d3cb2a1, { le: false, nanos: true }],   // nsec, swapped
]);

/** LINKTYPE_ETHERNET is 1; the writer in net-reverse only ever emits that. */
const LINKTYPE_NAMES = { 1: 'ETHERNET', 0: 'NULL', 101: 'RAW', 113: 'LINUX_SLL' };

/** A single record may not exceed this. A file claiming 4 GiB of one frame is a lie. */
const MAX_CAPTURED = 1 << 21;      // 2 MiB
/** And a file may not contain more than this many records. Bounds the read loop. */
const MAX_RECORDS = 200_000;

/**
 * Parse a pcap file.
 *
 * @param {Buffer} buf
 * @returns {{endian:string, nanos:boolean, version:[number,number], snaplen:number,
 *            linktype:number, linktypeName:string, packets:Array, truncated:boolean}}
 * @throws {PcapFormatError} on anything this reader refuses to interpret
 */
export function readPcapFile(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  if (buf.length < GLOBAL_HEADER) {
    throw new PcapFormatError(`file is ${buf.length} bytes: shorter than the ${GLOBAL_HEADER}-byte global header`);
  }

  /* The magic is read as LE first and, if that does not match, as BE. A file whose
     first four bytes are a magic in the other order is a valid file, not a broken one,
     and refusing it would be a parser that only reads what its own writer wrote. */
  const magicLe = buf.readUInt32LE(0);
  let endian = 'le';
  let spec = MAGICS.get(magicLe);
  if (!spec) {
    const magicBe = buf.readUInt32BE(0);
    spec = MAGICS.get(magicBe);
    if (spec) endian = 'be';
  }
  if (!spec) {
    throw new PcapFormatError(`not a pcap file: magic 0x${buf.subarray(0, 4).toString('hex')}`);
  }
  const rd16 = (o) => (endian === 'le' ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const rd32 = (o) => (endian === 'le' ? buf.readUInt32LE(o) : buf.readUInt32BE(o));

  const versionMajor = rd16(4);
  const versionMinor = rd16(6);
  if (versionMajor !== 2) {
    throw new PcapFormatError(`unsupported pcap version ${versionMajor}.${versionMinor} (this reader implements 2.x)`);
  }

  const snaplen = rd32(16);
  const linktype = rd32(20) & 0x0fffffff;   // the top 4 bits are FCS-length flags

  const packets = [];
  let off = GLOBAL_HEADER;
  let truncated = false;

  /* Walk records. Two separate guards, and the distinction matters: a record whose
     declared length runs off the end of the file is TRUNCATED -- a real thing that
     happens to real captures, and the reader reports it and stops. A file with more
     records than the cap allows is not truncated, it is implausible, and it is refused. */
  while (off < buf.length) {
    if (packets.length >= MAX_RECORDS) {
      throw new PcapFormatError(`more than ${MAX_RECORDS} records: refusing to keep walking`);
    }
    if (off + RECORD_HEADER > buf.length) {
      truncated = true;
      break;
    }
    const tsSec = rd32(off);
    const tsFrac = rd32(off + 4);
    const captured = rd32(off + 8);
    const original = rd32(off + 12);

    if (captured > MAX_CAPTURED) {
      throw new PcapFormatError(`record ${packets.length} declares ${captured} captured bytes (cap ${MAX_CAPTURED})`);
    }
    if (off + RECORD_HEADER + captured > buf.length) {
      /* THE bug this whole lab was built to find. Reading `buf.subarray(off+16,
         off+16+captured)` here instead would not throw -- subarray clamps -- it would
         silently hand back a SHORT frame and report `captured` as its length. The
         parser would go on to parse a frame that is not there. */
      truncated = true;
      break;
    }

    packets.push({
      index: packets.length,
      tsSec,
      tsFrac: spec.nanos ? tsFrac / 1e6 : tsFrac / 1e6,
      timestampResolution: spec.nanos ? 'nanoseconds' : 'microseconds',
      capturedLength: captured,
      originalLength: original,
      /** A record whose orig_len exceeds incl_len is a snaplen-truncated capture. Normal. */
      snapped: original > captured,
      data: buf.subarray(off + RECORD_HEADER, off + RECORD_HEADER + captured),
    });

    off += RECORD_HEADER + captured;
    if (captured === 0) {
      /* A zero-length record advances the offset by the header alone, so this loop
         always terminates. Without that property an attacker sets captured=0 forever
         and the parser spins. It is worth a comment because the guard is invisible. */
      continue;
    }
  }

  return {
    endian,
    nanos: spec.nanos,
    version: [versionMajor, versionMinor],
    snaplen,
    linktype,
    linktypeName: LINKTYPE_NAMES[linktype] || `UNKNOWN(${linktype})`,
    count: packets.length,
    packets,
    truncated,
    consumed: off,
  };
}

/* ------------------------------------------------------------------ the twin */

/**
 * THE FLAWED READER. This is the negative control's target, and it is a faithful
 * rendering of the mistake a person actually makes.
 *
 * Its three defects, each of them the obvious one:
 *   1. no bounds check before `subarray`, so a declared length past the end yields a
 *      silently short frame whose reported length lies about its own size;
 *   2. no MAX_CAPTURED cap, so a declared 2 GiB frame is accepted and a reader that
 *      copies it dies on the allocation;
 *   3. no MAX_RECORDS cap, so a file of 16-byte zero records is a 2-billion-iteration
 *      loop -- the hang, which is a finding in its own right and not a skip.
 *
 * It is here to be caught. If the fuzzer cannot catch this, the fuzzer cannot be
 * trusted on the reader that is actually hardened, and `loop.mjs` fails the run.
 */
export function readPcapFileFlawed(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  if (buf.length < GLOBAL_HEADER) {
    throw new PcapFormatError(`file is ${buf.length} bytes: shorter than the global header`);
  }
  const magicLe = buf.readUInt32LE(0);
  let endian = 'le';
  let spec = MAGICS.get(magicLe);
  if (!spec) {
    const magicBe = buf.readUInt32BE(0);
    spec = MAGICS.get(magicBe);
    if (spec) endian = 'be';
  }
  if (!spec) throw new PcapFormatError(`not a pcap file: magic 0x${buf.subarray(0, 4).toString('hex')}`);
  const rd16 = (o) => (endian === 'le' ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const rd32 = (o) => (endian === 'le' ? buf.readUInt32LE(o) : buf.readUInt32BE(o));

  if (rd16(4) !== 2) throw new PcapFormatError(`unsupported version ${rd16(4)}`);

  /* DEFECT 1 + 2: no captured-length validation. `data` is silently short when the
     record over-runs the file, and the object still reports `capturedLength: captured`.
     An analyst reading that report would believe they had a 4 GiB frame. */
  const packets = [];
  let off = GLOBAL_HEADER;
  while (off < buf.length) {
    if (off + RECORD_HEADER > buf.length) break;
    const captured = rd32(off + 8);
    packets.push({
      index: packets.length,
      tsSec: rd32(off),
      capturedLength: captured,
      originalLength: rd32(off + 12),
      data: buf.subarray(off + RECORD_HEADER, off + RECORD_HEADER + captured),
    });
    off += RECORD_HEADER + captured;
  }

  return {
    endian,
    count: packets.length,
    linktype: rd32(20) & 0x0fffffff,
    packets,
  };
}
