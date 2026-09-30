/* mutate.mjs — the named mutation strategies, and the recipe that makes a crash replayable.
 *
 * Coverage-guided fuzzing works by watching which edges the input reaches and steering
 * toward new ones. This engine has no instrumentation and no feedback loop, so it cannot
 * do that, and the README says so plainly. What it can do is apply the mutations that
 * actually break parsers, which is a shorter list than "mutate the bytes" sounds like:
 *
 *   - a parser trusts a LENGTH field it read out of the file, and the field says more
 *     bytes exist than the file has. Length-field corruption attacks that trust directly.
 *   - a parser loops N times where N came from the file. Integer injection on counts
 *     turns a bounded loop into a 4-billion-iteration one.
 *   - a parser indexes an array with a value from the file. Interesting values (0, -1,
 *     INT_MAX, and the neighbours of every field width) are the ones that land off the
 *     end.
 *   - a parser recurses on a structure whose depth it never bounded. Duplicate-and-truncate
 *     on a nested encoding is how that gets found.
 *
 * Every strategy records what it did as a `step`, and the step list IS the recipe. A
 * finding is reproducible because the recipe plus the seed hash is a complete description
 * of the input, and `replay.mjs` re-derives the bytes from exactly those two things.
 */
import { Rng } from './rng.mjs';

/* Boundary values, per field width. These are the integers that break code:
 *   0 and 1        empty and single-element, which skip the loop body entirely
 *   max and max-1  allocation-size overflow and off-by-one on the last element
 *   0x7fffffff     the classic signed/unsigned sign bit
 *   sign-extended negatives read as huge unsigned values
 */
export const INTERESTING_U8 = [0x00, 0x01, 0x7f, 0x80, 0x81, 0xfe, 0xff];
export const INTERESTING_U16 = [0x0000, 0x0001, 0x0002, 0x7fff, 0x8000, 0xfffe, 0xffff];
export const INTERESTING_U32 = [
  0x00000000, 0x00000001, 0x00000002, 0x00000010, 0x0000ffff, 0x7fffffff,
  0x80000000, 0xfffffffe, 0xffffffff, 0x40000000, 0x0fffffff,
];
export const INTERESTING_U64 = [
  0n, 1n, 2n, 0xffffffffn, 0x7fffffffffffffffn, 0x8000000000000000n,
  0xfffffffffffffffen, 0xffffffffffffffffn, 0x0000000100000000n,
];

const MAX_INPUT = 1 << 21; // 2 MiB. A fuzz input larger than this is not a parser test.

function clamp(buf) {
  return buf.length > MAX_INPUT ? buf.subarray(0, MAX_INPUT) : buf;
}

/* --------------------------------------------------------------- the strategies */

/** Flip 1..8 individual bits. The classic; finds single-byte field-width mistakes. */
export const bitFlip = (buf, rng) => {
  const out = Buffer.from(buf);
  if (out.length === 0) return out;
  const n = rng.between(1, 8);
  for (let i = 0; i < n; i++) out[rng.below(out.length)] ^= 1 << rng.below(8);
  return out;
};

/** Flip one whole byte to a boundary value. Catches == and < against 0 / 0xff. */
export const byteSet = (buf, rng) => {
  const out = Buffer.from(buf);
  if (out.length === 0) return out;
  out[rng.below(out.length)] = rng.pick(INTERESTING_U8);
  return out;
};

/**
 * Overwrite a 2/4/8-byte window at a random offset with a boundary integer, in both
 * byte orders. This is the strategy aimed at length and count fields: it does not need
 * to know where they are, because it hits every offset, and it prefers the values that
 * mean "huge" or "negative".
 */
export const intInject = (buf, rng) => {
  const out = Buffer.from(buf);
  if (out.length < 2) return out;
  const width = rng.pick([2, 4, 4, 8]);
  if (out.length < width) return out;
  const off = rng.below(out.length - width + 1);
  const table = width === 2 ? INTERESTING_U16 : width === 4 ? INTERESTING_U32 : INTERESTING_U64;
  const value = rng.pick(table);
  const le = rng.bool();
  if (width === 8) {
    if (le) out.writeBigUInt64LE(BigInt.asUintN(64, value), off);
    else out.writeBigUInt64BE(BigInt.asUintN(64, value), off);
  } else if (le) {
    out.writeUIntLE(value, off, width);
  } else {
    out.writeUIntBE(value, off, width);
  }
  return out;
};

/**
 * Truncate the input. A parser that reads a length field before it checks the file is
 * long enough dies here, and truncation is the cheapest way to find out.
 */
export const truncate = (buf, rng) => {
  if (buf.length <= 1) return Buffer.alloc(0);
  /* Bias toward the interesting lengths -- just past a header, just short of a record --
     rather than a uniform cut, which almost always lands in the middle of a payload. */
  const candidates = [];
  for (const anchor of HEADER_ANCHORS) {
    if (anchor < buf.length) candidates.push(anchor);
  }
  if (candidates.length && rng.bool(0.7)) {
    return Buffer.from(buf.subarray(0, rng.pick(candidates)));
  }
  return Buffer.from(buf.subarray(0, rng.between(0, buf.length - 1)));
};

/* Where a length field usually sits, relative to the start of the file. Truncating to
   one byte past a header boundary is the cut that turns "reads past the end" from a
   maybe into a certainty. */
const HEADER_ANCHORS = [0, 1, 2, 4, 8, 12, 16, 20, 24, 32, 40, 48, 56, 64, 72, 76, 80, 96, 120, 128, 140, 152, 160, 176, 192, 208, 240, 256];

/** Delete a run. Shrinks a length-field-relative structure into a malformed one. */
export const chunkDelete = (buf, rng) => {
  if (buf.length <= 2) return Buffer.from(buf);
  const len = rng.between(1, Math.max(1, Math.floor(buf.length / 3)));
  const off = rng.below(buf.length - len);
  return clamp(Buffer.concat([buf.subarray(0, off), buf.subarray(off + len)]));
};

/** Duplicate a run. Grows a count-relative structure past what the file declares. */
export const chunkDuplicate = (buf, rng) => {
  if (buf.length === 0) return Buffer.from(buf);
  const len = rng.between(1, Math.max(1, Math.floor(buf.length / 2)));
  const off = rng.below(buf.length - len + 1);
  return clamp(Buffer.concat([buf.subarray(0, off + len), buf.subarray(off, off + len), buf.subarray(off + len)]));
};

/** Replace a run with a run from elsewhere in the same input. */
export const byteSplice = (buf, rng) => {
  if (buf.length < 4) return Buffer.from(buf);
  const len = rng.between(1, Math.max(1, Math.floor(buf.length / 4)));
  const dst = rng.below(buf.length - len);
  const src = rng.below(buf.length - len);
  const out = Buffer.from(buf);
  buf.copy(out, dst, src, src + len);
  return out;
};

/** Replace a run with bytes drawn from the alphabet of the format. */
export const alphabetSplice = (buf, rng, alphabet) => {
  if (buf.length === 0 || !alphabet || !alphabet.length) return Buffer.from(buf);
  const out = Buffer.from(buf);
  const len = rng.between(1, Math.max(1, Math.min(64, out.length)));
  const off = rng.below(out.length - len + 1);
  for (let i = 0; i < len; i++) out[off + i] = alphabet[rng.below(alphabet.length)];
  return out;
};

/** Insert a run of boundary bytes. Grows a file past a declared boundary. */
export const chunkInsert = (buf, rng) => {
  const len = rng.between(1, 32);
  const off = rng.below(buf.length + 1);
  const run = Buffer.alloc(len);
  for (let i = 0; i < len; i++) run[i] = rng.pick(INTERESTING_U8);
  return clamp(Buffer.concat([buf.subarray(0, off), run, buf.subarray(off)]));
};

/** Zero a run. The "this field is absent" case, which is rarely the same as "is zero". */
export const chunkZero = (buf, rng) => {
  if (buf.length === 0) return Buffer.from(buf);
  const out = Buffer.from(buf);
  const len = rng.between(1, Math.max(1, Math.floor(out.length / 4)));
  const off = rng.below(out.length - len + 1);
  out.fill(0, off, off + len);
  return out;
};

/**
 * Text-shaped mutation, for the two targets whose input is source text rather than a
 * binary record. A byte flip in the middle of a UTF-8 sequence produces a replacement
 * character and teaches the parser nothing; what breaks a text parser is a run of
 * characters that keeps a regex engine backtracking.
 */
export const textRun = (buf, rng) => {
  const src = buf.toString('utf8');
  if (src.length === 0) return buf;
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789@._-+% \t';
  const len = rng.between(200, Math.min(400_000, Math.max(1000, src.length)));
  let s = '';
  for (let i = 0; i < len; i++) s += alphabet[rng.below(alphabet.length)];
  return clamp(Buffer.from(src + s, 'utf8'));
};

/**
 * Repeat one character a long way. The cheapest ReDoS probe there is, and the only
 * strategy that can find the class of defect this lab found twice.
 *
 * The upper bound matters and it was wrong first: at 60 000 characters the quadratic
 * regexes this lab hunts for cost well under the 4 s per-input ceiling, so a run with
 * this bound reported "the flawed twin SURVIVED" -- a false negative that read exactly
 * like a real one. Measured cost of the flawed accessor regex: 20k -> 0.1 s,
 * 50k -> 0.6 s, 100k -> 2.6 s. So the ceiling has to be reachable, and 400 000 puts a
 * quadratic engine decisively over 4 s while a linear one stays under 5 ms. That gap is
 * the whole measurement.
 */
export const textRepeat = (buf, rng) => {
  const src = buf.toString('utf8');
  /* The characters that appear in an obfuscator's identifier alphabet and in an email
     local part -- the two shapes the quadratic regexes in this repo are written against. */
  const ch = rng.pick('abzA0@._- \t\n');
  const n = rng.between(2000, 400_000);
  return clamp(Buffer.from(src + ch.repeat(n), 'utf8'));
};

/* ------------------------------------------------------------------- the table */

export const STRATEGIES = {
  bitFlip: { fn: bitFlip, kind: 'bit', about: 'flip 1-8 individual bits' },
  byteSet: { fn: byteSet, kind: 'bit', about: 'set one byte to a boundary value (0, 1, 0x7f, 0x80, 0xff)' },
  intInject: { fn: intInject, kind: 'int', about: 'overwrite a 2/4/8-byte window with a boundary integer, LE or BE' },
  truncate: { fn: truncate, kind: 'length', about: 'cut the input, biased to just past a header boundary' },
  chunkDelete: { fn: chunkDelete, kind: 'chunk', about: 'delete a run' },
  chunkDuplicate: { fn: chunkDuplicate, kind: 'chunk', about: 'duplicate a run' },
  byteSplice: { fn: byteSplice, kind: 'chunk', about: 'replace a run with a run from elsewhere in the same input' },
  chunkInsert: { fn: chunkInsert, kind: 'chunk', about: 'insert a run of boundary bytes' },
  chunkZero: { fn: chunkZero, kind: 'chunk', about: 'zero a run' },
  alphabetSplice: { fn: alphabetSplice, kind: 'chunk', about: 'replace a run with bytes from the format alphabet' },
  textRun: { fn: textRun, kind: 'text', about: 'append a long random run of identifier/email characters' },
  textRepeat: { fn: textRepeat, kind: 'text', about: 'append one character tens of thousands of times (ReDoS probe)' },
};

export const STRATEGY_NAMES = Object.keys(STRATEGIES);

/** Binary targets get the byte strategies; text targets also get the text ones. */
export function strategiesFor(kind) {
  return STRATEGY_NAMES.filter((n) => {
    const k = STRATEGIES[n].kind;
    return kind === 'text' ? true : k !== 'text';
  });
}

/* ----------------------------------------------------------------- the recipe */

/**
 * Mutate a seed `steps` times, recording each step.
 *
 * The returned recipe is complete: seed sha256 + the ordered step list re-derives the
 * bytes exactly, given the same run id. That is what makes a finding replayable without
 * storing the hostile input in git.
 *
 * @param {Buffer} seedBytes
 * @param {Rng} rng
 * @param {{maxSteps:number, kind:string, alphabet?:number[], salt?:string}} opts
 */
export function mutate(seedBytes, rng, { maxSteps = 1, kind = 'binary', alphabet = null, salt = '' } = {}) {
  let bytes = Buffer.from(seedBytes);
  const applied = [];
  const pool = strategiesFor(kind);
  /* The step count is drawn HERE, from the same stream, rather than by the caller.
     When the caller drew it, the replay -- which restarts from a fresh Rng at the same
     salt -- was one value behind and produced different bytes. The recipe now records
     the count, and `replayRecipe` reads it from there instead of re-deriving it. */
  const steps = 1 + rng.below(maxSteps);
  for (let i = 0; i < steps; i++) {
    const name = rng.pick(pool);
    const entry = { strategy: name };
    if (name === 'alphabetSplice' && alphabet) {
      bytes = STRATEGIES[name].fn(bytes, rng, alphabet);
      /* The ALPHABET ITSELF is recorded, not just its size. Recording only the length and
         rebuilding 0..n-1 on replay is the same class of bug as the two draw-order ones:
         it looks like a faithful re-derivation and it is not. Measured: 122 of 800
         round-trips mismatched, every one of them a recipe ending in alphabetSplice. */
      entry.alphabet = Array.from(alphabet);
    } else {
      bytes = STRATEGIES[name].fn(bytes, rng);
    }
    applied.push(entry);
  }
  return {
    bytes: clamp(bytes),
    recipe: { salt, kind, maxSteps, steps: applied.length, applied },
  };
}

/**
 * Re-derive a mutated input from a recipe. The inverse of `mutate`, and the reason a
 * crash can be replayed from its description alone.
 *
 * The subtlety that cost this lab a whole run the first time: the strategy SELECTION
 * draw has to be replayed too, not just the strategy's own draws. `mutate` picks a name
 * off the pool with one `rng.pick` and then the strategy consumes more; a replay that
 * skipped the selection would be one draw behind for every step and would silently
 * produce different bytes. It produced different bytes, and 58 of 58 triages failed
 * with a hash mismatch, which is exactly the failure this function exists to make
 * impossible -- the assertion caught the harness's own bug, not a parser's.
 *
 * So the selection is replayed and CHECKED: if the pool has been edited since the
 * recipe was written, the recorded name no longer matches what the stream picks, and
 * this throws rather than returning plausible-looking wrong bytes.
 */
export function replayRecipe(seedBytes, recipe, { kind = recipe.kind || 'binary' } = {}) {
  const rng = new Rng(recipe.salt);
  const pool = strategiesFor(kind);
  let bytes = Buffer.from(seedBytes);
  /* The step-count draw comes FIRST in `mutate` and so it comes first here. Leaving it
     out is what broke replay twice: the stream would be one value behind from the very
     first strategy selection, and the drift check below -- which exists to catch exactly
     this -- fired on the first step of every recipe. */
  if (recipe.maxSteps != null) {
    const count = 1 + rng.below(recipe.maxSteps);
    if (count !== recipe.applied.length) {
      throw new Error(`recipe drift: the stream yields ${count} steps, the recipe records ${recipe.applied.length}`);
    }
  }
  for (const step of recipe.applied) {
    const entry = STRATEGIES[step.strategy];
    if (!entry) throw new Error(`unknown strategy in recipe: ${step.strategy}`);
    const chosen = rng.pick(pool);
    if (chosen !== step.strategy) {
      throw new Error(`recipe drift at step ${step.strategy}: the stream now picks ${chosen}. `
        + 'The strategy pool or the seed set changed after this recipe was written.');
    }
    if (step.strategy === 'alphabetSplice') {
      bytes = entry.fn(bytes, rng, step.alphabet ?? Array.from({ length: step.alphabetBytes }, (_, i) => i & 0xff));
    } else {
      bytes = entry.fn(bytes, rng);
    }
  }
  return clamp(bytes);
}

/** Discard the draws a step did not use, so a replay lands on the same stream. */
export function rngFor(runId, target, index) {
  return new Rng(`${runId}|${target}|${index}`);
}
