/* rng.mjs — the run's entire source of randomness, and it is a pure function of a
 * string. No Math.random anywhere in this lab.
 *
 * The rule the lab exists to teach is "a crash you cannot reproduce is not a
 * finding". Reproducibility needs two things: a corpus that does not drift, and a
 * mutator whose choice sequence does not drift. This file is the second one.
 *
 * xoshiro128** over a seed expanded by splitmix32, because a 32-bit LCG has visible
 * short-period structure in the low bits and mutator offsets live in the low bits.
 */

/** FNV-1a: the run id string -> 32-bit seed. Stable across processes and platforms. */
export function seedFrom(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function splitmix32(a) {
  return function next() {
    a = (a + 0x9e3779b9) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 16), 0x21f0aaad) >>> 0;
    t = Math.imul(t ^ (t >>> 15), 0x735a2d97) >>> 0;
    return (t ^ (t >>> 15)) >>> 0;
  };
}

const rotl = (x, k) => ((x << k) | (x >>> (32 - k))) >>> 0;

export class Rng {
  /** @param {string|number} seed run id, or a raw 32-bit seed. */
  constructor(seed) {
    const sm = splitmix32(typeof seed === 'number' ? seed >>> 0 : seedFrom(String(seed)));
    this.s0 = sm(); this.s1 = sm(); this.s2 = sm(); this.s3 = sm();
    if ((this.s0 | this.s1 | this.s2 | this.s3) === 0) this.s0 = 1;
    this.calls = 0;
  }

  /** Raw 32-bit draw. xoshiro128**: see the reference algorithm's `next()` step. */
  u32() {
    this.calls++;
    const result = Math.imul(rotl(Math.imul(this.s1, 5) >>> 0, 7) >>> 0, 9) >>> 0;
    const t = (this.s1 << 9) >>> 0;
    this.s2 = (this.s2 ^ this.s0) >>> 0;
    this.s3 = (this.s3 ^ this.s1) >>> 0;
    this.s1 = (this.s1 ^ this.s2) >>> 0;
    this.s0 = (this.s0 ^ this.s3) >>> 0;
    this.s2 = (this.s2 ^ t) >>> 0;
    this.s3 = rotl(this.s3, 11);
    return result;
  }

  /** Uniform in [0, n). Rejection-sampled, so no modulo bias. */
  below(n) {
    if (n <= 0) return 0;
    const limit = 0x100000000 - (0x100000000 % n);
    let v = this.u32();
    while (v >= limit) v = this.u32();
    return v % n;
  }

  /** Uniform in [lo, hi] inclusive. */
  between(lo, hi) { return lo + this.below(hi - lo + 1); }

  /** Uniform element. */
  pick(list) { return list[this.below(list.length)]; }

  bool(pTrue = 0.5) { return this.below(1_000_000) < pTrue * 1_000_000; }

  /** Fisher-Yates over a copy. */
  shuffled(list) {
    const out = list.slice();
    for (let i = out.length - 1; i > 0; i--) {
      const j = this.below(i + 1);
      [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
  }
}
