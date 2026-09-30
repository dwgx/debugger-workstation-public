#!/usr/bin/env node
/* solve-m02.mjs -- recover m02's flattened control flow from the decompilation.
 *
 * The sample is a state machine: every basic block is a `case`, one variable
 * carries every control transfer, and the entry state is an array element. There
 * is no straight line to read, so the solver builds the successor graph and walks
 * it. What it recovers, and where each piece comes from:
 *
 *   entry state     `int <S> = <Arr>[<i>]` in Main, plus the initialiser of <Arr>
 *   initial acc     the first `<A> = <n>L;` in Main
 *   the transform   the `return` of Step -- multiplier and modulus
 *   per-block <K>   the literal in `<A> = Step(<A>, <K>)`
 *   per-block next  `<S> = <n>;` inside the branch the guard selects
 *   the guards      the `return` of each OpaqueN, evaluated at the id it is
 *                   actually called with, so the dead edges are dropped
 *
 * Two ways to be wrong, and the runner uses both as controls:
 *
 *   --ignore-opaque   take the `if` branch of every guard, i.e. trust the dead
 *                     edges. The walk cannot even complete, because a dead edge
 *                     sets the state but never feeds the accumulator.
 *   --entry <n>       start the walk somewhere other than the real entry. The
 *                     analysis completes and the answer is wrong, which is the
 *                     stronger kind of control: a complete, confident, incorrect
 *                     result.
 *
 *   node tools/solve-m02.mjs --asm out/m02/m02_flatten.dll
 *   node tools/solve-m02.mjs --asm ... --expect dbb9c662
 *   node tools/solve-m02.mjs --asm ... --entry 43 --expect dbb9c662   # must exit 4
 */
import { braces, decompile, evalCsharp, finish, flag, method, params, returnExpr } from './clrlib.mjs';

const asm = flag('asm') ? process.argv[process.argv.indexOf('--asm') + 1] : null;
if (!asm) {
  process.stderr.write('usage: solve-m02.mjs --asm <assembly> [--expect <acc>] [--entry <n>] [--ignore-opaque] [--json]\n');
  process.exit(2);
}

const src = await decompile(asm);
const die = (m) => { process.stderr.write(`solve-m02: ${m}\n`); process.exit(1); };
const main = method(src, 'Main');
if (!main) die('no Main in the decompilation');

/* ---- the accumulator transform ------------------------------------------ */
const stepBody = method(src, 'Step');
if (!stepBody) die('no Step method in the decompilation');
const stepExpr = returnExpr(stepBody);
const mult = (/\*\s*(\d+)/.exec(stepExpr) || [])[1];
const modText = (/%\s*([^;)]+)/.exec(stepExpr) || [])[1];
if (!mult || !modText) die(`cannot read the accumulator out of \`${stepExpr}\``);
const MULT = BigInt(mult);
const MOD = BigInt(evalCsharp(modText));

/* ---- entry state and initial accumulator -------------------------------- */
const init = /\bint\s+(\w+)\s*=\s*(\w+)\[(\d+)\]\s*;/.exec(main);
if (!init) die('cannot find the `int <S> = <Arr>[<i>]` initialiser in Main');
const [stateVar, arrVar, arrIndex] = [init[1], init[2], Number(init[3])];

const arrDecl = new RegExp(`readonly\\s+int\\[\\]\\s+${arrVar}\\s*=\\s*new\\s+int\\[\\d+\\]\\s*\\{([^}]*)\\}`).exec(src);
if (!arrDecl) die(`cannot find the initialiser of ${arrVar}`);
const boot = arrDecl[1].split(',').map((s) => Number(s.trim()));
if (!Number.isInteger(boot[arrIndex])) die(`${arrVar}[${arrIndex}] is out of range`);
const entry = boot[arrIndex];

const accInit = /\b(\w+)\s*=\s*(\d+)L\s*;/.exec(main);
if (!accInit) die('cannot find the initial accumulator in Main');
const ACC0 = BigInt(accInit[2]);

/* ---- the switch, split into cases --------------------------------------- */
const sw = new RegExp(`switch\\s*\\(\\s*${stateVar}\\s*\\)\\s*\\{`).exec(src);
if (!sw) die(`no \`switch (${stateVar})\` -- this is not a flattened dispatcher`);
const swOpen = src.indexOf('{', sw.index);
const swBody = src.slice(swOpen + 1, braces(src, swOpen));

const LABEL = /(?:case\s+-?\d+\s*:|default\s*:)/g;
const labels = [...swBody.matchAll(LABEL)];
const cases = new Map();
for (const hit of [...swBody.matchAll(/case\s+(-?\d+)\s*:/g)]) {
  const next = labels.find((m) => m.index > hit.index);
  cases.set(Number(hit[1]), swBody.slice(hit.index, next ? next.index : swBody.length));
}
if (cases.size === 0) die('the switch has no cases');

/* ---- guards: evaluate each OpaqueN at the argument it is called with ------ */
const ignoreOpaque = flag('ignore-opaque');
const guardLog = [];

function evaluateGuard(callText) {
  const call = /(\w+)\s*\(([^)]*)\)/.exec(callText);
  if (!call) return { known: false, value: false };
  const [, name, argText] = call;
  const body = method(src, name);
  if (!body) { guardLog.push(`${name} -> method not found`); return { known: false, value: false }; }
  const expr = returnExpr(body);
  const names = params(src, name);
  const args = argText.split(',').map((s) => s.trim());
  const env = {};
  names.forEach((n, i) => { env[n] = args[i]; });
  let value;
  try {
    value = Boolean(evalCsharp(expr, env));
  } catch (e) {
    guardLog.push(`${name}(${args.join(', ')}) -> UNEVALUABLE (${e.message})`);
    return { known: false, value: false };
  }
  guardLog.push(`${name}(${args.join(', ')}) -> ${value}`);
  return { known: true, value };
}

/**
 * Take the `if` block or the `else` block out of a guarded case body.
 *
 * The trap here is index arithmetic: `rest` is a suffix of `body`, so an offset
 * found inside `rest` has to be re-based before it is used to slice `body`.
 * Getting that wrong silently yields an empty block, which then reads as "this
 * state has no Step call" -- a misleading error for a perfectly ordinary case.
 */
function branch(body, guardValue) {
  const ifAt = /\bif\b/.exec(body);
  if (!ifAt) return body;
  const ifOpen = body.indexOf('{', ifAt.index);
  if (ifOpen < 0) return body;
  const ifClose = braces(body, ifOpen);
  const ifBlock = body.slice(ifOpen + 1, ifClose);
  if (guardValue) return ifBlock;
  const elseAt = /\belse\b/.exec(body.slice(ifClose + 1));
  if (!elseAt) return '';
  const elseOpen = body.indexOf('{', ifClose + 1 + elseAt.index);
  return body.slice(elseOpen + 1, braces(body, elseOpen));
}

/** Successor, accumulator contribution, and ambiguity verdict for one case. */
function resolve(id) {
  const body = cases.get(id);
  if (body === undefined) return { error: `no case for state ${id}` };

  const guardCall = /if\s*\(\s*(\w+\s*\([^)]*\))\s*\)/.exec(body);
  let live = body;
  if (guardCall) {
    const g = evaluateGuard(guardCall[1]);
    live = branch(body, ignoreOpaque ? true : g.value);
  }

  const k = new RegExp(`Step\\s*\\(\\s*\\w+\\s*,\\s*(-?\\d+)\\s*\\)`).exec(live);
  const next = new RegExp(`\\b${stateVar}\\s*=\\s*(-?\\d+)\\s*;`).exec(live);

  // How many successors does this case have on the page, ignoring the guard? More
  // than one is acceptable only when a guard was actually there to choose between
  // them. Otherwise the walk is picking an edge it has no evidence for, and the
  // answer is a guess wearing the costume of a result.
  const allNext = [...body.matchAll(new RegExp(`\\b${stateVar}\\s*=\\s*(-?\\d+)\\s*;`, 'g'))].map((m) => Number(m[1]));
  const ambiguous = new Set(allNext).size > 1 && !guardCall;

  if (!k) return { error: `state ${id}: no Step(<acc>, <k>) on the taken path`, ambiguous };
  if (!next) return { error: `state ${id}: no \`${stateVar} = <n>;\` on the taken path`, ambiguous };
  return { k: BigInt(k[1]), next: Number(next[1]), ambiguous };
}

/* ---- walk the graph ----------------------------------------------------- */
const entryArg = flag('entry') ? process.argv[process.argv.indexOf('--entry') + 1] : null;
const start = entryArg
  ? (entryArg.toLowerCase().startsWith('0x') ? parseInt(entryArg.slice(2), 16) : Number(entryArg))
  : entry;

let acc = ACC0;
let cur = start;
const order = [];
const seen = new Set();
const ambiguousStates = [];
let err = null;
let terminated = false;
while (cur !== -1) {
  if (seen.has(cur)) { err = `state ${cur} revisited -- the walk found a cycle it cannot follow`; break; }
  seen.add(cur);
  order.push(cur);
  const r = resolve(cur);
  if (r.ambiguous) ambiguousStates.push(cur);
  if (r.error) { err = r.error; break; }
  acc = ((acc * MULT) + r.k) % MOD;
  if (acc < 0n) acc += MOD;
  cur = r.next;
  if (order.length > cases.size + 1) { err = 'walk did not terminate'; break; }
  terminated = cur === -1;
}

const visited = new Set(order);
const unreached = [...cases.keys()].filter((c) => !visited.has(c));
const hex = (n) => n.toString(16).padStart(8, '0').toUpperCase();
const chain = order.map((c) => `0x${c.toString(16).toUpperCase().padStart(2, '0')}`).join(' -> ');

finish({
  ran: !err,
  valid: !err && terminated && order.length > 1 && ambiguousStates.length === 0,
  error: err ?? undefined,
  entry: start === entry
    ? `Boot[${arrIndex}] = 0x${entry.toString(16).toUpperCase()}`
    : `Boot[${arrIndex}] = 0x${entry.toString(16).toUpperCase()}  [OVERRIDDEN with --entry ${start}]`,
  transform: `(acc * ${MULT} + k) mod ${MOD}`,
  guards: ignoreOpaque ? [...guardLog, 'ALL GUARDS IGNORED -- dead edges trusted'] : guardLog,
  order: chain,
  blocks: `${order.length} reached, ${unreached.length} unreachable (${unreached.map((c) => `0x${c.toString(16).toUpperCase()}`).join(',') || 'none'})`,
  acc: `0x${hex(acc)}`,
  answer: hex(acc).toLowerCase(),
}, { expect: flag('expect') ? process.argv[process.argv.indexOf('--expect') + 1] : undefined });
