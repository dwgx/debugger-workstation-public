/* worker.mjs — one fuzz input, in its own process, with a hard ceiling on both time
 * and heap.
 *
 * WHY A SUBPROCESS AND NOT A try/catch. A hang is not an exception. A regex engine
 * backtracking through a 400 KB claim does not return control to the event loop, does
 * not check a deadline, and cannot be interrupted from inside. The only way to bound it
 * is to give up on the process. That is why this file exists: the parent measures wall
 * clock and kills, and it is honest that a killed process is the only available signal.
 *
 * The heap ceiling is the same argument. `--max-old-space-size` makes V8 abort rather
 * than grow, which is the difference between "the fuzzer found a 6 GB allocation" and
 * "the fuzzer took the machine down". Both are findings; only one of them is survivable.
 *
 * Protocol: the parent writes one JSON request line to stdin, the worker writes one JSON
 * response line to stdout. Nothing else crosses the pipe, so a worker that spews on
 * failure cannot desynchronise the parent -- the parent reads one line and moves on.
 */
import { classify, TARGET_BY_ID } from './targets.mjs';

let chunks = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => { chunks += d; });
process.stdin.on('end', () => run());

function run() {
  let req;
  try {
    req = JSON.parse(chunks);
  } catch (e) {
    process.stdout.write(JSON.stringify({ outcome: 'error', detail: `bad request: ${e.message}` }) + '\n');
    process.exit(2);
  }

  const target = TARGET_BY_ID[req.target];
  if (!target) {
    process.stdout.write(JSON.stringify({ outcome: 'error', detail: `unknown target ${req.target}` }) + '\n');
    process.exit(2);
  }
  const variant = req.variant === 'flawed' ? target.flawed : target.reference;
  const input = Buffer.from(req.input, 'base64');

  const started = process.hrtime.bigint();
  let response;
  try {
    const r = classify(variant, input);
    const heapMb = process.memoryUsage().heapUsed / (1024 * 1024);
    response = {
      outcome: r.outcome,
      detail: r.detail,
      code: r.code,
      ms: r.ms,
      wallMs: Number(process.hrtime.bigint() - started) / 1e6,
      heapMb: Math.round(heapMb * 10) / 10,
    };
  } catch (e) {
    /* classify() catches everything the target throws, so reaching here means the
       classifier itself broke. Report it rather than dying silently: a harness that
       fails open looks exactly like a harness that found nothing. */
    response = {
      outcome: 'harness-error',
      detail: `${e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : String(e)}`.slice(0, 400),
    };
  }
  process.stdout.write(JSON.stringify(response) + '\n');
  process.exit(0);
}

/* There is deliberately no self-abort timer here.

   An earlier draft had one, on the theory that a worker ought to be able to notice its
   own overrun. It cannot, and the reason is the whole reason this file is a subprocess:
   a regex engine backtracking through a 400 KB claim never yields to the event loop, so
   a timer scheduled on that loop does not fire. It would have looked like a safety net
   and been dead code. The only thing that can stop a synchronous hang is an external
   signal, so the parent measures wall clock and kills. See `driver.mjs`. */
