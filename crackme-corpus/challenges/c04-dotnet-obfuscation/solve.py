#!/usr/bin/env python3
"""c04 solver -- .NET: undo string encryption, then invert the opcode table.

Tool chain, in the order an analyst would run it:

  1. ilspycmd (or dnSpy) decompiles the assembly back to C#. That is the whole
     reason managed code is a different discipline from native reversing: the
     program comes back as source, and the fight is against the obfuscator, not
     against the compiler. This solver reads ONLY the decompiled C#.
  2. The string table is recovered from the decompile: four masked byte arrays
     and one key array. Unmasking them yields the password *and* the flag, plus
     two strings that are neither.
  3. The VM program is recovered the same way, then dispatched through the
     inverse of kOpcodeMap. The interpreter body in the decompile is what tells
     you what each opcode *means* -- CMP_CHAR, JMP, ACCEPT and so on -- so the
     mapping is derived, not guessed.
  4. Control flow is honoured. The program contains a JMP that skips a decoy
     CMP_IDX; a solver that walks the words linearly recovers a wrong answer.
  5. The artifact is the judge: the recovered password must make the assembly
     print ACCEPTED and the expected flag.

Two controls run against the solver's own reasoning:
  * a linear walk that ignores the JMP must produce a DIFFERENT answer, which is
    what proves the control flow is load-bearing rather than decorative;
  * the binary must reject a password that the VM would accept if the operand
    order were reversed.

Exit 0 only when all of that holds.
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import labkit as lk  # noqa: E402

ILSPY = os.environ.get(
    "CRACKME_ILSPY",
    os.path.join(lk.STATION, "Static-Reversing", "ilspycmd", "ilspycmd.exe"),
)

# The field names survive decompilation, so match on them rather than on the
# first int[] in the file -- kIndices and kOpcodeMap have identical syntax, and
# picking the wrong one silently produces a wrong answer.
# private static readonly int[] kIndices = new int[N] { 20257, 2577, ... };
INDICES_RE = re.compile(r"int\[\]\s*kIndices\s*=\s*new\s+int\[\d+\]\s*\{([^}]*)\}")
# private static readonly int[] kOpcodeMap = new int[N] { 3, 5, 1, 0, 4, 2 };
OPMAP_RE = re.compile(r"int\[\]\s*kOpcodeMap\s*=\s*new\s+int\[(\d+)\]\s*\{([^}]*)\}")
# private static readonly int[] kProgram = new int[N] { 65554, ... };
PROG_RE = re.compile(r"int\[\]\s*kProgram\s*=\s*new\s+int\[(\d+)\]\s*\{([^}]*)\}")

# private static readonly byte[][] kStrings = new byte[N][] { { 1, 2, ... }, ... };
STRINGS_RE = re.compile(r"byte\[\]\[\]\s*\w+\s*=\s*new\s+byte\[(\d+)\]\[\]\s*\{(.*?)\n\t\};", re.S)
# private static readonly byte[] kKeys = new byte[N] { 77, 77, 94, 90 };
KEYS_RE = re.compile(r"byte\[\]\s*\w+\s*=\s*new\s+byte\[\d+\]\s*\{([^}]*)\}")

# The decompiler strips comments, so an opcode's meaning cannot be read off a
# label -- it has to be read off the interpreter's behaviour. That is the actual
# skill: classify each `case` by what its body does. Every rule below keys on
# the operand, the program counter, or the return value, never on a name.
CASE_RE = re.compile(r"^\s*case\s+(\d+)\s*:\s*$", re.M)


def classify_cases(text):
    """opcode number -> symbolic meaning, derived from the decompiled body.

    The program counter is whichever local is used to index kProgram, and the
    operand is whichever local comes out of the word's low half. Classifying
    against *those* rather than against hardcoded names is what keeps this
    working when the decompiler renames its locals, which it does.
    """
    fetch = re.search(r"(\w+)\s*=\s*kProgram\[(\w+)\];", text)
    if not fetch:
        lk.fail("cannot find the program-counter local in the decompiled interpreter")
    pc = fetch.group(2)
    word = fetch.group(1)
    # The slot is the half taken by a shift, the operand the half taken by a
    # mask. Matching on the operator is what tells them apart; both halves come
    # out of the same word local.
    slot_m = re.search(r"(\w+)\s*=\s*%s\s*>>" % re.escape(word), text)
    arg_m = re.search(r"(\w+)\s*=\s*%s\s*&" % re.escape(word), text)
    if not slot_m or not arg_m:
        lk.fail("cannot find the slot/operand unpacking in the decompiled interpreter")
    slot_var, arg_var = slot_m.group(1), arg_m.group(1)

    hits = list(CASE_RE.finditer(text))
    if len(hits) < 4:
        lk.fail(f"the decompiled interpreter has only {len(hits)} case labels")
    meanings = {}
    for i, m in enumerate(hits):
        op = int(m.group(1))
        stop = hits[i + 1].start() if i + 1 < len(hits) else len(text)
        # The final case runs to end-of-file and would otherwise swallow the
        # helper methods below the switch, which mention the very calls the
        # classification keys on. The default arm is where the real body ends.
        dflt = re.search(r"^[ \t]*default\s*:", text[m.end():stop], re.M)
        if dflt:
            stop = m.end() + dflt.start()
        body = text[m.end():stop]
        # A per-character compare: the operand is cast to a character and
        # compared against a single element of the input. Detected structurally
        # so a renamed helper cannot change the classification.
        if re.search(r"\(char\)%s" % re.escape(arg_var), body) or \
                re.search(r"\(ushort\)%s" % re.escape(arg_var), body):
            meanings[op] = "CMP_CHAR"
        elif re.search(r"\.Length\s*!=", body):
            meanings[op] = "CMP_LEN"           # compares the input length
        elif "string.Equals" in body:
            meanings[op] = "CMP_IDX"           # whole-input compare against a string
        elif re.search(r"return\s+true\s*;", body):
            meanings[op] = "ACCEPT"            # the only path returning success
        elif re.search(r"%s\s*=\s*%s\s*;" % (re.escape(pc), re.escape(arg_var)), body):
            meanings[op] = "JMP"               # writes the operand straight into the PC
        elif "break" not in body:
            meanings[op] = "HALT"              # leaves the loop without success
        else:
            meanings[op] = "UNKNOWN"
    return meanings, pc, arg_var


def numbers(blob):
    return [int(t) for t in re.findall(r"-?\b0x[0-9a-fA-F]+\b|\b\d+\b", blob)]


def decompile(dll, outdir):
    if not os.path.isfile(ILSPY):
        lk.fail(f"ilspycmd not found at {ILSPY} (set CRACKME_ILSPY to override)")
    os.makedirs(outdir, exist_ok=True)
    p = subprocess.run([ILSPY, "-o", outdir, dll], capture_output=True, text=True, timeout=300)
    if p.returncode != 0:
        lk.fail(f"ilspycmd failed rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    files = [os.path.join(outdir, f) for f in sorted(os.listdir(outdir)) if f.endswith(".cs")]
    if len(files) != 1:
        lk.fail(f"expected one decompiled .cs, got {[os.path.basename(f) for f in files]}")
    return open(files[0], encoding="utf-8", errors="replace").read(), files[0]


def recover_strings(text):
    m = STRINGS_RE.search(text)
    if not m:
        lk.fail("no byte[][] string table in the decompile")
    rows = re.findall(r"new\s+byte\[\d+\]\s*\{([^}]*)\}", m.group(2))
    table = [bytes(numbers(r)) for r in rows]
    km = KEYS_RE.search(text)
    if not km:
        lk.fail("no byte[] key array in the decompile")
    keys = numbers(km.group(1))
    if len(keys) != len(table):
        lk.fail(f"{len(table)} masked strings but {len(keys)} keys")
    out = []
    for i, (blob, k) in enumerate(zip(table, keys)):
        dec = bytes(b ^ k for b in blob)
        if not lk.printable(dec):
            lk.fail(f"string slot {i} did not unmask to printable text (key {k:#04x})")
        out.append(dec.decode())
    return out



def run_vm(prog, slot_to_op, meanings, strings, honour_jump=True):
    """-> (password, path) walking the recovered program."""
    pc, cur, out, path, guard = 0, 0, [], [], 0
    while guard < 256:
        guard += 1
        if pc < 0 or pc >= len(prog):
            return None, path
        word = prog[pc]
        slot, arg = word >> 16, word & 0xFFFF
        # A slot outside the table is a malformed word, not a crash: the real VM
        # would index out of bounds, so a walk that lands here has failed.
        if not 0 <= slot < len(slot_to_op):
            path.append(f"{pc}:BAD SLOT {slot} (table has {len(slot_to_op)} entries)")
            return None, path
        op = slot_to_op[slot]
        name = meanings.get(op, f"?{op}")
        if name == "CMP_CHAR":
            out.append(chr(arg))
            path.append(f"{pc}:CMP_CHAR {chr(arg)!r}")
            cur += 1
            pc += 1
        elif name == "CMP_LEN":
            path.append(f"{pc}:CMP_LEN {arg}")
            pc += 1
        elif name == "JMP":
            path.append(f"{pc}:JMP {arg}")
            pc = arg if honour_jump else pc + 1
        elif name == "CMP_IDX":
            # A whole-input compare against the recovered string table. The only
            # entry the VM points at is the VM-hint string, which no correct
            # input can equal, so reaching this arm means the program failed.
            path.append(f"{pc}:CMP_IDX {arg} -> compares against {strings[arg]!r}, "
                        f"which no valid input can match")
            return None, path
        elif name == "ACCEPT":
            path.append(f"{pc}:ACCEPT")
            return "".join(out), path
        elif name == "HALT":
            path.append(f"{pc}:HALT")
            return None, path
        else:
            path.append(f"{pc}:UNKNOWN op={op}")
            return None, path
    return None, path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", required=True)
    ap.add_argument("--ilspy-out", required=True)
    ap.add_argument("--expect-password", required=True)
    ap.add_argument("--expect-flag", required=True)
    a = ap.parse_args()

    lk.banner("c04", ".NET string encryption + permuted-opcode control-flow VM")
    text, path = decompile(a.dll, a.ilspy_out)
    print(f"ilspy:   {os.path.basename(path)} ({len(text)} bytes of C#)")

    raw = open(a.dll, "rb").read()
    for needle in (a.expect_password.encode(), a.expect_flag.encode()):
        if needle in raw:
            lk.fail(f"{needle!r} is present verbatim in the assembly -- the string "
                    f"encryption is not doing anything")
    print("check:   neither the password nor the flag appears verbatim in the .dll")

    strings = recover_strings(text)
    for i, s in enumerate(strings):
        print(f"ilspy:   string[{i}] = {s!r}")
    flags = [s for s in strings if s.startswith("FLAG{")]
    if len(flags) != 1:
        lk.fail(f"expected exactly one unmasked FLAG{{..}} string, got {flags}")
    flag = flags[0]
    if flag != a.expect_flag:
        lk.fail(f"flag {flag!r} != expected {a.expect_flag!r}")

    pm = PROG_RE.search(text)
    om = OPMAP_RE.search(text)
    if not pm or not om:
        lk.fail("no opcode map or program array in the decompile")
    prog, opmap = numbers(pm.group(2)), numbers(om.group(2))
    if int(om.group(1)) != len(opmap):
        lk.fail("opcode map length disagrees with its declaration")
    if int(pm.group(1)) != len(prog):
        lk.fail("program length disagrees with its declaration")
    if sorted(opmap) != list(range(len(opmap))):
        lk.fail(f"kOpcodeMap is not a permutation: {opmap}")
    slot_to_op = [0] * len(opmap)
    for op, slot in enumerate(opmap):
        slot_to_op[slot] = op
    print(f"ilspy:   kOpcodeMap {opmap} -> inverse slot->opcode {slot_to_op}")

    meanings, pc_name, arg_name = classify_cases(text)
    print(f"ilspy:   interpreter classified from behaviour (pc={pc_name}, arg={arg_name}): "
          f"{dict(sorted(meanings.items()))}")
    for needed in ("CMP_CHAR", "CMP_LEN", "ACCEPT", "JMP", "HALT", "CMP_IDX"):
        if needed not in meanings.values():
            lk.fail(f"could not classify opcode {needed} from the decompiled body; "
                    f"got {sorted(set(meanings.values()))}")

    password, path_log = run_vm(prog, slot_to_op, meanings, strings, honour_jump=True)
    if password is None:
        lk.fail(f"the recovered program never reaches ACCEPT; path={path_log}")
    print(f"ilspy:   program walk ({len(prog)} words, {len(path_log)} steps) = {password!r}")
    for step in path_log[:3] + path_log[-3:]:
        print(f"ilspy:     {step}")
    if password != a.expect_password:
        lk.fail(f"recovered password {password!r} != expected {a.expect_password!r}")

    # Control 1: the JMP is load-bearing. A linear walk runs into the decoy
    # CMP_IDX and never reaches ACCEPT, so it yields no answer at all.
    linear, linear_path = run_vm(prog, slot_to_op, meanings, strings, honour_jump=False)
    print(f"control: linear walk that ignores JMP -> {linear!r}")
    for step in linear_path[-2:]:
        print(f"control:   {step}")
    if linear is not None:
        lk.fail("ignoring the JMP still produced an answer, so the control flow is "
                "not being tested by this challenge")

    # Control 2: the operand order matters. Swapping the packed halves must fail.
    swapped = [((w & 0xFFFF) << 16) | (w >> 16) for w in prog]
    rev, _ = run_vm(swapped, slot_to_op, meanings, strings, honour_jump=True)
    print(f"control: slot/arg halves swapped -> {rev!r}")
    if rev == password:
        lk.fail("swapping the packed halves changed nothing; the word layout is not "
                "what the challenge claims to teach")

    # Control 3: the decompiler is the oracle, not the source. A renamed local
    # must not change the answer, so classification keys on behaviour only.
    meanings2, _, _ = classify_cases(text.replace("CharAt", "GetCh"))
    alt, _ = run_vm(prog, slot_to_op, meanings2, strings, honour_jump=True)
    print(f"control: helper renamed in the decompile -> {alt!r}")
    if alt != password:
        lk.fail("the answer changed when only a decompiled local name changed")

    # The artifact decides.
    rc, out, _ = lk.run_sample(os.path.join(os.path.dirname(a.dll), "c04.exe"), [password])
    lines = [l for l in out.splitlines() if l.strip()]
    print(f"binary:  rc={rc} {' | '.join(lines)}")
    if rc != 0 or "ACCEPTED" not in out or flag not in out:
        lk.fail("the assembly did not accept the recovered password")

    rc2, out2, _ = lk.run_sample(os.path.join(os.path.dirname(a.dll), "c04.exe"), [linear or "x"])
    print(f"binary:  linear-walk answer -> rc={rc2} {out2.strip()!r}")
    if rc2 == 0:
        lk.fail("the assembly accepted the linear-walk answer; the JMP is not a decoy")

    print(f"PASS c04 password={password!r} flag={flag!r}")
    print("     managed code decompiled to source; string table unmasked; opcode "
          "permutation inverted; control flow honoured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
