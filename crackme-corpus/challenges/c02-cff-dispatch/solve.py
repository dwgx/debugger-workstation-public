#!/usr/bin/env python3
"""c02 solver -- control-flow flattening: rebuild the state machine.

What the tools give you:

  * Ghidra headless decompiles the dispatcher into a `switch (state)` with one
    `case` per basic block. Nothing in the export is contiguous text: the
    password exists only as an ordered walk of the graph.
  * The solver parses those cases structurally -- expected character, the state
    on match, the state on mismatch -- then finds the entry state as the only
    node with in-degree 0, and walks the match edges to the state that returns
    1. The path labels are the password.
  * radare2 re-derives the same immediates from the disassembly (a second tool,
    not the one that produced the hypothesis).
  * The artifact is the final judge: it must answer ACCEPTED.

Exit 0 only when all three agree.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import labkit as lk  # noqa: E402

CASE_RE = re.compile(r"^[ \t]*case[ \t]+(0x[0-9a-fA-F]+|\d+)[ \t]*:", re.M)
CHAR_RE = re.compile(r"==\s*'(\\?.|\\x[0-9a-fA-F]{2})'")
CONST_ASSIGN_RE = re.compile(r"=[ \t]*(0x[0-9a-fA-F]+|\d+)[ \t]*;")
RETURN_RE = re.compile(r"return[ \t]+(\d+)[ \t]*;")


def parse_dispatcher(text):
    """-> (cases{state:(char, ok, bad)}, accept, reject). Raises ValueError."""
    hits = list(CASE_RE.finditer(text))
    if not hits:
        raise ValueError("no `case N:` labels")
    cases, accept, reject = {}, set(), set()
    for i, m in enumerate(hits):
        state = int(m.group(1), 0)
        body = text[m.end():hits[i + 1].start() if i + 1 < len(hits) else len(text)]
        chars = CHAR_RE.findall(body)
        consts = [int(c, 0) for c in CONST_ASSIGN_RE.findall(body)]
        rets = RETURN_RE.findall(body)
        if chars:
            if len(chars) != 1 or len(consts) != 2:
                raise ValueError(f"case {state}: unexpected shape (chars={chars} consts={consts})")
            cases[state] = (chars[0], consts[0], consts[1])
        elif rets:
            (accept if int(rets[0]) == 1 else reject).add(state)
        else:
            raise ValueError(f"case {state}: no character test and no return")
    if len(accept) != 1 or len(reject) != 1:
        raise ValueError(f"expected one accept and one reject state, got {accept} / {reject}")
    return cases, accept.pop(), reject.pop()


def find_flat_dispatcher(files):
    """The one decompiled function that is a character-by-character flattening."""
    found = []
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        if "switch" not in t:
            continue
        try:
            cases, accept, reject = parse_dispatcher(t)
        except ValueError:
            continue
        if len(cases) >= 5:
            found.append((f, t, cases, accept, reject))
    if len(found) != 1:
        raise ValueError(f"expected exactly one flattened dispatcher, matched "
                         f"{[os.path.basename(f) for f, *_ in found]}")
    return found[0]


def walk(cases, accept, reject):
    targets = {s for (_, ok, bad) in cases.values() for s in (ok, bad)}
    entry = [s for s in cases if s not in targets]
    if len(entry) != 1:
        lk.fail(f"expected exactly one in-degree-0 entry state, got {entry}")
    state, out, seen = entry[0], [], 0
    while state not in (accept, reject):
        if state not in cases or seen > len(cases) + 1:
            lk.fail(f"walk fell off the graph at state {state}")
        ch, ok, _bad = cases[state]
        out.append(ch)
        state, seen = ok, seen + 1
    if state == reject:
        lk.fail("the match-only path lands on the reject state")
    return entry[0], accept, "".join(out)


def r2_second_opinion(exe, addr, cases, accept, reject, password):
    """radare2 re-derives the state graph from the disassembly, independently.

    Checks three things against the Ghidra-derived graph: the character
    immediates, the target states of the jump table, and every transition
    constant the dispatcher writes.
    """
    text = lk.r2("aaa", f"s {addr:#x}", "pdc", exe=exe)
    cmp_chars = set(re.findall(r"- 0x[0-9a-f]+ // '(.)' // \d+", text))
    jump_targets = {int(v) for v in re.findall(r"^[ \t]*case (\d+)", text, re.M)}
    edges = {int(v, 0) for v in re.findall(r"\[var_[0-9a-f]+h\] = (0x[0-9a-f]+|\d+)", text)}

    want_chars = set(password)
    want_edges = {s for (_, ok, bad) in cases.values() for s in (ok, bad)}
    print(f"r2:     cmp immediates decode to {sorted(cmp_chars)}")
    print(f"r2:     jump-table cases {sorted(jump_targets)}; transition constants {sorted(edges)}")
    if not want_chars <= cmp_chars:
        lk.fail(f"r2's disassembly is missing character immediates {sorted(want_chars - cmp_chars)}")
    if not {accept, reject} <= jump_targets:
        lk.fail(f"r2 did not see both terminal states as jump-table targets")
    if not want_edges <= edges:
        lk.fail(f"r2's transition constants miss {sorted(want_edges - edges)}")
    return len(cmp_chars)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--ghidra-out", required=True)
    ap.add_argument("--expect-password", required=True)
    ap.add_argument("--expect-flag", required=True)
    a = ap.parse_args()

    lk.banner("c02", "control-flow flattening (dispatcher switch)")
    files = lk.ghidra_files(a.ghidra_out)
    try:
        path, text, cases, accept, reject = find_flat_dispatcher(files)
    except ValueError as e:
        lk.fail(str(e))
    print(f"ghidra: dispatcher = {os.path.basename(path)}")
    print(f"ghidra: {len(cases)} states parsed; accept={accept} reject={reject}")
    entry, accept2, password = walk(cases, accept, reject)
    print(f"ghidra: entry state {entry} -> accept {accept2}; graph walk labels = {password!r}")

    addr = int(re.search(r"_([0-9a-fA-F]{6,})\.c$", path).group(1), 16)
    r2_second_opinion(a.exe, addr, cases, accept, reject, password)

    raw = open(a.exe, "rb").read()
    if password.encode() in raw:
        lk.fail("the password is present as plain bytes -- the flattening did not hide it")
    print("check:  the password does not appear anywhere in the file as bytes")

    rc, out, _ = lk.run_sample(a.exe, [password])
    lines = [l for l in out.splitlines() if l.strip()]
    print(f"binary: rc={rc} {' | '.join(lines)}")
    if rc != 0 or "ACCEPTED" not in out:
        lk.fail("the binary rejected the recovered password")
    flag = lines[1] if len(lines) > 1 else ""
    if password != a.expect_password:
        lk.fail(f"password {password!r} != expected {a.expect_password!r}")
    if flag != a.expect_flag:
        lk.fail(f"flag {flag!r} != expected {a.expect_flag!r}")

    print(f"PASS c02 password={password!r} flag={flag!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
