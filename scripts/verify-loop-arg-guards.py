#!/usr/bin/env python3
"""Check that every lab loop's argument guard can ACCEPT, not merely refuse.

WHY THIS EXISTS. Measured 2026-10-05. Five of the nine lab loops guarded their arguments with

    const ALLOWED = new Set('--json');            // three loops
    const ALLOWED = new Set('--json', '--quiet'); // two loops

Both are wrong. `new Set` takes ONE argument, so the second form silently discarded
'--quiet'. And a string is iterable, so the first form yielded Set{'-','j','s','o','n'} —
characters, not flags. Every one of those guards therefore REFUSED every legitimate flag
it was written to allow.

It survived a long time because it fails open in the direction everybody tests. The guards
were introduced to stop a lab silently ignoring an argument, and they demonstrably did that:
a bogus argument was refused, and a no-argument run stayed green. Both facts are true of a
guard that refuses everything. Nobody had run a loop with a flag it actually declares.

THE RULE. A guard has two obligations and the second is the one that gets skipped:

    refuse what it cannot honour   <- tested, and it passed
    accept what it can honour      <- untested, and it was broken

This file checks the second statically, in milliseconds, by requiring the allow-set to be
built from an array literal or a spread -- never from a bare string, and never with more
than one positional argument. It deliberately does NOT execute the loops: fuzz-lab alone
exceeds 400 s un-budgeted, and a gate that takes seven minutes to say "you spelled a Set
wrong" is a gate nobody runs.

A runtime accept/reject check belongs in assert-probes.py, which already pays for the loop
run and can afford to assert both directions there. See the note appended to each loop.

Exit 0 on success. Any violation exits 1 and names the file and line.
"""
from __future__ import annotations

import pathlib
import re
import sys

def _split_args(inner: str) -> list[str]:
    """Split a Set() argument list on top-level commas only. Returns [] when unbalanced."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = ""
    esc = False
    for ch in inner:
        if esc:
            buf.append(ch); esc = False; continue
        if ch == "\\" and quote:
            buf.append(ch); esc = True; continue
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"`":
            quote = ch; buf.append(ch); continue
        if ch in "[{(":
            depth += 1; buf.append(ch); continue
        if ch in "]})":
            depth -= 1; buf.append(ch); continue
        if ch == "," and depth == 0:
            parts.append("".join(buf)); buf = []; continue
        buf.append(ch)
    if quote or depth:
        return []                       # unbalanced -- we cannot parse it, so claim nothing
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _is_string_literal(arg: str) -> bool:
    """True only for a quoted literal. `new Set(x)` and `new Set(f(x))` are legitimate: the
    argument is an expression whose value we cannot see, and the guard's correctness then
    depends on the caller. Only a literal tells us the guard is wrong."""
    return len(arg) >= 2 and arg[0] in "'\"`" and arg[-1] == arg[0]


def check(path: pathlib.Path) -> list[str]:
    """-> list of violation strings for one file (empty means it passed)."""
    problems: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:                                   # pragma: no cover
        return [f"{path.name}: cannot read ({exc})"]

    text = "\n".join(lines)
    # Match the whole declaration, then count parens to find where it ends.
    for m in re.finditer(r"^[ \t]*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new Set\(", text, re.M):
        name = m.group(1)
        start = m.end()                       # just past the '('
        depth, i, quote, esc = 1, start, "", False
        while i < len(text) and depth:
            ch = text[i]
            if esc:
                esc = False
            elif ch == "\\" and quote:
                esc = True
            elif quote:
                if ch == quote:
                    quote = ""
            elif ch in "'\"`":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        if depth:
            continue                           # unbalanced; say nothing rather than guess

        inner = text[start:i - 1]
        lineno = text.count("\n", 0, m.start()) + 1
        args = _split_args(inner)

        if not args:
            problems.append(
                f"{path.name}:{lineno}: `{name} = new Set()` is empty, so the guard refuses "
                f"EVERY argument. A guard that refuses everything looks exactly like one that "
                f"works."
            )
            continue

        if len(args) > 1:
            problems.append(
                f"{path.name}:{lineno}: `{name} = new Set(...)` was given {len(args)} positional "
                f"arguments. Set accepts ONE; the rest are discarded with no error, so those "
                f"flags are not in the allow-set and are refused."
            )
            continue

        if _is_string_literal(args[0]):
            problems.append(
                f"{path.name}:{lineno}: `{name} = new Set({args[0]})` builds a set of CHARACTERS, "
                f"because a string is iterable. Every flag it means to allow is refused. "
                f"Write new Set([{args[0]}])."
            )
    return problems


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    loops = sorted(root.glob("*/tools/loop.mjs"))
    if not loops:
        print(f"{__file__}: found no */tools/loop.mjs under {root}", file=sys.stderr)
        return 1

    problems: list[str] = []
    guarded = 0
    for loop in loops:
        problems.extend(check(loop))
        if "new Set(" in loop.read_text(encoding="utf-8", errors="replace"):
            guarded += 1

    for p in problems:
        print(f"  {p}", file=sys.stderr)

    print(f"verify-loop-arg-guards: {len(loops)} loops, {guarded} with a new Set guard, "
          f"{len(problems)} violation(s).")
    if problems:
        print("A guard that refuses everything looks exactly like a guard that works until "
              "you try to use it. Test the ACCEPT direction.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())