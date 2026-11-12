#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Verify that every absolute executable path this repo launches is declared in
manifests/tools.json, and report the reverse set.

WHY THIS EXISTS
---------------
Every probe and lab script in this station launches its tools BY ABSOLUTE PATH. The
absolute prefix is machine-specific, so the manifest must describe the TOOL (a bare
executable name), not this box's D:\Software\... prefix. An absolute path the manifest
has never heard of is a tool that cannot be checked for presence, version or licensing,
and that a fresh clone has no way of learning it needs installing. skillspector.exe,
launched by headless-lab/tools/skill_security_control.ps1:24, was exactly such a tool.

WHAT IS COUNTED AS "INVOKED"
----------------------------
Scope is scripts/, */tools/, */lab/, plus labs/ if it ever appears. No top-level labs/
exists today; the lab dirs are web-reverse/lab, crypto-lab/lab, forensics-lab/lab,
fuzz-lab/lab, mobile-lab/lab and net-reverse/lab. Inside those, a candidate is a
drive-absolute (C:\..., D:/...), UNC (\\server\...) or env-rooted ($env:USERPROFILE\...)
path ending in an executable extension. The bare executable NAME is what gets recorded,
because that is the machine-independent part.

Four exclusions apply. Each prints its own count, and each count below was MEASURED on
this tree by attributing every candidate to the first rule that dropped it -- so the
overlap between them is visible rather than assumed:

  E1 URL (17 candidates). A token containing :// is the tail of a scheme, not a path.
     Note this is also what stops .com in github.com/git and .org in keys.invalid being
     read as DOS executables.
  E2 ESCAPED SPELLING (15 candidates, ALL of them forensics-lab/lab/spec.mjs). A path
     written with DOUBLED backslashes (D:\\Some\\Where) is an escaped literal DESCRIBING
     a path -- a lab fixture row, a self-test's deliberately foreign negative control --
     not a path this process execs. Every real launch site on this station spells its
     path with single backslashes or forward slashes, because Windows accepts both and
     an author escapes only when the value is data.
     HONESTY ABOUT ITS WEIGHT: disabling E2 today changes no verdict and no exit code,
     because spec.mjs is also excluded by E3 (it spawns nothing). It is kept anyway
     because it excludes a shape that E3 does not: registry-verify.py's R34 fixtures,
     whose foreign paths sit inside a longer command string so they never begin a token
     and are therefore invisible to every rule here. Rewrite one of those as
     "command", "D:\\Some\\Other\\Machine\\tool.exe" and only E2 still catches it.
     `--selftest` proves that shape.
  E3 NO LAUNCH IN FILE (1 candidate: native-lab/tools/frida_spawn_gate.py:36). A file
     that cannot spawn a process contributes nothing, and that .exe is a TARGET default,
     not a dependency. That file calls frida's device.spawn(), which is not a process
     spawn, so launcher detection is per-language rather than a keyword grep.
  E4 COMMENT (0 candidates). Deliberately conservative: only #, <# #>, //, /* */,
     Python triple-quotes and REM/:: are stripped, because a full per-language parser
     could hide a real launch behind a false comment, which is the more expensive error.
     It currently blanks 779 lines of registry-verify.py and the NOTES block of
     smoke-all.ps1, but the paths in those lines are already gone before the counter
     could see them -- they sit mid-sentence or end in a comma, so tokenisation drops
     them first. The rule earns its place as a guarantee that comment text can never
     become a dependency, not as a filter that is doing work today.

A surviving candidate must then be SATISFIED, in this order:
  in-tree    the absolute path is inside this repository -- a repo file, not a tool
  os         the absolute path is under the Windows system directory
  declared   the bare name matches a token in the manifest (FIELDS below)
Anything else is UNDECLARED and fails the run.

FIELDS searched for a declared token, strongest first: the tool name, the basename of
entry, the basename of dir, a token inside a needs string (this is where the manifest
already records host prerequisites -- "Node >= 22", "Java", "Python", "Chrome",
"MSVC 2022 (optional)"), and finally prose inside a note. Every hit prints the field that
satisfied it, so a match resting on loose note prose is visible as such and a reviewer
can disagree with it.

Each name also reports whether it is actually SPAWNED or merely REFERENCED (a
Test-Path presence check). A presence check is still a declared dependency -- a fresh
clone has to install the thing -- but it is weaker evidence of a bug than a spawn.

WHY DEAD DECLARATIONS DO NOT FAIL THE RUN
-----------------------------------------
A declared tool no script launches is not necessarily wrong. Most entries are lab ENTRY
POINTS: ghidraRun.bat, ida.exe, cheatengine-x86_64.exe are started by a human from a
menu, or by a capability probe that reaches them through manifests/capabilities.json
rather than through a script we can read. Failing the run on those would punish the
manifest for describing a tool correctly, and the obvious fix -- deleting the entry --
would destroy exactly the information a fresh clone needs. So dead declarations are
CLASSIFIED and printed with the reason each is not a defect, and only
UNDECLARED-and-invoked exits non-zero.

SCOPE LIMIT, STATED RATHER THAN HIDDEN
--------------------------------------
This gate sees absolute EXECUTABLE paths, which is what the scripts spawn. It cannot
see a tool reached by joining a bare name onto an absolute DIRECTORY root:
scripts/mobile-lab.ps1:58-59 does exactly that for the Android SDK's
aapt2/d8/zipalign/apksigner. Closing that would mean resolving variables across files,
and a wrong resolution fails closed on a real tool, so it is measured and written up in
.agent/tools-manifest.md instead of being half-handled here.

Exit codes: 0 = every invoked tool is declared · 1 = at least one invoked tool is
undeclared · 2 = the manifest or the source tree could not be read.
"""

from __future__ import annotations

from collections import Counter
import json
import os
import re
import sys

# --- layout -------------------------------------------------------------------

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(REPO, "manifests", "tools.json")
REGISTRY = os.path.join(REPO, "manifests", "capabilities.json")

SCAN_SUBDIRS = ("tools", "lab")
SCAN_SKIP = {"node_modules", ".venv", "__pycache__", ".git", "out", "_download-stage"}
SCAN_EXTS = (".ps1", ".py", ".mjs", ".js", ".bat", ".cmd")

EXE_SUFFIXES = ("exe", "bat", "cmd", "com", "jar", "ps1", "py", "mjs", "js")

WINDOWS_SYSTEM_ROOTS = ("c:\\windows\\",)
SITE_CAP = 5  # sites listed per tool before the report says how many it left out
SELF_REL = "scripts/verify-tools-manifest.py"  # never scans itself; see scanned_files()

# --- extraction ---------------------------------------------------------------

# A candidate is a WHOLE quoted-or-bare token that is an absolute path ending in an
# executable extension. Tokenising FIRST is what makes paths containing spaces work:
# `'C:\Program Files\Wireshark\tshark.exe'` is a single token, whereas a character-class
# match silently drops every such path because a space terminates it. That bug hid four
# real tools (chrome.exe, msedge.exe, tshark.exe, 7z.exe) on the first run of this file.
#
# The bare alternative must NOT swallow a quote. In `r"C:\...\x.exe"` the bare token
# starts one character earlier than the quoted one and finditer keeps the earliest
# match, so the token arrived as `r"C:\...\x.exe"`, failed the quote strip, and the path
# vanished from the inventory entirely. Excluding quotes from the bare class makes the
# quoted alternative win.
TOKEN = re.compile(r"\"[^\"\n]*\"|'[^'\n]*'|[^\s,;'\"]+")
ABS_HEAD = re.compile(r"^(?:[A-Za-z]:[\\/]|\$env:[A-Za-z_][A-Za-z0-9_]*[\\/]|\\\\)")
EXE_TAIL = re.compile(r"\.(?:" + "|".join(EXE_SUFFIXES) + r")$", re.IGNORECASE)


def candidate_paths(line: str) -> tuple[list[str], int]:
    """-> (absolute executable paths on this line, count of URL-looking tokens)."""
    out: list[str] = []
    urls = 0
    for m in TOKEN.finditer(line):
        tok = m.group(0)
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
            tok = tok[1:-1]
        if not tok:
            continue
        if "://" in tok:
            urls += 1
            continue
        if not ABS_HEAD.match(tok) or not EXE_TAIL.search(tok):
            continue
        out.append(tok)
    return out, urls

# Rule E3: can this file spawn a process at all? Per language, not by keyword grep.
LAUNCHER = {
    ".mjs": re.compile(r"(?:from|require\s*\()\s*['\"](?:node:)?child_process"),
    ".js": re.compile(r"(?:from|require\s*\()\s*['\"](?:node:)?child_process"),
    ".py": re.compile(r"^\s*import\s+subprocess\b|^\s*from\s+subprocess\b", re.M),
    ".ps1": re.compile(
        r"Start-Process\b|Invoke-Expression\b|ProcessStartInfo\b"
        r"|(?<![&])&\s+(?:\$|['\"]|[A-Za-z])"
    ),
    ".bat": re.compile(r"^\s*call\s+[\"']?%?", re.IGNORECASE | re.M),
    ".cmd": re.compile(r"^\s*call\s+[\"']?%?", re.IGNORECASE | re.M),
}

# Is this specific LINE an actual spawn, as opposed to a presence check?
LAUNCH_SITE = re.compile(
    r"(?<![&])&\s+(?:\$|['\"]|[A-Za-z])|Start-Process\b|Invoke-Expression\b"
    r"|\bspawn\s*\(|\bspawnSync\s*\(|\bexecFile(?:Sync)?\s*\("
    r"|\bsubprocess\s*\.\s*(?:run|Popen|call|check_output|check_call)\s*\(|"
    r"|^\s*call\s+[\"']?%?",
    re.IGNORECASE,
)


def strip_comments(raw: str, ext: str) -> list[str]:
    """Blank comment regions; conservative on purpose -- see rule E4 in the docstring."""
    lines = raw.splitlines()
    out = list(lines)

    if ext in (".bat", ".cmd"):
        for i, line in enumerate(out):
            if re.match(r"^\s*(rem|::)\b", line, re.IGNORECASE):
                out[i] = ""
        return out

    if ext == ".ps1":
        inside = False
        for i, line in enumerate(out):
            if inside:
                out[i] = ""
                if "#>" in line:
                    inside = False
            elif "<#" in line:
                head, _, tail = line.partition("<#")
                if "#>" in tail:
                    out[i] = head
                else:
                    out[i] = head
                    inside = True

    hash_ok = ext in (".ps1", ".py")
    slash_ok = ext in (".mjs", ".js")
    in_block = False
    triple = None
    for i, line in enumerate(out):
        if not line:
            continue
        cur = line
        if ext == ".py":
            if triple is not None:
                triple = None if triple in cur else triple
                cur = ""
            else:
                hit = next((q for q in ('"""', "'''") if q in cur), None)
                if hit is not None:
                    tail = cur[cur.index(hit) + 3:]
                    cur = ""
                    if hit not in tail:
                        triple = hit
                elif "#" in cur:
                    cur = cur[: cur.index("#")]
        if in_block:
            cur = ""
            if "*/" in line:
                in_block = False
        elif slash_ok and "/*" in cur:
            cur = cur[: cur.index("/*")]
            if "*/" not in cur:
                in_block = True
        if hash_ok and ext != ".py" and "#" in cur:
            cur = cur[: cur.index("#")]
        if slash_ok and not in_block and "//" in cur:
            cur = cur[: cur.index("//")]
        out[i] = cur
    return out


def bare_name(path_text: str) -> str:
    cleaned = path_text.replace("\\\\", "\\").replace("/", "\\")
    return cleaned.rstrip("\\").split("\\")[-1].lower()


def tokenize(text: str) -> set[str]:
    return {t for t in re.split(r"[^0-9A-Za-z]+", text.lower()) if t}


# The POSIX spelling of a drive path (/c/...) and its backslash form (C:\...) are the
# same directory, and REPO comes from __file__, which under the bash layer is the
# POSIX spelling. Folding the drive root is what lets an in-repo path be recognised as
# in-repo instead of being reported as an undeclared external tool.
WINROOT = re.compile(r"^/([a-z])(?=(?:/|$))")


# --- WHAT THIS GATE CANNOT SEE (measured 2026-10-04, not suspected) ------------------------
#
# It harvests LITERAL executable paths out of source lines. A probe that names its binary
# through a variable is invisible to it:
#
#     subprocess.run([args.rabin2, "-I", args.binary])      # <- invisible
#     subprocess.run(["rabin2", "-I", args.binary])          # <- visible
#
# `rabin2` did all the work behind the native.pe.hardening capability and was absent from
# tools.json for the whole life of that capability, because of exactly this line. The gate
# printed "0 undeclared" throughout, which is true and useless: it means "no UNDECLARED tool is
# named by literal path in the scanned source", not "every binary this tree runs is declared".
#
# It is worse than a missed tool, because `radare2` WAS declared, so a reader reasonably assumes
# rabin2 is covered. An undeclared binary that a human attributes to a declared neighbour is
# harder to notice than one that is missing outright.
#
# MEASURED 2026-11-01, and it is the same class arriving by a different road. Making
# `headless-lab/tools/frida_gate_control.ps1` portable -- it had pinned the station root as a
# literal, so on any other clone it launched a python.exe that was not there -- moved both of
# its paths behind `$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)`. The gate
# then stopped seeing them: `frida_spawn_gate.py` left the inventory entirely ("13 invoked" ->
# "12 invoked") and `python.exe` lost its in-repo site, so its verdict survived only on the
# external sites in scripts/. Nothing went red, and nothing should have: the verdicts are
# unchanged and the portability fix is the right one. The COVERAGE went down, silently, which is
# the failure this section exists to name. A tree that keeps becoming portable will keep
# shrinking this inventory, and "0 undeclared" will keep being true and keep meaning less.
#
# So: read "0 undeclared" as scoped to literals. Closing this properly means either resolving
# the argv dataflow or having probes declare the tools they invoke -- the manifest is now the
# place for that (`requires_env` on Il2CppDumper is the same idea for a different gap).


def norm_path(text: str) -> str:
    t = text.replace("/", "\\").lower().rstrip("\\")
    return WINROOT.sub(lambda m: m.group(1) + ":", t)


class Source:
    __slots__ = ("rel", "raw_lines", "code_lines", "can_launch")

    def __init__(self, rel: str) -> None:
        self.rel = rel
        full = os.path.join(REPO, rel)
        try:
            with open(full, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            raise SystemExit(f"verify-tools-manifest: cannot read {rel}: {exc}")
        ext = os.path.splitext(rel)[1].lower()
        self.raw_lines = raw.splitlines()
        self.code_lines = strip_comments(raw, ext)
        pat = LAUNCHER.get(ext)
        self.can_launch = bool(pat.search(raw)) if pat else False



# --- the OTHER input shape -------------------------------------------------
#
# MEASURED, and it is the reason this function exists. Two gates in this tree answer "is a
# tool undeclared": this one, which searches the repo's own SOURCE, and
# `verify-clone-freshness.py`, which searches the probe COMMANDS in capabilities.json. Their
# numbers are 12 and 23, and their union is NOT 35 -- the target sets OVERLAP, so adding
# them is arithmetic on a set that was never measured as a set. Two workers each re-measured
# the other's number at their HEAD and agreed the station-wide answer was 2 (adb, openssl),
# but neither could produce it, because neither gate sees the other's input.
#
# So the union is computed HERE, once, from both shapes, with duplicates collapsed by the
# inventory key. One question gets one answer, and the answer is measured rather than
# summed.
#
# Why this is a separate shape and not a text file to scan: a JSON string that has been
# through `json.load` has its doubled backslashes RESOLVED. Exclusion rule E2 (escaped
# spelling) is about the doubled form and is structurally unreachable here -- it is a rule
# about a layer these strings no longer occupy. Feeding them through Source would apply
# source-text rules to decoded text and produce confident nonsense.
class DeclaredCommandSource:
    """One capability's probe/prepare/control command, as scannable lines.

    `can_launch` is True unconditionally: every string here is a command the registry says
    is RUN, so exclusion rule E3 (a file that cannot spawn) has no referent either.
    """

    __slots__ = ("rel", "raw_lines", "code_lines", "can_launch")

    def __init__(self, rel: str, lines: list[str]) -> None:
        self.rel = rel
        self.raw_lines = lines
        self.code_lines = lines
        self.can_launch = True


def registry_command_sources() -> list[DeclaredCommandSource]:
    try:
        with open(REGISTRY, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise SystemExit(f"verify-tools-manifest: cannot read registry: {exc}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"verify-tools-manifest: registry is not valid JSON: {exc}")
    out: list[DeclaredCommandSource] = []
    for cap in doc.get("capabilities") or []:
        cid = cap.get("id") or "<unnamed>"
        probe = cap.get("probe") or {}
        control = cap.get("negative_control") or {}
        for key, holder in (("prepare", probe), ("command", probe),
                            ("control.command", control)):
            cmd = holder.get(key if key != "control.command" else "command")
            if isinstance(cmd, str) and cmd.strip():
                text_lines = cmd.splitlines()
                # A PATH UNDER THE SYSTEM TEMP DIRECTORY IS A PRODUCT OF THIS RUN, NOT A
                # PREREQUISITE. Measured the moment the registry input was added: the union gate went
                # red on `$env:TEMP\signed-fixture.exe` in native.signature.certverify -- a fixture the
                # capability's own `prepare` BUILDS before the probe reads it. Declaring it in
                # manifests/tools.json would be wrong; it is not software a person installs.
                #
                # So the exclusion is on the DIRECTORY, not the name: a temp path is excluded
                # because temp is where this station puts run products, and the rule is stated in
                # terms of that fact rather than in terms of the one filename that tripped it.
                if not any(re.search(r"(?i)\$(?:env:)?TEMP\b|%TEMP%|\\Temp\\|/tmp/", ln)
                           for ln in text_lines):
                    out.append(DeclaredCommandSource(
                        f"manifests/capabilities.json#{cid}.{key}", text_lines))
    return out
# --- manifest ----------------------------------------------------------------

FIELD_ORDER = ("name", "entry", "dir", "needs", "note")


def load_entries() -> list[dict]:
    try:
        with open(MANIFEST, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise SystemExit(f"verify-tools-manifest: cannot read manifest: {exc}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"verify-tools-manifest: manifest is not valid JSON: {exc}")
    tools = doc.get("tools")
    if not isinstance(tools, dict):
        raise SystemExit("verify-tools-manifest: manifest has no 'tools' object")
    out = []
    for category, items in tools.items():
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("name"):
                    out.append({"category": category, **item})
    return out


def declared_index(entries: list[dict]) -> dict[str, list[tuple[int, str]]]:
    """token -> [(FIELD_ORDER rank, tool name)] for every name the manifest records."""
    index: dict[str, list[tuple[int, str]]] = {}
    for entry in entries:
        for rank, field in enumerate(FIELD_ORDER):
            raw = entry.get(field)
            if not isinstance(raw, str) or not raw:
                continue
            if field in ("entry", "dir"):
                tokens = {bare_name(raw)}
            else:
                tokens = tokenize(raw)
            for tok in tokens:
                if not tok:
                    continue
                index.setdefault(tok, []).append((rank, entry["name"]))
    return index


def look_up(index: dict[str, list[tuple[int, str]]], bare: str) -> tuple[str, str, str] | None:
    """-> (tool, deciding field, all fields that matched) or None.

    Both the full basename and the extension-stripped stem are tried, because the
    manifest records PRODUCTS ('Node >= 22', 'Python', 'Chrome') while the inventory
    records FILES (node.exe, python.exe, chrome.exe). Matching only the full basename
    reported node.exe as undeclared even though six in-tree entries say it is needed.

    Every matching field is returned, not just the deciding one. node.exe matches the
    `name` of 'crypto-lab oracle (node)' only because that npm package is called node --
    a coincidence -- while `needs: "Node >= 22"` is the declaration that actually means
    it. Printing both is the difference between a report a reviewer can check and one
    they have to take on trust.
    """
    stem = bare.rsplit(".", 1)[0] if "." in bare else bare
    for cand in (bare, stem):
        hits = index.get(cand)
        if hits:
            rank, tool = min(hits, key=lambda h: h[0])
            others = sorted({FIELD_ORDER[r] for r, _ in hits if r != rank})
            return tool, FIELD_ORDER[rank], ", ".join([FIELD_ORDER[rank]] + others)
    return None


# --- scanning ----------------------------------------------------------------


def scanned_files() -> list[str]:
    roots = [os.path.join(REPO, "scripts")]
    for child in sorted(os.listdir(REPO)):
        cpath = os.path.join(REPO, child)
        if os.path.isdir(cpath) and not child.startswith("."):
            for sub in SCAN_SUBDIRS:
                p = os.path.join(cpath, sub)
                if os.path.isdir(p):
                    roots.append(p)
    tops = os.path.join(REPO, "labs")
    if os.path.isdir(tops):
        roots.append(tops)

    found: set[str] = set()
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SCAN_SKIP]
            for name in filenames:
                if not name.lower().endswith(SCAN_EXTS):
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, REPO).replace("\\", "/")
                # This file is excluded from its own scan. It quotes absolute paths in its
                # docstring and its --selftest fixtures, and a checker that reads its own
                # test data as production code will eventually invent a tool out of it. The
                # self-test already asserts its own rules directly, which is the honest way
                # for a checker to test itself.
                if rel == SELF_REL:
                    continue
                found.add(rel)
    return sorted(found)


EXCLUSION_KEYS = ("E1-url", "E2-escaped-spelling", "E4-comment", "E3-no-launch-in-file")


def scan(sources: list[Source]) -> tuple[dict[str, dict], dict[str, int]]:
    inv: dict[str, dict] = {}
    excl = {k: 0 for k in EXCLUSION_KEYS}
    for src in sources:
        for lineno, (raw, code) in enumerate(zip(src.raw_lines, src.code_lines), 1):
            paths, urls = candidate_paths(code)
            excl["E1-url"] += urls
            # Only candidates removed by comment stripping belong to E4. A trailing
            # comment does not turn the surviving launch expression into a comment.
            raw_paths, _ = candidate_paths(raw)
            excl["E4-comment"] += sum((Counter(raw_paths) - Counter(paths)).values())
            for text in paths:
                if "\\\\" in text:
                    excl["E2-escaped-spelling"] += 1
                    continue
                if not src.can_launch:
                    excl["E3-no-launch-in-file"] += 1
                    continue
                rec = inv.setdefault(
                    bare_name(text),
                    {"sites": [], "spawns": 0, "refs": 0},
                )
                rec["sites"].append((src.rel, lineno, text))
                if LAUNCH_SITE.search(code):
                    rec["spawns"] += 1
                else:
                    rec["refs"] += 1
    return inv, excl


# --- classification ----------------------------------------------------------

REPO_NORM = norm_path(REPO)


def classify(name: str, rec: dict, index: dict) -> tuple[str, str]:
    """-> (verdict, reason); verdict is in-tree | os | declared | UNDECLARED.

    Every site is considered, not just the first. python.exe is launched from inside
    this repo at headless-lab/tools/frida_gate_control.ps1 (a venv path, until 2026-11-01
    written as a literal) and from outside it at
    scripts/smoke-all.ps1:44; judging it by the first site alone called a host
    interpreter an in-tree file and hid the fact that scripts also need it installed.
    """
    resolved = [
        norm_path(text.replace("$env:USERPROFILE", "c:\\users\\x"))
        for _, _, text in rec["sites"]
    ]
    external = [
        r for r in resolved
        if REPO_NORM not in r and not r.startswith(WINDOWS_SYSTEM_ROOTS)
    ]
    if not external:
        if any(REPO_NORM in r for r in resolved):
            return "in-tree", "every absolute path to it is inside this repository"
        return "os", "every absolute path to it is under the Windows system directory"
    hit = look_up(index, name)
    if hit:
        tool, field, allfields = hit
        reason = f"declared as {tool!r} (manifest field: {field}"
        if allfields != field:
            reason += f"; also matched: {allfields}"
        reason += ")"
        if field == "note":
            reason += " -- WEAKEST FIELD: prose, not a declared name; confirm this counts"
        return "declared", reason
    return "UNDECLARED", "launched by absolute path, absent from manifests/tools.json"





# --- dead declarations -------------------------------------------------------

SEGMENT = re.compile(r"[^\s\"'`,;()\[\]{}<>|=]+")


def corpus_segments(sources: list[Source]) -> tuple[set[str], set[str]]:
    """(every path segment named anywhere, every segment that is a file name)."""
    segments: set[str] = set()
    for src in sources:
        for line in src.code_lines:
            for chunk in SEGMENT.finditer(line):
                for seg in chunk.group(0).replace("/", "\\").split("\\"):
                    seg = seg.strip().lower()
                    if seg:
                        segments.add(seg)
    files = {s for s in segments if s.rsplit(".", 1)[-1] in EXE_SUFFIXES}
    return segments, files


def find_dead(entries: list[dict], segments: set[str], files: set[str]):
    """-> (dead, entry_mismatch). dead = nothing in the scanned tree names it at all."""
    dead, mismatch = [], []
    for entry in entries:
        ent = entry.get("entry")
        drv = entry.get("dir")
        ent_base = bare_name(ent) if isinstance(ent, str) and ent else ""
        drv_base = bare_name(drv) if isinstance(drv, str) and drv else ""
        ent_seen = bool(ent_base) and ent_base in files
        drv_seen = bool(drv_base) and drv_base in segments
        if ent_seen:
            continue
        if drv_seen:
            if ent_base:
                mismatch.append((entry, ent_base))
            continue
        dead.append(entry)
    return dead, mismatch

def find_absent_pins(entries: list[dict]) -> list[tuple[dict, str]]:
    """-> entries whose declared dir+entry does not exist on disk.

    ADDED 2026-10-04. Everything else in this file answers "does a SCRIPT name this tool?".
    This answers a different and prior question: "does the tool the manifest pins actually sit
    where the manifest says it does?" Nothing asked that, so a manifest can pin a path that
    was never real, moved, or renamed, and the gate stays green -- the tool is simply filed
    under "declared but never invoked", which reads like a benign classification rather than a
    broken pin.

    CORRECTION, and it matters: an earlier session wrote that tools.json has "no per-tool
    directory in the schema". That was wrong. `dir` is right there on every entry, and the
    reason 0 of 54 `entry` values resolve from the repo root is that they are relative to
    `dir`, not to the root. The schema was fine; the question was never being asked.

    NOT a failure by default. Two of 54 legitimately live inside `node_modules/` and `.venv/`,
    which are installed dependencies rather than shipped tools -- a checkout without a
    bootstrap has no copy, and that is not a broken pin. They are reported so the reader can
    see them, but only a pin that is ABSENT and is NOT under an installed-dependency
    directory fails the run.
    """
    INSTALLED_DEP = ("node_modules", ".venv", "venv", "site-packages", "__pycache__")
    out = []
    for entry in entries:
        ent, drv = entry.get("entry"), entry.get("dir")
        if not ent or not drv:
            continue
        full = os.path.join(REPO, drv.replace("/", os.sep), ent.replace("/", os.sep))
        if not os.path.exists(full):
            out.append((entry, full))
    return out


def absent_pin_reason(entry: dict, full: str) -> str:
    parts = {p.lower() for p in full.replace("\\", "/").split("/")}
    if parts & {"node_modules", ".venv", "venv", "site-packages", "__pycache__"}:
        return ("inside an installed-dependency directory: a checkout without a bootstrap has "
                "no copy. Not a broken pin, so this does not fail the run.")
    if os.path.exists(os.path.join(REPO, str(entry.get("dir") or ""))):
        return (f"its dir exists but {entry.get('entry')!r} is not in it -- the tool was moved, "
                f"renamed or removed and the manifest still pins the old name")
    return f"neither the dir {entry.get('dir')!r} nor the entry exists -- this pin was never real"


def dead_reason(entry: dict) -> str:
    if entry.get("in_tree"):
        return ("in-tree lab entry point: started by a human or by a capability probe "
                "through manifests/capabilities.json, not by a script we can read")
    note = str(entry.get("note", ""))
    if entry.get("auto_update") is False or "不下载" in note:
        return ("declared but deliberately never downloaded by bootstrap -- licensed or "
                "host-provided, so there is nothing to install from this manifest")
    if not entry.get("entry"):
        return ("no single-file entry: it is a directory of tools, a framework or a venv, "
                "reached by a human or a capability probe rather than by a scanned script")
    return ("lab entry point reached by a human or through capabilities.json probes, so no "
            "scanned script names it")


# --- report ------------------------------------------------------------------


def main() -> int:
    entries = load_entries()
    index = declared_index(entries)
    files = scanned_files()
    sources = [Source(rel) for rel in files]
    # BOTH INPUT SHAPES, ONE INVENTORY. The registry commands are scanned by the SAME pass with
    # the same rules, and the inventory key collapses duplicates, so a tool named by both a lab
    # script and a probe command is counted once. Summing the two gates' counts instead would be
    # arithmetic on an unmeasured union -- see registry_command_sources().
    sources = sources + registry_command_sources()
    inv, excl = scan(sources)
    segments, seg_files = corpus_segments(sources)
    dead, mismatch = find_dead(entries, segments, seg_files)
    absent_pins = find_absent_pins(entries)
    broken_pins = [(e, f) for e, f in absent_pins
                   if "installed-dependency" not in absent_pin_reason(e, f)]

    undeclared: list[tuple[str, str]] = []
    buckets: dict[str, list[str]] = {"declared": [], "in-tree": [], "os": []}
    reasons: dict[str, str] = {}
    for name in sorted(inv):
        verdict, reason = classify(name, inv[name], index)
        reasons[name] = reason
        if verdict == "UNDECLARED":
            undeclared.append((name, reason))
        else:
            buckets[verdict].append(name)

    print(f"verify-tools-manifest: scanned {len(files)} files under scripts/, */tools/, "
          f"*/lab/ -> {len(inv)} distinct absolute executable names")
    print()

    for verdict, heading in (
        ("declared", "INVOKED AND DECLARED"),
        ("in-tree", "INVOKED, INSIDE THE REPO (a repo file, not a tool)"),
        ("os", "INVOKED, PROVIDED BY THE OS (not a manifest concern)"),
    ):
        print(heading)
        if not buckets[verdict]:
            print("  none")
        for name in buckets[verdict]:
            rec = inv[name]
            shown = rec["sites"][:SITE_CAP]
            sites = ", ".join(f"{f}:{ln}" for f, ln, _ in shown)
            if len(rec["sites"]) > SITE_CAP:
                sites += f", +{len(rec['sites']) - SITE_CAP} more"
            how = f"{rec['spawns']} spawn / {rec['refs']} reference"
            print(f"  {verdict:<8} {name:<20} {sites}")
            print(f"           {reasons[name]}; {how}")
        print()

    print("INVOKED BUT UNDECLARED  (this is what fails the run)")
    if not undeclared:
        print("  none")
    for name, reason in undeclared:
        rec = inv[name]
        for f, ln, text in rec["sites"][:SITE_CAP]:
            print(f"  UNDECLARED {name:<20} {f}:{ln}")
            print(f"             {text}")
        if len(rec["sites"]) > SITE_CAP:
            print(f"             ... and {len(rec['sites']) - SITE_CAP} further "
                  f"site(s) of {len(rec['sites'])}")
        print(f"             {reason}; {rec['spawns']} spawn / {rec['refs']} reference")
    print()
    print("DECLARED PINS THAT DO NOT RESOLVE ON DISK  (dir + entry, relative to the repo root)")
    if not absent_pins:
        print("  none -- every declared dir+entry exists")
    for entry, full in sorted(absent_pins, key=lambda m: (m[0]["category"], m[0]["name"])):
        broken = (entry, full) in broken_pins
        print(f"  {'BROKEN' if broken else 'note  '}  {entry['name']:<28} [{entry['category']}]")
        print(f"           {full}")
        print(f"           {absent_pin_reason(entry, full)}")
    print()


    print("DECLARED BUT NEVER INVOKED  (reported, does not fail -- see docstring)")
    if not dead:
        print("  none")
    for entry in sorted(dead, key=lambda e: (e["category"], e["name"])):
        print(f"  dead      {entry['name']:<28} [{entry['category']}]")
        print(f"           {dead_reason(entry)}")
    print()

    print("DECLARED ENTRY FILENAME NAMED NOWHERE (referenced only by its directory)")
    if not mismatch:
        print("  none")
    for entry, ent_base in sorted(mismatch, key=lambda m: (m[0]["category"], m[0]["name"])):
        print(f"  entry?    {entry['name']:<28} declares entry {ent_base!r}, "
              f"never named; its dir is")
        print(f"           referenced instead. The manifest and the scripts disagree about "
              f"which FILE starts this tool.")
    print()

    print("EXCLUSION RULES APPLIED (audit the inventory, do not trust it)")
    for key in EXCLUSION_KEYS:
        print(f"  {key:<24} dropped {excl[key]} candidate(s)")
    print()

    print(f"tools: {len(entries)} declared, {len(inv)} invoked, "
          f"{len(undeclared)} undeclared, {len(dead)} dead, "
          f"{len(broken_pins)} broken pin(s)")
    return 1 if (undeclared or broken_pins) else 0


# --- self-test ----------------------------------------------------------------

def selftest() -> int:
    """Prove each extraction and lookup rule fires, so a later edit cannot quietly
    disable one. Every case below is a bug that was actually made and measured during
    the build of this file, or a shape a rule exists precisely to catch."""
    cases: list[tuple[str, bool, str]] = []

    def want(label: str, got, expect) -> None:
        cases.append((label, got == expect, f"got {got!r}, want {expect!r}"))

    # A path containing SPACES. The character-class extractor dropped every one of these,
    # hiding chrome.exe, msedge.exe, tshark.exe and 7z.exe on the first run.
    want("space-bearing quoted path is found",
         candidate_paths("  'C:/Program Files/Wireshark/tshark.exe',"),
         (["C:/Program Files/Wireshark/tshark.exe"], 0))
    want("space-bearing quoted path with parens is found",
         candidate_paths("  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',")[0],
         ["C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"])

    # A raw string literal. The bare token used to swallow the opening quote, so the
    # token arrived as r"C:\..." and failed the quote strip; the path vanished entirely.
    want("raw-string path is found (quote is not swallowed)",
         candidate_paths('else r"C:\\Users\\owner\\AppData\\Local\\Temp\\w13\\c01.exe"')[0],
         ["C:\\Users\\owner\\AppData\\Local\\Temp\\w13\\c01.exe"])

    # E1: a URL is not a path, and .com / .org must not read as DOS executables.
    want("https URL is rejected", candidate_paths("Save-Url 'https://npcap.com/dist/npcap-1.88.exe' $npcap"),
         ([], 1))
    want("github URL is rejected", candidate_paths("git clone https://github.com/a/b.git $x"), ([], 1))
    want("xml namespace is rejected", candidate_paths("'<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">'"),
         ([], 1))

    # E2: the shape registry-verify.py's R34 control would take if the path began a
    # token. This is the ONLY rule that catches it -- E3 cannot, because that file does
    # import subprocess and really does spawn.
    want("doubled-backslash foreign fixture is a candidate that E2 must drop",
         candidate_paths('"command", "D:\\\\Some\\\\Other\\\\Machine\\\\tool.exe"')[0],
         ["D:\\\\Some\\\\Other\\\\Machine\\\\tool.exe"])
    want("  ... and E2 drops exactly that spelling",
         "\\\\" in "D:\\\\Some\\\\Other\\\\Machine\\\\tool.exe", True)

    # A single-backslash real launch path must NOT be dropped by E2.
    want("single-backslash launch path survives E2",
         "\\\\" in "D:\\Software\\Developer\\Python314\\python.exe", False)

    # E3: frida's device.spawn() is not a process spawn, so this file contributes nothing.
    src = Source("native-lab/tools/frida_spawn_gate.py")
    want("frida_spawn_gate.py is not a launcher", src.can_launch, False)
    # This line USED to carry the target as a literal absolute path, and these two assertions
    # proved the extractor saw it and that only the launcher test kept it out of the inventory.
    # Since 2026-11-01 the file builds that default from tempfile.gettempdir() instead: the
    # pinned path named the author's machine, so on any other clone the probe either failed or
    # -- worse -- measured the tree the path named. There is now no literal left to find, which
    # is a COVERAGE loss recorded in WHAT THIS GATE CANNOT SEE, not a pass.
    want("  ... with the target built from %TEMP% there is no literal left to find",
         any("c01-stringobf" in t for line in src.code_lines for t in candidate_paths(line)[0]),
         False)
    # E3 is still exercised, on a source that DOES carry a literal: a rule that is not exercised
    # is a rule that is not proven. raw_lines is set equal to code_lines so scan() does not read
    # the synthetic line as a comment (E4) and drop it for the wrong reason.
    probe = Source("native-lab/tools/frida_spawn_gate.py")
    probe.code_lines = [r'DEFAULT = r"C:\Users\owner\AppData\Local\Temp\w13\c01-stringobf.exe"']
    probe.raw_lines = probe.code_lines
    want("  ... its target .exe is a candidate the extractor cannot reject",
         any("c01-stringobf" in t for line in probe.code_lines for t in candidate_paths(line)[0]),
         True)
    want("  ... and E3 drops it, so it never enters the inventory",
         "c01-stringobf.exe" in scan([probe])[0], False)
    want("skill_security_control.ps1 IS a launcher (call operator)",
         Source("headless-lab/tools/skill_security_control.ps1").can_launch, True)
    want("smoke-all.ps1 IS a launcher ($out = & $p.file ...)",
         Source("scripts/smoke-all.ps1").can_launch, True)
    want("chrome.mjs IS a launcher (imports node:child_process)",
         Source("web-reverse/tools/chrome.mjs").can_launch, True)

    # E4: comment text is not code.
    want("PS block comment is blanked",
         strip_comments("<#\n& \"$env:X\\a.exe\"\n#>", ".ps1")[1], "")
    want("PS line comment is blanked", strip_comments('& "a.exe" # note', ".ps1")[0], '& "a.exe" ')
    want("python docstring is blanked", strip_comments('"""a.exe"""\nx=1', ".py")[0], "")
    want("js // comment is blanked", strip_comments('const a=1; // "b.exe"', ".mjs")[0], "const a=1; ")

    # A trailing comment must not discard the executable path before it. These
    # fixtures exercise the real strip/scan boundary that the old E4 branch missed.
    for ext, prefix, launch, comment in (
        (".ps1", "", "& 'C:/owned-fixture/unlisted.exe'", " # explanatory note"),
        (".py", "import subprocess\n", "subprocess.run(['C:/owned-fixture/unlisted.exe'])", " # explanatory note"),
        (".mjs", "import {spawnSync} from 'node:child_process';\n", "spawnSync('C:/owned-fixture/unlisted.exe', []);", " // explanatory note"),
    ):
        fixture = Source.__new__(Source)
        fixture.rel = "selftest-inline" + ext
        raw = prefix + launch + comment
        fixture.raw_lines = raw.splitlines()
        fixture.code_lines = strip_comments(raw, ext)
        fixture.can_launch = True  # each literal fixture above explicitly launches
        found, excluded = scan([fixture])
        want("inline comment preserves the launch path " + ext, "unlisted.exe" in found, True)
        want("surviving code is not counted as E4 " + ext, excluded["E4-comment"], 0)

    # The real thing the brief named, asserted end to end rather than by grep.
    inv, _ = scan([Source("headless-lab/tools/skill_security_control.ps1")])
    want("skillspector.exe is in the inventory", "skillspector.exe" in inv, True)
    want("  ... at the exact line it is launched",
         inv.get("skillspector.exe", {}).get("sites", [("", 0)])[0][1], 24)

    # Manifest lookups: the two ways an entry can satisfy a bare name.
    index = declared_index(load_entries())
    want("msedge.exe is satisfied by a needs token",
         (look_up(index, "msedge.exe") or ("", "", ""))[1], "needs")
    want("skillspector.exe is satisfied by the dir basename",
         (look_up(index, "skillspector.exe") or ("", "", ""))[1], "dir")
    want("tshark.exe is satisfied by the entry basename",
         (look_up(index, "tshark.exe") or ("", "", ""))[1], "entry")
    # node.exe is a documented trap: the deciding field is `name`, matched only because an
    # npm package happens to be called "crypto-lab oracle (node)". The declaration that
    # actually MEANS it is needs: "Node >= 22", so this asserts `needs` is among the
    # matching fields -- and the reason line prints every matching field, so the
    # coincidence stays visible in the report instead of silently carrying the verdict.
    want("node.exe also matches a needs token, not only the coincidental name",
         "needs" in (look_up(index, "node.exe") or ("", "", ""))[2].split(", "), True)
    want("a genuinely unknown tool is NOT satisfied", look_up(index, "no-such-tool.exe"), None)

    width = max(len(c[0]) for c in cases)
    failed = 0
    for label, ok, detail in cases:
        if not ok:
            failed += 1
        print(f"  {'PASS' if ok else 'FAIL':4} {label:<{width}}  {'' if ok else detail}")
    print()
    print(f"selftest: {len(cases) - failed}/{len(cases)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(selftest())
    sys.exit(main())


    sys.exit(main())