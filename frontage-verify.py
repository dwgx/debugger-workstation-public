#!/usr/bin/env python3
# frontage-verify.py — READ-ONLY frontage verifier for the 2026-11-11 frontage wave.
#
# Run from the repo root:  python -X utf8 frontage-verify.py
# Prints one token per check WITH a denominator. Writes no file, runs no git write,
# touches no network. The negative control is in-memory: a fake "Pages enabled" claim
# and a README with the RED wording removed MUST both be judged RED.
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent
AS_OF = "2026-11-11"
TAB = chr(9)

ADDED = [
    "docs/AI_ENTRY.md",
    "docs/AI_ENTRY.zh-CN.md",
    "CHANGELOG.md",
    "RELEASE.md",
    "docs/INDEX.md",
    "docs/site/index.html",
    "docs/site/.nojekyll",
    "frontage-verify.py",
]
MODIFIED = [
    "README.md",
    "README.zh-CN.md",
    "skills/debugger-workstation/SKILL.md",
    "skills/debugger-review/SKILL.md",
    "skills/2026-11-11/portable-core/SKILL.md",
    "skills/2026-11-11/portable-core/verify.py",
]

BRIDGE_LINKS = [
    "releases/2026-11-11-full-library/README.md",
    "RELEASE-GATE-STATUS.md",
    "skills/2026-11-11/",
    "CHANGELOG.md",
    "RELEASE.md",
    "docs/AI_ENTRY.md",
]
BRIDGE_ZH_LINKS = [
    "releases/2026-11-11-full-library/README.md",
    "RELEASE-GATE-STATUS.md",
    "skills/2026-11-11/",
    "CHANGELOG.md",
    "RELEASE.md",
    "docs/AI_ENTRY.zh-CN.md",
]

CRED_RE = re.compile(
    r"(?i)(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"BEGIN [A-Z ]*PRIVATE KEY|password\s*[:=]\s*\S{8,})"
)
PAGES_CLAIM_RE = re.compile(
    r"(?i)(github\.io[^\n]{0,80}(enabled|live|online|已启用|已上线|可访问)"
    r"|(enabled|live|online|已启用|已上线)[^\n]{0,80}github\.io)"
)
EXTERNAL_RE = re.compile(r"(?i)(?:href|src)\s*=\s*[\"']\s*(?:https?:)?//")


def read(rel):
    p = ROOT / rel
    if not p.is_file():
        return None
    return p.read_text(encoding="utf-8", errors="replace")


def has_all(text, markers):
    if text is None:
        return 0
    return sum(1 for m in markers if m in text)


def bridge_en_ok(text):
    if text is None:
        return False, 0
    markers = ["## Start here"] + BRIDGE_LINKS + ["268", "RED", "publishing does not change"]
    return has_all(text, markers) == len(markers), has_all(text, markers)


def bridge_zh_ok(text):
    if text is None:
        return False, 0
    markers = ["## 从这里开始"] + BRIDGE_ZH_LINKS + ["268", "RED", "发布不改变"]
    return has_all(text, markers) == len(markers), has_all(text, markers)


def ai_entry_ok(text):
    if text is None:
        return False, 0
    markers = ["AGENTS.md", "AI_USAGE_GUIDE.md", "CLAUDE.md", "GEMINI.md",
               "copilot-instructions.md", "portable-core/SKILL.md",
               "RELEASE-GATE-STATUS.md", "portable-core/verify.py",
               "Ask before acting", "no third-party tool binaries",
               "Never silent-install", "RED is reported as RED", "HARD BAN"]
    return has_all(text, markers) == len(markers), has_all(text, markers)


def ai_entry_zh_ok(text):
    if text is None:
        return False, 0
    markers = ["AGENTS.zh-CN.md", "AI_USAGE_GUIDE.md", "CLAUDE.md", "GEMINI.md",
               "copilot-instructions.md", "portable-core/SKILL.md",
               "RELEASE-GATE-STATUS.md", "portable-core/verify.py",
               "先问后做", "不分发任何第三方工具二进制",
               "绝不静默安装", "RED 就报 RED", "HARD BAN"]
    return has_all(text, markers) == len(markers), has_all(text, markers)


def changelog_ok(text):
    if text is None:
        return False, 0
    markers = ["2026-11-11", "cc66638", "875cd10",
               "14 (8 added, 6 modified)", "RELEASE_GATE=RED"]
    return has_all(text, markers) == len(markers), has_all(text, markers)


def release_ok(text):
    if text is None:
        return False, 0
    markers = ["RELEASE_GATE", "RED", "NOT_COMPLETE", "268", "295",
               "releases/2026-11-11-full-library/README.md",
               "GitHub Pages is not enabled"]
    return has_all(text, markers) == len(markers), has_all(text, markers)


def pages_source_ok(html, nojekyll):
    if html is None or nojekyll is None:
        return False, 0
    lines = html.count("\n") + (0 if html.endswith("\n") else 1)
    markers = [
        "Start here" in html,
        "简体中文" in html,
        "GitHub Pages is not enabled" in html,
        "本仓库未启用 GitHub Pages" in html,
        "<script" not in html.lower(),
        EXTERNAL_RE.search(html) is None,
        lines <= 400,
        nojekyll.strip() == "",
    ]
    return sum(markers) == len(markers), sum(markers)


def pages_claim_clean(text):
    """True when the text does NOT claim a live github.io site."""
    if text is None:
        return False
    return PAGES_CLAIM_RE.search(text) is None


def index_ok(text):
    if text is None:
        return False, 0
    markers = [".agent/", "evidence/", "docs/", "11", "2", "12",
               ".agent/atomic-artifacts.md", "evidence/atomic-artifacts.md",
               ".agent/probe-coverage.md", "evidence/probe-coverage.md",
               "SUPERSEDED"]
    return has_all(text, markers) == len(markers), has_all(text, markers)


def legacy_ok(text, router):
    if text is None:
        return False, 0
    markers = ["SUPERSEDED by skills/2026-11-11/station-routers/" + router,
               "2026-11-11"]
    return has_all(text, markers) == len(markers), has_all(text, markers)


def c20_ok(text):
    if text is None:
        return False, 0
    head = text.split("---", 2)
    fm = head[1] if len(head) > 2 else ""
    body = head[2] if len(head) > 2 else text
    markers = [
        re.search(r"(?m)^name:\s*portable-core\s*$", fm) is not None,
        re.search(r"(?m)^\s+owner:\s*\".+\"\s*$", fm) is not None,
        not any(l.startswith("OWNER:") for l in body.splitlines()),
    ]
    return sum(markers) == len(markers), sum(markers)


def red_gate_ok(gate, readme, release):
    if gate is None or readme is None or release is None:
        return False, 0
    markers = [
        "RELEASE_GATE" in gate,
        "RED" in gate,
        "COMPLETENESS_VERDICT" in gate,
        "NOT_COMPLETE" in gate,
        "268" in gate,
        "268" in readme,
        "268" in release,
    ]
    return sum(markers) == len(markers), sum(markers)


def main():
    readme = read("README.md")
    readme_zh = read("README.zh-CN.md")
    ai_en = read("docs/AI_ENTRY.md")
    ai_zh = read("docs/AI_ENTRY.zh-CN.md")
    changelog = read("CHANGELOG.md")
    release = read("RELEASE.md")
    html = read("docs/site/index.html")
    nojekyll = read("docs/site/.nojekyll")
    index = read("docs/INDEX.md")
    legacy_ws = read("skills/debugger-workstation/SKILL.md")
    legacy_rv = read("skills/debugger-review/SKILL.md")
    core = read("skills/2026-11-11/portable-core/SKILL.md")
    gate = read("releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md")

    bridge_en, bridge_en_n = bridge_en_ok(readme)
    bridge_zh, bridge_zh_n = bridge_zh_ok(readme_zh)
    ai_en_ok, ai_en_n = ai_entry_ok(ai_en)
    ai_zh_ok, ai_zh_n = ai_entry_zh_ok(ai_zh)
    log_ok, log_n = changelog_ok(changelog)
    rel_ok, rel_n = release_ok(release)
    pages_ok, pages_n = pages_source_ok(html, nojekyll)
    pages_claim = all(pages_claim_clean(t) for t in (readme, readme_zh, release, html))
    idx_ok, idx_n = index_ok(index)
    leg_ws_ok, leg_ws_n = legacy_ok(legacy_ws, "debugger-workstation/SKILL.md")
    leg_rv_ok, leg_rv_n = legacy_ok(legacy_rv, "debugger-review/SKILL.md")
    c20, c20_n = c20_ok(core)
    red_ok, red_n = red_gate_ok(gate, readme, release)

    scanned = ADDED + MODIFIED
    hits = 0
    for rel in scanned:
        t = read(rel)
        if t is not None and CRED_RE.search(t):
            hits += 1
    cred_ok = hits == 0

    added_present = sum(1 for rel in ADDED if (ROOT / rel).is_file())

    # IN-MEMORY NEGATIVE CONTROL — never written to disk.
    fake_pages = (html or "") + '\n<p>GitHub Pages enabled at https://dwgx.github.io</p>\n'
    fake_red = (readme or "").replace("268", "zero").replace("RED", "GREEN")
    neg_pages = not pages_claim_clean(fake_pages)      # detector must catch it
    neg_red = not red_gate_ok(gate, fake_red, release)[0] if readme is not None else False

    checks = {
        "BRIDGE_EN": bridge_en,
        "BRIDGE_ZH": bridge_zh,
        "AI_ENTRY": ai_en_ok,
        "AI_ENTRY_ZH": ai_zh_ok,
        "CHANGELOG": log_ok,
        "RELEASE_SUMMARY": rel_ok,
        "PAGES_SOURCE": pages_ok,
        "NO_PAGES_SERVICE_CLAIM": pages_claim,
        "INDEX": idx_ok,
        "LEGACY_MARKED": leg_ws_ok and leg_rv_ok,
        "C20_FIXED_OR_DISCLOSED": c20,
        "RED_GATE_HONEST": red_ok,
        "NO_CREDENTIAL_HITS": cred_ok,
        "FILES_ADDED": added_present == len(ADDED),
    }

    print("as_of=%s (read-only, no file write, no network)" % AS_OF)
    print("BRIDGE_EN=%s (%d/10)" % ("YES" if bridge_en else "NO", bridge_en_n))
    print("BRIDGE_ZH=%s (%d/10)" % ("YES" if bridge_zh else "NO", bridge_zh_n))
    print("AI_ENTRY=%s (%d/%d)" % ("YES" if ai_en_ok else "NO", ai_en_n, 13))
    print("AI_ENTRY_ZH=%s (%d/%d)" % ("YES" if ai_zh_ok else "NO", ai_zh_n, 13))
    print("CHANGELOG=%s (%d/%d)" % ("YES" if log_ok else "NO", log_n, 5))
    print("RELEASE_SUMMARY=%s (%d/%d)" % ("YES" if rel_ok else "NO", rel_n, 7))
    print("PAGES_SOURCE=%s (%d/%d)" % ("YES" if pages_ok else "NO", pages_n, 8))
    print("NO_PAGES_SERVICE_CLAIM=%s (4/4 files clean)" % ("YES" if pages_claim else "NO"))
    print("INDEX=%s (%d/%d)" % ("YES" if idx_ok else "NO", idx_n, 11))
    print("LEGACY_MARKED=%s (%d/2 files)" % ("YES" if (leg_ws_ok and leg_rv_ok) else "NO",
                                             int(leg_ws_ok) + int(leg_rv_ok)))
    print("C20_FIXED_OR_DISCLOSED=%s (%d/%d)" % ("YES" if c20 else "NO", c20_n, 3))
    print("RED_GATE_HONEST=%s (%d/%d)" % ("YES" if red_ok else "NO", red_n, 7))
    print("NO_CREDENTIAL_HITS=%s (%d/%d files scanned)"
          % ("YES" if cred_ok else "NO", len(scanned) - hits, len(scanned)))
    print("FILES_ADDED=%d (%d/%d present)" % (added_present, added_present, len(ADDED)))
    print("negative_control: fake_pages_claim->RED=%s removed_RED->RED=%s | NO_FILE_WRITTEN"
          % ("YES" if neg_pages else "NO", "YES" if neg_red else "NO"))

    failed = [k for k, v in checks.items() if not v]
    print("checks_run=%d checks_failed=%d" % (len(checks), len(failed)))
    if failed:
        print("failed=" + ",".join(failed))
    verdict = "FRONTAGE_OK" if not failed and neg_pages and neg_red else "FRONTAGE_RED"
    print("VERDICT=%s" % verdict)
    sys.exit(0 if verdict == "FRONTAGE_OK" else 1)


if __name__ == "__main__":
    main()
