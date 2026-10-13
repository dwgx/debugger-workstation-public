#!/usr/bin/env python3
"""Owner attestation layer: a nonce challenge the Owner must answer in his own transcript.

WHY THIS EXISTS. `gate.ps1` verifies that an Owner word is present and not obviously
self-asserted -- never that the Owner SAID it. Measured 2026-10-14 (`.agent/HANDOFF.md:256-262`):
one call to `gate.ps1 -Action New` with any non-whitespace `-OwnerWord` mints `attested:true`.
This layer does not touch the gate (HARD: `gate.ps1` and schema `gate/grant@2` stay untouched).
It adds the part the gate cannot have: a fresh, single-use nonce that must appear in a
USER-attribution message in the channel's omp transcript, NEWER than the challenge, plus a
sentence that names the object -- and only then is this script willing to call
`gate.ps1 -Action New` with the Owner's actual sentence as `-OwnerWord`.

THE TRUST MODEL, STATED HONESTLY (design doc 2026-10-14, sections 1.4 and 3). Every local
artifact here -- transcripts, this script, the ledger -- is writable by code running as this
user. The claim is freshness + specificity + detectability, NOT unforgeability. What the layer
buys: a canned or replayed sentence dies (fresh nonce, single-use, TTL); the act is bound to
the exact case and target; and `attest/ledger.jsonl` is a hash chain, so a grant minted by
calling `gate.ps1` directly is a NAMED, visible fact at the next `verify-all` instead of an
unnoticed string. A partial edit of the ledger is detected; a full rewrite is possible by
same-user code, which is why the pushed remote copy is the authority.

ACTIONS
  Challenge -CaseDir X -Channel <project> -Target T
        nonce (10 hex, inside the design's 8-12), TTL (default 30 min), single-use; appended
        to `attest/challenges.jsonl`; prints the relay line for the Owner to answer.
  Mint -CaseDir X -Channel <project> -Sentence "..."
        verifies the reply (fail-closed, one exit code per refusal), then calls
        `gate.ps1 -Action New`; on success writes `owner-attest.json` into the case dir and
        appends the evidence entry to `attest/ledger.jsonl`.
  Verify
        walks the ledger hash chain; resolves every evidence reference; classifies every
        `grant.json` under the missions root as ledgered / pre-attest / UNLEDGERED.
        REPORT-ONLY: exit 0 unless the CHAIN itself is broken.
  --selftest
        planted cases in a temp dir with a synthetic transcript.

EXIT CODES (each refusal its own code and message; 0 = ok)
   2  usage / bad parameter value
   3  case dir missing or not a directory
   4  sentence empty or whitespace
   5  no nonce-shaped token (8-12 hex) in the sentence
   6  nonce was never challenged
   7  nonce was challenged for a different case/channel
   8  nonce already used (single-use)
   9  nonce expired (TTL)
  10  channel unknown / no transcripts in it
  11  nonce not in a user-attribution message NEWER than the challenge
  12  sentence names neither the target basename nor the case_id
  13  gate.ps1 refused the mint (its own exit code is in the message)
  14  ledger chain broken, or the challenges/ledger file is unreadable (Verify, Mint)
  15  post-mint bookkeeping failed (sidecar/ledger write; the grant IS minted and UNLEDGERED)
  16  the sentence matches more than one challenged nonce
  17  target missing or not a file
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

STATION = Path(__file__).resolve().parents[1]
DEFAULT_SESSIONS_ROOT = Path.home() / ".omp" / "agent" / "sessions"
DEFAULT_CHALLENGES = STATION / "attest" / "challenges.jsonl"
DEFAULT_LEDGER = STATION / "attest" / "ledger.jsonl"
DEFAULT_MISSIONS = Path("E:/missions")
DEFAULT_GATE = Path(__file__).resolve().parent / "gate.ps1"

# The first link of the chain. Named rather than 64 zeros so a reader can tell "the chain
# starts here" from "somebody wrote a zero hash".
GENESIS = "genesis"

# 8-12 hex, on word boundaries: the design fixes the nonce shape and this is the only thing
# Mint accepts as "the Owner answered with the challenge". Case-insensitive on purpose -- the
# Owner may type the token uppercase; the relay line prints it lowercase.
NONCE_RE = re.compile(r"\b[0-9a-fA-F]{8,12}\b")

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_CASEDIR = 3
EXIT_SENTENCE = 4
EXIT_NO_TOKEN = 5
EXIT_UNKNOWN_NONCE = 6
EXIT_WRONG_SCOPE = 7
EXIT_USED = 8
EXIT_EXPIRED = 9
EXIT_CHANNEL = 10
EXIT_NO_USER_MSG = 11
EXIT_NAMED_TARGET = 12
EXIT_GATE = 13
EXIT_CHAIN = 14
EXIT_BOOKKEEPING = 15
EXIT_AMBIGUOUS = 16
EXIT_TARGET = 17


class StateError(Exception):
    """challenges/ledger bytes are not the JSONL this layer wrote."""


def now_ms() -> int:
    return int(time.time() * 1000)


def iso(ms: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_sha(obj: dict) -> str:
    """Deterministic hash of a ledger entry: sorted keys, compact separators, ASCII.

    The stored line is written for humans (`ensure_ascii=False`); the hash is computed from
    the PARSED values re-serialised here, so the two never need to be byte-identical.
    """
    return sha256_hex(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def refuse(code: int, message: str) -> None:
    print(f"REFUSED (exit {code}): {message}")
    raise SystemExit(code)


def load_jsonl(path: Path, what: str) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = path.read_bytes()
    except OSError as ex:
        raise StateError(f"{what} unreadable: {path}: {ex}") from ex
    out: list[dict] = []
    for n, raw in enumerate(data.split(b"\n"), 1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw.decode("utf-8"))
        except Exception as ex:
            raise StateError(f"{what} corrupt at line {n}: {ex}") from ex
        if not isinstance(rec, dict):
            raise StateError(f"{what} line {n} is not a JSON object")
        out.append(rec)
    return out


def append_jsonl(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    with open(path, "ab") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())


# ---------------------------------------------------------------------------
# Resolution helpers. Fail-closed: an input this layer cannot resolve to exactly one
# object is a refusal, never a guess.

def resolve_case_dir(value) -> Path:
    if value is None or not str(value).strip():
        refuse(EXIT_USAGE, "-CaseDir is required for this action")
    p = Path(str(value)).expanduser()
    if not p.is_dir():
        refuse(EXIT_CASEDIR, f"case dir missing or not a directory: {value}")
    return p.resolve()


def resolve_target(value) -> Path:
    if value is None or not str(value).strip():
        refuse(EXIT_USAGE, "-Target is required for Challenge")
    p = Path(str(value)).expanduser()
    if not p.is_file():
        refuse(EXIT_TARGET, f"target missing or not a file: {value}")
    return p.resolve()


def resolve_channel(sessions_root: Path, channel) -> Path:
    """Resolve -Channel to exactly one omp session directory under the sessions root.

    Exact name first (the directory names are `--D--Project-<private-tree>--`-shaped), then
    case-insensitive, then a UNIQUE substring. Zero or several matches refuse, and the
    refusal names what it saw -- an ambiguous channel silently picking one transcript is
    how a verification reads the wrong conversation.
    """
    if channel is None or not str(channel).strip():
        refuse(EXIT_USAGE, "-Channel is required for this action")
    if not sessions_root.is_dir():
        refuse(EXIT_CHANNEL, f"sessions root not found: {sessions_root}")
    dirs = sorted(p for p in sessions_root.iterdir() if p.is_dir())
    exact = [p for p in dirs if p.name == str(channel)]
    if exact:
        return exact[0]
    low = str(channel).lower()
    ci = [p for p in dirs if p.name.lower() == low]
    if ci:
        return ci[0]
    sub = [p for p in dirs if low in p.name.lower()]
    if len(sub) == 1:
        return sub[0]
    if not sub:
        refuse(EXIT_CHANNEL, f"unknown channel '{channel}': no session directory under {sessions_root} matches it")
    shown = ", ".join(p.name for p in sub[:8]) + ("..." if len(sub) > 8 else "")
    refuse(EXIT_CHANNEL, f"ambiguous channel '{channel}': {len(sub)} session directories match ({shown}); pass the full directory name")


def transcript_files(channel_dir: Path) -> list[Path]:
    return sorted(p for p in channel_dir.glob("*.jsonl") if p.is_file())


def message_text(content) -> str:
    """The Owner's words from a message record. Blocks observed in live transcripts are
    `{"type": "text", "text": ...}`; a bare string is accepted too so a format change
    degrades into a refusal rather than a crash."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "\n".join(parts)
    return ""


def find_user_reply(channel_dir: Path, nonce: str, newer_than_ms: int):
    """First user-attribution message in the channel containing the nonce, NEWER than the
    challenge record. Both conditions are the design's (Option A): role AND attribution must
    be 'user' (an assistant message, or a user record the harness did not attribute to the
    user, does not count), and the message must postdate the challenge (a planted older line
    is exactly the forgery this ordering exists to kill). Returns None or the evidence dict.
    """
    needle = nonce.lower()
    for path in transcript_files(channel_dir):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for idx, raw in enumerate(data.split(b"\n")):
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw.decode("utf-8"))
            except Exception:  # noqa: BLE001 - a line we cannot read is a line we skip
                continue
            if not isinstance(rec, dict):
                continue
            msg = rec.get("message")
            if not isinstance(msg, dict):
                continue
            if msg.get("role") != "user" or msg.get("attribution") != "user":
                continue
            ts = msg.get("timestamp")
            if isinstance(ts, bool) or not isinstance(ts, (int, float)):
                continue
            ts = int(ts)
            if ts <= newer_than_ms:
                continue
            if needle not in message_text(msg.get("content")).lower():
                continue
            return {
                "path": str(path),
                "line_index": idx,
                "line_sha256": sha256_hex(raw),
                "ts_ms": ts,
            }
    return None


# ---------------------------------------------------------------------------
# Actions.

def cmd_challenge(args) -> int:
    case_dir = resolve_case_dir(args.CaseDir)
    channel_dir = resolve_channel(Path(args.SessionsRoot), args.Channel)
    if not transcript_files(channel_dir):
        refuse(EXIT_CHANNEL, f"channel '{channel_dir.name}' holds no *.jsonl transcripts under {channel_dir}; there is nowhere to verify the reply")
    target = resolve_target(args.Target)
    try:
        ttl = int(args.TtlMin)
    except (TypeError, ValueError):
        refuse(EXIT_USAGE, f"-TtlMin must be an integer number of minutes, got {args.TtlMin!r}")
    if ttl < 1:
        refuse(EXIT_USAGE, f"-TtlMin must be >= 1 minute, got {ttl}")

    challenges_path = Path(args.ChallengesPath)
    try:
        prior = load_jsonl(challenges_path, "challenges file")
    except StateError as ex:
        refuse(EXIT_CHAIN, str(ex))
    nonce = secrets.token_hex(5)  # 10 hex chars, inside the 8-12 the design fixes
    taken = {str(r.get("nonce", "")).lower() for r in prior}
    while nonce in taken:
        nonce = secrets.token_hex(5)

    rec = {
        "seq": (int(prior[-1].get("seq", 0)) + 1 if prior else 1),
        "ts": now_ms(),
        "nonce": nonce,
        "case_id": case_dir.name,
        "channel": channel_dir.name,
        "target": str(target),
        "ttl_min": ttl,
    }
    try:
        append_jsonl(challenges_path, rec)
    except OSError as ex:
        refuse(EXIT_BOOKKEEPING, f"could not append the challenge to {challenges_path}: {ex}")

    print(f"CHALLENGE seq={rec['seq']} case_id={rec['case_id']} channel={rec['channel']} ttl_min={ttl} expires={iso(rec['ts'] + ttl * 60_000)}")
    print(f"Owner: reply with {nonce} to authorise {rec['case_id']} ({rec['target']})")
    return EXIT_OK


def cmd_mint(args) -> int:
    sentence = args.Sentence if isinstance(args.Sentence, str) else ""
    if not sentence.strip():
        refuse(EXIT_SENTENCE, "the sentence is empty or whitespace; -OwnerWord must be the Owner's actual sentence, and this layer will not send it without one")
    case_dir = resolve_case_dir(args.CaseDir)
    channel_dir = resolve_channel(Path(args.SessionsRoot), args.Channel)
    challenges_path = Path(args.ChallengesPath)
    ledger_path = Path(args.LedgerPath)

    try:
        challenges = load_jsonl(challenges_path, "challenges file")
        ledger = load_jsonl(ledger_path, "ledger")
    except StateError as ex:
        refuse(EXIT_CHAIN, str(ex))

    tokens = {t.lower() for t in NONCE_RE.findall(sentence)}
    if not tokens:
        refuse(EXIT_NO_TOKEN, "the sentence carries no nonce-shaped token (8-12 hex); relay the exact `Owner: reply with ...` line from Challenge and use the Owner's reply verbatim")

    in_scope = [r for r in challenges
                if str(r.get("case_id", "")) == case_dir.name
                and str(r.get("channel", "")) == channel_dir.name
                and str(r.get("nonce", "")).lower() in tokens]
    if len({str(r.get("nonce", "")).lower() for r in in_scope}) > 1:
        refuse(EXIT_AMBIGUOUS, f"the sentence matches {len(in_scope)} challenged nonces for this case/channel; one reply authorises one challenge")
    if not in_scope:
        elsewhere = [r for r in challenges if str(r.get("nonce", "")).lower() in tokens]
        if elsewhere:
            r = elsewhere[-1]
            refuse(EXIT_WRONG_SCOPE, f"nonce {r.get('nonce')} was challenged for case_id={r.get('case_id')} channel={r.get('channel')}, not case_id={case_dir.name} channel={channel_dir.name}")
        refuse(EXIT_UNKNOWN_NONCE, "no challenge record carries any nonce-shaped token from the sentence; run Challenge first")
    rec = max(in_scope, key=lambda r: int(r.get("seq", 0)))
    nonce = str(rec.get("nonce"))

    if any(str(e.get("nonce", "")).lower() == nonce.lower() for e in ledger):
        refuse(EXIT_USED, f"nonce {nonce} is already used (single-use); run Challenge again for a fresh one")
    ts = int(rec.get("ts", 0))
    ttl = int(rec.get("ttl_min", 30))
    if now_ms() > ts + ttl * 60_000:
        refuse(EXIT_EXPIRED, f"nonce {nonce} expired: challenged {iso(ts)} with TTL {ttl} min; run Challenge again and ask the Owner to answer the fresh line")

    ev = find_user_reply(channel_dir, nonce, ts)
    if ev is None:
        refuse(EXIT_NO_USER_MSG, f"nonce {nonce} does not appear in any user-attribution message newer than the challenge in {channel_dir}/*.jsonl (a record needs message.role=='user' AND message.attribution=='user' AND message.timestamp > the challenge); an assistant message does not count")

    target_raw = str(rec.get("target", "")).strip()
    if not target_raw:
        refuse(EXIT_TARGET, f"the challenge record seq={rec.get('seq')} carries no target; challenge again")
    target = Path(target_raw)
    if target.name.lower() not in sentence.lower() and case_dir.name.lower() not in sentence.lower():
        refuse(EXIT_NAMED_TARGET, f"the sentence names neither the target basename ({target.name}) nor the case_id ({case_dir.name}); a pronoun does not authorise an object")

    if args.Containment is None or not str(args.Containment).strip():
        refuse(EXIT_USAGE, "-Containment is required for Mint (gate.ps1 refuses to guess one; see KnownContainments in gate.ps1)")
    if args.Lane is None or not str(args.Lane).strip():
        refuse(EXIT_USAGE, "-Lane must be a non-blank lane (gate.ps1 defaults to debug); a blank lane would mint a grant with an empty capability set")
    provenance = args.Provenance if isinstance(args.Provenance, str) and args.Provenance.strip() else (
        f"Owner nonce {nonce} in omp channel {rec.get('channel')}: "
        f"user-attribution reply line {ev['line_index']} of {ev['path']} "
        f"(line sha256 {ev['line_sha256'][:16]}), transcript ts {ev['ts_ms']}"
    )

    gate = Path(args.GatePath)
    if not gate.is_file():
        refuse(EXIT_GATE, f"gate.ps1 not found at {gate}")
    cmd = ["powershell", "-NoProfile", "-File", str(gate),
           "-Action", "New", "-Target", str(target), "-Provenance", provenance,
           "-OwnerWord", sentence, "-CaseDir", str(case_dir),
           "-Containment", str(args.Containment), "-Lane", str(args.Lane)]
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=180, check=False)
    except Exception as ex:  # noqa: BLE001 - report, never crash mid-authorisation
        refuse(EXIT_GATE, f"gate.ps1 could not be run: {type(ex).__name__}: {ex}")
    out = res.stdout.decode("utf-8", errors="replace").strip()
    gate_obj = None
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                gate_obj = json.loads(line)
                break
            except Exception:  # noqa: BLE001
                continue
    if res.returncode != 0 or not (isinstance(gate_obj, dict) and gate_obj.get("ok") is True):
        detail = out or res.stderr.decode("utf-8", errors="replace").strip()
        refuse(EXIT_GATE, f"gate.ps1 refused the mint (exit {res.returncode}): {detail[:600]}")
    grant = gate_obj.get("grant") if isinstance(gate_obj.get("grant"), dict) else {}
    target_sha = str(grant.get("target_sha256") or "") or sha256_file(target)

    sidecar = {
        "nonce": nonce,
        "challenge_ref": {
            "path": str(challenges_path),
            "seq": int(rec.get("seq", 0)),
            "channel": str(rec.get("channel")),
            "ts": ts,
        },
        "transcript_path": str(ev["path"]),
        "line_index": int(ev["line_index"]),
        "line_sha256": ev["line_sha256"],
        "sentence": sentence,
        "owner_verified": True,
    }
    sidecar_path = case_dir / "owner-attest.json"
    try:
        sidecar_path.write_text(json.dumps(sidecar, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError as ex:
        refuse(EXIT_BOOKKEEPING, f"the grant WAS minted but the sidecar could not be written ({sidecar_path}): {ex}; the grant is UNLEDGERED")

    # Re-read the ledger: another mint may have appended since the used-check. Chain, not lock
    # -- the station's discipline is one writer per tree; a race would be visible in Verify.
    try:
        ledger_now = load_jsonl(ledger_path, "ledger")
    except StateError as ex:
        refuse(EXIT_BOOKKEEPING, f"the grant WAS minted but the ledger is unreadable/corrupt ({ex}); the grant is UNLEDGERED")
    entry = {
        "seq": (int(ledger_now[-1].get("seq", 0)) + 1 if ledger_now else 1),
        "ts": now_ms(),
        "case_id": case_dir.name,
        "target_sha256": target_sha,
        "owner_word_sha256": sha256_hex(sentence.encode("utf-8")),
        "nonce": nonce,
        "evidence_ref": {
            "path": str(ev["path"]),
            "line_index": int(ev["line_index"]),
            "line_sha256": ev["line_sha256"],
        },
        "prev_sha": (str(ledger_now[-1].get("sha")) if ledger_now else GENESIS),
    }
    entry["sha"] = canonical_sha(entry)
    try:
        append_jsonl(ledger_path, entry)
    except OSError as ex:
        refuse(EXIT_BOOKKEEPING, f"the grant WAS minted but the ledger append failed ({ledger_path}): {ex}; the grant is UNLEDGERED")

    print(f"MINT OK case_id={case_dir.name} nonce={nonce} ledger_seq={entry['seq']} sidecar={sidecar_path}")
    print(f"  evidence: {ev['path']}:{ev['line_index']} (line sha256 {ev['line_sha256'][:16]}...)")
    print(f"  gate: {out}")
    return EXIT_OK


def cmd_verify(args) -> int:
    ledger_path = Path(args.LedgerPath)
    missions = Path(args.MissionsRoot)
    print("OWNER-ATTEST VERIFY (report-only; exit 0 unless the ledger chain itself is broken)")
    print(f"  ledger: {ledger_path}")
    entries: list[dict] = []
    if not ledger_path.exists():
        print("  CHAIN: no ledger file yet (nothing to walk)")
    else:
        try:
            entries = load_jsonl(ledger_path, "ledger")
        except StateError as ex:
            print(f"  CHAIN: BROKEN (unreadable) -- {ex}")
            return EXIT_CHAIN

    broken = ""
    prev = GENESIS
    for i, e in enumerate(entries, 1):
        if e.get("seq") != i:
            broken = f"entry {i} carries seq {e.get('seq')!r}, expected {i} (a record was dropped or reordered)"
            break
        if e.get("prev_sha") != prev:
            broken = f"entry {i} (seq {e.get('seq')}) prev_sha {str(e.get('prev_sha'))[:16]}... does not match the previous sha {str(prev)[:16]}..."
            break
        body = {k: v for k, v in e.items() if k != "sha"}
        got = canonical_sha(body)
        if got != e.get("sha"):
            broken = f"entry {i} (seq {e.get('seq')}) sha mismatch: stored {str(e.get('sha'))[:16]}... recomputed {got[:16]}... (a field was edited after the chain was written)"
            break
        prev = e.get("sha")
    if broken:
        print(f"  CHAIN: BROKEN -- {broken}")
        return EXIT_CHAIN
    print(f"  CHAIN: OK ({len(entries)} entries, seq 1..{len(entries)})" if entries else "  CHAIN: OK (0 entries)")

    resolved = 0
    unresolved: list[tuple[object, str]] = []
    for e in entries:
        ref = e.get("evidence_ref") if isinstance(e.get("evidence_ref"), dict) else {}
        raw_path = str(ref.get("path", "")).strip()
        line_index = ref.get("line_index")
        want = str(ref.get("line_sha256", ""))
        why = ""
        if not raw_path:
            why = "evidence_ref carries no path"
        else:
            p = Path(raw_path)
            if not p.is_file():
                why = f"transcript missing: {p}"
            else:
                try:
                    data = p.read_bytes()
                except OSError as ex:
                    why = f"transcript unreadable: {ex}"
                else:
                    parts = data.split(b"\n")
                    if not isinstance(line_index, int) or isinstance(line_index, bool) or not 0 <= line_index < len(parts):
                        why = f"line index {line_index!r} out of range (file holds {len(parts)} lines)"
                    else:
                        got = sha256_hex(parts[line_index])
                        if got != want:
                            why = f"line {line_index} sha256 mismatch: ledger {want[:16]}... vs file {got[:16]}..."
        if why:
            unresolved.append((e.get("seq"), why))
        else:
            resolved += 1
    print(f"  EVIDENCE: {len(entries)} refs -- {resolved} resolved, {len(unresolved)} unresolved")
    for seq, why in unresolved:
        print(f"    UNRESOLVED seq {seq}: {why}")

    dups = [n for n, c in Counter(str(e.get("nonce", "")) for e in entries).items() if c > 1]
    if dups:
        print(f"  WARN: nonce reused in the ledger: {', '.join(dups)} (single-use violated)")

    grants: list[Path] = []
    if missions.is_dir():
        for root, _dirs, files in os.walk(missions):
            if "grant.json" in files:
                grants.append(Path(root) / "grant.json")

    # The ledger epoch: the moment this layer existed on this machine. The ledger file's
    # creation time is that moment; the first record's ts is the floor that survives a clone
    # (where the file's creation time is the clone, not the layer). Grants older than the
    # epoch are grandfathered pre-attest; NEVER retro-attested.
    cands = []
    if ledger_path.exists():
        try:
            cands.append(int(ledger_path.stat().st_ctime * 1000))
        except OSError:
            pass
    if entries:
        try:
            cands.append(int(entries[0].get("ts")))
        except (TypeError, ValueError):
            pass
    epoch = min(cands) if cands else None

    ledgered = 0
    pre = 0
    unledgered: list[tuple[Path, str]] = []
    unreadable: list[tuple[Path, str]] = []
    for g in sorted(grants):
        try:
            obj = json.loads(g.read_text(encoding="utf-8-sig"))
            if not isinstance(obj, dict):
                raise ValueError("not a JSON object")
        except Exception as ex:  # noqa: BLE001 - report the file, do not die
            unreadable.append((g, f"{type(ex).__name__}: {ex}"))
            continue
        case_id = g.parent.name
        tsha = str(obj.get("target_sha256") or "")
        word = obj.get("owner_word") if isinstance(obj.get("owner_word"), str) else ""
        owh = sha256_hex(word.encode("utf-8"))
        if any(e.get("case_id") == case_id and str(e.get("target_sha256")) == tsha and str(e.get("owner_word_sha256")) == owh for e in entries):
            ledgered += 1
            continue
        try:
            mtime_ms = int(g.stat().st_mtime * 1000)
        except OSError:
            mtime_ms = 0
        if epoch is not None and mtime_ms < epoch:
            pre += 1
        else:
            unledgered.append((g, case_id))

    if not missions.is_dir():
        print(f"  GRANTS: missions root not present: {missions} (nothing to classify)")
    else:
        epoch_txt = iso(epoch) if epoch is not None else "an undefined epoch"
        tail = f", {len(unreadable)} unreadable" if unreadable else ""
        print(f"  GRANTS: {len(grants)} grant.json under {missions} -- {ledgered} ledgered, {pre} pre-attest (mtime before {epoch_txt}), {len(unledgered)} UNLEDGERED{tail}")
        for g, cid in unledgered:
            print(f"    UNLEDGERED {g} (case_id={cid}) -- no ledger entry matches case_id + target sha256 + owner-word sha256")
        for g, why in unreadable:
            print(f"    UNREADABLE {g} -- {why}")
    print("owner-attest verify: done (report only)")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Selftest. Planted cases in a temp dir with a synthetic transcript. The valid-flow case
# calls the REAL gate.ps1, because the integration is the thing being proven; every other
# case refuses before the gate is reached.

def _env(root: Path) -> dict:
    sessions = root / "sessions" / "test-channel"
    sessions.mkdir(parents=True, exist_ok=True)
    (root / "attest").mkdir(parents=True, exist_ok=True)
    case_dir = root / "case-valid"
    case_dir.mkdir(parents=True, exist_ok=True)
    target = case_dir / "c01-stringobf.exe"
    target.write_bytes(b"MZ" + bytes(62))
    # Challenge refuses a channel with no transcripts, so the file exists before the
    # challenge; replies are APPENDED after it (their ts must postdate the challenge).
    transcript = sessions / "2026-01-01T00-00-00-000Z_selftest.jsonl"
    transcript.write_bytes(json.dumps({"type": "session", "id": "selftest"}).encode("utf-8") + b"\n")
    return {
        "root": root,
        "sessions": root / "sessions",
        "challenges": root / "attest" / "challenges.jsonl",
        "ledger": root / "attest" / "ledger.jsonl",
        "case": case_dir,
        "target": target,
        "transcript": transcript,
    }


def _plant_reply(env: dict, text: str, ts_ms: int, role: str = "user", attribution: str = "user") -> None:
    msg = {"role": role, "content": [{"type": "text", "text": text}], "timestamp": ts_ms}
    if attribution is not None:
        msg["attribution"] = attribution
    rec = {"type": "message", "id": "selftest-reply", "parentId": "selftest",
           "timestamp": iso(ts_ms), "message": msg}
    with open(env["transcript"], "ab") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False).encode("utf-8") + b"\n")


def _ns(**kw) -> argparse.Namespace:
    base = dict(Action=None, CaseDir=None, Channel=None, Target=None, Sentence=None,
                Containment="loopback_capture", Lane="debug", TtlMin=30,
                SessionsRoot=str(DEFAULT_SESSIONS_ROOT), ChallengesPath=str(DEFAULT_CHALLENGES),
                LedgerPath=str(DEFAULT_LEDGER), MissionsRoot=str(DEFAULT_MISSIONS),
                GatePath=str(DEFAULT_GATE), Provenance=None, selftest=False)
    base.update(kw)
    return argparse.Namespace(**base)


def _call(fn, ns: argparse.Namespace) -> tuple[int, str]:
    """Run an action in-process, capturing its stdout; return (exit code, output)."""
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        code = fn(ns)
    except SystemExit as ex:
        code = ex.code if isinstance(ex.code, int) else 2
    finally:
        sys.stdout = old
    return code, buf.getvalue()


def _env_args(env: dict, **kw) -> argparse.Namespace:
    base = dict(CaseDir=str(env["case"]), Channel="test-channel",
                SessionsRoot=str(env["sessions"]), ChallengesPath=str(env["challenges"]),
                LedgerPath=str(env["ledger"]))
    base.update(kw)
    return _ns(**base)


def _mint_args(env: dict, sentence: str, **kw) -> argparse.Namespace:
    return _env_args(env, Sentence=sentence, **kw)


def _challenge_and_nonce(env: dict) -> tuple[int, str, str]:
    rc, out = _call(cmd_challenge, _env_args(env, Target=str(env["target"])))
    if rc != 0:
        return rc, "", out
    recs = [json.loads(ln) for ln in env["challenges"].read_text(encoding="utf-8").splitlines() if ln.strip()]
    return rc, str(recs[-1].get("nonce")), out


def cmd_selftest(args) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="owner-attest-selftest-"))
    env1 = _env(tmp / "e1")
    results: list[tuple[str, bool, str]] = []

    def c_valid() -> tuple[bool, str]:
        rc, nonce, out = _challenge_and_nonce(env1)
        if rc != 0:
            return False, f"Challenge exit {rc}: {out.strip()}"
        sentence = f"go {nonce} - analyze c01-stringobf.exe"
        _plant_reply(env1, sentence, now_ms() + 1000)
        rc2, out2 = _call(cmd_mint, _mint_args(env1, sentence))
        if rc2 != 0:
            return False, f"Mint exit {rc2}: {out2.strip()[-400:]}"
        side = env1["case"] / "owner-attest.json"
        if not side.is_file():
            return False, "sidecar owner-attest.json missing after a successful mint"
        s = json.loads(side.read_text(encoding="utf-8"))
        if s.get("owner_verified") is not True or s.get("nonce") != nonce or s.get("sentence") != sentence:
            return False, f"sidecar fields wrong: {s}"
        lines = env1["transcript"].read_bytes().split(b"\n")
        if not isinstance(s.get("line_index"), int) or sha256_hex(lines[s["line_index"]]) != s.get("line_sha256"):
            return False, "sidecar line_sha256 does not match the transcript line it names"
        led = [json.loads(ln) for ln in env1["ledger"].read_text(encoding="utf-8").splitlines() if ln.strip()]
        if len(led) != 1 or led[0].get("nonce") != nonce or led[0].get("prev_sha") != GENESIS:
            return False, f"ledger entry wrong: {led}"
        if not (env1["case"] / "grant.json").is_file():
            return False, "gate.ps1 did not write grant.json into the case dir"
        return True, f"nonce={nonce}, sidecar + grant.json + ledger seq 1 written"

    def c_replay() -> tuple[bool, str]:
        led = [json.loads(ln) for ln in env1["ledger"].read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not led:
            return False, "no ledger entry from the valid-flow case to replay"
        nonce = str(led[0].get("nonce"))
        rc, out = _call(cmd_mint, _mint_args(env1, f"go {nonce} - analyze c01-stringobf.exe"))
        return rc == EXIT_USED, f"exit {rc} (want {EXIT_USED}): {out.strip().splitlines()[-1] if out.strip() else ''}"

    def c_stale() -> tuple[bool, str]:
        env = _env(tmp / "e2")
        rc, nonce, out = _challenge_and_nonce(env)
        if rc != 0:
            return False, f"Challenge exit {rc}: {out.strip()}"
        recs = [json.loads(ln) for ln in env["challenges"].read_text(encoding="utf-8").splitlines() if ln.strip()]
        recs[-1]["ts"] = now_ms() - 31 * 60 * 1000  # older than the 30 min TTL
        env["challenges"].write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
        _plant_reply(env, f"go {nonce} - analyze c01-stringobf.exe", now_ms() + 1000)
        rc2, out2 = _call(cmd_mint, _mint_args(env, f"go {nonce} - analyze c01-stringobf.exe"))
        return rc2 == EXIT_EXPIRED, f"exit {rc2} (want {EXIT_EXPIRED}): {out2.strip().splitlines()[-1] if out2.strip() else ''}"

    def c_assistant_only() -> tuple[bool, str]:
        env = _env(tmp / "e3")
        rc, nonce, out = _challenge_and_nonce(env)
        if rc != 0:
            return False, f"Challenge exit {rc}: {out.strip()}"
        _plant_reply(env, f"go {nonce} - analyze c01-stringobf.exe", now_ms() + 1000,
                     role="assistant", attribution="assistant")
        rc2, out2 = _call(cmd_mint, _mint_args(env, f"go {nonce} - analyze c01-stringobf.exe"))
        return rc2 == EXIT_NO_USER_MSG, f"exit {rc2} (want {EXIT_NO_USER_MSG}): {out2.strip().splitlines()[-1] if out2.strip() else ''}"

    def c_older_reply() -> tuple[bool, str]:
        env = _env(tmp / "e8")
        rc, nonce, out = _challenge_and_nonce(env)
        if rc != 0:
            return False, f"Challenge exit {rc}: {out.strip()}"
        _plant_reply(env, f"go {nonce} - analyze c01-stringobf.exe", now_ms() - 60 * 1000)
        rc2, out2 = _call(cmd_mint, _mint_args(env, f"go {nonce} - analyze c01-stringobf.exe"))
        return rc2 == EXIT_NO_USER_MSG, f"exit {rc2} (want {EXIT_NO_USER_MSG}): {out2.strip().splitlines()[-1] if out2.strip() else ''}"

    def c_named_target() -> tuple[bool, str]:
        env = _env(tmp / "e4")
        rc, nonce, out = _challenge_and_nonce(env)
        if rc != 0:
            return False, f"Challenge exit {rc}: {out.strip()}"
        sentence = f"go {nonce} please"
        _plant_reply(env, sentence, now_ms() + 1000)
        rc2, out2 = _call(cmd_mint, _mint_args(env, sentence))
        return rc2 == EXIT_NAMED_TARGET, f"exit {rc2} (want {EXIT_NAMED_TARGET}): {out2.strip().splitlines()[-1] if out2.strip() else ''}"

    def c_unknown_channel() -> tuple[bool, str]:
        env = _env(tmp / "e6")
        rc, out = _call(cmd_challenge, _env_args(env, Channel="no-such-channel-xyz", Target=str(env["target"])))
        return rc == EXIT_CHANNEL, f"exit {rc} (want {EXIT_CHANNEL}): {out.strip().splitlines()[-1] if out.strip() else ''}"

    def c_tampered_ledger() -> tuple[bool, str]:
        empty = env1["root"] / "missions-none"
        rc0, out0 = _call(cmd_verify, _ns(LedgerPath=str(env1["ledger"]), MissionsRoot=str(empty)))
        if rc0 != 0:
            return False, f"Verify on the untouched ledger exited {rc0} (want 0): {out0.strip()[-300:]}"
        tampered = env1["root"] / "ledger-tampered.jsonl"
        entry = json.loads(env1["ledger"].read_text(encoding="utf-8").splitlines()[0])
        entry["case_id"] = "tampered-case"
        tampered.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        rc1, out1 = _call(cmd_verify, _ns(LedgerPath=str(tampered), MissionsRoot=str(empty)))
        return rc1 == EXIT_CHAIN, f"exit {rc1} (want {EXIT_CHAIN}): {out1.strip().splitlines()[-1] if out1.strip() else ''}"

    def c_classify() -> tuple[bool, str]:
        missions = env1["root"] / "missions"
        (missions / "case-valid").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(env1["case"] / "grant.json", missions / "case-valid" / "grant.json")
        old = missions / "fake-old" / "grant.json"
        old.parent.mkdir(parents=True, exist_ok=True)
        old.write_text(json.dumps({"schema": "gate/grant@2", "owner_word": "ancient", "target_sha256": "0" * 64}), encoding="utf-8")
        os.utime(old, (1577836800, 1577836800))  # 2020-01-01, before the ledger epoch
        new = missions / "fake-new" / "grant.json"
        new.parent.mkdir(parents=True, exist_ok=True)
        new.write_text(json.dumps({"schema": "gate/grant@2", "owner_word": "direct-mint", "target_sha256": "1" * 64}), encoding="utf-8")
        rc, out = _call(cmd_verify, _ns(LedgerPath=str(env1["ledger"]), MissionsRoot=str(missions)))
        line = next((ln.strip() for ln in out.splitlines() if "GRANTS:" in ln), "")
        ok = rc == 0 and "1 ledgered" in line and "1 pre-attest" in line and "1 UNLEDGERED" in line
        return ok, f"exit {rc}: {line}"

    def run(name: str, fn) -> None:
        try:
            ok, detail = fn()
        except Exception as ex:  # noqa: BLE001 - a crashing case is a failing case
            ok, detail = False, f"{type(ex).__name__}: {ex}"
        results.append((name, ok, detail))

    run("valid flow passes (challenge -> Owner reply -> mint -> sidecar + ledger)", c_valid)
    run("replay: a used nonce refuses", c_replay)
    run("stale nonce refuses", c_stale)
    run("nonce only in an assistant message refuses", c_assistant_only)
    run("reply older than the challenge refuses", c_older_reply)
    run("sentence missing the target name refuses", c_named_target)
    run("unknown channel refuses", c_unknown_channel)
    run("tampered ledger detected by Verify", c_tampered_ledger)
    run("Verify classifies ledgered / pre-attest / UNLEDGERED", c_classify)

    width = max(len(n) for n, _, _ in results)
    passed = 0
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
        passed += 1 if ok else 0
    total = len(results)
    if passed == total:
        print(f"SELFTEST {passed}/{total} PASSED")
        shutil.rmtree(tmp, ignore_errors=True)
        return EXIT_OK
    print(f"SELFTEST {passed}/{total} FAILED")
    print(f"  (temp tree kept for inspection: {tmp})")
    return 1


# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="owner-attest.py",
        description="Owner nonce attestation layer: Challenge -> Owner reply -> Mint via gate.ps1.",
    )
    p.add_argument("-Action", choices=["Challenge", "Mint", "Verify"], default=None)
    p.add_argument("-CaseDir", default=None)
    p.add_argument("-Channel", default=None,
                   help="omp session directory under the sessions root: exact name (use -Channel=<name> when it starts with '--'), or a unique substring such as '<private-tree>'")
    p.add_argument("-Target", default=None, help="Challenge only: the object the Owner is asked to authorise")
    p.add_argument("-Sentence", default=None, help="Mint only: the Owner's reply, verbatim")
    p.add_argument("-Containment", default=None, help="Mint only: gate.ps1 containment class (required)")
    p.add_argument("-Lane", default="debug", help="Mint only: gate.ps1 lane (default debug)")
    p.add_argument("-TtlMin", default=30, help="Challenge only: minutes the nonce stays valid (default 30)")
    p.add_argument("-Provenance", default=None,
                   help="Mint only: gate.ps1 -Provenance override; default is the transcript evidence string")
    p.add_argument("-SessionsRoot", default=str(DEFAULT_SESSIONS_ROOT))
    p.add_argument("-ChallengesPath", default=str(DEFAULT_CHALLENGES))
    p.add_argument("-LedgerPath", default=str(DEFAULT_LEDGER))
    p.add_argument("-MissionsRoot", default=str(DEFAULT_MISSIONS), help="Verify only")
    p.add_argument("-GatePath", default=str(DEFAULT_GATE))
    p.add_argument("--selftest", action="store_true")
    return p


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - older/redirected stdio is fine
        pass
    args = build_parser().parse_args(argv)
    if args.selftest:
        return cmd_selftest(args)
    if args.Action == "Challenge":
        return cmd_challenge(args)
    if args.Action == "Mint":
        return cmd_mint(args)
    if args.Action == "Verify":
        return cmd_verify(args)
    print("REFUSED (exit 2): one of -Action {Challenge,Mint,Verify} or --selftest is required")
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
