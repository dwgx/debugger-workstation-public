#!/usr/bin/env python3
"""Bounded local CLI runner and provenance checks, stdlib only.

The caller pins a pre-run plan digest. This is tamper detection under a trusted
local runner, not a signature or protection against a writer controlling the
runner, plan, and all evidence. Manifest provenance is not a git observation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
PLAN_VERSION = "debugger-run-plan.1"
STEPS = ["verify-inputs", "intent", "dispatch", "collect", "cleanup", "evaluate", "publish"]
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MANDATORY_SOURCE = ["scripts/assert-probes.py", "scripts/verify-profile.py",
                    "scripts/runner_evidence.py", "schemas/run-receipt.v3.json"]
EXIT = {"PROFILE_PASS": 0, "PROFILE_FAIL": 1, "PROFILE_BLOCKED": 2, "PROFILE_NOT_RUN": 3}
LIMITS = [
    "Selected Python CLI profile only; no public-core, MCP, provider, or release verdict.",
    "Trusted local runner; no protection against an account replacing all trusted inputs and observations.",
    "Python executable and selected source bytes are bound; the full operating system and Python standard library are not attested.",
    "Windows cleanup covers the direct child only; Windows descendant/job-object coverage is NOT_VERIFIED.",
]


class ContractError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise ContractError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key: " + key)
        result[key] = value
    return result


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=no_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ContractError("invalid JSON constant: " + value)))


def write_once(path, value):
    """Exclusive, durable file creation; never replaces a prior attempt's bytes."""
    with open(path, "xb") as fh:
        fh.write(canonical(value) + b"\n")
        fh.flush()
        os.fsync(fh.fileno())


def identity(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), "not a regular owned file: " + str(p))
    return {"sha256": sha256_file(p), "size_bytes": p.stat().st_size}


def within(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def owned(root, relative):
    require(isinstance(relative, str) and relative and "\\" not in relative,
            "invalid relative artifact path")
    pos = PurePosixPath(relative)
    win = PureWindowsPath(relative)
    require(not pos.is_absolute() and not win.drive and ".." not in pos.parts
            and "." not in relative.split("/"), "path escapes owner: " + relative)
    root = Path(root).resolve()
    result = root.joinpath(*pos.parts)
    require(within(result, root), "path escapes owner: " + relative)
    cursor = root
    for part in pos.parts:
        cursor = cursor / part
        require(not cursor.is_symlink(), "symlink is not owned evidence: " + relative)
    return result


def check_identity(path, expected, label):
    observed = identity(path)
    require(observed == {"sha256": expected["sha256"], "size_bytes": expected["size_bytes"]},
            label + " byte identity mismatch")
    return observed


def python_identity():
    executable = Path(sys.executable).resolve()
    return {"executable": str(executable), "version": sys.version.split()[0], **identity(executable)}


def freeze_source_manifest(root, paths, commit, dirty):
    """Data helper for a caller-owned freeze. No plan or denominator is selected."""
    return {"manifest_version": "source-manifest.1", "commit": commit, "dirty": dirty,
            "files": [{"path": name, **identity(owned(root, name))} for name in sorted(set(paths))]}


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def plan_and_oracle(path, expected_sha):
    require(isinstance(expected_sha, str) and DIGEST.fullmatch(expected_sha),
            "caller must supply --expected-plan-sha256 sha256:<64 hex>")
    path = Path(path).resolve()
    require(sha256_file(path) == expected_sha, "caller-pinned plan digest mismatch")
    plan = load_json(path)
    keys = {"plan_version", "run_id", "attempt_id", "parent_attempt", "source", "runtime", "tool", "target",
            "profile", "oracle", "required_case_ids", "checks_total", "required_steps", "run_root", "execution", "outputs"}
    require(isinstance(plan, dict) and set(plan) == keys, "unsupported run plan fields")
    require(plan["plan_version"] == PLAN_VERSION, "unsupported plan version")
    for name in ("run_id", "attempt_id"):
        require(isinstance(plan[name], str) and IDENTIFIER.fullmatch(plan[name]), "invalid " + name)
    for name in ("run_root",):
        require(Path(plan[name]).is_absolute(), name + " must be absolute")
    source = plan["source"]
    require(set(source) == {"kind", "root", "repo", "commit", "dirty", "manifest_path", "manifest_sha256"},
            "unsupported source plan fields")
    require(source["kind"] in ("manifest-snapshot", "git-checkout"), "unsupported provenance kind")
    require(isinstance(source["repo"], str) and source["repo"], "missing source repository identity")
    require(isinstance(source["commit"], str) and re.fullmatch("[0-9a-f]{40}", source["commit"]), "invalid pinned commit")
    require(type(source["dirty"]) is bool, "dirty must be boolean")
    require(Path(source["root"]).is_absolute(), "source root must be absolute")
    require(not within(path, source["root"]), "trusted plan must be outside the source tree")
    require(not within(plan["run_root"], source["root"]), "run root must be outside the source tree")
    for name, key in ((source["manifest_path"], "manifest"), (plan["oracle"]["path"], "oracle")):
        require(Path(name).is_absolute() and not within(name, source["root"]), key + " must be external and absolute")
    require(set(plan["runtime"]) == {"executable", "version", "sha256", "size_bytes"}, "invalid runtime identity")
    require(set(plan["tool"]) == {"path", "sha256", "size_bytes"}, "invalid tool identity")
    require(set(plan["target"]) == {"path", "sha256", "size_bytes", "kind", "fixture_id"}, "invalid target identity")
    require(Path(plan["target"]["path"]).is_absolute(), "target path must be absolute")
    require(set(plan["profile"]) == {"id", "version", "capability_id", "limitations"}, "invalid selected profile")
    require(plan["profile"]["id"].startswith("bounded-cli-") and isinstance(plan["profile"]["limitations"], list)
            and plan["profile"]["limitations"], "profile must be an explicitly limited bounded CLI profile")
    require(set(plan["oracle"]) == {"path", "sha256"}, "invalid oracle identity")
    require(sha256_file(plan["oracle"]["path"]) == plan["oracle"]["sha256"], "frozen oracle digest mismatch")
    oracle = load_json(plan["oracle"]["path"])
    require(set(oracle) == {"oracle_version", "parser", "checks"} and oracle["oracle_version"] == "bounded-cli-oracle.1"
            and oracle["parser"] == "json-object@1", "unsupported bounded oracle")
    checks = oracle["checks"]
    require(isinstance(checks, list) and checks, "oracle checks must not be empty")
    ids = []
    for check in checks:
        require(isinstance(check, dict) and isinstance(check.get("id"), str) and IDENTIFIER.fullmatch(check["id"]),
                "invalid check id")
        kind = check.get("kind")
        keys = {"id", "kind"} if kind == "integrity" else ({"id", "kind", "expected_exit"} if kind == "execution"
                                                        else {"id", "kind", "pointer", "expected"})
        require(kind in ("integrity", "execution", "semantic", "negative") and set(check) == keys, "unsupported check definition")
        if kind == "execution":
            require(type(check["expected_exit"]) is int, "expected_exit must be an integer")
        if kind in ("semantic", "negative"):
            require(isinstance(check["pointer"], str) and check["pointer"].startswith("/"), "JSON pointer must start with /")
        ids.append(check["id"])
    require(len(ids) == len(set(ids)), "duplicate oracle check id")
    require(plan["required_case_ids"] == ids, "required set differs from frozen oracle")
    require(type(plan["checks_total"]) is int and plan["checks_total"] == len(ids), "frozen denominator mismatch")
    require({c["kind"] for c in checks} == {"integrity", "execution", "semantic", "negative"}, "all four bounded evidence layers required")
    require(plan["required_steps"] == STEPS, "unsupported required execution steps")
    execution = plan["execution"]
    require(set(execution) == {"argv", "timeout_s", "cancel_file"}, "unsupported execution settings")
    require(type(execution["timeout_s"]) in (int, float) and 0 < execution["timeout_s"] <= 3600,
            "timeout must be positive and bounded")
    argv = execution["argv"]
    require(isinstance(argv, list) and all(isinstance(item, str) for item in argv)
            and argv[:4] == ["{python}", "-I", "-B", "{tool}"] and argv.count("{target}") == 1,
            "bounded runner requires isolated Python, tool, and exactly one frozen target")
    require(execution["cancel_file"] is None or Path(execution["cancel_file"]).is_absolute(), "cancel file must be absolute")
    require(isinstance(plan["outputs"], list) and len(plan["outputs"]) == len(set(plan["outputs"])), "duplicate outputs")
    for rel in plan["outputs"]:
        require(rel.startswith("artifacts/"), "tool output must live under attempt artifacts/")
        owned(Path(plan["run_root"]) / "attempts" / plan["attempt_id"], rel)
    parent = plan["parent_attempt"]
    if parent is not None:
        require(set(parent) == {"attempt_id", "terminal_path", "terminal_sha256"}
                and isinstance(parent["attempt_id"], str) and IDENTIFIER.fullmatch(parent["attempt_id"])
                and parent["attempt_id"] != plan["attempt_id"] and Path(parent["terminal_path"]).is_absolute(), "invalid parent attempt")
    return plan, oracle


def source_observation(plan):
    source = plan["source"]
    require(sha256_file(source["manifest_path"]) == source["manifest_sha256"], "source manifest digest mismatch")
    manifest = load_json(source["manifest_path"])
    require(set(manifest) == {"manifest_version", "commit", "dirty", "files"}
            and manifest["manifest_version"] == "source-manifest.1", "unsupported source manifest")
    require(manifest["commit"] == source["commit"] and manifest["dirty"] is source["dirty"], "source commit/dirty differs from pinned manifest")
    files = manifest["files"]
    require(isinstance(files, list) and files, "empty source manifest")
    seen = set()
    for entry in files:
        require(set(entry) == {"path", "sha256", "size_bytes"} and entry["path"] not in seen,
                "duplicate or malformed source entry")
        seen.add(entry["path"])
        check_identity(owned(source["root"], entry["path"]), entry, "source " + entry["path"])
    required = MANDATORY_SOURCE + [plan["tool"]["path"]]
    if plan["tool"]["path"] == "net-reverse/tools/pcap_reader.py":
        required.append("scripts/probe_artifact.py")
    require(set(required) <= seen, "source manifest omits runner/verifier/schema/tool dependencies")
    # The helper running now must be the helper whose source tree was observed.
    require(Path(__file__).resolve() == owned(source["root"], "scripts/runner_evidence.py").resolve(),
            "runner/verifier was not loaded from the pinned source root")
    git_head = None
    if source["kind"] == "git-checkout":
        run = subprocess.run(["git", "-C", source["root"], "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        require(run.returncode == 0, "cannot observe git HEAD")
        git_head = run.stdout.strip()
        require(git_head == source["commit"], "observed git HEAD mismatch")
        dirty = subprocess.run(["git", "-C", source["root"], "status", "--porcelain", "--untracked-files=all"],
                               capture_output=True, text=True, timeout=10)
        require(dirty.returncode == 0 and bool(dirty.stdout.strip()) is source["dirty"], "observed git dirty status mismatch")
    return {"kind": source["kind"], "repo": source["repo"], "commit": source["commit"], "dirty": source["dirty"],
            "manifest_sha256": source["manifest_sha256"], "files_sha256": digest_bytes(canonical(files)),
            "commit_observation": "git-HEAD" if git_head else "pinned-manifest", "git_head": git_head}


def observe_inputs(plan):
    source = source_observation(plan)
    runtime = python_identity()
    require(runtime == plan["runtime"], "actual Python executable/version differs from plan")
    tool = plan["tool"]
    check_identity(owned(plan["source"]["root"], tool["path"]), tool, "selected tool")
    check_identity(plan["target"]["path"], plan["target"], "target")
    return source, runtime


def inventory(attempt):
    result = []
    for path in sorted(Path(attempt).rglob("*")):
        require(not path.is_symlink(), "attempt contains a symlink")
        if path.is_file() and not (path.parent == Path(attempt) and path.name in ("intent.json", "receipt.json", "terminal.json")):
            rel = path.relative_to(attempt).as_posix()
            result.append({"path": rel, **identity(path)})
    return result


def check_inventory(attempt, entries):
    require(isinstance(entries, list) and entries, "empty artifact inventory")
    seen = set()
    for entry in entries:
        require(set(entry) == {"path", "sha256", "size_bytes"} and entry["path"] not in seen, "duplicate artifact inventory")
        seen.add(entry["path"])
        check_identity(owned(attempt, entry["path"]), entry, "artifact " + entry["path"])
    require(inventory(attempt) == entries, "unrecorded or changed attempt artifacts")


def check_parent(plan, seen=None):
    parent = plan["parent_attempt"]
    if parent is None:
        return
    seen = set() if seen is None else set(seen)
    require(parent["attempt_id"] not in seen and len(seen) < 32, "retry chain is cyclic or exceeds 32 attempts")
    seen.add(parent["attempt_id"])
    terminal_path = Path(parent["terminal_path"]).resolve()
    require(sha256_file(terminal_path) == parent["terminal_sha256"], "parent terminal changed")
    terminal = load_json(terminal_path)
    require(terminal.get("terminal_version") == "runner-terminal.1" and terminal.get("attempt_id") == parent["attempt_id"],
            "parent terminal identity mismatch")
    require(terminal.get("outcome") != "PROFILE_PASS", "retry parent must preserve a non-passing attempt")
    require(terminal_path.parent.name == parent["attempt_id"], "parent artifact ownership mismatch")
    require(sha256_file(terminal_path.parent / "intent.json") == terminal["intent_sha256"], "parent intent changed")
    require(sha256_file(terminal_path.parent / "receipt.json") == terminal["receipt_sha256"], "parent receipt changed")
    check_inventory(terminal_path.parent, terminal["artifacts"])
    intent = load_json(terminal_path.parent / "intent.json")
    receipt = load_json(terminal_path.parent / "receipt.json")
    require(intent["plan_sha256"] == terminal["plan_sha256"], "parent intent plan binding mismatch")
    require(sha256_file(intent["plan_path"]) == intent["plan_sha256"], "parent frozen plan changed")
    parent_plan = load_json(intent["plan_path"])
    require(parent_plan["attempt_id"] == parent["attempt_id"], "parent plan attempt mismatch")
    require(receipt["parent_attempt_id"] == (parent_plan["parent_attempt"] or {}).get("attempt_id"), "parent ancestry mismatch")
    check_parent(parent_plan, seen)


def pointer_value(value, pointer):
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
            value = value[int(token)]
        else:
            raise ContractError("JSON pointer missing: " + pointer)
    return value


def strict_equal(left, right):
    return type(left) is type(right) and canonical(left) == canonical(right)


def evaluate_checks(oracle, attempt, process, outputs):
    parse_error = None
    try:
        data = load_json(Path(attempt) / "stdout.bin")
        require(isinstance(data, dict), "stdout is not a JSON object")
    except (OSError, ValueError, UnicodeError) as exc:
        data, parse_error = None, str(exc)
    missing = [name for name in outputs if not owned(attempt, name).is_file()]
    rows = []
    for check in oracle["checks"]:
        status, detail = "passed", "frozen assertion satisfied"
        try:
            kind = check["kind"]
            if kind == "integrity":
                require(parse_error is None, "invalid structured output: " + str(parse_error))
                require(not missing, "required tool artifacts missing: " + ", ".join(missing))
            elif kind == "execution":
                require(process["backend_executed"] is True and process["terminal_state"] == "exited",
                        "backend did not reach a normal terminal state")
                require(type(process["observed_exit"]) is int and process["observed_exit"] == check["expected_exit"],
                        "observed process exit violates frozen exit contract")
                require(process["cleanup"]["status"] == "converged" and process["cleanup"]["child_reaped"] is True,
                        "cleanup did not converge")
            else:
                require(parse_error is None, "cannot assert unparsed stdout")
                value = pointer_value(data, check["pointer"])
                equal = strict_equal(value, check["expected"])
                require(equal if kind == "semantic" else not equal,
                        "semantic assertion differs" if kind == "semantic" else "negative control failed to reject wrong assertion")
        except (ContractError, KeyError, TypeError) as exc:
            status, detail = "failed", str(exc)
        rows.append({"id": check["id"], "kind": check["kind"], "status": status, "detail": detail})
    return rows


def outcome(process, rows, problems):
    if not process["backend_executed"]:
        return "PROFILE_NOT_RUN"
    if process["terminal_state"] != "exited" or process["cleanup"]["status"] != "converged":
        return "PROFILE_BLOCKED"
    if problems or any(row["status"] != "passed" for row in rows):
        return "PROFILE_FAIL"
    return "PROFILE_PASS"


def live_group_members(group):
    """Linux procfs observation, excluding dead zombies. None means unsupported."""
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    members = []
    for name in proc.iterdir():
        if not name.name.isdigit():
            continue
        try:
            tail = (name / "stat").read_text().rsplit(")", 1)[1].split()
            if int(tail[2]) == group and tail[0] != "Z":
                members.append(int(name.name))
        except (OSError, ValueError, IndexError):
            continue
    return members


def cleanup_process(proc, interrupted):
    if os.name == "nt":
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
        proc.wait(timeout=3)
        return {"status": "not_converged" if interrupted else "converged", "scope": "direct-child-only",
                "child_reaped": proc.poll() is not None,
                "detail": "Windows descendant cleanup NOT_VERIFIED"}
    group = proc.pid
    for sig, budget in ((signal.SIGTERM, 0.4), (signal.SIGKILL, 0.8)):
        members = live_group_members(group)
        if proc.poll() is None or members:
            try:
                os.killpg(group, sig)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            proc.poll()
            members = live_group_members(group)
            if proc.poll() is not None and members == []:
                break
            time.sleep(0.01)
        if proc.poll() is not None and members == []:
            break
    proc.wait(timeout=3)
    members = live_group_members(group)
    return {"status": "converged" if members == [] else "not_converged", "scope": "posix-process-group",
            "child_reaped": proc.poll() is not None, "detail": "remaining live group members: " + repr(members)}


def run_plan(plan_path, expected_sha):
    plan, oracle = plan_and_oracle(plan_path, expected_sha)
    attempt = Path(plan["run_root"]).resolve() / "attempts" / plan["attempt_id"]
    attempt.parent.mkdir(parents=True, exist_ok=True)
    attempt.mkdir(exist_ok=False)
    intent = {"intent_version": "runner-intent.1", "plan_path": str(Path(plan_path).resolve()),
              "plan_sha256": expected_sha, "run_id": plan["run_id"], "attempt_id": plan["attempt_id"],
              "parent_attempt_id": (plan["parent_attempt"] or {}).get("attempt_id"),
              "created_utc": utc(), "created_ns": time.monotonic_ns()}
    write_once(attempt / "intent.json", intent)
    process = {"started_utc": utc(), "finished_utc": utc(), "started_ns": None, "cleanup_finished_ns": None,
               "pid": None, "backend_executed": False, "terminal_state": "not_run", "observed_exit": None,
               "timeout_s": plan["execution"]["timeout_s"], "cancelled": False,
               "cleanup": {"status": "not_applicable", "scope": "no-child", "child_reaped": True, "detail": "no dispatch"}}
    source, runtime, argv, problems, completed = None, None, [], [], ["intent"]
    stop = []
    previous_handlers = {}
    proc = None
    try:
        source, runtime = observe_inputs(plan)
        check_parent(plan)
        completed.insert(0, "verify-inputs")
        (attempt / "inputs").mkdir()
        (attempt / "work").mkdir()
        (attempt / "artifacts").mkdir()
        target_copy = attempt / "inputs" / "target.bin"
        shutil.copyfile(plan["target"]["path"], target_copy)
        check_identity(target_copy, plan["target"], "copied target")
        replacements = {"{python}": runtime["executable"], "{tool}": str(owned(plan["source"]["root"], plan["tool"]["path"])),
                        "{target}": str(target_copy), "{attempt}": str(attempt)}
        argv = [replacements.get(arg, arg) for arg in plan["execution"]["argv"]]
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", DEBUGGER_PROBE_ARTIFACT_ROOT=str(attempt / "artifacts"))
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[sig] = signal.signal(sig, lambda signum, frame: stop.append(signum))
        # A cancellation already observed by the caller prevents dispatch. This
        # is distinct from cancellation after Popen, which must retain executed=true.
        if stop or (plan["execution"]["cancel_file"] is not None and Path(plan["execution"]["cancel_file"]).exists()):
            process.update(terminal_state="cancelled", cancelled=True)
            raise ContractError("cancelled before dispatch; no child was started")
        with open(attempt / "stdout.bin", "xb") as stdout, open(attempt / "stderr.bin", "xb") as stderr:
            flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
            proc = subprocess.Popen(argv, cwd=attempt / "work", env=env, stdout=stdout, stderr=stderr, shell=False, **flags)
            process.update(pid=proc.pid, backend_executed=True, started_utc=utc(), started_ns=time.monotonic_ns())
            completed.append("dispatch")
            deadline = time.monotonic() + plan["execution"]["timeout_s"]
            while proc.poll() is None:
                cancelled = bool(stop) or (plan["execution"]["cancel_file"] is not None and Path(plan["execution"]["cancel_file"]).exists())
                if cancelled:
                    process.update(terminal_state="cancelled", cancelled=True)
                    break
                if time.monotonic() >= deadline:
                    process["terminal_state"] = "timeout"
                    break
                time.sleep(0.01)
            else:
                process["terminal_state"] = "exited"
            process["cleanup"] = cleanup_process(proc, process["terminal_state"] != "exited")
            process["observed_exit"] = proc.returncode
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
        process.update(finished_utc=utc(), cleanup_finished_ns=time.monotonic_ns())
        completed.extend(["collect", "cleanup"])
        require(observe_inputs(plan) == (source, runtime), "input identity changed while child ran")
        check_identity(target_copy, plan["target"], "target changed while child ran")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        problems.append(type(exc).__name__ + ": " + str(exc))
        if proc is not None and proc.poll() is None:
            try:
                process["cleanup"] = cleanup_process(proc, True)
                process["observed_exit"] = proc.returncode
            except (OSError, subprocess.SubprocessError) as cleanup_error:
                process["cleanup"] = {"status": "not_converged", "scope": "unknown", "child_reaped": False, "detail": str(cleanup_error)}
            process["terminal_state"] = "interrupted"
        process.update(finished_utc=utc(), cleanup_finished_ns=time.monotonic_ns())
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    for name in ("stdout.bin", "stderr.bin"):
        if not (attempt / name).exists():
            (attempt / name).write_bytes(b"")
    artifacts = inventory(attempt)
    rows = evaluate_checks(oracle, attempt, process, plan["outputs"])
    completed.append("evaluate")
    verdict = outcome(process, rows, problems)
    completed.append("publish")
    receipt = {"schema_version": "run-receipt.3", "run_id": plan["run_id"], "attempt_id": plan["attempt_id"],
               "parent_attempt_id": intent["parent_attempt_id"], "plan_sha256": expected_sha, "profile": plan["profile"],
               "source": source, "runtime": runtime, "tool": plan["tool"], "target": plan["target"],
               "invocation": {"argv": argv, "cwd": str(attempt / "work"),
                              "artifact_root": str(attempt / "artifacts"),
                              "env_keys": ["DEBUGGER_PROBE_ARTIFACT_ROOT", "PYTHONDONTWRITEBYTECODE", "PYTHONUTF8"]},
               "execution": process, "completed_steps": completed, "artifacts": artifacts, "checks": rows,
               "result": {"verdict": verdict, "checks_total": plan["checks_total"], "required_case_ids": plan["required_case_ids"]},
               "problems": problems, "limitations": LIMITS + plan["profile"]["limitations"]}
    write_once(attempt / "receipt.json", receipt)
    terminal = {"terminal_version": "runner-terminal.1", "run_id": plan["run_id"], "attempt_id": plan["attempt_id"],
                "plan_sha256": expected_sha, "intent_sha256": sha256_file(attempt / "intent.json"),
                "receipt_path": "receipt.json", "receipt_sha256": sha256_file(attempt / "receipt.json"),
                "published_ns": time.monotonic_ns(), "published_utc": utc(), "process": process,
                "artifacts": artifacts, "outcome": verdict, "status": "complete" if verdict in ("PROFILE_PASS", "PROFILE_FAIL") else "incomplete"}
    write_once(attempt / "terminal.json", terminal)
    return {"verdict": verdict, "terminal": str(attempt / "terminal.json"), "receipt": str(attempt / "receipt.json"),
            "checks_total": plan["checks_total"], "problems": problems}


def verify_run(plan_path, expected_sha, terminal_path, receipt_path=None):
    """Recompute from caller-pinned plan, current inputs and retained raw bytes."""
    report = {"mode": "product", "verdict": "PROFILE_FAIL", "checks_total": 0, "check_results": [], "reasons": [],
              "profile_scope": "selected bounded CLI; full B/C/D NOT_VERIFIED"}
    try:
        plan, oracle = plan_and_oracle(plan_path, expected_sha)
        report["checks_total"] = plan["checks_total"]
        attempt = Path(plan["run_root"]).resolve() / "attempts" / plan["attempt_id"]
        require(Path(terminal_path).resolve() == attempt / "terminal.json", "terminal belongs to a different attempt")
        if not Path(terminal_path).is_file():
            report["verdict"] = "PROFILE_BLOCKED"
            raise ContractError("runner terminal missing; complete JSON alone is not terminal evidence")
        terminal = load_json(terminal_path)
        terminal_keys = {"terminal_version", "run_id", "attempt_id", "plan_sha256", "intent_sha256", "receipt_path",
                         "receipt_sha256", "published_ns", "published_utc", "process", "artifacts", "outcome", "status"}
        require(set(terminal) == terminal_keys and terminal.get("terminal_version") == "runner-terminal.1", "unknown runner terminal version or fields")
        require(terminal.get("run_id") == plan["run_id"] and terminal.get("attempt_id") == plan["attempt_id"]
                and terminal.get("plan_sha256") == expected_sha, "terminal run/attempt/plan binding mismatch")
        intent_path = attempt / "intent.json"
        require(sha256_file(intent_path) == terminal["intent_sha256"], "attempt intent changed")
        intent = load_json(intent_path)
        for key in ("run_id", "attempt_id", "plan_sha256"):
            require(intent[key] == terminal[key], "intent/terminal " + key + " mismatch")
        require(intent["plan_path"] == str(Path(plan_path).resolve()), "intent plan locator mismatch")
        require(intent["parent_attempt_id"] == (plan["parent_attempt"] or {}).get("attempt_id"), "parent pointer mismatch")
        require(terminal["receipt_path"] == "receipt.json", "terminal receipt ownership mismatch")
        selected = Path(receipt_path).resolve() if receipt_path else attempt / "receipt.json"
        require(selected == attempt / "receipt.json", "receipt is not owned by selected attempt")
        require(sha256_file(selected) == terminal["receipt_sha256"], "receipt bytes changed after terminal publication")
        receipt = load_json(selected)
        source, runtime = observe_inputs(plan)
        check_parent(plan)
        schema = load_json(owned(plan["source"]["root"], "schemas/run-receipt.v3.json"))
        # Imported only here, via the already pinned verifier file, to share its
        # small JSON-Schema implementation without a dependency or module cycle.
        import importlib.util
        verifier_path = owned(plan["source"]["root"], "scripts/verify-profile.py")
        spec = importlib.util.spec_from_file_location("bounded_schema_validator", verifier_path)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        errors = verifier.validate(receipt, schema)
        require(not errors, "v3 receipt schema: " + "; ".join(errors[:4]))
        require(receipt["source"] == source, "receipt source provenance differs from observed/pinned source")
        require(receipt["runtime"] == runtime and receipt["tool"] == plan["tool"] and receipt["target"] == plan["target"],
                "receipt runtime/tool/target identity mismatch")
        for key in ("run_id", "attempt_id", "plan_sha256"):
            require(receipt[key] == terminal[key], "receipt " + key + " binding mismatch")
        require(receipt["parent_attempt_id"] == intent["parent_attempt_id"] and receipt["profile"] == plan["profile"],
                "receipt parent/profile mismatch")
        replacements = {"{python}": runtime["executable"], "{tool}": str(owned(plan["source"]["root"], plan["tool"]["path"])),
                        "{target}": str(attempt / "inputs" / "target.bin"), "{attempt}": str(attempt)}
        require(receipt["invocation"]["argv"] == [replacements.get(arg, arg) for arg in plan["execution"]["argv"]]
                and receipt["invocation"]["cwd"] == str(attempt / "work"), "observed invocation differs from frozen argv/cwd")
        require(receipt["invocation"]["artifact_root"] == str(attempt / "artifacts")
                and receipt["invocation"]["env_keys"] == ["DEBUGGER_PROBE_ARTIFACT_ROOT", "PYTHONDONTWRITEBYTECODE", "PYTHONUTF8"],
                "per-attempt artifact environment binding mismatch")
        require(receipt["limitations"] == LIMITS + plan["profile"]["limitations"], "receipt removes or changes frozen limitations")
        process = terminal["process"]
        require(strict_equal(receipt["execution"], process), "receipt execution contradicts runner terminal")
        require(process["timeout_s"] == plan["execution"]["timeout_s"], "timeout contract mismatch")
        if process["backend_executed"]:
            require(type(process["pid"]) is int and process["pid"] > 0 and type(process["observed_exit"]) is int,
                    "invalid runner PID/exit observation")
            require(type(process["started_ns"]) is int and type(process["cleanup_finished_ns"]) is int
                    and intent["created_ns"] <= process["started_ns"] <= process["cleanup_finished_ns"] <= terminal["published_ns"],
                    "intent/dispatch/cleanup/publication order invalid")
            require(receipt["completed_steps"] == plan["required_steps"], "required execution steps incomplete or reordered")
        else:
            require(process["pid"] is None and process["observed_exit"] is None and process["started_ns"] is None
                    and process["terminal_state"] in ("cancelled", "not_run") and process["cleanup"]["scope"] == "no-child"
                    and process["cleanup"]["status"] == "not_applicable", "unstarted attempt contradicts process observations")
            require("dispatch" not in receipt["completed_steps"] and "collect" not in receipt["completed_steps"],
                    "unstarted attempt claims dispatch or collection")
            require(type(process["cleanup_finished_ns"]) is int
                    and intent["created_ns"] <= process["cleanup_finished_ns"] <= terminal["published_ns"],
                    "unstarted attempt publication order invalid")
        require(process["cancelled"] is (process["terminal_state"] == "cancelled"), "cancellation state mismatch")
        require(strict_equal(receipt["artifacts"], terminal["artifacts"]), "receipt artifact inventory differs from runner")
        check_inventory(attempt, terminal["artifacts"])
        check_identity(attempt / "inputs" / "target.bin", plan["target"], "retained input target")
        ids = [row["id"] for row in receipt["checks"]]
        require(ids == plan["required_case_ids"] and len(ids) == len(set(ids)), "receipt required checks missing, duplicate or reordered")
        require(receipt["result"]["required_case_ids"] == plan["required_case_ids"]
                and type(receipt["result"]["checks_total"]) is int and receipt["result"]["checks_total"] == plan["checks_total"],
                "receipt denominator differs from pre-run plan")
        rows = evaluate_checks(oracle, attempt, process, plan["outputs"])
        report["check_results"] = rows
        require(receipt["checks"] == rows, "receipt checks differ from recomputed output assertions")
        verdict = outcome(process, rows, receipt["problems"])
        require(receipt["result"]["verdict"] == verdict and terminal["outcome"] == verdict, "declared verdict differs from recomputed verdict")
        require(terminal["status"] == ("complete" if verdict in ("PROFILE_PASS", "PROFILE_FAIL") else "incomplete"),
                "terminal completeness contradicts process outcome")
        report["verdict"] = verdict
        report["reasons"] = [row["id"] + ": " + row["detail"] for row in rows if row["status"] != "passed"] + receipt["problems"]
        if verdict == "PROFILE_PASS":
            report["reasons"].append("caller-pinned plan, observed CLI terminal, cleanup, input identities and all selected checks agree")
        report["provenance_kind"] = source["commit_observation"]
        report["limitations"] = receipt["limitations"]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        report["reasons"].append(type(exc).__name__ + ": " + str(exc))
    return report
