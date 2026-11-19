#!/usr/bin/env python3
"""Inventory every manifest tool; optionally run bounded, explicit CLI version probes.

Inventory is not execution or acceptance. GUI entries, libraries and source files
remain presence-only. No target sample, GUI, driver, network service or installer
is started. --probe executes only the reviewed PROBES table below, without a shell.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_LIMIT = 1024 * 1024
PROBES = {
    "capa": (["--version"], r"capa(?:\.exe)?\s+(\d+\.\d+\S*)"),
    "FLOSS": (["--version"], r"floss(?:\.exe)?\s+v?(\d+\.\d+\S*)"),
    "YARA-X": (["--version"], r"yara-x-cli\s+(\d+\.\d+\S*)"),
    "radare2": (["-v"], r"radare2\s+(\d+\.\d+\S*)"),
    "rabin2": (["-v"], r"rabin2\s+(\d+\.\d+\S*)"),
    "7-Zip full": ([], r"7-Zip\s+(\d+\.\d+\S*)"),
    "7-Zip extra": ([], r"7-Zip(?:\s+\(\w+\))?\s+(\d+\.\d+\S*)"),
    "UPX": (["-V"], r"upx\s+(\d+\.\d+\S*)"),
    "ilspycmd": (["--version"], r"ilspycmd:\s+(\d+\.\d+\S*)"),
    "Wireshark": (["--version"], r"(?:TShark|Wireshark).*?(\d+\.\d+\.\d+\S*)"),
    "Apktool": (["--version"], r"(?m)^\s*(\d+\.\d+\.\d+\S*)\s*$"),
    "AssetRipper": (["--version"], r"AssetRipper\.GUI\.Web\s+(\d+\.\d+\.\d+\S*)"),
}


class WindowsJob:
    """Own a suspended process before it can create descendants (stdlib only)."""
    def __init__(self):
        from ctypes import wintypes as w
        size = ctypes.c_size_t
        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                        ("flags", w.DWORD), ("min_ws", size), ("max_ws", size),
                        ("active_limit", w.DWORD), ("affinity", size),
                        ("priority", w.DWORD), ("scheduling", w.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("read_ops", "write_ops", "other_ops",
                                                     "read_bytes", "write_bytes", "other_bytes")]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", IO), ("process_memory", size),
                        ("job_memory", size), ("peak_process", size), ("peak_job", size)]
        class Accounting(ctypes.Structure):
            _fields_ = [(n, ctypes.c_int64) for n in ("user", "kernel", "period_user", "period_kernel")] + [
                (n, w.DWORD) for n in ("faults", "total", "active", "terminated")]
        self.Accounting = Accounting
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        specs = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "IsProcessInJob": ([w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "CreateToolhelp32Snapshot": ([w.DWORD, w.DWORD], w.HANDLE),
            "OpenThread": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "ResumeThread": ([w.HANDLE], w.DWORD),
            "OpenProcess": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
        }
        for name, (args, restype) in specs.items():
            fn = getattr(self.k, name); fn.argtypes = args; fn.restype = restype
        self.handle = self.k.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = Extended(); info.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE
        try:
            self.check(self.k.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)))
        except BaseException:
            self.close(); raise

    @staticmethod
    def check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def attach_and_resume(self, proc):
        from ctypes import wintypes as w
        self.check(self.k.AssignProcessToJobObject(self.handle, int(proc._handle)))
        member = w.BOOL()
        self.check(self.k.IsProcessInJob(int(proc._handle), self.handle, ctypes.byref(member)))
        if not member.value:
            raise RuntimeError("process is not in its owned Job")
        class ThreadEntry(ctypes.Structure):
            _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("tid", w.DWORD),
                        ("pid", w.DWORD), ("priority", w.LONG), ("delta", w.LONG), ("flags", w.DWORD)]
        for name in ("Thread32First", "Thread32Next"):
            getattr(self.k, name).argtypes = [w.HANDLE, ctypes.POINTER(ThreadEntry)]
            getattr(self.k, name).restype = w.BOOL
        snapshot = self.k.CreateToolhelp32Snapshot(4, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        tids = []
        try:
            entry = ThreadEntry(); entry.size = ctypes.sizeof(entry)
            ok = self.k.Thread32First(snapshot, ctypes.byref(entry))
            while ok:
                if entry.pid == proc.pid:
                    tids.append(entry.tid)
                ok = self.k.Thread32Next(snapshot, ctypes.byref(entry))
            if ctypes.get_last_error() != 18:
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.k.CloseHandle(snapshot)
        if len(tids) != 1:
            raise RuntimeError("expected exactly one suspended primary thread")
        thread = self.k.OpenThread(2, False, tids[0])
        if not thread:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if self.k.ResumeThread(thread) != 1:
                raise RuntimeError("unexpected primary thread suspend count")
        finally:
            self.k.CloseHandle(thread)

    def terminate(self):
        # ActiveProcesses can reach zero before Windows finishes releasing files.
        # Retain exact owned process handles and wait for their termination signals.
        from ctypes import wintypes as w
        handles = []
        capacity = 32
        try:
            while True:
                buffer = ctypes.create_string_buffer(8 + ctypes.sizeof(ctypes.c_size_t) * capacity)
                if self.k.QueryInformationJobObject(self.handle, 3, buffer, len(buffer), None):
                    break
                if ctypes.get_last_error() != 234 or capacity >= 4096:
                    raise ctypes.WinError(ctypes.get_last_error())
                capacity *= 2
            count = w.DWORD.from_buffer(buffer, 4).value
            pids = (ctypes.c_size_t * count).from_buffer(buffer, 8)
            for pid in pids:
                handle = self.k.OpenProcess(0x00101000, False, pid)
                if not handle:
                    if ctypes.get_last_error() == 87:  # process already exited
                        continue
                    raise ctypes.WinError(ctypes.get_last_error())
                handles.append(handle)
                member = w.BOOL()
                self.check(self.k.IsProcessInJob(handle, self.handle, ctypes.byref(member)))
                if not member.value:
                    raise RuntimeError("observed process handle no longer belongs to the owned Job")
            self.check(self.k.TerminateJobObject(self.handle, 1))
            deadline = time.monotonic() + 3
            for handle in handles:
                remaining = max(1, int((deadline - time.monotonic()) * 1000))
                if self.k.WaitForSingleObject(handle, remaining) != 0:
                    raise RuntimeError("owned process did not signal termination")
        finally:
            for handle in handles:
                self.k.CloseHandle(handle)
        deadline = time.monotonic() + 3
        while True:
            info = self.Accounting()
            self.check(self.k.QueryInformationJobObject(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None))
            if info.active == 0:
                return {"kind": "windows-job", "active_processes": 0,
                        "process_handles_waited": len(handles)}
            if time.monotonic() >= deadline:
                raise RuntimeError("owned Job did not become empty")
            time.sleep(.02)

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle); self.handle = None


def run_probe(argv, timeout, cwd=None):
    """Capture a real process, keep both streams, bound time/output and own cleanup."""
    start = time.monotonic()
    result = {"argv": argv, "timeout_seconds": timeout, "exit_code": None,
              "timed_out": False, "output_limit_exceeded": False, "error": None}
    proc = job = None
    with tempfile.TemporaryDirectory(prefix="station-smoke-") as temp:
        output = Path(temp) / "stdout"; error = Path(temp) / "stderr"
        try:
            with output.open("wb") as stdout, error.open("wb") as stderr:
                if os.name == "nt":
                    job = WindowsJob()
                proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                        stdout=stdout, stderr=stderr,
                                        creationflags=0x08000204 if job else 0,
                                        start_new_session=(os.name != "nt"))
                result["pid"] = proc.pid
                if job:
                    job.attach_and_resume(proc)
                    result["launch_order"] = ["create_suspended", "assign_job", "verify_membership", "resume"]
                while proc.poll() is None:
                    if time.monotonic() - start >= timeout:
                        result["timed_out"] = True; break
                    if output.stat().st_size + error.stat().st_size > OUTPUT_LIMIT:
                        result["output_limit_exceeded"] = True; break
                    time.sleep(.02)
                result["exit_code"] = proc.poll()
        except (OSError, RuntimeError, ValueError) as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                if job:
                    result["cleanup"] = job.terminate()
                elif proc:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    result["cleanup"] = {"kind": "owned-posix-process-group", "signal": "SIGKILL"}
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                result["cleanup_error"] = f"{type(exc).__name__}: {exc}"
            finally:
                if proc:
                    try:
                        # Assignment may fail before membership. Even if Job observation
                        # fails, retain and reclaim this exact just-created process.
                        if proc.poll() is None:
                            proc.kill()
                        proc.wait(timeout=3)
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        result["cleanup_error"] = f"{type(exc).__name__}: {exc}"
                if job:
                    job.close()
        for name, path in (("stdout", output), ("stderr", error)):
            digest = hashlib.sha256(); size = 0; prefix = bytearray()
            if path.exists():
                with path.open("rb") as stream:
                    while chunk := stream.read(65536):
                        digest.update(chunk); size += len(chunk)
                        if len(prefix) < 65536:
                            prefix.extend(chunk[:65536 - len(prefix)])
            result[name] = prefix.decode("utf-8", errors="replace")
            result[name + "_bytes"] = size
            result[name + "_sha256"] = digest.hexdigest()
        result["output_limit_exceeded"] |= result["stdout_bytes"] + result["stderr_bytes"] > OUTPUT_LIMIT
    result["seconds"] = round(time.monotonic() - start, 3)
    return result


def judge(result, pattern):
    match = re.search(pattern, result.get("stdout", "") + "\n" + result.get("stderr", ""), re.I)
    ok = (result.get("exit_code") == 0 and not result.get("timed_out")
          and not result.get("output_limit_exceeded") and not result.get("error")
          and not result.get("cleanup_error") and match is not None)
    return {"status": "VERSION_VERIFIED" if ok else "PROBE_FAILED",
            "observed_version": match.group(1) if match else None,
            "declared_pin_accepted": False}


def expand_path(text):
    # Accept Windows-style placeholders even when inventory runs on another OS.
    text = re.sub(r"%([^%]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), text)
    return os.path.expanduser(os.path.expandvars(text))


def resolve_entry(root, tool):
    directory = expand_path(tool["dir"])
    if re.search(r"%[^%]+%|\$\{?\w+", directory):
        return None, "unresolved environment variable"
    if os.name != "nt" and PureWindowsPath(directory).is_absolute():
        return None, "Windows absolute path on a non-Windows host"
    base = Path(directory)
    if not base.is_absolute():
        base = root / base
    return base / tool["entry"] if tool.get("entry") else base, None


def inspect(root, manifest, selected, probe, timeout):
    data = json.loads(manifest.read_text(encoding="utf-8-sig"))
    items = [(category, tool) for category, tools in data["tools"].items() for tool in tools]
    names = [t["name"] for _, t in items]
    if len(names) != len(set(names)):
        raise ValueError("duplicate tool name in manifest")
    unknown = sorted(set(selected) - set(names))
    if unknown:
        raise ValueError("unknown tool selection: " + ", ".join(unknown))
    rows = []
    for category, tool in items:
        if selected and tool["name"] not in selected:
            continue
        path, reason = resolve_entry(root, tool)
        row = {"name": tool["name"], "category": category, "declared_version": tool.get("version"),
               "official_source": tool.get("official_source"), "path": str(path) if path else None,
               "status": "UNRESOLVED" if reason else "MISSING", "reason": reason,
               "probe_requested": bool(probe), "runtime_tested": False}
        if path and path.exists():
            row["status"] = "FILE_PRESENT" if path.is_file() else "DIRECTORY_PRESENT"
        plan = PROBES.get(tool["name"])
        if probe and plan and row["status"] == "FILE_PRESENT":
            args, pattern = plan
            argv = [str(path), *args]
            if path.suffix.lower() == ".jar":
                java = shutil.which("java")
                if not java:
                    row.update(status="BLOCKED", reason="java is not on PATH")
                    rows.append(row); continue
                argv = [java, "-jar", str(path), *args]
            elif os.name != "nt" and path.suffix.lower() == ".exe":
                row.update(status="BLOCKED", reason="Windows executable on a non-Windows host")
                rows.append(row); continue
            run = run_probe(argv, timeout)
            row.update(judge(run, pattern))
            row["runtime_tested"] = not bool(run.get("error"))
            row["probe"] = run
        elif probe and plan:
            row.update(status="BLOCKED", reason=reason or "declared executable is missing")
        elif probe:
            row["reason"] = "no reviewed automatic version probe; presence is not execution"
        rows.append(row)
    counts = {status: sum(r["status"] == status for r in rows) for status in sorted({r["status"] for r in rows})}
    failed = counts.get("PROBE_FAILED", 0)
    blocked = counts.get("BLOCKED", 0)
    code = 1 if failed else (2 if probe and blocked else 0)
    return {"schema": "station-tool-smoke.1", "at_utc": datetime.now(timezone.utc).isoformat(),
            "mode": "bounded-cli-probes" if probe else "inventory-only", "install_root": str(root),
            "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "summary": {"manifest_total": len(items), "selected": len(rows), "statuses": counts,
                        "version_verified": counts.get("VERSION_VERIFIED", 0),
                        "runtime_calls": sum(r["runtime_tested"] for r in rows),
                        "full_tool_acceptance": False}, "tools": rows, "exit_code": code}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-root", type=Path, default=ROOT)
    parser.add_argument("--manifest", type=Path, default=ROOT / "manifests/tools.json")
    parser.add_argument("--tool", action="append", default=[], help="exact manifest name; repeat to select")
    parser.add_argument("--probe", action="store_true", help="run reviewed CLI version flags; never launch a GUI or installer")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--report", type=Path, help="write a new JSON report; existing files are refused")
    args = parser.parse_args(argv)
    try:
        if not 0.05 <= args.timeout <= 120:
            raise ValueError("timeout must be between 0.05 and 120 seconds")
        if args.report and args.report.exists():
            raise ValueError("report already exists; choose a fresh output path")
        result = inspect(args.install_root.resolve(), args.manifest.resolve(), args.tool, args.probe, args.timeout)
        rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            with args.report.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
        if args.json:
            print(rendered, end="")
        else:
            for row in result["tools"]:
                print(f"{row['status']:18} {row['name']}: {row.get('observed_version') or row['reason'] or row['path']}")
            print("SUMMARY " + json.dumps(result["summary"], ensure_ascii=False))
            print("Version/presence checks only; full tool or demo acceptance is not asserted.")
        return result["exit_code"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"smoke-tools: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
