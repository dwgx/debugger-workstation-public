#!/usr/bin/env python3
"""Bounded raw MCP stdio client for offline provider acceptance.

Corrections vs. the prior harness (see changed-harness.diff):
  * read_id uses a dedicated reader thread + queue.Queue.get(timeout=...).
    The prior version called blocking stdout.readline() inside a
    time.monotonic() loop, which CANNOT time out when no line arrives;
    the deadline was checked only after readline returned. A real timeout
    now fires while the provider process is still alive.
  * Create the owned process SUSPENDED, assign a non-breakaway Job Object,
    verify actual membership, then resume its sole primary thread. Nothing
    in the launched command executes during the Popen-to-assignment gap.
  * close() retains handles to observed processes, records Job membership,
    terminates the Job and observes ActiveProcesses == 0 before closing its
    handle. Retained process handles detect orphans without an ancestor chain.
  * Process-observation failure is UNKNOWN/error, never an empty population.

No PATH guessing, no installs, no global config changes.
"""
import json
import ctypes
from ctypes import wintypes
import os
import queue
import subprocess
import sys
import threading
import time

CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004

# This Windows acceptance harness requires pywin32; absence fails closed.
try:
    import win32api
    import win32con
    import win32job
    import win32event
    import win32process
    _HAS_JOB = True
except Exception:
    _HAS_JOB = False


def now_utc():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def snap_all():
    """Bounded snapshot. Collection/parse failures are not evidence of zero."""
    ps = (
        "$ErrorActionPreference='Stop'; "
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
        "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,"
        "Name,CreationDate,CommandLine | ConvertTo-Json -Compress"
    )
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="strict", timeout=8.0, check=True)
    out = r.stdout.strip()
    if not out:
        raise RuntimeError("process snapshot returned no data")
    data = json.loads(out)
    data = data if isinstance(data, list) else [data]
    if not data or any(not isinstance(p, dict) or "ProcessId" not in p for p in data):
        raise RuntimeError("process snapshot returned an invalid population")
    return data


def snap_tree(root_pid, all_procs=None):
    """Return processes whose ancestor chain includes root_pid (inclusive)."""
    procs = all_procs if all_procs is not None else snap_all()
    by_pid = {}
    for p in procs:
        try:
            by_pid[int(p["ProcessId"])] = p
        except Exception:
            continue
    result = []
    for pid in by_pid:
        cur, seen = pid, set()
        while cur and cur not in seen:
            if cur == root_pid:
                result.append(by_pid[pid])
                break
            seen.add(cur)
            parent = by_pid.get(cur)
            try:
                cur = int(parent["ParentProcessId"]) if parent else 0
            except Exception:
                cur = 0
    return result


def pid_alive(pid):
    """Observation errors propagate; this helper is not identity-sensitive."""
    return any(int(p.get("ProcessId") or 0) == int(pid) for p in snap_all())


def open_suspended_primary_thread(pid):
    """Open only the single thread of our newly created suspended process."""
    class THREADENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
                    ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD)]
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for name in ("Thread32First", "Thread32Next"):
        fn = getattr(k32, name)
        fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
        fn.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    snapshot = k32.CreateToolhelp32Snapshot(0x00000004, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    tids = []
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k32.Thread32First(snapshot, ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID == pid:
                tids.append(int(entry.th32ThreadID))
            ok = k32.Thread32Next(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        k32.CloseHandle(snapshot)
    if len(tids) != 1:
        raise RuntimeError("suspended owned process has %s threads, expected 1" % len(tids))
    return win32api.OpenThread(0x0002, False, tids[0]), tids[0]


def job_observation(job):
    return {"pids": list(win32job.QueryInformationJobObject(
                job, win32job.JobObjectBasicProcessIdList)),
            "accounting": win32job.QueryInformationJobObject(
                job, win32job.JobObjectBasicAccountingInformation)}


class RawMcp:
    def __init__(self, cmd, cwd, env, timeout=40.0, tag=""):
        self.cmd = cmd
        self.cwd = cwd
        self.env = env
        self.timeout = timeout
        self.tag = tag
        self.proc = None
        self.req = []
        self.res = []
        self.stderr_chunks = []
        self._next_id = 1
        self._q = None
        self._reader = None
        self._job = None
        self._job_supported = False
        self._job_note = None
        self.start_observation = {}

    def start(self):
        if not _HAS_JOB:
            raise RuntimeError("pywin32 Job Object support required; launch refused")
        flags = CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW | CREATE_SUSPENDED
        self.proc = subprocess.Popen(
            self.cmd, cwd=self.cwd, env=self.env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=flags, bufsize=0,
        )
        thread = None
        try:
            thread, tid = open_suspended_primary_thread(self.proc.pid)
            self._assign_job()
            membership = job_observation(self._job)
            if self.proc.pid not in membership["pids"]:
                raise RuntimeError("owned suspended process missing from assigned Job")
            previous_suspend_count = win32process.ResumeThread(thread)
            if previous_suspend_count != 1:
                raise RuntimeError("unexpected primary-thread suspend count: %r" % previous_suspend_count)
            self.start_observation = {
                "creation_flags": flags, "primary_thread_id": tid,
                "membership_before_resume": membership,
                "resume_previous_suspend_count": previous_suspend_count,
                "order": ["create_suspended", "assign_job", "query_membership", "resume_thread"],
            }
        except BaseException:
            if self._job:
                win32job.TerminateJobObject(self._job, 1)
                win32api.CloseHandle(self._job)
                self._job = None
            if self.proc.poll() is None:
                self.proc.kill()  # only the just-created owned process
            self.proc.wait(timeout=3.0)
            raise
        finally:
            if thread:
                win32api.CloseHandle(thread)
        self._q = queue.Queue()
        self._reader = threading.Thread(target=self._stdout_reader, daemon=True)
        self._reader.start()
        self._stderr_t = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_t.start()
        return self

    def _assign_job(self):
        job = None
        try:
            job = win32job.CreateJobObject(None, "")
            info = win32job.QueryInformationJobObject(
                job, win32job.JobObjectExtendedLimitInformation)
            info["BasicLimitInformation"]["LimitFlags"] |= (
                win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
            win32job.SetInformationJobObject(
                job, win32job.JobObjectExtendedLimitInformation, info)
            # Popen's retained handle identifies this exact process, not a reused PID.
            win32job.AssignProcessToJobObject(job, int(self.proc._handle))
            self._job = job
            self._job_supported = True
            self._job_note = "KILL_ON_JOB_CLOSE Job Object assigned while primary thread suspended"
        except Exception as e:
            self._job_note = "Job Object assignment failed: %r" % (e,)
            try:
                if job:
                    win32api.CloseHandle(job)
            except Exception:
                pass
            raise

    def _stdout_reader(self):
        try:
            for raw in iter(self.proc.stdout.readline, b""):
                text = raw.decode("utf-8", "replace").rstrip("\r\n")
                self._q.put({"t": now_utc(), "raw": text, "bytes": len(raw)})
        finally:
            self._q.put(None)  # EOF sentinel

    def _drain_stderr(self):
        while True:
            b = self.proc.stderr.read(1)
            if not b:
                break
            self.stderr_chunks.append(b)

    def send(self, method, params=None, notify=False, timeout=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            msg["id"] = self._next_id
            self._next_id += 1
        line = json.dumps(msg, ensure_ascii=False, separators=(",", ":"))
        self.req.append({"t": now_utc(), "raw": line})
        try:
            self.proc.stdin.write((line + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise RuntimeError("stdin write failed: %r" % (e,))
        if not notify:
            return self.read_id(msg["id"], timeout=timeout)

    def read_id(self, want_id, timeout=None):
        """Real bounded read: blocks on Queue.get(timeout), not on readline.

        Records raw lines as they arrive (including interleaved notifications)
        and returns the first JSON-RPC message with the requested id. Raises
        TimeoutError on deadline expiry even if the process is still alive.
        """
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "no response for id=%s within %.3fs (process alive=%s)"
                    % (want_id, self.timeout if timeout is None else timeout,
                       self.proc.poll() is None))
            try:
                item = self._q.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError(
                    "no response for id=%s within %.3fs (process alive=%s)"
                    % (want_id, self.timeout if timeout is None else timeout,
                       self.proc.poll() is None))
            if item is None:
                raise EOFError("provider stdout closed before id=%s" % want_id)
            self.res.append({"t": item["t"], "raw": item["raw"]})
            try:
                obj = json.loads(item["raw"])
            except Exception:
                continue
            if obj.get("id") == want_id:
                return obj

    def initialize(self, client_name="ws-advisor-probe", protocol="2025-11-25"):
        r = self.send("initialize", {
            "protocolVersion": protocol,
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "1.0.0"},
        })
        self.send("notifications/initialized", {}, notify=True)
        return r

    def close(self, grace=3.0):
        """Reclaim this Job and verify membership plus exact retained handles."""
        root_pid = self.proc.pid if self.proc else None
        rec = {
            "at": now_utc(), "pid": root_pid,
            "job_supported": self._job_supported, "job_note": self._job_note,
            "start_observation": self.start_observation,
            "observation_errors": [], "retained_identities": [],
        }
        before, after, held = [], [], {}

        def observe(label, fn):
            try:
                return fn()
            except Exception as e:
                rec["observation_errors"].append({"stage": label, "error": repr(e)})
                return None

        all_before = observe("snapshot_before", snap_all)
        if all_before is not None:
            before = snap_tree(root_pid, all_before)
        rec["tree_before_close"] = before
        membership = observe("job_before", lambda: job_observation(self._job))
        rec["job_before_close"] = membership
        seen_pids = {int(p["ProcessId"]) for p in before}
        if membership is not None:
            seen_pids.update(membership["pids"])
        for pid in sorted(seen_pids):
            h = None
            try:
                h = win32api.OpenProcess(0x1000 | 0x00100000, False, pid)
                identity = {"pid": pid, "creation_time": str(
                    win32process.GetProcessTimes(h)["CreationTime"])}
                held[pid] = h
                rec["retained_identities"].append(identity)
            except Exception as e:
                if h is not None and pid not in held:
                    win32api.CloseHandle(h)
                rec["observation_errors"].append({
                    "stage": "retain_identity", "pid": pid, "error": repr(e)})
        try:
            if self.proc and self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except Exception as e:
            rec["observation_errors"].append({"stage": "close_stdin", "error": repr(e)})
        if self.proc:
            try:
                self.proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass
            rec["root_exit_before_job_terminate"] = self.proc.poll()
        # Also reclaim descendants when the wrapper itself exited gracefully.
        if self._job:
            try:
                win32job.TerminateJobObject(self._job, 1)
                rec["job_terminate_called"] = True
                deadline = time.monotonic() + grace
                while True:
                    last = job_observation(self._job)
                    if last["accounting"]["ActiveProcesses"] == 0 or time.monotonic() >= deadline:
                        break
                    time.sleep(0.02)
                rec["job_after_terminate"] = last
            except Exception as e:
                rec["observation_errors"].append({"stage": "terminate_job", "error": repr(e)})
            finally:
                win32api.CloseHandle(self._job)
                self._job = None
        if self.proc:
            try:
                self.proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=grace)
                rec["observation_errors"].append({"stage": "root_fallback_kill"})
            rec["returncode"] = self.proc.returncode
        try:
            self._reader.join(timeout=2)
            self._stderr_t.join(timeout=2)
            if self._reader.is_alive() or self._stderr_t.is_alive():
                raise RuntimeError("owned pipe reader thread remained alive after Job teardown")
        except Exception as e:
            rec["observation_errors"].append({"stage": "reader_join", "error": repr(e)})
        rec["stderr_bytes"] = sum(len(x) for x in self.stderr_chunks)
        rec["stderr"] = b"".join(self.stderr_chunks).decode("utf-8", "replace")
        rec["survivor_pids"] = []
        handle_deadline = time.monotonic() + grace
        rec["retained_handle_wait_budget_seconds"] = grace
        for pid, h in held.items():
            try:
                wait_ms = max(0, int((handle_deadline - time.monotonic()) * 1000))
                state = win32event.WaitForSingleObject(h, wait_ms)
                if state != win32event.WAIT_OBJECT_0:
                    rec["survivor_pids"].append(pid)
            except Exception as e:
                rec["observation_errors"].append({"stage": "retained_handle_wait", "pid": pid, "error": repr(e)})
            finally:
                win32api.CloseHandle(h)
        all_after = observe("snapshot_after", snap_all)
        if all_after is not None:
            after = snap_tree(root_pid, all_after)
        rec["snapshot_after_status"] = "observed" if all_after is not None else "UNKNOWN"
        rec["tree_after_close"] = after
        # Additional global identity comparison detects a known orphan even
        # if its ancestors exited and PID reuse occurred elsewhere.
        seen_identity = {(int(p["ProcessId"]), str(p.get("CreationDate"))) for p in before}
        rec["known_snapshot_survivors"] = [
            {"pid": int(p["ProcessId"]), "creation_time": str(p.get("CreationDate"))}
            for p in (all_after or [])
            if (int(p["ProcessId"]), str(p.get("CreationDate"))) in seen_identity]
        rec["tree_empty_after_close"] = all_after is not None and len(after) == 0
        rec["observed_cleanup_ok"] = (
            rec.get("returncode") is not None and rec["tree_empty_after_close"]
            and not rec["survivor_pids"] and not rec["known_snapshot_survivors"]
            and rec.get("job_after_terminate", {}).get("accounting", {}).get("ActiveProcesses") == 0
            and not rec["observation_errors"]
        )
        return rec

