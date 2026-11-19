"""Router acceptance harness for WSA-EXECPACK-ROUTER-20261111 (round2: WSA-ROUND2-ROUTER-20261112).

Runs the fixed case suite against two builds of the router:

  OLD        tests/router_acceptance/old_server.py
             frozen snapshot of cead32200a692d454b354a84562f619db0de1ef0
             sha256 283873d4055498ff9ac755725816f3c736ce270426c212c0ed1f4e3ddb6b6f0d
  CANDIDATE  mcp/debugger-router/server.py (the minimal fix under review)

Two suites, selected with --suite:

  baseline (default)  the eleven original cases: five negative controls that must be RED
                      on OLD (the defect reproduces) and GREEN on CANDIDATE, and six
                      regression controls that must be GREEN on both builds.
  r2                  the round2 delta: four negative cases (R2-01 last startup waiter
                      cancelled, R2-02 startup ceiling vs longer call timeout, R2-03
                      in-flight cancel then blocked/timeout, R2-04 close caller
                      cancelled), the R2-05 shared-startup control, and two data-level
                      gate cases (R2-06 OLD RED needs its specified reason, R2-07 a
                      complete green payload cannot override a nonzero harness exit).

Transport: the real `mcp` stdio client drives an actual child process running the
offline fixture `fake_backend.py` (copied verbatim from the exec pack, sha256
75b089a64490e3ed79ece2462cf92694eeb5801e6fecf1d8b7d93361d92b1bd8). No network, no
samples, no GUI, no third-party tools. When the real SDK is not importable the harness
reports every case as not_run with SDK_MOCKED=YES -- it never fabricates a GREEN.

Each case gets a fresh module instance and a fresh fixture directory, so module-level
state (_SESSIONS, _OWNED, the shutdown flag) cannot leak between cases.

Usage:
    python -X utf8 -B tests/router_acceptance/acceptance_harness.py
    python -X utf8 -B tests/router_acceptance/acceptance_harness.py --case startup_deadline
    python -X utf8 -B tests/router_acceptance/acceptance_harness.py --suite r2
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import importlib.util
import json
import os
import shutil
import signal
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRODUCT_ROOT = Path(os.environ.get("ROUTER_PRODUCT_ROOT", str(HERE.parents[1]))).resolve()
OLD_SERVER = HERE / "old_server.py"
CANDIDATE_SERVER = PRODUCT_ROOT / "mcp" / "debugger-router" / "server.py"
BACKEND = HERE / "fake_backend.py"

OLD_SHA256 = "283873d4055498ff9ac755725816f3c736ce270426c212c0ed1f4e3ddb6b6f0d"
BACKEND_SHA256 = "75b089a64490e3ed79ece2462cf92694eeb5801e6fecf1d8b7d93361d92b1bd8"

# Startup ceiling the round2 cases configure, and the product's cleanup budget used only
# to bound how long a case observes convergence. Both are observation windows, not
# product knobs the harness may tighten to manufacture a GREEN.
STARTUP_CAP = 5.0
CLEANUP_BUDGET = 15.0

ENV_KEYS = (
    "ROUTER_AUDIT_CONTROL",
    "ROUTER_AUDIT_EVENTS",
    "ROUTER_AUDIT_MODE",
    "DEBUGGER_ROUTER_IDLE_TIMEOUT",
    "DEBUGGER_ROUTER_STARTUP_TIMEOUT",
)


def sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def sdk_available() -> bool:
    try:
        return importlib.util.find_spec("mcp") is not None
    except (ImportError, ValueError):
        return False


def sdk_version() -> str:
    try:
        import importlib.metadata as metadata

        return metadata.version("mcp")
    except Exception:  # noqa: BLE001 - reported, never fatal
        return "unknown"


def load_router(path: Path, label: str):
    """Import one router build under a unique module name (fresh module-level state)."""
    spec = importlib.util.spec_from_file_location(label, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load router module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _alive(pid: int) -> bool:
    """Liveness probe that is safe on Windows (os.kill(pid, 0) would terminate there)."""
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def _terminate(pid: int) -> None:
    """Kill one fixture pid recorded in this run's own event log (never by process name)."""
    if os.name != "nt":
        with suppress(ProcessLookupError):
            os.kill(pid, signal.SIGTERM)
        return
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
    if not handle:
        return
    try:
        kernel32.TerminateProcess(handle, 1)
    finally:
        kernel32.CloseHandle(handle)


def verdict(checks, **observed) -> dict:
    failed = [name for name, ok in checks if not ok]
    return {
        "green": not failed,
        "reason": "ok" if not failed else "failed: " + ", ".join(failed),
        "observed": observed,
    }


class Fixture:
    """One offline backend configuration plus its event log and release tokens."""

    def __init__(self, router, name: str, mode: str = "normal"):
        self.router = router
        self.name = name
        self.mode = mode
        self.root = Path(tempfile.mkdtemp(prefix=f"router-acc-{name}-"))
        self.control = self.root / "control"
        self.control.mkdir()
        self.events_path = self.root / "events.jsonl"
        self.events_path.write_text("")
        launcher = self.root / "fake.cmd"
        launcher.write_text(
            "@echo off\r\n"
            f'"{sys.executable}" -X utf8 -B "{BACKEND}" %*\r\n'
            "exit /b %ERRORLEVEL%\r\n"
        )
        self.config = self.root / "config.json"
        self.config.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "fake": {"command": str(launcher)},
                        "other": {"command": str(launcher)},
                    }
                }
            )
        )
        router.BACKEND_CONFIG = self.config
        self._saved_env = {key: os.environ.get(key) for key in ENV_KEYS}
        os.environ.update(
            {
                "ROUTER_AUDIT_CONTROL": str(self.control),
                "ROUTER_AUDIT_EVENTS": str(self.events_path),
                "ROUTER_AUDIT_MODE": mode,
                "DEBUGGER_ROUTER_IDLE_TIMEOUT": "0",
                # Only the hung-initialize cases need an explicit ceiling; leaving the
                # default in place everywhere else keeps the other cases unchanged.
                "DEBUGGER_ROUTER_STARTUP_TIMEOUT": f"{STARTUP_CAP:g}" if mode == "hold_initialize" else "30",
            }
        )
        self.sessions = []

    def events(self) -> list[dict]:
        items = []
        for line in self.events_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            with suppress(json.JSONDecodeError):
                items.append(json.loads(line))
        return items

    def spawned_pids(self) -> list[int]:
        return [item["pid"] for item in self.events() if item["event"] == "spawn"]

    def release(self, token: str) -> None:
        (self.control / token).touch()

    async def wait_event(self, event: str, timeout: float = 6.0, **fields) -> dict:
        async def found():
            while True:
                for item in self.events():
                    if item["event"] == event and all(item.get(k) == v for k, v in fields.items()):
                        return item
                await asyncio.sleep(0.01)

        return await asyncio.wait_for(found(), timeout)

    async def stop(self) -> None:
        with suppress(Exception):
            for item in self.events():
                if item["event"] == "waiting":
                    self.release(item["token"])
        unique = {}
        owned = list(getattr(self.router, "_OWNED", ()))
        for session in list(self.sessions) + list(self.router._SESSIONS.values()) + owned:
            unique[id(session)] = session
        for session in unique.values():
            if not session._task.done():
                session._task.cancel()
        for session in unique.values():
            with suppress(BaseException):
                await asyncio.wait_for(session._task, 8.0)
        self.router._SESSIONS.clear()
        await asyncio.sleep(0.2)
        for pid in self.spawned_pids():
            if _alive(pid):
                _terminate(pid)
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        await asyncio.sleep(0.2)
        shutil.rmtree(self.root, ignore_errors=True)


async def call(router, sid: str, action: str = "echo", timeout: float = 5.0, **arguments):
    result = await router.call_backend_tool(
        "fake",
        "audit",
        json.dumps({"action": action, **arguments}),
        timeout_seconds=timeout,
        session_id=sid,
    )
    return result, json.loads(result["content"][0]["text"])


async def wait_until(predicate, timeout: float = 6.0) -> None:
    async def wait():
        while not predicate():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(wait(), timeout)


# --------------------------------------------------------------------------- cases


async def case_queued_cancellation(router, fixture: Fixture) -> dict:
    """A caller that cancels while its request is still queued must not mutate anything."""
    first = asyncio.create_task(call(router, "queue", "hold", token="release-first", mark="first"))
    tasks = [first]
    try:
        await fixture.wait_event("waiting", token="release-first")
        second = asyncio.create_task(
            call(router, "queue", "set_target", target="cancelled-target", mark="cancelled-queued-mutation")
        )
        tasks.append(second)
        session = router._SESSIONS["queue"]
        await wait_until(lambda: session._queue.qsize() == 1)
        second.cancel()
        with suppress(asyncio.CancelledError):
            await second
        caller_cancelled = second.cancelled()
        fixture.release("release-first")
        await first
        _, barrier = await call(router, "queue", mark="after-cancel-barrier")
        events = fixture.events()
        touched = [item for item in events if item.get("mark") == "cancelled-queued-mutation"]
        return verdict(
            [
                ("caller_cancellation_propagated", caller_cancelled),
                ("queued_operation_not_executed", not touched),
                ("backend_state_unchanged", barrier["target"] is None),
            ],
            queued_mutation_events=len(touched),
            backend_target_after_cancel=barrier["target"],
        )
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        for task in tasks:
            with suppress(BaseException):
                await asyncio.wait_for(task, 5.0)


async def case_close_active_future(router, fixture: Fixture) -> dict:
    """close_backend_session must terminate the caller that was in flight."""
    request = asyncio.create_task(
        call(router, "close-active", "hold", token="never-release", timeout=60.0, mark="active-during-close")
    )
    try:
        waiting = await fixture.wait_event("waiting", token="never-release")
        session = router._SESSIONS["close-active"]
        fixture.sessions.append(session)
        started = time.monotonic()
        close_result = await asyncio.wait_for(router.close_backend_session("close-active"), 25)
        elapsed = time.monotonic() - started
        await asyncio.sleep(0.1)
        terminated = request.done()
        error = request.exception() if terminated and not request.cancelled() else None
        return verdict(
            [
                ("close_reported_one_session", close_result.get("closed_count") == 1),
                ("close_returned_within_budget", elapsed < 20.0),
                ("supervisor_finished", session._task.done()),
                ("active_request_terminated", terminated),
                ("active_request_failed_not_hung", isinstance(error, RuntimeError)),
            ],
            close_elapsed_seconds=round(elapsed, 3),
            close_result=close_result,
            request_state="done" if terminated else "pending",
            error=str(error),
            child_alive_after_close=_alive(waiting["pid"]),
        )
    finally:
        if not request.done():
            request.cancel()
        with suppress(BaseException):
            await asyncio.wait_for(request, 5.0)


async def case_closeall_registry_race(router, fixture: Fixture) -> dict:
    """close-all must not unregister a replacement created under the same session_id."""
    await router.open_backend_session("fake", "A", idle_timeout_seconds=0)
    await router.open_backend_session("fake", "B", idle_timeout_seconds=0)
    old_a, old_b = router._SESSIONS["A"], router._SESSIONS["B"]
    fixture.sessions += [old_a, old_b]
    held = asyncio.create_task(call(router, "A", "hold", token="release-A", timeout=60, mark="A-held"))
    tasks = [held]
    try:
        await fixture.wait_event("waiting", token="release-A")
        closing = asyncio.create_task(router.close_backend_session("*"))
        tasks.append(closing)
        await wait_until(lambda: "A" not in router._SESSIONS and old_a.close_reason is not None)
        await router.close_backend_session("B")
        _, new_b_data = await call(router, "B", mark="replacement-B")
        new_b = router._SESSIONS.get("B")
        fixture.release("release-A")
        await held
        close_result = await closing
        listed = await router.list_backend_sessions()
        replacement_kept = (
            new_b is not None
            and new_b is not old_b
            and router._SESSIONS.get("B") is new_b
            and new_b.alive
        )
        _, reused = await call(router, "B", mark="reuse-B")
        no_duplicate_process = reused["pid"] == new_b_data["pid"]
        async with router._router_lifespan(None):
            pass
        lifespan_closed = (not new_b.alive) and ("B" not in router._SESSIONS)
        child_reaped = not _alive(new_b_data["pid"])
        post_shutdown_error = None
        try:
            await call(router, "B", mark="post-shutdown")
        except RuntimeError as exc:
            post_shutdown_error = str(exc)
        shutdown_converged = post_shutdown_error is not None and "shutting down" in post_shutdown_error
        return verdict(
            [
                ("replacement_still_registered", replacement_kept),
                ("listed_sessions_match_registry", listed["count"] == 1),
                ("same_id_reuses_replacement", no_duplicate_process),
                ("lifespan_closed_replacement", lifespan_closed),
                ("replacement_child_reaped", child_reaped),
                ("shutdown_refuses_new_session", shutdown_converged),
            ],
            closeall_result=close_result,
            listed_sessions_after_close=listed["count"],
            replacement_pid=new_b_data["pid"],
            reused_pid=reused["pid"],
            post_shutdown_error=post_shutdown_error,
        )
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        for task in tasks:
            with suppress(BaseException):
                await asyncio.wait_for(task, 5.0)


async def case_startup_deadline(router, fixture: Fixture) -> dict:
    """A hung initialize must be cut off at the caller's deadline and the child reaped."""
    started = time.monotonic()
    task = asyncio.create_task(
        router.list_backend_tools("fake", timeout_seconds=5.0, session_id="init-hang", close_after=True)
    )
    try:
        await fixture.wait_event("initialize")
        # The 5s deadline plus process teardown has to finish inside this window.
        with suppress(BaseException):
            await asyncio.wait_for(asyncio.shield(task), 9.0)
        terminated = task.done()
        error = task.exception() if terminated and not task.cancelled() else None
        elapsed = time.monotonic() - started
        if not terminated:
            task.cancel()
            with suppress(BaseException):
                await asyncio.wait_for(task, 5.0)
        await asyncio.sleep(0.5)
        spawn = next((item["pid"] for item in fixture.events() if item["event"] == "spawn"), None)
        registered = "init-hang" in router._SESSIONS
        child_alive = _alive(spawn) if spawn else None
        return verdict(
            [
                ("startup_wait_terminated", terminated),
                ("startup_failed_with_runtime_error", isinstance(error, RuntimeError)),
                ("startup_error_names_failure", error is not None and "failed to start" in str(error)),
                ("deadline_respected", terminated and elapsed <= 9.0),
                ("hung_session_unregistered", not registered),
                ("hung_child_reaped", child_alive is False),
            ],
            elapsed_seconds=round(elapsed, 3),
            error=str(error),
            child_pid=spawn,
            child_alive_after_deadline=child_alive,
        )
    finally:
        if not task.done():
            task.cancel()
            with suppress(BaseException):
                await asyncio.wait_for(task, 5.0)


async def case_active_cancellation(router, fixture: Fixture) -> dict:
    """Cancelling an in-flight call must not leave a silently reusable warm session."""
    task = asyncio.create_task(
        call(router, "active", "hold", token="release-active", target="mutation-after-cancel", mark="active-mutation")
    )
    try:
        waiting = await fixture.wait_event("waiting", token="release-active")
        session = router._SESSIONS["active"]
        fixture.sessions.append(session)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        caller_cancelled = task.cancelled()
        fixture.release("release-active")
        with suppress(asyncio.TimeoutError):
            await wait_until(lambda: session._task.done(), timeout=8.0)
        _, after = await call(router, "active")
        starts = [
            item
            for item in fixture.events()
            if item.get("mark") == "active-mutation" and item["event"] == "call_start"
        ]
        return verdict(
            [
                ("caller_cancellation_propagated", caller_cancelled),
                ("cancelled_session_retired", not session.alive),
                ("outcome_marked_unknown", getattr(session, "outcome_unknown", 0) == 1),
                ("close_reason_names_outcome_unknown", "outcome unknown" in (session.close_reason or "").lower()),
                ("no_silent_warm_reuse", after["pid"] != waiting["pid"]),
                ("fresh_process_has_clean_state", after["target"] is None),
                ("mutation_not_replayed", len(starts) == 1),
            ],
            first_pid=waiting["pid"],
            new_pid=after["pid"],
            outcome_unknown=getattr(session, "outcome_unknown", 0),
            close_reason=session.close_reason,
            mutation_dispatches=len(starts),
            backend_target_after_cancel=after["target"],
        )
    finally:
        if not task.done():
            task.cancel()
            with suppress(BaseException):
                await asyncio.wait_for(task, 5.0)


async def case_warm_session_single_process(router, fixture: Fixture) -> dict:
    """Twelve concurrent callers on one session_id create exactly one process."""
    batch = await asyncio.gather(*(call(router, "same-create-id", mark=f"concurrent-{i}") for i in range(12)))
    pids = {item[1]["pid"] for item in batch}
    created = sum(1 for item in batch if not item[0]["session_reused"])
    return verdict(
        [
            ("one_process_for_twelve_callers", len(pids) == 1),
            ("exactly_one_creation", created == 1),
        ],
        concurrent_callers=12,
        distinct_pids=len(pids),
        creations=created,
    )


async def case_state_continuity(router, fixture: Fixture) -> dict:
    """A warm session keeps its state across calls."""
    _, first = await call(router, "state-A", "set_target", target="target-A")
    _, second = await call(router, "state-A")
    return verdict(
        [
            ("same_process_reused", second["pid"] == first["pid"]),
            ("state_persisted", second["target"] == "target-A"),
        ],
        pid=second["pid"],
        target_after_second_call=second["target"],
    )


async def case_cross_id_isolation(router, fixture: Fixture) -> dict:
    """Different session ids are different processes with independent state."""
    _, first = await call(router, "state-A", "set_target", target="target-A")
    _, other = await call(router, "state-B")
    return verdict(
        [
            ("separate_process", other["pid"] != first["pid"]),
            ("separate_state", other["target"] is None),
        ],
        pid_a=first["pid"],
        pid_b=other["pid"],
        target_b=other["target"],
    )


async def case_backend_conflict_reject(router, fixture: Fixture) -> dict:
    """A session_id already owned by another backend must be rejected."""
    await call(router, "state-A")
    conflict = None
    try:
        await router.open_backend_session("other", "state-A")
    except ValueError as exc:
        conflict = str(exc)
    return verdict(
        [("conflict_rejected", conflict is not None and "belongs to backend" in conflict)],
        conflict=conflict,
    )


async def case_timeout_cleanup(router, fixture: Fixture) -> dict:
    """A normal call timeout fails the call and the queued follower, then reclaims."""
    first = asyncio.create_task(
        call(router, "timeout", "hold", token="never-release", timeout=5.0, mark="timed-out")
    )
    tasks = [first]
    try:
        waiting = await fixture.wait_event("waiting", token="never-release")
        session = router._SESSIONS["timeout"]
        fixture.sessions.append(session)
        second = asyncio.create_task(call(router, "timeout", mark="pending-after-timeout"))
        tasks.append(second)
        outcomes = await asyncio.wait_for(asyncio.gather(first, second, return_exceptions=True), 20)
        with suppress(asyncio.TimeoutError):
            await wait_until(lambda: session._task.done() and not _alive(waiting["pid"]), timeout=10.0)
        queued_executed = any(
            item.get("mark") == "pending-after-timeout" for item in fixture.events()
        )
        unregistered = "timeout" not in router._SESSIONS
        _, replacement = await call(router, "timeout")
        return verdict(
            [
                ("both_callers_failed", all(isinstance(item, RuntimeError) for item in outcomes)),
                ("queued_request_failed_without_execution", not queued_executed),
                ("session_unregistered", unregistered),
                ("child_reaped", not _alive(waiting["pid"])),
                ("replacement_is_fresh", replacement["pid"] != waiting["pid"] and replacement["target"] is None),
            ],
            errors=[str(item) for item in outcomes],
            timed_out_pid=waiting["pid"],
            replacement_pid=replacement["pid"],
        )
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        for task in tasks:
            with suppress(BaseException):
                await asyncio.wait_for(task, 5.0)


async def case_idle_reclaim(router, fixture: Fixture) -> dict:
    """An idle warm session is reclaimed by the idle timer."""
    await router.open_backend_session("fake", "idle", idle_timeout_seconds=0.15)
    session = router._SESSIONS["idle"]
    fixture.sessions.append(session)
    with suppress(asyncio.TimeoutError):
        await wait_until(lambda: session._task.done() and "idle" not in router._SESSIONS, timeout=10.0)
    return verdict(
        [
            ("idle_session_reclaimed", session._task.done() and "idle" not in router._SESSIONS),
            ("reclaim_reason_recorded", "idle for" in (session.close_reason or "")),
        ],
        close_reason=session.close_reason,
    )


# --------------------------------------------------------------- round2 delta cases
#
# One function per round2 contract item. Each process-level case reproduces the
# counterexample on OLD (frozen cead322) and must be GREEN on the candidate; the two
# data-level gate cases check the acceptance gate itself. R2_OLD_RED_SPEC fixes the
# failure class (a behavioural `failed:` list, never a setup/driver exception) and the
# minimum failed checks that identify each counterexample.


async def _settled(session, seconds: float) -> bool:
    """True once the supervisor task is done, checked at a bounded monotonic deadline."""
    with suppress(asyncio.TimeoutError):
        await wait_until(lambda: session._task.done(), timeout=seconds)
    return session._task.done()


async def r2_case_startup_last_waiter(router, fixture: Fixture) -> dict:
    """R2-01: the startup deadline must survive the last startup waiter being cancelled."""
    started = time.monotonic()
    task = asyncio.create_task(
        router.list_backend_tools("fake", timeout_seconds=12.0, session_id="r2-last-waiter", close_after=True)
    )
    try:
        await fixture.wait_event("initialize")
        session = router._SESSIONS["r2-last-waiter"]
        fixture.sessions.append(session)
        spawn = next((item["pid"] for item in fixture.events() if item["event"] == "spawn"), None)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        caller_cancelled = task.cancelled()
        # No caller is left to hold a timer: only the supervisor's own bound remains.
        converged = await _settled(session, STARTUP_CAP + CLEANUP_BUDGET + 1.0)
        elapsed = time.monotonic() - started
        await asyncio.sleep(0.3)
        child_alive = _alive(spawn) if spawn else None
        return verdict(
            [
                ("caller_cancellation_propagated", caller_cancelled),
                ("supervisor_converged_within_budget", converged),
                ("terminal_state_recorded", "startup" in (session.close_reason or "")),
                ("child_reaped", child_alive is False),
                ("never_ready", session._initialized is False),
            ],
            elapsed_seconds=round(elapsed, 3),
            close_reason=session.close_reason,
            child_pid=spawn,
            child_alive_after_budget=child_alive,
        )
    finally:
        if not task.done():
            task.cancel()
            with suppress(BaseException):
                await asyncio.wait_for(task, 5.0)


async def r2_case_startup_ceiling(router, fixture: Fixture) -> dict:
    """R2-02: a longer per-call timeout must not extend the configured startup ceiling."""
    started = time.monotonic()
    task = asyncio.create_task(
        router.list_backend_tools("fake", timeout_seconds=12.0, session_id="r2-ceiling", close_after=True)
    )
    try:
        await fixture.wait_event("initialize")
        spawn = next((item["pid"] for item in fixture.events() if item["event"] == "spawn"), None)
        # The call asked for 12s; the configured ceiling is STARTUP_CAP, so this bound
        # is already generous and anything past it is the amplification being tested.
        # asyncio.wait (not wait_for) so the expected failure is an observation here.
        await asyncio.wait({task}, timeout=STARTUP_CAP + 3.0)
        elapsed = time.monotonic() - started
        terminated = task.done()
        error = task.exception() if terminated and not task.cancelled() else None
        await asyncio.sleep(0.3)
        child_alive = _alive(spawn) if spawn else None
        return verdict(
            [
                ("startup_failed_within_ceiling", terminated and elapsed <= STARTUP_CAP + 3.0),
                ("failure_names_startup", error is not None and "failed to start" in str(error)),
                ("child_reaped", child_alive is False),
            ],
            elapsed_seconds=round(elapsed, 3),
            error=str(error),
            child_pid=spawn,
            child_alive_after_ceiling=child_alive,
        )
    finally:
        if not task.done():
            task.cancel()
            with suppress(BaseException):
                await asyncio.wait_for(task, 5.0)


async def r2_case_active_cancel_blocked(router, fixture: Fixture) -> dict:
    """R2-03: an in-flight cancel retires the session and records outcome_unknown on every
    terminal state, including a backend left blocked until its own call timeout."""
    request = asyncio.create_task(
        call(router, "r2-active", "hold", token="r2-never-release", timeout=5.0, mark="r2-active-hold")
    )
    try:
        waiting = await fixture.wait_event("waiting", token="r2-never-release")
        session = router._SESSIONS["r2-active"]
        fixture.sessions.append(session)
        request.cancel()
        with suppress(asyncio.CancelledError):
            await request
        caller_cancelled = request.cancelled()
        # Nothing releases the hold: the backend blocks until its own 5s call timeout.
        retired = await _settled(session, 2.5)
        healthy_after_cancel = session.alive
        listed = await router.list_backend_sessions()
        exits = [item for item in listed["recently_closed"] if item["session_id"] == "r2-active"]
        unknown = sum(int(item.get("outcome_unknown") or 0) for item in exits)
        no_silent_reuse = None
        if retired:
            try:
                _, fresh = await asyncio.wait_for(call(router, "r2-active", mark="r2-after-cancel"), 10.0)
                no_silent_reuse = fresh["pid"] != waiting["pid"]
            except Exception:  # noqa: BLE001 - a failed call also proves the session was not reused
                no_silent_reuse = True
        return verdict(
            [
                ("caller_cancellation_propagated", caller_cancelled),
                ("retired_promptly", retired),
                ("unknown_recorded_in_exit_log", unknown >= 1),
                ("unknown_counted_once", unknown == 1),
                ("no_silent_warm_reuse", no_silent_reuse is True),
            ],
            healthy_after_cancel=healthy_after_cancel,
            outcome_unknown_in_recent=unknown,
            exit_reasons=[item.get("close_reason") for item in exits],
            first_pid=waiting["pid"],
        )
    finally:
        if not request.done():
            request.cancel()
        with suppress(BaseException):
            await asyncio.wait_for(request, 5.0)


async def r2_case_close_caller_cancel(router, fixture: Fixture) -> dict:
    """R2-04: cancelling the close caller must not lose the cleanup ownership."""
    request = asyncio.create_task(
        call(router, "r2-close", "hold", token="r2-close-hold", timeout=60.0, mark="r2-close-active")
    )
    closing = None
    try:
        waiting = await fixture.wait_event("waiting", token="r2-close-hold")
        session = router._SESSIONS["r2-close"]
        fixture.sessions.append(session)
        closing = asyncio.create_task(router.close_backend_session("r2-close"))
        with suppress(asyncio.TimeoutError):
            await wait_until(lambda: router._SESSIONS.get("r2-close") is not session, timeout=6.0)
        detached = router._SESSIONS.get("r2-close") is not session
        closing.cancel()
        with suppress(asyncio.CancelledError):
            await closing
        close_caller_cancelled = closing.cancelled()
        # A normal lifespan exit must converge whatever the abandoned close still owned.
        async with router._router_lifespan(None):
            pass
        shutdown_flag = bool(getattr(router, "_SHUTDOWN", False))
        converged = session._task.done()
        await asyncio.sleep(0.2)
        request_settled = request.done()
        if request.done() and not request.cancelled():
            with suppress(BaseException):
                request.exception()
        owned = getattr(router, "_OWNED", None)
        owned_drained = owned is not None and not list(owned)
        child_alive = _alive(waiting["pid"])
        listed = await router.list_backend_sessions()
        exits = [item for item in listed["recently_closed"] if item["session_id"] == "r2-close"]
        unknown = sum(int(item.get("outcome_unknown") or 0) for item in exits)
        return verdict(
            [
                ("close_caller_cancelled", close_caller_cancelled),
                ("detached_from_map", detached),
                ("shutdown_flag_set", shutdown_flag),
                ("supervisor_converged", converged),
                ("request_settled", request_settled),
                ("unknown_recorded", unknown >= 1),
                ("owned_registry_drained", owned_drained),
                ("child_reaped", child_alive is False),
            ],
            close_reason=session.close_reason,
            request_state="done" if request_settled else "pending",
            outcome_unknown_in_recent=unknown,
            child_alive_after_shutdown=child_alive,
        )
    finally:
        if closing is not None and not closing.done():
            closing.cancel()
            with suppress(BaseException):
                await asyncio.wait_for(closing, 5.0)
        if not request.done():
            request.cancel()
        with suppress(BaseException):
            await asyncio.wait_for(request, 5.0)


async def r2_case_shared_startup_waiter(router, fixture: Fixture) -> dict:
    """R2-05 (control): cancelling one waiter on a shared startup must not kill it."""
    first = asyncio.create_task(
        router.list_backend_tools("fake", timeout_seconds=12.0, session_id="r2-shared", close_after=False)
    )
    second = asyncio.create_task(router.open_backend_session("fake", "r2-shared", idle_timeout_seconds=0))
    try:
        await fixture.wait_event("initialize")
        with suppress(asyncio.TimeoutError):
            await wait_until(lambda: "r2-shared" in router._SESSIONS, timeout=6.0)
        session = router._SESSIONS["r2-shared"]
        fixture.sessions.append(session)
        first.cancel()
        with suppress(asyncio.CancelledError):
            await first
        cancelled = first.cancelled()
        fixture.release("release_init")
        result = await asyncio.wait_for(second, 12.0)
        spawns = [item for item in fixture.events() if item["event"] == "spawn"]
        return verdict(
            [
                ("one_waiter_cancelled", cancelled),
                ("remaining_waiter_succeeded", result.get("session_id") == "r2-shared"),
                ("exactly_one_spawn", len(spawns) == 1),
                ("one_generation", router._SESSIONS.get("r2-shared") is session),
                ("session_alive_after_initialize", session.alive),
            ],
            spawn_count=len(spawns),
            tool_count=result.get("tool_count"),
            pid=spawns[0]["pid"] if spawns else None,
        )
    finally:
        for task in (first, second):
            if not task.done():
                task.cancel()
            with suppress(BaseException):
                await asyncio.wait_for(task, 5.0)


async def r2_case_gate_old_red_reason(_router, _fixture: Fixture) -> dict:
    """R2-06: an OLD RED caused by a setup/driver error must not satisfy the gate."""
    base = synthetic_baseline_results()

    def summarise(rows):
        return summarize(rows)

    def injected_exception():
        rows = [dict(item) for item in base]
        for item in rows:
            if item["label"] == "OLD" and item["kind"] == "negative":
                item["reason"] = "harness_exception RuntimeError: injected fixture setup failure"
        return rows

    def injected_old_green():
        rows = [dict(item) for item in base]
        for item in rows:
            if item["label"] == "OLD" and item["kind"] == "negative":
                item["green"] = True
                item["reason"] = "ok"
                break
        return rows

    def injected_new_exception():
        rows = [dict(item) for item in base]
        for item in rows:
            if item["label"] == "NEW" and item["kind"] == "negative":
                item["green"] = False
                item["reason"] = "harness_exception RuntimeError: injected fixture setup failure"
                break
        return rows

    def duplicate_row():
        rows = [dict(item) for item in base]
        rows.append(dict(rows[0]))
        return rows

    def dropped_case():
        return [dict(item) for item in base if item["case"] != "startup_deadline"]

    def control_red():
        rows = [dict(item) for item in base]
        for item in rows:
            if item["label"] == "OLD" and item["kind"] == "control":
                item["green"] = False
                item["reason"] = "failed: injected"
                break
        return rows

    def unknown_case():
        rows = [dict(item) for item in base]
        rows.append({"case": "not_a_case", "kind": "negative", "label": "OLD", "green": False,
                     "reason": "failed: injected", "observed": {}})
        return rows

    baseline_accepted = acceptance_ok(summarise(base))
    injections = [
        ("injected_old_exception_rejected", injected_exception),
        ("injected_old_green_rejected", injected_old_green),
        ("injected_new_exception_rejected", injected_new_exception),
        ("duplicate_row_rejected", duplicate_row),
        ("dropped_case_rejected", dropped_case),
        ("control_red_rejected", control_red),
        ("unknown_case_rejected", unknown_case),
    ]
    checks = [("synthetic_baseline_accepted", baseline_accepted)]
    observed = {"baseline": summarise(base)}
    for name, build in injections:
        summary = summarise(build())
        checks.append((name, not acceptance_ok(summary)))
        observed[name] = {key: summary[key] for key in ("old_red", "new_green", "control_keep", "old_reason_ok",
                                                        "unique_rows", "case_set_ok")}
    return verdict(checks, **observed)


async def r2_case_gate_harness_exit(_router, _fixture: Fixture) -> dict:
    """R2-07: a complete green payload must not override a nonzero harness exit."""
    results = synthetic_baseline_results()
    payload = {"summary": summarize(results), "results": results}
    accepted, reason = gate_ok(0, payload)
    checks = [("complete_green_payload_accepted", accepted)]
    observed = {"exit_zero": reason}

    dropped = [dict(item) for item in results if item["case"] != "active_cancellation"]
    duplicate = [dict(item) for item in results] + [dict(results[0])]
    mismatched = {"summary": {**payload["summary"], "old_red": 0}, "results": results}
    for name, code, body in (
        ("nonzero_exit_rejected", 7, payload),
        ("missing_payload_rejected", 0, None),
        ("truncated_payload_rejected", 0, {"summary": payload["summary"]}),
        ("dropped_case_rejected", 0, {"summary": summarize(dropped), "results": dropped}),
        ("duplicate_row_rejected", 0, {"summary": summarize(duplicate), "results": duplicate}),
        ("summary_mismatch_rejected", 0, mismatched),
    ):
        ok, why = gate_ok(code, body)
        checks.append((name, not ok))
        observed[name] = why
    return verdict(checks, **observed)


CASES = [
    ("queued_cancellation", "negative", case_queued_cancellation),
    ("close_active_future", "negative", case_close_active_future),
    ("closeall_registry_race", "negative", case_closeall_registry_race),
    ("startup_deadline", "negative", case_startup_deadline),
    ("active_cancellation", "negative", case_active_cancellation),
    ("warm_session_single_process", "control", case_warm_session_single_process),
    ("state_continuity", "control", case_state_continuity),
    ("cross_id_isolation", "control", case_cross_id_isolation),
    ("backend_conflict_reject", "control", case_backend_conflict_reject),
    ("timeout_cleanup", "control", case_timeout_cleanup),
    ("idle_reclaim", "control", case_idle_reclaim),
]

R2_CASES = [
    ("r2_startup_last_waiter", "negative", r2_case_startup_last_waiter),
    ("r2_startup_ceiling", "negative", r2_case_startup_ceiling),
    ("r2_active_cancel_blocked", "negative", r2_case_active_cancel_blocked),
    ("r2_close_caller_cancel", "negative", r2_case_close_caller_cancel),
    ("r2_shared_startup_waiter", "control", r2_case_shared_startup_waiter),
    ("r2_gate_old_red_reason", "gate", r2_case_gate_old_red_reason),
    ("r2_gate_harness_exit", "gate", r2_case_gate_harness_exit),
]

# The round2 counterexamples this suite adds on top of the original eleven: R2-01, R2-03
# and R2-04. R2-02 is the startup-ceiling assertion and R2-05 keeps the shared-waiter
# control; both are counted separately so the headline number is not inflated.
R2_NEW_CASES = 3

MODES = {
    "startup_deadline": "hold_initialize",
    "r2_startup_last_waiter": "hold_initialize",
    "r2_startup_ceiling": "hold_initialize",
    "r2_shared_startup_waiter": "hold_initialize",
}

NEGATIVE_TOTAL = sum(1 for _, kind, _ in CASES if kind == "negative")
CONTROL_TOTAL = sum(1 for _, kind, _ in CASES if kind == "control")
CASE_COUNT = len(CASES)
R2_NEGATIVE_TOTAL = sum(1 for _, kind, _ in R2_CASES if kind == "negative")
R2_CONTROL_TOTAL = sum(1 for _, kind, _ in R2_CASES if kind == "control")
R2_GATE_TOTAL = sum(1 for _, kind, _ in R2_CASES if kind == "gate")
R2_CASE_COUNT = len(R2_CASES)

# What an OLD RED must look like: a behavioural failure (never a harness/driver
# exception) whose failed-check list contains at least the checks that identify the
# counterexample. Anything else is a setup failure and must not satisfy the gate.
OLD_RED_SPEC = {
    "queued_cancellation": {"min_failed": {"queued_operation_not_executed"}},
    "close_active_future": {"min_failed": {"active_request_terminated"}},
    "closeall_registry_race": {"min_failed": {"replacement_still_registered"}},
    "startup_deadline": {"min_failed": {"startup_wait_terminated", "startup_failed_with_runtime_error"}},
    "active_cancellation": {"min_failed": {"cancelled_session_retired", "outcome_marked_unknown"}},
}

R2_OLD_RED_SPEC = {
    "r2_startup_last_waiter": {"min_failed": {"supervisor_converged_within_budget", "child_reaped"}},
    "r2_startup_ceiling": {"min_failed": {"startup_failed_within_ceiling"}},
    "r2_active_cancel_blocked": {"min_failed": {"retired_promptly", "unknown_recorded_in_exit_log"}},
    "r2_close_caller_cancel": {"min_failed": {"request_settled", "unknown_recorded"}},
}


def old_red_reason_ok(case: str, item: dict | None, spec: dict) -> bool:
    """An OLD negative counts only when it failed behaviourally in the specified way."""
    if item is None or item.get("green") is not False:
        return False
    reason = str(item.get("reason") or "")
    if not reason.startswith("failed:"):
        return False  # harness_exception / not_run are setup or driver failures, not contract RED
    failed = {part.strip() for part in reason[len("failed:"):].split(",") if part.strip()}
    return spec[case]["min_failed"] <= failed


async def run_case(case_id: str, kind: str, fn, module_path: Path, label: str) -> dict:
    router = load_router(module_path, f"router_{label}_{case_id}")
    fixture = Fixture(router, case_id, MODES.get(case_id, "normal"))
    try:
        outcome = await fn(router, fixture)
    except Exception as exc:  # noqa: BLE001 - a crashing case is a failed case, not a crash
        outcome = {"green": False, "reason": f"harness_exception {type(exc).__name__}: {exc}", "observed": {}}
    finally:
        await fixture.stop()
    return {
        "case": case_id,
        "kind": kind,
        "label": label,
        "green": bool(outcome["green"]),
        "reason": outcome["reason"],
        "observed": outcome["observed"],
    }


def summarize(results: list[dict], cases=CASES, spec: dict | None = None) -> dict:
    """Derive the acceptance numbers from the rows; never from a reported summary."""
    spec = OLD_RED_SPEC if spec is None else spec
    keys = [(item.get("case"), item.get("label")) for item in results]
    by_key = {(item.get("case"), item.get("label")): item for item in results}
    negative = [case for case, kind, _ in cases if kind == "negative"]
    control = [case for case, kind, _ in cases if kind == "control"]
    gate = [case for case, kind, _ in cases if kind == "gate"]
    return {
        "old_red": sum(1 for case in negative if (by_key.get((case, "OLD")) or {}).get("green") is False),
        "new_green": sum(1 for case in negative if (by_key.get((case, "NEW")) or {}).get("green") is True),
        "control_keep": sum(
            1
            for case in control
            if (by_key.get((case, "OLD")) or {}).get("green") is True
            and (by_key.get((case, "NEW")) or {}).get("green") is True
        ),
        "gate_ok": sum(1 for case in gate if (by_key.get((case, "GATE")) or {}).get("green") is True),
        "old_reason_ok": all(old_red_reason_ok(case, by_key.get((case, "OLD")), spec) for case in negative),
        "negative_total": len(negative),
        "control_total": len(control),
        "gate_total": len(gate),
        "case_count": len({item.get("case") for item in results}),
        "unique_rows": len(keys) == len(set(keys)),
        "case_set_ok": {item.get("case") for item in results} == {case for case, _, _ in cases},
        "sdk_mocked": "NO" if sdk_available() else "YES",
    }


def acceptance_ok(summary: dict) -> bool:
    """The single gate ROUTER-VERIFY re-checks; a pure function of the summary."""
    return (
        summary.get("sdk_mocked") == "NO"
        and summary.get("case_count") == CASE_COUNT == 11
        and summary.get("unique_rows") is True
        and summary.get("case_set_ok") is True
        and summary.get("old_reason_ok") is True
        and summary.get("negative_total") == NEGATIVE_TOTAL == 5
        and summary.get("control_total") == CONTROL_TOTAL == 6
        and summary.get("old_red") == NEGATIVE_TOTAL
        and summary.get("new_green") == NEGATIVE_TOTAL
        and summary.get("control_keep") == CONTROL_TOTAL
    )


def acceptance_ok_r2(summary: dict) -> bool:
    """Gate for the round2 suite: same rules, round2 denominators."""
    return (
        summary.get("sdk_mocked") == "NO"
        and summary.get("case_count") == R2_CASE_COUNT
        and summary.get("unique_rows") is True
        and summary.get("case_set_ok") is True
        and summary.get("old_reason_ok") is True
        and summary.get("negative_total") == R2_NEGATIVE_TOTAL == 4
        and summary.get("control_total") == R2_CONTROL_TOTAL == 1
        and summary.get("gate_total") == R2_GATE_TOTAL == 2
        and summary.get("old_red") == R2_NEGATIVE_TOTAL
        and summary.get("new_green") == R2_NEGATIVE_TOTAL
        and summary.get("control_keep") == R2_CONTROL_TOTAL
        and summary.get("gate_ok") == R2_GATE_TOTAL
    )


def synthetic_baseline_results() -> list[dict]:
    """A complete, otherwise-accepting eleven-case row set built from the fixed spec.

    Used only by the R2-06/R2-07 gate cases: the gate must accept this shape and reject
    each single mutation of it. It is data, not a claim that a run happened.
    """
    rows = []
    for case_id, kind, _ in CASES:
        if kind == "negative":
            rows.append({
                "case": case_id, "kind": kind, "label": "OLD", "green": False,
                "reason": "failed: " + ", ".join(sorted(OLD_RED_SPEC[case_id]["min_failed"])),
                "observed": {},
            })
        else:
            rows.append({"case": case_id, "kind": kind, "label": "OLD", "green": True, "reason": "ok", "observed": {}})
        rows.append({"case": case_id, "kind": kind, "label": "NEW", "green": True, "reason": "ok", "observed": {}})
    return rows


def gate_ok(exit_code: int, payload: dict | None, cases=CASES, accept=None, spec: dict | None = None) -> tuple[bool, str]:
    """Release gate: completion, then structure, then acceptance.

    Exit 0 comes first on purpose: a complete-looking all-green JSON payload cannot
    override a nonzero harness exit, a truncated payload, a dropped case or a duplicate
    row. Returns (accepted, reason) so a rejection always names its cause.
    """
    accept = acceptance_ok if accept is None else accept
    if exit_code != 0:
        return False, f"harness exited {exit_code}; a nonzero exit is a failed run regardless of its payload"
    if not isinstance(payload, dict):
        return False, "no machine-readable RESULT_JSON"
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        return False, "RESULT_JSON has no results list"
    keys = [(item.get("case"), item.get("label")) for item in results]
    if len(keys) != len(set(keys)):
        return False, "duplicate case/label rows"
    if {item.get("case") for item in results} != {case for case, _, _ in cases}:
        return False, "case set differs from the fixed suite"
    derived = summarize(results, cases, spec)
    if derived != payload.get("summary"):
        return False, "reported summary does not match the rows"
    if not accept(derived):
        return False, f"acceptance not met: {derived}"
    return True, "ok"


def mark(item: dict | None) -> str:
    if item is None:
        return "not_run"
    return "GREEN" if item["green"] else "RED"


async def run_all(selected: list[str] | None, suite: str = "baseline") -> int:
    cases = CASES if suite == "baseline" else R2_CASES
    accept = acceptance_ok if suite == "baseline" else acceptance_ok_r2
    spec = OLD_RED_SPEC if suite == "baseline" else R2_OLD_RED_SPEC
    negative_total = NEGATIVE_TOTAL if suite == "baseline" else R2_NEGATIVE_TOTAL
    control_total = CONTROL_TOTAL if suite == "baseline" else R2_CONTROL_TOTAL
    case_count = CASE_COUNT if suite == "baseline" else R2_CASE_COUNT
    print(
        json.dumps(
            {
                "event": "environment",
                "suite": suite,
                "python": sys.version.split()[0],
                "platform": sys.platform,
                "mcp": sdk_version() if sdk_available() else "absent",
                "sdk_mocked": "NO" if sdk_available() else "YES",
                "product_root": str(PRODUCT_ROOT),
                "old_sha256": sha256(OLD_SERVER) if OLD_SERVER.is_file() else "missing",
                "candidate_sha256": sha256(CANDIDATE_SERVER) if CANDIDATE_SERVER.is_file() else "missing",
                "fixture_sha256": sha256(BACKEND) if BACKEND.is_file() else "missing",
                "expected_old_sha256": OLD_SHA256,
                "expected_fixture_sha256": BACKEND_SHA256,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    if not sdk_available():
        print("SDK_MOCKED=YES: the real mcp SDK is not importable; no case was executed.", flush=True)
        for case_id, kind, _ in cases:
            print(f"{case_id} OLD=not_run NEW=not_run reason=real MCP SDK unavailable", flush=True)
        print(
            f"SUMMARY OLD_RED=0/{negative_total} NEW_GREEN=0/{negative_total} "
            f"CONTROL_KEEP=0/{control_total} CASE_COUNT={case_count} SDK_MOCKED=YES",
            flush=True,
        )
        print("VERDICT=ROUTER_ACCEPTANCE_NOT_RUN", flush=True)
        return 2

    wanted = set(selected) if selected else {case for case, _, _ in cases}
    results = []
    for case_id, kind, fn in cases:
        if case_id not in wanted:
            continue
        if kind == "gate":
            # Data-level gate case: no backend, so one row under a single label.
            results.append(await run_case(case_id, kind, fn, CANDIDATE_SERVER, "GATE"))
            continue
        for label, path in (("OLD", OLD_SERVER), ("NEW", CANDIDATE_SERVER)):
            results.append(await run_case(case_id, kind, fn, path, label))

    by_key = {(item["case"], item["label"]): item for item in results}
    for case_id, kind, _ in cases:
        if case_id not in wanted:
            continue
        old_item, new_item = by_key.get((case_id, "OLD")), by_key.get((case_id, "NEW"))
        if kind == "gate":
            gate_item = by_key.get((case_id, "GATE"))
            print(f"{case_id} GATE={mark(gate_item)} reason={(gate_item or {}).get('reason', 'not_run')}", flush=True)
        else:
            print(
                f"{case_id} OLD={mark(old_item)} NEW={mark(new_item)} "
                f"reason=OLD:{(old_item or {}).get('reason', 'not_run')} NEW:{(new_item or {}).get('reason', 'not_run')}",
                flush=True,
            )
        for item in (old_item, new_item, by_key.get((case_id, "GATE"))):
            if item is not None:
                print(
                    json.dumps(
                        {
                            "event": "observation",
                            "case": case_id,
                            "kind": kind,
                            "label": item["label"],
                            "green": item["green"],
                            "observed": item["observed"],
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )

    summary = summarize(results, cases, spec)
    print("RESULT_JSON=" + json.dumps({"summary": summary, "results": results}, sort_keys=True), flush=True)
    if suite == "baseline":
        print(
            f"SUMMARY OLD_RED={summary['old_red']}/{negative_total} "
            f"NEW_GREEN={summary['new_green']}/{negative_total} "
            f"CONTROL_KEEP={summary['control_keep']}/{control_total} "
            f"CASE_COUNT={summary['case_count']} SDK_MOCKED={summary['sdk_mocked']}",
            flush=True,
        )
    else:
        print(
            f"SUMMARY R2_OLD_RED={summary['old_red']}/{negative_total} "
            f"R2_NEW_GREEN={summary['new_green']}/{negative_total} "
            f"R2_CONTROL_KEEP={summary['control_keep']}/{control_total} "
            f"R2_GATE_OK={summary['gate_ok']}/{summary['gate_total']} "
            f"CASE_COUNT={summary['case_count']} SDK_MOCKED={summary['sdk_mocked']}",
            flush=True,
        )
    ok = accept(summary) and len(wanted) == case_count
    print(f"HARNESS_VERDICT={'OK' if ok else 'NOT_OK'}", flush=True)
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Router acceptance harness (OLD vs CANDIDATE).")
    parser.add_argument("--suite", choices=("baseline", "r2"), default="baseline")
    parser.add_argument("--case", action="append", dest="cases")
    args = parser.parse_args()
    cases = CASES if args.suite == "baseline" else R2_CASES
    valid = [case for case, _, _ in cases]
    if args.cases and any(case not in valid for case in args.cases):
        parser.error(f"unknown case for suite {args.suite}: {sorted(set(args.cases) - set(valid))}")
    for path in (OLD_SERVER, CANDIDATE_SERVER, BACKEND):
        if not path.is_file():
            print(f"missing required file: {path}", flush=True)
            return 2
    if sha256(OLD_SERVER) != OLD_SHA256:
        print("old_server.py does not match the frozen snapshot sha256", flush=True)
        return 2
    return asyncio.run(run_all(args.cases, args.suite))


if __name__ == "__main__":
    sys.exit(main())
