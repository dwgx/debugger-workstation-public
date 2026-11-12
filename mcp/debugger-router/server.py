import asyncio
import builtins
import itertools
import json
import os
import time
import weakref
from collections import deque
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.server.fastmcp import FastMCP


# ROOT resolves to the actual install path: DEBUGGER_ROOT env var wins, else the
# directory two levels above this file (MCP/debugger-router/server.py -> root).
ROOT = Path(os.environ.get("DEBUGGER_ROOT", Path(__file__).resolve().parents[2])).resolve()
# CANONICAL_ROOT is only used to translate legacy absolute paths that may appear
# in a .mcp.json authored on the original install. Distributed configs use the
# {{DEBUGGER_ROOT}} template instead, so this rarely matters. Override with
# DEBUGGER_CANONICAL_ROOT if your config carries a different hardcoded prefix.
CANONICAL_ROOT = Path(os.environ.get("DEBUGGER_CANONICAL_ROOT", r"D:\Tool\debugger"))
MCP_ROOT = ROOT / "MCP"
BACKEND_CONFIG = MCP_ROOT / ".mcp.json"

BACKEND_META: dict[str, dict[str, str]] = {
    "ghidra": {"category": "static-reversing", "note": "Ghidra project/plugin backed analysis."},
    "ida": {"category": "static-reversing", "note": "Wrapper routing correction (2026-11-12): uses idalib-mcp --stdio, preferring the project .venv with an explicit machine-local fallback. Requires compatible IDA/idalib and license; check installed upstream requirements. The GUI/plugin port 13337 route is separate and is not established by this wrapper."},
    "radare2": {"category": "static-reversing", "note": "radare2/r2mcp binary analysis; needs radare2 + r2mcp installed via r2pm."},
    "x64dbg": {"category": "debugger", "note": "x64dbg automate bridge; needs debugger session for live work."},
    "jadx": {"category": "mobile", "note": "JADX GUI/plugin backed APK/DEX inspection."},
    "apktool": {"category": "mobile", "note": "APK decode/build/resource/smali workspace operations."},
    "frida": {"category": "mobile-runtime", "note": "Frida device/process runtime automation."},
    "imhex": {"category": "static-reversing", "note": "ImHex API backed binary/hex operations."},
    "yaraflux": {"category": "rules", "note": "YARA rules, sample storage, and scanning."},
    "mobsf": {"category": "mobile", "note": "MobSF scan API bridge; needs MobSF service for real scans."},
    "ilspy": {"category": "dotnet", "note": ".NET assembly inspection/decompilation."},
    "dnspy": {"category": "dotnet", "note": ".NET assembly inspection and patch helper tools."},
    "wireshark": {"category": "network", "note": "tshark/Wireshark pcap analysis and capture helpers."},
    "reqable": {"category": "network", "note": "Reqable HAR/API/WebSocket analysis workspace."},
    "reclass": {"category": "memory", "note": "ReClass.NET memory structure bridge; needs ReClass GUI/plugin."},
    "sevenzip": {"category": "unpacking", "note": "7-Zip archive listing/extract/update helpers."},
    "cheatengine": {"category": "memory", "note": "Cheat Engine Lua bridge; needs CE and bridge loaded for live work."},
    "volatility3": {"category": "memory-forensics", "note": "Volatility3 memory-image forensics; exposes Vol3 plugins as tools."},
    "virustotal": {"category": "threat-intel", "note": "VirusTotal URL/file/IP/domain intel; needs VIRUSTOTAL_API_KEY; sends IOCs to the public VT API."},
    "rea": {"category": "multi-target", "note": "REA (morluto/rea) — reverse-engineering across native binaries, JS/Electron, .NET, APK, websites, firmware, crashes; npm package rea-agents pinned 6.4.0; native targets need a Ghidra/IDA/Hopper provider, JS/.NET work standalone."},
}

INSTRUCTIONS = (
    "Lightweight router for a local portable debugger/reverse-engineering MCP backend set. "
    "Only this router is meant to start with the AI client by default; it starts heavy backends on demand and keeps "
    "each backend process warm between calls (one process per session_id) until it is closed or idles out. "
    "Use list_backends and list_backend_tools before calling unfamiliar tools. "
    "Before destructive writes, process injection, live capture, debugger/memory mutation, or system-level actions, "
    "explain the risk and rollback path to the user first."
)

@asynccontextmanager
async def _router_lifespan(_server: FastMCP):
    # A warm backend is a child process; the router must not leave one behind when
    # the MCP client goes away. stdio_client also puts each child in a Windows job
    # object (KILL_ON_JOB_CLOSE), so an abrupt router death still reaps the tree.
    global _SHUTDOWN
    _SHUTDOWN = False
    try:
        yield {}
    finally:
        # Shutdown must converge: once the client is gone no new backend may be
        # started, and every warm process is reclaimed exactly once -- including one
        # whose close caller was cancelled after it left the address map.
        _SHUTDOWN = True
        await _close_sessions("*")
        if await _await_owned():
            # A supervisor that outlived the cleanup budget is cancelled rather than
            # left running behind a client that is already gone.
            loop = asyncio.get_running_loop()
            stuck = [session for session in list(_OWNED) if session.loop is loop]
            for session in stuck:
                session._task.cancel()
            with suppress(BaseException):
                await asyncio.wait({session._task for session in stuck}, timeout=1.0)


mcp = FastMCP("debugger-router", instructions=INSTRUCTIONS, log_level="ERROR", lifespan=_router_lifespan)


def _resolve_command(command: str) -> str:
    command = command.replace("{{DEBUGGER_ROOT}}", str(ROOT))
    # A bare executable name (no path separator, e.g. "python", "r2pm") is meant
    # to be resolved via PATH by the OS, not rebased under ROOT.
    if "/" not in command and "\\" not in command:
        return command
    try:
        path = Path(command)
    except Exception:
        return command
    if not path.is_absolute():
        return str((ROOT / path).resolve())
    try:
        relative = path.relative_to(CANONICAL_ROOT)
    except ValueError:
        return command
    return str(ROOT / relative)


@dataclass(frozen=True)
class BackendSpec:
    """Spawn inputs pinned by one warm session; environment values stay private."""

    command: str
    args: tuple[str, ...] = ()
    cwd: str | None = None
    env: tuple[tuple[str, str], ...] = ()
    env_inherit: tuple[str, ...] = ()
    env_policy: str = "legacy-full"


def _descriptor_error(name: str, field: str, reason: str) -> ValueError:
    # Do not interpolate rejected values: arguments/env may contain credentials.
    return ValueError(json.dumps({"code": "INVALID_BACKEND_DESCRIPTOR", "backend": name,
                                 "field": field, "reason": reason}, ensure_ascii=True))


def _env_key(key: str) -> str:
    return key.upper() if os.name == "nt" else key


def _checked_env_key(name: str, field: str, key: Any) -> str:
    if not isinstance(key, str) or not key or "=" in key or "\0" in key:
        raise _descriptor_error(name, field, "environment names must be nonempty strings without '=' or NUL")
    return _env_key(key)


def _parse_backend(name: str, cfg: Any) -> BackendSpec:
    if not isinstance(cfg, dict):
        raise _descriptor_error(name, "descriptor", "must be an object")
    known = {"command", "args", "cwd", "env", "env_inherit"}
    if set(cfg) - known:
        raise _descriptor_error(name, "descriptor", "unsupported fields")
    command = cfg.get("command")
    if not isinstance(command, str) or not command.strip() or "\0" in command:
        raise _descriptor_error(name, "command", "must be a nonempty string without NUL")
    args = cfg.get("args", [])
    if not isinstance(args, list) or any(not isinstance(arg, str) or "\0" in arg for arg in args):
        raise _descriptor_error(name, "args", "must be a list of strings without NUL")
    cwd = cfg.get("cwd")
    if "cwd" in cfg:
        if not isinstance(cwd, str) or not cwd.strip() or "\0" in cwd:
            raise _descriptor_error(name, "cwd", "must be a nonempty directory string without NUL")
        directory = Path(cwd.replace("{{DEBUGGER_ROOT}}", str(ROOT)))
        if not directory.is_absolute():
            directory = ROOT / directory
        directory = directory.resolve()
        if not directory.is_dir():
            raise _descriptor_error(name, "cwd", "directory does not exist")
        cwd = str(directory)
    environment = cfg.get("env", {})
    if not isinstance(environment, dict):
        raise _descriptor_error(name, "env", "must be an object of string values")
    env: dict[str, str] = {}
    for key, value in environment.items():
        normalized = _checked_env_key(name, "env", key)
        if normalized in env:
            raise _descriptor_error(name, "env", "duplicate case-insensitive environment names")
        if not isinstance(value, str) or "\0" in value:
            raise _descriptor_error(name, "env", "values must be strings without NUL")
        env[normalized] = value
    inherited = cfg.get("env_inherit", [])
    if not isinstance(inherited, list):
        raise _descriptor_error(name, "env_inherit", "must be a list of environment names")
    inherit: list[str] = []
    for key in inherited:
        normalized = _checked_env_key(name, "env_inherit", key)
        if normalized in inherit:
            raise _descriptor_error(name, "env_inherit", "duplicate environment names")
        inherit.append(normalized)
    return BackendSpec(command=_resolve_command(command), args=tuple(args), cwd=cwd,
                       env=tuple(sorted(env.items())), env_inherit=tuple(sorted(inherit)),
                       env_policy="legacy-full" if set(cfg) == {"command"} else "platform-safe")


def _load_backends() -> dict[str, BackendSpec]:
    # utf-8-sig tolerates a UTF-8 BOM in hand-edited/generated config.
    path = BACKEND_CONFIG
    if not path.is_file():
        path = ROOT / "mcp" / ".mcp.json.template"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("mcpServers", {}), dict):
        raise _descriptor_error("*", "mcpServers", "must be an object")
    return {name: _parse_backend(name, cfg) for name, cfg in data.get("mcpServers", {}).items()
            if name != "debugger-router"}


def _backend_env(spec: BackendSpec | None = None) -> dict[str, str]:
    if spec is None or spec.env_policy == "legacy-full":
        env = os.environ.copy()
    else:
        # stdio_client itself merges this platform baseline again. Deliberately use
        # that same public SDK baseline; do not promise a zero-environment sandbox.
        env = {_env_key(key): value for key, value in get_default_environment().items()}
        parent = {_env_key(key): value for key, value in os.environ.items()}
        for key in spec.env_inherit:
            if key not in parent:
                raise _descriptor_error("*", "env_inherit", "requested parent variable is absent")
            env[key] = parent[key]
        env.update(spec.env)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["FASTMCP_SHOW_SERVER_BANNER"] = "false"
    env["FASTMCP_CHECK_FOR_UPDATES"] = "off"
    env["FASTMCP_ENABLE_RICH_LOGGING"] = "false"
    env["PATH"] = str(MCP_ROOT / "bin") + os.pathsep + env.get("PATH", "")
    return env


def _windows_command(spec: BackendSpec, env: dict[str, str]) -> str:
    """Resolve strict commands using the backend PATH, not the Router's PATH."""
    path = Path(spec.command)
    suffixes = [""] + [ext for ext in env.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if ext]
    if path.is_absolute():
        bases = [path]
    else:
        cwd = Path(spec.cwd) if spec.cwd else Path.cwd()
        bases = []
        for entry in env.get("PATH", "").split(os.pathsep):
            directory = Path(entry.strip('"')) if entry else cwd
            if not directory.is_absolute():
                directory = cwd / directory
            bases.append(directory / path)
    for base in bases:
        for suffix in suffixes:
            candidate = Path(str(base) + suffix)
            if candidate.is_file():
                return str(candidate.resolve())
    raise _descriptor_error("*", "command", "executable not found on the selected backend PATH")


def _stdio_params(spec: BackendSpec | str) -> StdioServerParameters:
    # Internal legacy callers may still supply the historical command string.
    if isinstance(spec, str):
        spec = BackendSpec(command=spec)
    env = _backend_env(spec)
    command = spec.command
    if spec.env_policy == "platform-safe" and os.name == "nt":
        command = _windows_command(spec, env)
    if command.lower().endswith((".cmd", ".bat")):
        if spec.env_policy == "legacy-full":
            return StdioServerParameters(command="cmd.exe", args=["/c", command], env=env)
        if os.name != "nt":
            raise _descriptor_error("*", "command", "batch descriptors require Windows")
        # CALL avoids cmd /c's outer-quote stripping for a quoted script plus
        # multiple arguments. Refuse CALL expansion/metacharacters rather than
        # pretending CRT quoting is a general cmd.exe escaping algorithm.
        forbidden = '\r\n"&|<>^%!()'
        if any(any(char in value for char in forbidden) for value in (command, *spec.args)):
            raise _descriptor_error("*", "args", "batch literal subset excludes shell metacharacters, quotes and line breaks; use a direct executable")
        interpreter = str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "cmd.exe")
        return StdioServerParameters(command=interpreter,
                                     args=["/d", "/v:off", "/c", "call", command, *spec.args],
                                     env=env, cwd=spec.cwd)
    return StdioServerParameters(command=command, args=list(spec.args), env=env, cwd=spec.cwd)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _timeout_cap() -> float:
    """Ceiling for one backend call: DEBUGGER_ROUTER_TIMEOUT seconds, default 900.

    The old ceiling was a hardcoded 300s, which could not cover this station's own
    fuzz runs (634s measured), so the value is now read per call from the environment.
    """
    return max(5.0, _env_float("DEBUGGER_ROUTER_TIMEOUT", 900.0))


def _idle_timeout() -> float:
    """Seconds an unused backend process may stay warm: DEBUGGER_ROUTER_IDLE_TIMEOUT, default 600.

    A value <= 0 keeps warm processes alive until the client closes them.
    """
    return _env_float("DEBUGGER_ROUTER_IDLE_TIMEOUT", 600.0)


def _startup_deadline() -> float:
    """Ceiling for spawn + MCP initialize: DEBUGGER_ROUTER_STARTUP_TIMEOUT, default 30s.

    A call's own timeout also covers startup (the router passes it down), so a backend
    whose initialize never answers cannot hold a caller past the deadline it asked for.
    """
    return max(5.0, _env_float("DEBUGGER_ROUTER_STARTUP_TIMEOUT", 30.0))


def _clamp_timeout(value: float | None) -> float:
    if value is None:
        return _timeout_cap()
    try:
        timeout = float(value)
    except Exception:
        timeout = _timeout_cap()
    return max(5.0, min(timeout, _timeout_cap()))


def _parse_args(arguments_json: str | None) -> dict[str, Any]:
    if not arguments_json:
        return {}
    parsed = json.loads(arguments_json)
    if not isinstance(parsed, dict):
        raise ValueError("arguments_json must decode to a JSON object")
    return parsed


def _describe_exc(exc: BaseException) -> str:
    """Name the real failure: anyio wraps a stdio startup error in an ExceptionGroup."""
    group_type = getattr(builtins, "BaseExceptionGroup", None)
    while group_type is not None and isinstance(exc, group_type) and exc.exceptions:
        exc = exc.exceptions[0]
    return f"{type(exc).__name__}: {exc}"


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="json", exclude_none=True))
    return repr(value)


class _Request:
    """One queued backend operation, owned by a caller and dispatched by the supervisor.

    `dispatched` flips only when the supervisor is about to run the operation, so a
    request cancelled while it was still queued is dropped instead of executed, and a
    request cancelled while it was running is reported as an unknown outcome instead
    of being silently retried against a warm session.
    """

    __slots__ = ("request_id", "operation", "timeout", "future", "dispatched", "cancelled", "abort_reason")

    def __init__(self, request_id: int, operation, timeout: float, future: asyncio.Future):
        self.request_id = request_id
        self.operation = operation
        self.timeout = timeout
        self.future = future
        self.dispatched = False
        self.cancelled = False
        # Set by the close path when it settles a dispatched request that is still
        # running, so the supervisor can name that outcome instead of guessing
        # "caller cancelled".
        self.abort_reason: str | None = None

    def settle(self, result: Any = None, error: BaseException | None = None) -> bool:
        """Complete the caller's future at most once; return whether it was still open."""
        if self.future.done():
            return False
        if error is not None:
            self.future.set_exception(error)
        else:
            self.future.set_result(result)
        return True


class _BackendSession:
    """One backend MCP process kept warm across router calls, addressed by session_id.

    anyio requires a context manager to be exited in the task that entered it, so
    `stdio_client` and `ClientSession` are owned by a single supervisor task; callers
    hand their operation to that task over a queue instead of driving the session
    themselves. Calls to one session are therefore serialized (the backends here are
    single-context bridges anyway), and a session that times out or raises is killed
    rather than reused: a wedged backend must not silently swallow the next call.
    """

    def __init__(self, session_id: str, backend: str, command: BackendSpec | str, idle_timeout: float):
        self.session_id = session_id
        self.backend = backend
        self.spec = command if isinstance(command, BackendSpec) else BackendSpec(command=command)
        self.command = self.spec.command
        self.idle_timeout = idle_timeout
        self.loop = asyncio.get_running_loop()
        self.started_at = time.monotonic()
        self.last_used = self.started_at
        self.calls = 0
        self.close_reason: str | None = None
        self.start_error: str | None = None
        self._initialized = False
        self._ready = asyncio.Event()
        self._queue: asyncio.Queue = asyncio.Queue()
        # The operation currently running in the supervisor, and how many dispatched
        # calls ended without a confirmed outcome (caller cancelled, session closed).
        self._active: _Request | None = None
        self.outcome_unknown = 0
        self._request_ids = itertools.count(1)
        self._closer: asyncio.Task | None = None
        self._task = self.loop.create_task(self._serve())
        # Ownership is separate from the address map: the session stays owned until
        # its supervisor task is done, so detaching it from _SESSIONS while it closes
        # cannot drop the responsibility to reap the supervisor and its child.
        _OWNED.add(self)
        self._task.add_done_callback(self._release_ownership)

    @property
    def alive(self) -> bool:
        return not self._task.done() and self.close_reason is None

    def info(self) -> dict[str, Any]:
        now = time.monotonic()
        return {
            "session_id": self.session_id,
            "backend": self.backend,
            "alive": self.alive,
            "calls": self.calls,
            "uptime_seconds": round(now - self.started_at, 1),
            "idle_seconds": round(now - self.last_used, 1),
            "idle_timeout_seconds": self.idle_timeout,
            "close_reason": self.close_reason,
            "outcome_unknown": self.outcome_unknown,
        }

    async def start(self, deadline: float | None = None) -> None:
        """Wait for spawn + initialize; the supervisor owns the startup deadline.

        The wait is the caller's own budget (if it asked for a shorter one) capped by
        DEBUGGER_ROUTER_STARTUP_TIMEOUT, so a longer per-call timeout can never extend
        startup past the configured ceiling. The deadline itself lives in the
        supervisor task: a caller that stops waiting removes only its own wait, never
        the bound on the process it asked for, and never another caller's.
        """
        limit = _startup_deadline() if deadline is None else min(float(deadline), _startup_deadline())
        limit = max(0.0, limit)
        if not self._ready.is_set():
            try:
                await asyncio.wait_for(self._ready.wait(), limit)
            except asyncio.TimeoutError:
                # This caller's wait is over; the supervisor's own deadline still owns
                # the process. Give a teardown it has already started one bounded grace
                # so the failure is reported against a converged session when both
                # deadlines are the same -- never longer than the close grace, and the
                # caller never cancels the supervisor.
                await asyncio.wait({self._task}, timeout=_CLOSE_GRACE)
                if self.start_error:
                    raise RuntimeError(
                        f"backend '{self.backend}' failed to start: {self.start_error}"
                    ) from None
                raise RuntimeError(
                    f"backend '{self.backend}' failed to start: not initialized after {limit:g}s"
                ) from None
        if self.start_error:
            raise RuntimeError(f"backend '{self.backend}' failed to start: {self.start_error}")

    async def request(self, operation, timeout: float):
        if not self.alive:
            raise RuntimeError(f"session '{self.session_id}' is closed ({self.close_reason or 'not ready'})")
        request = _Request(next(self._request_ids), operation, timeout, self.loop.create_future())
        self._queue.put_nowait(request)
        if self._task.done():
            # The supervisor died between the check above and the enqueue; nothing
            # will ever pop this request, so fail it here instead of hanging.
            raise RuntimeError(f"session '{self.session_id}' is closed ({self.close_reason or 'died'})")
        try:
            return await request.future
        except asyncio.CancelledError:
            # The caller gave up. A request still queued must not run at all; one that
            # was already dispatched may have mutated the backend, which the supervisor
            # records as an unknown outcome instead of replaying it.
            request.cancelled = True
            if not request.future.done():
                request.future.cancel()
            raise

    def begin_close(self, reason: str = "closed by client") -> asyncio.Task:
        """Record the close and return the single cleanup task that converges it.

        The cleanup task belongs to the session, not to whoever asked for the close:
        cancelling that caller ends only its own wait. Ownership is held in _OWNED
        until the supervisor task is done, so shutdown can still find a session that
        was detached from the address map while its close was in progress.
        """
        if self.close_reason is None:
            self.close_reason = reason
        self._fail_pending(self.close_reason)
        self._queue.put_nowait(None)  # sentinel: leave the supervisor loop when idle
        if self._closer is None:
            self._closer = self.loop.create_task(self._converge())
            self._closer.add_done_callback(_consume)
        return self._closer

    async def close(self, reason: str = "closed by client") -> None:
        # shield: a cancelled caller must not cancel the cleanup it asked for.
        await asyncio.shield(self.begin_close(reason))

    async def _converge(self) -> None:
        """Idempotent teardown: bounded grace for the call in flight, then kill and reap."""
        # Give the call that is already running a bounded chance to finish, so a
        # graceful close does not discard work that is about to complete; a wedged
        # call is cut off here instead of holding the close open.
        await asyncio.wait({self._task}, timeout=_CLOSE_GRACE)
        if not self._task.done():
            active = self._active
            if active is not None:
                # An in-flight operation cannot be stopped cooperatively: the caller is
                # told the outcome is unknown and the process is killed, so the warm
                # session is never silently reused after a close.
                active.abort_reason = (
                    f"session '{self.session_id}' closed while request was in flight: {self.close_reason}"
                )
                active.settle(error=RuntimeError(active.abort_reason))
            self._task.cancel()
            with suppress(BaseException):
                await asyncio.wait_for(self._task, _CLEANUP_BUDGET)
        if self._task.done():
            _consume(self._task)

    def _release_ownership(self, task: asyncio.Task) -> None:
        _OWNED.discard(self)
        _consume(task)

    def _retire(self, reason: str, unknown: bool) -> None:
        """Record one terminal outcome; `unknown` is counted once per dispatched request."""
        if unknown:
            self.outcome_unknown += 1
        if self.close_reason is None:
            self.close_reason = reason

    async def _serve(self) -> None:
        limit = _startup_deadline()
        try:
            async with stdio_client(_stdio_params(self.spec)) as (read, write):
                async with ClientSession(read, write) as session:
                    # The startup budget belongs to this task, which also owns the
                    # context managers: a caller that gives up or is cancelled can no
                    # longer remove the bound on spawn + initialize.
                    try:
                        await asyncio.wait_for(session.initialize(), limit)
                    except asyncio.TimeoutError:
                        self.close_reason = f"startup exceeded {limit:g}s; session killed"
                        return
                    self._initialized = True
                    self._ready.set()
                    await self._pump(session)
        except asyncio.CancelledError:
            if self.close_reason is None:
                self.close_reason = "cancelled"
            raise
        except Exception as exc:  # noqa: BLE001 - a dead backend must not kill the router
            if self.close_reason is None:
                self.close_reason = _describe_exc(exc)
        finally:
            if self.close_reason is None:
                self.close_reason = "closed"
            if not self._initialized:
                self.start_error = self.close_reason
            self._ready.set()
            self._fail_pending(self.close_reason)
            _RECENT.append(self.info())
            _forget(self)

    async def _pump(self, session: ClientSession) -> None:
        while True:
            request = await self._next_request()
            if request is None:
                return
            if request.cancelled or request.future.done():
                # Cancelled while still queued: the operation was never dispatched, so
                # it must not touch the backend at all.
                continue
            request.dispatched = True
            self._active = request
            try:
                served, result = await self._run(session, request)
            finally:
                self._active = None
            if not served:
                return
            self.calls += 1
            self.last_used = time.monotonic()
            request.settle(result=result)

    async def _run(self, session: ClientSession, request: _Request) -> tuple[bool, Any]:
        """Run one dispatched operation while watching the caller's future.

        Returns (served, result); served=False means this session is retiring and the
        caller's future was already settled. Watching both sides means a caller that
        stops waiting retires the session at once instead of leaving it looking healthy
        until the operation's own deadline, and the unknown-outcome record is written on
        every terminal path (success after cancel, timeout, transport failure, close)
        rather than only when the operation happens to return successfully.
        """
        operation = asyncio.ensure_future(request.operation(session))
        try:
            await asyncio.wait(
                {operation, request.future},
                timeout=request.timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if operation.done():
                if operation.cancelled():
                    self._retire("backend call was cancelled without a result; outcome unknown", unknown=True)
                    request.settle(error=RuntimeError(self.close_reason))
                    return False, None
                error = operation.exception()
                if error is None:
                    if request.abort_reason is not None or request.cancelled or request.future.done():
                        self._retire(
                            "caller stopped waiting while the call completed; mutation outcome unknown",
                            unknown=True,
                        )
                        request.settle(error=RuntimeError(self.close_reason))
                        return False, None
                    return True, operation.result()
                self._retire(f"backend call failed: {_describe_exc(error)}; mutation outcome unknown",
                             unknown=request.dispatched)
                request.settle(error=RuntimeError(self.close_reason))
                return False, None
            if request.abort_reason is not None:
                reason, unknown = request.abort_reason, True
            elif request.cancelled or request.future.done():
                reason = "caller cancelled while the call was in flight; mutation outcome unknown"
                unknown = True
            else:
                reason = f"call exceeded {request.timeout:g}s; session killed; mutation outcome unknown"
                unknown = request.dispatched
            self._retire(reason, unknown=unknown)
            request.settle(error=RuntimeError(self.close_reason))
            return False, None
        except asyncio.CancelledError:
            # Router shutdown or close while a call was in flight: part of it may have
            # reached the backend, so the outcome is recorded as unknown.
            self._retire(
                f"session terminated while request was in flight: {self.close_reason or 'cancelled'}",
                unknown=request.dispatched,
            )
            request.settle(error=RuntimeError(
                f"session '{self.session_id}' terminated while request was in flight: "
                f"{self.close_reason or 'cancelled'}"
            ))
            raise
        finally:
            if not operation.done():
                operation.cancel()

    async def _next_request(self):
        while True:
            if self.close_reason is not None:
                return None
            if self.idle_timeout <= 0:
                return await self._queue.get()
            remaining = self.idle_timeout - (time.monotonic() - self.last_used)
            if remaining <= 0:
                self.close_reason = f"idle for {self.idle_timeout:g}s; reclaimed"
                return None
            try:
                return await asyncio.wait_for(self._queue.get(), remaining)
            except asyncio.TimeoutError:
                continue

    def _fail_pending(self, reason: str) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if item is None:
                continue
            item.settle(error=RuntimeError(f"session '{self.session_id}' closed: {reason}"))


_SESSIONS: dict[str, _BackendSession] = {}
# Every created supervisor stays owned here until its own task is done. This registry
# is independent of the address map on purpose: a session detached from _SESSIONS (by
# close, or by a replacement under the same id) is still a live process someone has to
# reap, and shutdown must be able to find it.
_OWNED: "set[_BackendSession]" = set()
# Set for the life of the process once the MCP client's lifespan ends: shutdown must
# converge, so a late call may not spawn a backend behind the client's back.
_SHUTDOWN = False
# Time-box for exiting the supervisor task and its child process, kept separate from
# the per-call operation deadline.
_CLEANUP_BUDGET = 15.0
# How long a close lets the call already in flight finish before the process is killed.
_CLOSE_GRACE = 2.0
# Why a backend died is the first question after a failed call, and the session is gone
# from _SESSIONS by then; keep the last few exits as data instead of as a log line.
_RECENT: "deque[dict[str, Any]]" = deque(maxlen=8)
# asyncio.Lock binds to the loop that first awaits it; smoke scripts run one
# asyncio.run per backend, so the lock is keyed by loop and dropped with it.
_SESSION_LOCKS: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = weakref.WeakKeyDictionary()


def _consume(task: asyncio.Task) -> None:
    """Read a task's terminal state so an unobserved task never logs 'never retrieved'."""
    if task.cancelled():
        return
    with suppress(BaseException):
        task.exception()


def _session_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _SESSION_LOCKS.get(loop)
    if lock is None:
        lock = asyncio.Lock()
        _SESSION_LOCKS[loop] = lock
    return lock


def _forget(session: _BackendSession) -> None:
    if _SESSIONS.get(session.session_id) is session:
        _SESSIONS.pop(session.session_id, None)


async def _get_session(
    backend: str,
    session_id: str | None = None,
    idle_timeout_seconds: float | None = None,
    startup_timeout: float | None = None,
) -> tuple[_BackendSession, bool]:
    """Return (session, created). The default session id is the backend name."""
    backends = _load_backends()
    if backend not in backends:
        raise ValueError(f"Unknown backend '{backend}'. Use list_backends first.")
    if _SHUTDOWN:
        raise RuntimeError("router is shutting down; refusing to start a new backend session")
    sid = (session_id or "").strip() or backend
    async with _session_lock():
        session = _SESSIONS.get(sid)
        if session is not None and (session.loop is not asyncio.get_running_loop() or not session.alive):
            _SESSIONS.pop(sid, None)
            session = None
        if session is not None and session.backend != backend:
            raise ValueError(f"session '{sid}' belongs to backend '{session.backend}', not '{backend}'")
        if session is not None and session.spec != backends[backend]:
            raise ValueError("DESCRIPTOR_CHANGED: close the existing session or choose a new session_id")
        if session is not None and idle_timeout_seconds is not None:
            session.idle_timeout = float(idle_timeout_seconds)
        created = session is None
        if created:
            idle = _idle_timeout() if idle_timeout_seconds is None else float(idle_timeout_seconds)
            session = _BackendSession(sid, backend, backends[backend], idle)
            _SESSIONS[sid] = session
    await session.start(startup_timeout)
    return session, created


async def _close_sessions(session_id: str = "*") -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    async with _session_lock():
        targets = [
            session
            for sid, session in list(_SESSIONS.items())
            if session.loop is loop and (session_id in ("", "*") or sid == session_id)
        ]
    for session in targets:
        async with _session_lock():
            # Detach by object identity: a replacement registered under the same
            # session_id while this close was in progress must stay registered.
            if _SESSIONS.get(session.session_id) is session:
                _SESSIONS.pop(session.session_id, None)
        await session.close("closed by client")
    return {
        "closed": [session.session_id for session in targets],
        "closed_count": len(targets),
        "remaining": sorted(sid for sid, session in _SESSIONS.items() if session.loop is loop and session.alive),
    }


async def _await_owned(budget: float = _CLEANUP_BUDGET) -> list[str]:
    """Wait until every owned supervisor is terminal; return any that outlived `budget`.

    Ownership does not depend on _SESSIONS, so this also converges a session that was
    detached from the address map by a close whose caller was then cancelled.
    """
    loop = asyncio.get_running_loop()
    deadline = time.monotonic() + budget
    while True:
        pending = [session for session in list(_OWNED) if session.loop is loop and not session._task.done()]
        if not pending:
            return []
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return sorted(session.session_id for session in pending)
        await asyncio.wait({session.begin_close("router shutting down") for session in pending}, timeout=remaining)


async def _with_backend(
    backend: str,
    timeout_seconds: float | None,
    operation: Callable[[ClientSession], Awaitable[Any]],
    session_id: str | None = None,
    close_after: bool = False,
    idle_timeout_seconds: float | None = None,
) -> tuple[Any, dict[str, Any]]:
    timeout = _clamp_timeout(timeout_seconds)
    session, created = await _get_session(
        backend, session_id, idle_timeout_seconds, startup_timeout=timeout
    )
    try:
        result = await session.request(operation, timeout)
    finally:
        if close_after:
            await session.close("close_after requested")
    meta = {
        "session_id": session.session_id,
        "session_reused": not created,
        "session_calls": session.calls,
        "timeout_seconds": timeout,
    }
    return result, meta


@mcp.tool()
def list_backends() -> dict[str, Any]:
    """List available on-demand debugger MCP backends without starting them."""
    backends = _load_backends()
    return {
        "count": len(backends),
        "default_startup": "Only debugger-router should be enabled by default; these backends start on the first router call that needs them and then stay warm.",
        "session_policy": {
            "warm_processes": "A backend process stays alive between calls; the default session id is the backend name.",
            "idle_timeout_seconds": _idle_timeout(),
            "call_timeout_seconds": _timeout_cap(),
        },
        "backends": [
            {
                "name": name,
                "command": spec.command,
                "args_count": len(spec.args),
                "cwd": spec.cwd,
                "env_policy": spec.env_policy,
                "env_keys": [key for key, _ in spec.env],
                "env_inherit": list(spec.env_inherit),
                "category": BACKEND_META.get(name, {}).get("category", "unknown"),
                "note": BACKEND_META.get(name, {}).get("note", ""),
            }
            for name, spec in sorted(backends.items())
        ],
    }


@mcp.tool()
async def list_backend_tools(
    backend: str,
    include_schemas: bool = False,
    timeout_seconds: float = 40.0,
    session_id: str | None = None,
    close_after: bool = False,
) -> dict[str, Any]:
    """List one backend's tools on its warm session (session_id defaults to the backend name).

    The process stays warm for the call_backend_tool that usually follows; pass close_after=true
    when sweeping many backends and you do not intend to use them.
    """

    async def operation(session: ClientSession):
        tools_result = await session.list_tools()
        tools = []
        for tool in tools_result.tools:
            item = {
                "name": tool.name,
                "description": (tool.description or "")[:1200],
            }
            if include_schemas:
                item["input_schema"] = _jsonable(getattr(tool, "inputSchema", None))
            tools.append(item)
        return {
            "backend": backend,
            "tool_count": len(tools),
            "tools": tools,
        }

    started = time.monotonic()
    result, meta = await _with_backend(
        backend, timeout_seconds, operation, session_id=session_id, close_after=close_after
    )
    result.update(meta)
    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    return result


@mcp.tool()
async def call_backend_tool(
    backend: str,
    tool_name: str,
    arguments_json: str = "{}",
    timeout_seconds: float | None = None,
    session_id: str | None = None,
    close_after: bool = False,
) -> dict[str, Any]:
    """Call one backend tool on its warm session, keeping the backend process alive for the next call.

    session_id addresses the backend process: omit it to reuse the backend's default session,
    or pass a new id to run a second, independent process of the same backend. timeout_seconds
    is clamped to DEBUGGER_ROUTER_TIMEOUT (default 900); a call that exceeds it kills the session
    instead of leaving a wedged process behind.
    """
    arguments = _parse_args(arguments_json)

    async def operation(session: ClientSession):
        call = await session.call_tool(tool_name, arguments)
        return {
            "backend": backend,
            "tool": tool_name,
            "is_error": bool(getattr(call, "isError", False)),
            "content": _jsonable(getattr(call, "content", None)),
            "structured_content": _jsonable(getattr(call, "structuredContent", None)),
        }

    started = time.monotonic()
    result, meta = await _with_backend(
        backend,
        timeout_seconds,
        operation,
        session_id=session_id,
        close_after=close_after,
    )
    result.update(meta)
    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    return result


@mcp.tool()
async def smoke_backend(backend: str, timeout_seconds: float = 40.0) -> dict[str, Any]:
    """Start one backend once and verify MCP initialize plus tools/list, then reclaim it."""
    started = time.monotonic()
    result = await list_backend_tools(
        backend=backend,
        include_schemas=False,
        timeout_seconds=timeout_seconds,
        close_after=True,
    )
    return {
        "backend": backend,
        "status": "PASS" if result.get("tool_count", 0) > 0 else "FAIL_NO_TOOLS",
        "tool_count": result.get("tool_count", 0),
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }


@mcp.tool()
async def open_backend_session(
    backend: str,
    session_id: str | None = None,
    idle_timeout_seconds: float | None = None,
) -> dict[str, Any]:
    """Start (or reuse) a backend process and keep it warm for later call_backend_tool calls."""
    started = time.monotonic()

    async def operation(session: ClientSession):
        tools_result = await session.list_tools()
        return {"tool_count": len(tools_result.tools)}

    session, created = await _get_session(
        backend, session_id, idle_timeout_seconds, startup_timeout=_clamp_timeout(120.0)
    )
    detail = await session.request(operation, _clamp_timeout(120.0))
    return {
        "backend": backend,
        "session_id": session.session_id,
        "created": created,
        "tool_count": detail["tool_count"],
        "idle_timeout_seconds": session.idle_timeout,
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }


@mcp.tool()
async def list_backend_sessions() -> dict[str, Any]:
    """List backend processes kept warm between calls, plus the last few that were reclaimed."""
    loop = asyncio.get_running_loop()
    sessions = [session.info() for session in _SESSIONS.values() if session.loop is loop and session.alive]
    return {
        "count": len(sessions),
        "sessions": sorted(sessions, key=lambda item: item["session_id"]),
        "recently_closed": list(_RECENT),
        "policy": {
            "default_session_id": "the backend name",
            "idle_timeout_seconds": _idle_timeout(),
            "call_timeout_seconds": _timeout_cap(),
        },
    }


@mcp.tool()
async def close_backend_session(session_id: str = "*") -> dict[str, Any]:
    """Close one warm backend session by id, or every session when session_id is '*'."""
    result = await _close_sessions(session_id)
    if session_id not in ("", "*") and not result["closed"]:
        raise ValueError(f"No live session '{session_id}'. Use list_backend_sessions first.")
    return result


@mcp.tool()
def workflow_help() -> dict[str, Any]:
    """Show how the AI client should use this router and how to start direct MCP profiles when needed."""
    return {
        "normal_workflow": [
            "Use list_backends to choose a backend.",
            "Use list_backend_tools with include_schemas=true when arguments are unclear.",
            "Use call_backend_tool to run the specific backend tool.",
            "The backend process stays warm between calls; reuse the same session_id instead of paying startup again.",
        ],
        "sessions": [
            "A backend process outlives a single call: the default session id is the backend name.",
            "Pass session_id to address a specific process, or open_backend_session to start one explicitly.",
            "list_backend_sessions shows warm processes, their idle age, and why a closed one died.",
            "close_backend_session('*') reclaims every warm process; the router also does this on shutdown.",
            "An unused session is reclaimed after DEBUGGER_ROUTER_IDLE_TIMEOUT seconds (default 600, <=0 disables).",
            "One call may run for up to DEBUGGER_ROUTER_TIMEOUT seconds (default 900); exceeding it kills that session.",
            "close_after=true on a call keeps the old one-shot behavior: start, call, reclaim.",
        ],
        "direct_profile_examples": [
            "codex --profile mcp-mobile",
            "codex --profile mcp-re",
            "codex --profile mcp-net",
            "codex --profile mcp-ce",
            "codex --profile mcp-all",
        ],
        "important_limit": (
            "Some MCP clients do not currently hot-add new MCP tool lists into an already running session. "
            "The router is the default on-demand workaround."
        ),
    }


if __name__ == "__main__":
    mcp.run()
