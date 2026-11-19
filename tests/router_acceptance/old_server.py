import asyncio
import builtins
import json
import os
import time
import weakref
from collections import deque
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
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
    "ida": {"category": "static-reversing", "note": "IDA Pro plugin bridge (port 13337); needs user-supplied IDA Pro 8.3+ with the ida-pro-mcp plugin installed."},
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
    try:
        yield {}
    finally:
        await _close_sessions("*")


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


def _load_backends() -> dict[str, str]:
    # utf-8-sig tolerates a UTF-8 BOM in case the config was hand-edited or
    # written by a tool that prepends one.
    path = BACKEND_CONFIG
    if not path.is_file():
        path = ROOT / "mcp" / ".mcp.json.template"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    servers = data.get("mcpServers", {})
    backends: dict[str, str] = {}
    for name, cfg in servers.items():
        if name == "debugger-router":
            continue
        command = cfg.get("command")
        if command:
            backends[name] = _resolve_command(command)
    return backends


def _backend_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["FASTMCP_SHOW_SERVER_BANNER"] = "false"
    env["FASTMCP_CHECK_FOR_UPDATES"] = "off"
    env["FASTMCP_ENABLE_RICH_LOGGING"] = "false"
    env["PATH"] = str(MCP_ROOT / "bin") + os.pathsep + env.get("PATH", "")
    return env


def _stdio_params(command: str) -> StdioServerParameters:
    if command.lower().endswith((".cmd", ".bat")):
        return StdioServerParameters(command="cmd.exe", args=["/c", command], env=_backend_env())
    return StdioServerParameters(command=command, args=[], env=_backend_env())


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


class _BackendSession:
    """One backend MCP process kept warm across router calls, addressed by session_id.

    anyio requires a context manager to be exited in the task that entered it, so
    `stdio_client` and `ClientSession` are owned by a single supervisor task; callers
    hand their operation to that task over a queue instead of driving the session
    themselves. Calls to one session are therefore serialized (the backends here are
    single-context bridges anyway), and a session that times out or raises is killed
    rather than reused: a wedged backend must not silently swallow the next call.
    """

    def __init__(self, session_id: str, backend: str, command: str, idle_timeout: float):
        self.session_id = session_id
        self.backend = backend
        self.command = command
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
        self._task = self.loop.create_task(self._serve())

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
        }

    async def start(self) -> None:
        await self._ready.wait()
        if self.start_error:
            raise RuntimeError(f"backend '{self.backend}' failed to start: {self.start_error}")

    async def request(self, operation, timeout: float):
        if not self.alive:
            raise RuntimeError(f"session '{self.session_id}' is closed ({self.close_reason or 'not ready'})")
        future = self.loop.create_future()
        self._queue.put_nowait((operation, timeout, future))
        if self._task.done():
            # The supervisor died between the check above and the enqueue; nothing
            # will ever pop this request, so fail it here instead of hanging.
            raise RuntimeError(f"session '{self.session_id}' is closed ({self.close_reason or 'died'})")
        try:
            return await future
        finally:
            if not future.done():
                future.cancel()

    async def close(self, reason: str = "closed by client") -> None:
        if self.close_reason is None:
            self.close_reason = reason
        self._queue.put_nowait(None)  # sentinel: leave the supervisor loop
        try:
            await asyncio.wait_for(self._task, 15.0)
        except asyncio.TimeoutError:
            pass  # wait_for already cancelled the task; its cleanup is time-boxed by the SDK
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001,S110 - teardown already reported via close_reason
            pass

    async def _serve(self) -> None:
        try:
            async with stdio_client(_stdio_params(self.command)) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
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
            operation, timeout, future = request
            try:
                result = await asyncio.wait_for(operation(session), timeout)
            except asyncio.TimeoutError:
                self.close_reason = f"call exceeded {timeout:g}s; session killed"
                if not future.done():
                    future.set_exception(RuntimeError(self.close_reason))
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - transport failure poisons this session only
                self.close_reason = f"backend call failed: {_describe_exc(exc)}"
                if not future.done():
                    future.set_exception(RuntimeError(self.close_reason))
                return
            self.calls += 1
            self.last_used = time.monotonic()
            if not future.done():
                future.set_result(result)

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
            _, _, future = item
            if not future.done():
                future.set_exception(RuntimeError(f"session '{self.session_id}' closed: {reason}"))


_SESSIONS: dict[str, _BackendSession] = {}
# Why a backend died is the first question after a failed call, and the session is gone
# from _SESSIONS by then; keep the last few exits as data instead of as a log line.
_RECENT: "deque[dict[str, Any]]" = deque(maxlen=8)
# asyncio.Lock binds to the loop that first awaits it; smoke scripts run one
# asyncio.run per backend, so the lock is keyed by loop and dropped with it.
_SESSION_LOCKS: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = weakref.WeakKeyDictionary()


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
) -> tuple[_BackendSession, bool]:
    """Return (session, created). The default session id is the backend name."""
    backends = _load_backends()
    if backend not in backends:
        raise ValueError(f"Unknown backend '{backend}'. Use list_backends first.")
    sid = (session_id or "").strip() or backend
    async with _session_lock():
        session = _SESSIONS.get(sid)
        if session is not None and (session.loop is not asyncio.get_running_loop() or not session.alive):
            _SESSIONS.pop(sid, None)
            session = None
        if session is not None and session.backend != backend:
            raise ValueError(f"session '{sid}' belongs to backend '{session.backend}', not '{backend}'")
        if session is not None and idle_timeout_seconds is not None:
            session.idle_timeout = float(idle_timeout_seconds)
        created = session is None
        if created:
            idle = _idle_timeout() if idle_timeout_seconds is None else float(idle_timeout_seconds)
            session = _BackendSession(sid, backend, backends[backend], idle)
            _SESSIONS[sid] = session
    await session.start()
    return session, created


async def _close_sessions(session_id: str = "*") -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    targets = [
        session
        for sid, session in list(_SESSIONS.items())
        if session.loop is loop and (session_id in ("", "*") or sid == session_id)
    ]
    for session in targets:
        _SESSIONS.pop(session.session_id, None)
        await session.close("closed by client")
    return {
        "closed": [session.session_id for session in targets],
        "closed_count": len(targets),
        "remaining": sorted(sid for sid, session in _SESSIONS.items() if session.loop is loop and session.alive),
    }


async def _with_backend(
    backend: str,
    timeout_seconds: float | None,
    operation: Callable[[ClientSession], Awaitable[Any]],
    session_id: str | None = None,
    close_after: bool = False,
    idle_timeout_seconds: float | None = None,
) -> tuple[Any, dict[str, Any]]:
    session, created = await _get_session(backend, session_id, idle_timeout_seconds)
    timeout = _clamp_timeout(timeout_seconds)
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
                "command": command,
                "category": BACKEND_META.get(name, {}).get("category", "unknown"),
                "note": BACKEND_META.get(name, {}).get("note", ""),
            }
            for name, command in sorted(backends.items())
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

    session, created = await _get_session(backend, session_id, idle_timeout_seconds)
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
