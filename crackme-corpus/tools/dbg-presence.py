#!/usr/bin/env python3
"""dbg-presence -- run a sample as the debuggee of a real Win32 debugger.

Why this exists: crackme #3 detects being debugged, and the only honest way to
demonstrate that is to actually debug it. The station ships no headless
debugger (no cdb.exe -- the Windows SDK here has only dbghelp.dll), and the
GUI debuggers cannot be driven from a script, so this is a ~120-line debugger
built on the Win32 debug API:

    CreateProcessW(..., DEBUG_ONLY_THIS_PROCESS)   -> PEB->BeingDebugged = 1
    WaitForDebugEvent / ContinueDebugEvent loop

It is the minimum needed to be "a debugger" as far as the target is concerned:
it sets the debug flag, it receives the debug events, and it lets the process
run to completion. The debuggee's stdout is captured through an inheritable
pipe and echoed, so the effect of being observed is visible in the output.

Usage:  dbg-presence.py <exe> [args...]
Exit:   the debuggee's exit code (2 if the harness itself failed).
"""
import ctypes
import sys
import threading
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

DEBUG_ONLY_THIS_PROCESS = 0x00000002
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT = 0x1
EXIT_PROCESS_DEBUG_EVENT = 0x5
EXCEPTION_BREAKPOINT = 0x80000003
HANDLE_FLAG_INHERIT = 0x00000001
STARTF_USESTDHANDLES = 0x00000100
INFINITE = 0xFFFFFFFF


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", wintypes.LPVOID),
                ("bInheritHandle", wintypes.BOOL)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", wintypes.DWORD),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
                ("u", ctypes.c_byte * 200)]

    def info_dword(self):
        return int.from_bytes(bytes(self.u[0:4]), "little")


def die(msg):
    print(f"dbg-presence: FAIL {msg} (winerror={ctypes.get_last_error()})")
    sys.exit(2)


def cmdline_of(argv):
    """Quote for CreateProcessW's lpCommandLine."""
    return " ".join('"' + a.replace('"', '\\"') + '"' if (" " in a or not a) else a for a in argv)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    argv = sys.argv[1:]

    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
    rd, wr = wintypes.HANDLE(), wintypes.HANDLE()
    if not k32.CreatePipe(ctypes.byref(rd), ctypes.byref(wr), ctypes.byref(sa), 0):
        die("CreatePipe")
    k32.SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0)

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    si.dwFlags = STARTF_USESTDHANDLES
    si.hStdInput = k32.GetStdHandle(-10)
    si.hStdOutput = wr
    si.hStdError = wr
    pi = PROCESS_INFORMATION()

    line = ctypes.create_unicode_buffer(cmdline_of(argv))
    ok = k32.CreateProcessW(None, line, None, None, True, DEBUG_ONLY_THIS_PROCESS,
                            None, None, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        die(f"CreateProcessW({argv[0]})")
    k32.CloseHandle(wr)

    chunks = []

    def pump_stdout():
        buf = ctypes.create_string_buffer(4096)
        read = wintypes.DWORD()
        while k32.ReadFile(rd, buf, 4096, ctypes.byref(read), None):
            if read.value == 0:
                break
            data = buf.raw[:read.value]
            chunks.append(data)
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    reader = threading.Thread(target=pump_stdout, daemon=True)
    reader.start()

    ev = DEBUG_EVENT()
    exit_code = None
    events = 0
    while True:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), INFINITE):
            die("WaitForDebugEvent")
        events += 1
        if ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
            exit_code = ev.info_dword()
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
            break
        cont = DBG_CONTINUE
        if ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT and ev.info_dword() != EXCEPTION_BREAKPOINT:
            cont = DBG_EXCEPTION_NOT_HANDLED
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

    reader.join(timeout=5)
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)
    print(f"dbg-presence: pid={pi.dwProcessId} debug-events={events} exit={exit_code} "
          f"(PEB->BeingDebugged was set for the whole run)")
    return exit_code if exit_code is not None else 2


if __name__ == "__main__":
    sys.exit(main())
