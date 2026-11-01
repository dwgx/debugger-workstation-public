#!/usr/bin/env python3
"""frida_runtime_facts.py -- three runtime addresses out of a spawned self-built PE, as JSON.

WHY THIS EXISTS. `dynamic.win.frida` produces runtime.module.base, runtime.export.addr and
runtime.hook.addr, and its probe measured all three -- but the probe is a fixed `frida -f`
one-liner against $env:TEMP\\fridaprobe\\target.exe, so nothing could hand it a target. The
entry's not_callable.reason records that the three shapes it tried for an invoke were refused
by R16/R10 because they carried the instrumentation itself in argv. The fix is not a cleverer
argv: it is this script, which owns the instrumentation and takes ONE path.

The ordering is the whole capability and is copied from native-lab/tools/frida_spawn_gate.py,
which measured it: spawn(suspended) -> attach -> create_script -> load -> resume. The
`frida -f` CLI resumes BEFORE the script loads, which is why no callback fires there and why
this entry's does_not_prove says the probe proved addresses and not interception.

WHY NOT `import frida_spawn_gate`. Its module level dup2's fd 1 to catch the spawned target's
inherited handle, and sets TARGET/MODE from argv at import time. Importing it from a second
caller would redirect the caller's stdout as a side effect. The staging rule below is
deliberately the same rule, restated in ten lines rather than imported at that cost.

STDOUT IS ONE JSON OBJECT. mission.ps1 merges stdout and stderr before parsing, so every
diagnostic -- and anything the target prints -- goes to stderr.

Exit: 0 all three addresses resolved, 1 refused (not a repo/%TEMP% .exe), 2 could not run.
"""
import argparse
import json
import os
import shutil
import sys
import tempfile
import threading

import frida

STATION = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# STDOUT MUST BE PURE JSON, AND A PYTHON-LEVEL SWAP IS NOT ENOUGH. The spawned target
# INHERITS this process's fd 1 and prints its own `usage: <exe> <password>` line there, which
# is exactly how this wrapper first shipped a broken invoke: exit 0, valid JSON, and one line
# of the target's output ahead of it, so json.loads failed at character 0. Same defect and
# same fix as native-lab/tools/frida_spawn_gate.py:28-46 -- dup2 fd 1 onto fd 2 for the whole
# run, keep a private duplicate of the original for the ONE object that must be parsed.
_OUT_FD = os.dup(1)
os.dup2(2, 1)
sys.stdout = sys.stderr


def write_json(obj):
    (os.fdopen(_OUT_FD, "w") if _OUT_FD is not None else sys.stdout).write(json.dumps(obj) + "\n")


def refuse(msg, code=1, **extra):
    write_json(dict(ok=False, exit=code, error=msg, **extra))
    sys.exit(code)


def _under(path, root):
    """Is `path` inside `root`? Cross-drive pairs raise in commonpath, and a containment
    check that CRASHES on the very input it exists to refuse is worse than no check --
    measured: --target C:\\Windows\\System32\\notepad.exe raised
    ValueError: Paths don't have the same drive, so the refusal never printed."""
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:
        return False


def pe_image_base(path):
    """PE ImageBase, parsed directly. The static VA the caller may hand us is in IMAGE space,
    so the RVA is `va - ImageBase` -- and this is the only place that offset comes from."""
    import struct
    with open(path, "rb") as fh:
        data = fh.read(0x1000)
    if data[:2] != b"MZ":
        raise ValueError("not an MZ image")
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\x00\x00":
        raise ValueError("no PE signature")
    opt = e + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B else struct.unpack_from("<I", data, opt + 28)[0]
    return {"magic": hex(magic), "entry_rva": entry, "image_base": base}


JS = r"""
var RVA = %(rva)d;
var EXPORT_NAME = %(export_name)s;
var mod = Process.mainModule;
send({kind: "module", name: mod.name, base: mod.base.toString(), size: mod.size,
      path: String(mod.path)});
try {
  var exp = Module.getGlobalExportByName(EXPORT_NAME);
  send({kind: "export", name: EXPORT_NAME, addr: exp.toString()});
} catch (e) {
  send({kind: "export-error", message: String(e.message || e)});
}
var hook = mod.base.add(RVA);
var inImage = hook.compare(mod.base) >= 0 && hook.compare(mod.base.add(mod.size)) < 0;
try {
  Interceptor.attach(hook, { onEnter: function () { send({kind: "HIT", tid: Process.getCurrentThreadId()}); } });
  send({kind: "attached", at: hook.toString(), inImage: inImage});
} catch (e) {
  send({kind: "attach-error", message: String(e.message || e), at: hook.toString(), inImage: inImage});
}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="a self-built PE (.exe)")
    ap.add_argument("--static-va", default=None,
                    help="optional IMAGE-space address (e.g. a native.func.addr fact); "
                         "its RVA is taken as va - ImageBase")
    ap.add_argument("--export", default="printf", help="export name to resolve (default printf)")
    ap.add_argument("--stage-dir", default=None,
                    help="where to put the executed copy. Default: a fresh %%TEMP%% dir, removed "
                         "afterwards. The registry passes {scratch:frida}, which mission.ps1 "
                         "creates inside the mission case dir, so write_scope: case_dir is true.")
    ap.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args()

    target = os.path.abspath(a.target)
    if not os.path.isfile(target):
        refuse("no such file: %s" % target)
    if not target.lower().endswith(".exe"):
        refuse("refusing %r: this lane spawns a Windows PE from the corpus, not an arbitrary file" % target)

    # The entry's own gate_prohibitions declare `target_must_be_self_authored` with operand
    # require: repo_or_temp. Enforced here so the declaration is not just a comment.
    roots = [os.path.abspath(STATION), os.path.abspath(tempfile.gettempdir())]
    if not any(_under(target, r) for r in roots if os.path.isdir(r)):
        refuse("refusing %r: not under the station tree or %%TEMP%% (gate_prohibitions: "
               "target_must_be_self_authored / repo_or_temp)" % target)

    facts = pe_image_base(target)
    if a.static_va:
        va = int(a.static_va, 16) if str(a.static_va).lower().startswith("0x") else int(a.static_va)
        rva = va - facts["image_base"]
        basis = "static_va %#x - ImageBase %#x" % (va, facts["image_base"])
        if rva < 0:
            refuse("static VA %#x is below ImageBase %#x, so it is not in this image"
                   % (va, facts["image_base"]))
    else:
        rva = facts["entry_rva"]
        basis = "PE entry RVA %#x (no --static-va given)" % rva

    # The repository original is NEVER executed: the staged copy is what gets spawned.
    # When --stage-dir is supplied the copy lives there and the caller owns the directory;
    # otherwise it is a fresh %TEMP% dir that this script removes on the way out.
    owned = a.stage_dir is None
    stage_dir = tempfile.mkdtemp(prefix="fridafacts-") if owned else os.path.abspath(a.stage_dir)
    os.makedirs(stage_dir, exist_ok=True)
    staged = os.path.join(stage_dir, os.path.basename(target))
    shutil.copy2(target, staged)

    events = []
    result = {}
    done = threading.Event()
    device = frida.get_local_device()
    pid = device.spawn([staged])
    session = device.attach(pid)
    try:
        def on_message(message, data):
            if message.get("type") == "send":
                payload = message["payload"]
                events.append(payload)
                # The script's own last statement is the attach attempt; waiting on it rather
                # than on a fixed sleep means a slow host costs nothing and a script that
                # never reports is still bounded by --timeout.
                if payload.get("kind") in ("attached", "attach-error"):
                    done.set()
            elif message.get("type") == "error":
                events.append({"kind": "script-error", "message": str(message.get("description"))})
                done.set()

        script = session.create_script(JS % {"rva": rva, "export_name": json.dumps(a.export)})
        script.on("message", on_message)
        script.load()          # main thread is STILL suspended here -- this is the ordering
        device.resume(pid)

        done.wait(a.timeout)   # bounded: a script that never reports must not hang the round

        module = next((e for e in events if e.get("kind") == "module"), {})
        export = next((e for e in events if e.get("kind") == "export"), {})
        export_err = next((e for e in events if e.get("kind") == "export-error"), {})
        attached = next((e for e in events if e.get("kind") == "attached"), {})
        attach_err = next((e for e in events if e.get("kind") == "attach-error"), {})
        hit = next((e for e in events if e.get("kind") == "HIT"), {})

        result = {
            "ok": bool(module.get("base") and export.get("addr") and (attached or attach_err)),
            "exit": 0,
            "target": target,
            "staged": staged,
            "module": {"name": module.get("name"), "base": module.get("base"), "size": module.get("size")},
            "module_base": module.get("base"),
            "export_name": a.export,
            "export_addr": export.get("addr"),
            "hook_addr": attached.get("at") or attach_err.get("at"),
            "hook_in_image": attached.get("inImage") if attached else attach_err.get("inImage"),
            "hook_attach": "ACCEPTED" if attached else ("REFUSED: %s" % attach_err.get("message") if attach_err else "not attempted"),
            "hook_basis": basis,
            "hit": hit or None,
            "caveat": "These are ADDRESSES from ONE process lifetime, re-randomised on the next "
                      "spawn -- read them at runtime, never hardcode them. `hook_attach: ACCEPTED` "
                      "says the address was attachable; `hit` is the only field that would say a "
                      "callback FIRED, and it is usually null because this target's entry point "
                      "does not call the hooked address again before the wait expires.",
        }
        if export_err:
            result["export_error"] = export_err.get("message")
    finally:
        for fn in (session.detach, lambda: device.kill(pid)):
            try:
                fn()
            except Exception:
                pass
        if owned:
            shutil.rmtree(stage_dir, ignore_errors=True)

    write_json(result)
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    sys.exit(main())
