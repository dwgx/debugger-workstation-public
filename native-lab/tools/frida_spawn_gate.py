#!/usr/bin/env python3
"""
frida_spawn_gate.py -- minimal headless spawn-gate interception proof.

The frida CLI resumes the main thread BEFORE the script is loaded, so no
onEnter ever fires against a spawn-gated process.  This recipe keeps the API
ordering that actually intercepts:

    spawn (suspended) -> attach -> create_script -> load -> resume

Modes
-----
positive     hook the real PE entry point; expect exactly one HIT.
neg-badaddr  hook an address one module-size past the end of the image.
             Must fail with an attach error WHILE the module base still
             resolved -- it must fail for its own reason, and be
             distinguishable from a rebase failure.
neg-rebase   ask for a module that is genuinely not loaded.  Must be
             reported as REBASE-FAILURE with no address computed at all --
             a different reason again.

Terminates on its own: the target is a single-shot self-authored crackme and
the recipe kills it as soon as the verdict is decided.  No --timeout, no
polling loop, no sleep.
"""
import json
import struct
import sys
import os
import shutil
import tempfile
import threading

import frida

TARGET = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tempfile.gettempdir(), "w13", "c01-stringobf.exe")
MODE = sys.argv[2] if len(sys.argv) > 2 else "positive"
ARGV_PW = sys.argv[3] if len(sys.argv) > 3 else "C01-TABLE-XOR-9F2A"

EXIT = {"INTERCEPT-PROVEN": 0, "NEGCTL-OK": 0, "INTERCEPT-FAILED": 5,
        "NEGCTL-BROKEN": 4, "REBASE-FAILURE": 3}


def pe_entry_rva(path):
    """Parse the PE headers directly -- no third-party dependency."""
    with open(path, "rb") as fh:
        data = fh.read(0x1000)
    if data[:2] != b"MZ":
        raise ValueError("not an MZ image")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("no PE signature")
    coff = e_lfanew + 4
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    return {"magic": hex(magic), "entry_rva": entry, "size_of_image": size_of_image}


JS = r"""
var MODE = %(mode)s;
var ENTRY_RVA = %(entry)d;
var mod = Process.mainModule;

// The rebase is reported on its own event, before any address is computed,
// so "bad address" can never be confused with "failed to rebase".
send({kind: "module", name: mod.name, base: mod.base.toString(),
      size: mod.size, path: mod.path});

if (MODE === "neg-rebase") {
  // Genuine failure: ask for a module that is genuinely not loaded.  On
  // Windows findModuleByName returns null instead of raising, so the honest
  // shape of a rebase failure is a null base -- and the first real error is
  // therefore a COMPUTE error, never an attach error.
  var missing = Process.findModuleByName("w13-no-such-module.dll");
  send({kind: "rebase", ok: false, base: String(missing),
        reason: "target module not loaded: base is " + String(missing)});
  try {
    Interceptor.attach(missing.base.add(ENTRY_RVA), {
      onEnter: function () { send({kind: "HIT"}); }
    });
    send({kind: "attached"});
  } catch (e) {
    send({kind: "compute-error", message: String(e.message || e)});
  }
} else {
  var base = mod.base;
  var target = (MODE === "neg-badaddr")
    ? base.add(mod.size + 0x1000)   // outside every mapping of this image
    : base.add(ENTRY_RVA);
  send({kind: "rebase", ok: true, target: target.toString(),
        inImage: target.compare(base) >= 0 &&
                 target.compare(base.add(mod.size)) < 0});
  try {
    Interceptor.attach(target, {
      onEnter: function () {
        send({kind: "HIT", at: target.toString(), tid: Process.getCurrentThreadId()});
      }
    });
    send({kind: "attached", target: target.toString()});
  } catch (e) {
    send({kind: "attach-error", target: target.toString(), message: String(e.message || e)});
  }
}
"""


# STDOUT MUST BE PURE JSON once this recipe is callable, because mission.ps1 runs a capability as
# `& $runner @argList 2>&1 | Out-String` and MERGES the two streams. Every human-readable line --
# the [stage], [pe], [spawn], [js], [resu], [end] narration that makes this recipe worth reading --
# goes to stderr, and exactly one JSON object goes to stdout. Measured on native.disasm.capstone:
# mixing them cost a whole mission round that reported ok:false while the same command worked
# perfectly by hand with exit 0. Set FRIDA_GATEWAY=0 to get the narration on stdout instead, which
# is what a human running it interactively wants.
_HUMAN = os.environ.get("FRIDA_GATEWAY", "1") != "0"
_REAL_STDOUT = sys.stdout
_OUT_FD = None
if _HUMAN:
    # A PYTHON-LEVEL sys.stdout swap is NOT ENOUGH, and finding that out cost a mission round.
    # The spawned target INHERITS this process's file descriptors, so the crackme's own
    # `ACCEPTED` / `FLAG{...}` lines arrive on the real fd 1 no matter what Python's sys.stdout
    # points at. Measured: with only the Python swap, stdout carried two lines of the TARGET'S
    # output ahead of the JSON and ConvertFrom-Json failed at character 0.
    #
    # So the DESCRIPTOR is redirected with dup2 -- fd 1 points at fd 2 for the whole run, which
    # catches the child's inherited handle as well as our own prints -- and a private duplicate
    # of the original fd 1 is kept purely for emit_json to write the one object to be parsed.
    _OUT_FD = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr

def emit_json(mode, target, ok, verdict, hit_at, hit_count, tid=None):
    """The ONE object that goes to stdout. Everything else went to stderr above."""
    (os.fdopen(_OUT_FD, "w") if _OUT_FD is not None else _REAL_STDOUT).write(json.dumps({
        "ok": ok, "exit": 0 if ok else 5, "mode": mode, "target": target,
        "verdict": verdict,
        "runtime_hook_hit": {"at": hit_at, "count": hit_count, "tid": tid},
        "instrument_ordering": "spawn(suspended) -> create_script -> load -> resume. The CLI does "
                               "the opposite and therefore cannot intercept; this ordering is the "
                               "whole entry.",
        "caveat": "SELF-BUILT CORPUS TARGETS ONLY, run from a %TEMP% copy -- the repository "
                  "original is staged and never executed. Instrumenting your own program on your "
                  "own machine is not running a sample; running an UNTRUSTED one here is a STOP.",
    }) + "\n")
    _REAL_STDOUT.flush()

def run_mode(mode, target, argv_pw):
    facts = pe_entry_rva(target)
    print("[pe  ] %s" % json.dumps(facts))

    device = frida.get_local_device()
    pid = device.spawn([target, argv_pw])
    print("[spawn] pid=%d suspended=True" % pid)

    session = device.attach(pid)
    events, ready, decided = [], threading.Event(), threading.Event()
    hit, attach_err, rebase, compute_err = {}, {}, {}, {}

    def on_message(message, data):
        if message.get("type") != "send":
            return
        p = message["payload"]
        events.append(p)
        kind = p.get("kind")
        print("[js  ] %s" % json.dumps(p))
        if kind in ("attached", "attach-error", "rebase", "compute-error"):
            ready.set()
        if kind == "HIT":
            hit.update(p)
            decided.set()
        elif kind == "attach-error":
            attach_err.update(p)
            decided.set()
        elif kind == "compute-error":
            compute_err.update(p)
            decided.set()
        elif kind == "rebase" and p.get("ok") is False:
            rebase.update(p)
            decided.set()

    script = session.create_script(JS % {"mode": json.dumps(mode), "entry": facts["entry_rva"]})
    script.on("message", on_message)
    script.load()                       # main thread is STILL suspended here
    print("[load] script loaded while main thread suspended")
    ready.wait(10.0)

    def teardown():
        for fn in (session.detach, lambda: device.kill(pid)):
            try:
                fn()
            except Exception:
                pass

    if mode == "neg-rebase":
        decided.wait(5.0)
        module = next((e for e in events if e.get("kind") == "module"), {})
        # A genuine rebase failure must surface as a COMPUTE error (there is
        # no base to add an RVA to), never as an attach error.  If an attach
        # error appeared here the control would be passing for the wrong
        # reason and would be indistinguishable from neg-badaddr.
        ok = (rebase.get("ok") is False and rebase.get("base") == "null"
              and bool(compute_err) and not attach_err and not hit)
        print("[end] main-module base still reported: %s" % module.get("base"))
        print("[end] reason=%s" % rebase.get("reason"))
        print("[end] failed while COMPUTING the address (no base): %s"
              % compute_err.get("message"))
        print("[end] attach never attempted: attach_error=%s" % (attach_err or None))
        print("[end] verdict=%s" % ("REBASE-FAILURE" if ok else "NEGCTL-BROKEN"))
        teardown()
        return 3 if ok else 4

    if mode == "neg-badaddr":
        decided.wait(5.0)
        module = next((e for e in events if e.get("kind") == "module"), {})
        rb = next((e for e in events if e.get("kind") == "rebase"), {})
        ok = bool(attach_err) and rb.get("ok") is True and rb.get("inImage") is False
        print("[end] module base resolved: %s (%s)" % (module.get("base"), module.get("name")))
        print("[end] rebase succeeded: yes -- target %s is outside the image" % rb.get("target"))
        print("[end] attach failed for its OWN reason: %s" % attach_err.get("message"))
        print("[end] verdict=%s bad-address (distinguishable from rebase failure)"
              % ("NEGCTL-OK" if ok else "NEGCTL-BROKEN"))
        teardown()
        emit_json(mode, target, ok,
                  "NEGCTL-OK bad-address" if ok else "NEGCTL-BROKEN", None, 0)
        return 0 if ok else 4

    device.resume(pid)                  # resume only AFTER load
    print("[resu] main thread resumed")
    decided.wait(15.0)
    ok = bool(hit) and hit.get("at") is not None
    print("[end] hit count=%d at=%s" % (sum(1 for e in events if e.get("kind") == "HIT"),
                                        hit.get("at")))
    print("[end] verdict=%s" % ("INTERCEPT-PROVEN" if ok else "INTERCEPT-FAILED"))
    teardown()
    emit_json(mode, target, ok,
              "INTERCEPT-PROVEN" if ok else "INTERCEPT-FAILED",
              hit.get("at"), sum(1 for e in events if e.get("kind") == "HIT"),
              hit.get("tid"))
    return 0 if ok else 5


# WHY THIS EXISTS NOW. The recipe is being made CALLABLE, which means mission.ps1 passes a
# repository path directly. Two rules make that unsafe as written, and both are enforced here
# rather than trusted to the caller:
#
#   1. THE REPO BINARY IS NEVER EXECUTED. crackme-corpus/out/ holds the corpus IDA databases, so a
#      strayed write or a stray .i64 there destroys an artefact other capabilities depend on. The
#      target is copied into a fresh %TEMP% directory and that copy is what gets spawned.
#   2. THE TARGET MUST LOOK LIKE A CORPUS FILE. Naming is the only signal available at this layer,
#      so it is checked explicitly and the refusal is loud rather than a crash later.
#
# Defence in depth, not a substitute for the gate: dynamic.win.frida.intercept carries
# escalation_class owner_word because a mission that EXECUTES a target must never be a runtime
# self-decision.
def stage_copy(path: str) -> str:
    if not path.lower().endswith(".exe"):
        print("[stage] REFUSING %r: expected a .exe from the corpus" % path, file=sys.stderr)
        sys.exit(2)
    d = tempfile.mkdtemp(prefix="fridagate-")
    dst = os.path.join(d, os.path.basename(path))
    shutil.copy2(path, dst)
    print("[stage] copied to %%TEMP%% %s (%d bytes); the repository original is never executed"
          % (dst, os.path.getsize(dst)), file=sys.stderr)
    return dst

if __name__ == "__main__":
    sys.exit(run_mode(MODE, stage_copy(TARGET), ARGV_PW))
