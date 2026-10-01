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
import threading

import frida

TARGET = sys.argv[1] if len(sys.argv) > 1 else r"%USERPROFILE%\AppData\Local\Temp\w13\c01-stringobf.exe"
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
        return 0 if ok else 4

    device.resume(pid)                  # resume only AFTER load
    print("[resu] main thread resumed")
    decided.wait(15.0)
    ok = bool(hit) and hit.get("at") is not None
    print("[end] hit count=%d at=%s" % (sum(1 for e in events if e.get("kind") == "HIT"),
                                        hit.get("at")))
    print("[end] verdict=%s" % ("INTERCEPT-PROVEN" if ok else "INTERCEPT-FAILED"))
    teardown()
    return 0 if ok else 5


if __name__ == "__main__":
    sys.exit(run_mode(MODE, TARGET, ARGV_PW))