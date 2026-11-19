"""Controlled dependency: logs mock ownership, never calls a real Frida API."""
import json
import os
import shutil
from pathlib import Path

ROOT = Path(os.environ["CLEANUP_CASE_ROOT"])
MODE = os.environ["CLEANUP_MODE"]
OWNED_PID = 730001

def log(event, **data):
    with (ROOT / "events.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"event": event, **data}) + "\n")

log("frida.mock.import", source=__file__)
if MODE == "copy-fail":
    def fail_copy(*args, **kwargs):
        log("copy.failure")
        raise OSError("MOCK_COPY_FAILURE")
    shutil.copy2 = fail_copy

class Script:
    def on(self, name, callback):
        assert name == "message"
        self.callback = callback
    def load(self):
        log("script.load")
        for payload in (
            {"kind": "module", "name": "fixture.exe", "base": "0x1000", "size": 4096},
            {"kind": "export", "name": "printf", "addr": "0x2000"},
            {"kind": "attached", "at": "0x1010", "inImage": True},
        ):
            self.callback({"type": "send", "payload": payload}, None)

class Session:
    def create_script(self, source):
        log("script.create")
        return Script()
    def detach(self):
        log("session.detach")

class Device:
    def spawn(self, argv):
        log("device.spawn", argv=argv)
        if MODE == "spawn-fail":
            raise RuntimeError("MOCK_SPAWN_FAILURE")
        (ROOT / "mock-owned-pid").write_text(str(OWNED_PID), encoding="utf-8")
        return OWNED_PID
    def attach(self, pid):
        log("device.attach", pid=pid)
        assert pid == OWNED_PID, "FOREIGN_PID_ATTACH"
        if MODE in ("attach-fail", "caller-stage-fail"):
            raise RuntimeError("MOCK_ATTACH_FAILURE")
        return Session()
    def resume(self, pid):
        log("device.resume", pid=pid)
        assert pid == OWNED_PID
    def kill(self, pid):
        log("device.kill", pid=pid)
        assert pid == OWNED_PID, "FOREIGN_PID_KILL"
        (ROOT / "mock-owned-pid").unlink()

def get_local_device():
    log("device.get")
    return Device()
