package com.lab.mobilelab;

import android.os.Debug;
import android.os.Process;

/**
 * Anti-tamper / anti-instrumentation DETECTION in our own sample.
 *
 * Scope note, and it matters: everything here DETECTS and REPORTS. There is no obfuscation,
 * no root-hiding, no anti-dump trick, and no attempt to defeat an analyst. It exists so the
 * lab's Frida detector has a known-positive target to score, and so the same detector can be
 * pointed at a real app to answer "is this app looking at me?" — which is a question about
 * OUR instrumentation, not an attack on theirs.
 *
 * The three signals are the standard, publicly documented ones:
 *   1. android.os.Debug.isDebuggerConnected() / Debug.waitingForDebugger()
 *   2. TracerPid != 0 in /proc/self/status  (a debugger or a ptracer attached)
 *   3. a scan of /proc/self/maps for "frida" / "gadget" / "xposed" substrings
 */
public class IntegrityGuard {

    /** Substrings an injected instrumentation agent typically leaves in the process maps. */
    private static final String[] AGENT_MARKERS = {
            "frida", "gadget", "xposed", "substrate", "riru", "zygisk"
    };

    private static final int TRACER_PID_NOT_ATTACHED = 0;

    public boolean isBeingDebugged() {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger();
    }

    /**
     * TracerPid is the kernel's own answer to "does anything have ptrace on me".
     * Signal #2. Returns the pid, or 0 when nothing is attached.
     */
    public int tracerPid() {
        String status = readProcFile("/proc/self/status");
        if (status == null) {
            return -1; /* unknown — reported as unknown, never as "clean" */
        }
        for (String line : status.split("\n")) {
            if (line.startsWith("TracerPid:")) {
                try {
                    return Integer.parseInt(line.substring("TracerPid:".length()).trim());
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    public boolean hasTracedProcess() {
        return tracerPid() != TRACER_PID_NOT_ATTACHED;
    }

    /**
     * Signal #3: read the process memory map and look for agent module names.
     * This is the check the lab's Frida detector mirrors, so the detector is scored against
     * a target whose implementation we can read.
     */
    public boolean hasFridaServer() {
        String maps = readProcFile("/proc/self/maps");
        if (maps == null) {
            return false;
        }
        String lower = maps.toLowerCase();
        for (String marker : AGENT_MARKERS) {
            if (lower.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    /** The full posture, as a human-readable line. */
    public String report() {
        return "debugger=" + isBeingDebugged()
                + " tracerPid=" + tracerPid()
                + " agentMarkers=" + hasFridaServer()
                + " pid=" + Process.myPid();
    }

    /**
     * Deliberately naive file read. Real code would use NIO; the naive form keeps the
     * static analyser's job honest (a literal "/proc/self/maps" is a high-signal string).
     */
    private String readProcFile(String path) {
        try {
            java.io.InputStream in = new java.io.FileInputStream(path);
            byte[] buf = new byte[8192];
            int n = in.read(buf);
            in.close();
            return new String(buf, 0, Math.max(n, 0), "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }
}
