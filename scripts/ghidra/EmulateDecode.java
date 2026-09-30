// EmulateDecode.java -- GhidraScript: run a function's p-code with controlled inputs.
//
// WHY THIS EXISTS
// ---------------
// Ghidra ships a p-code emulator (ghidra.app.emulator) and nothing in this repo used it.
// It turns a DYNAMIC question into a static one: "what does this decode to?" normally
// needs a debugger, a process, and patience. Under emulation it needs one function,
// five register writes, and a step loop.
//
// The demonstration is our own c01-stringobf, whose main() compares argv[1] against a
// buffer produced by sub_140001000(&table, 18, 11, 90, out). The table entry is a
// byte rotation plus XOR. Emulating the call yields the real string, and the string
// must equal the ground truth the corpus records: FLAG{c01_string_table_xor}.
//
// The plaintext FLAG{...} in .rdata is a DECOY. `strings | grep FLAG` returns it and is
// wrong. An emulation result that merely looked plausible would be caught by that
// comparison, which is the whole point of checking against ground truth rather than
// eyeballing the output.
//
// NOTHING IS EXECUTED. This walks p-code inside Ghidra's analyser. The binary never
// runs, there is no process, no debugger, and no device.
//
// Usage (postScript args, in order):
//   0 function address (hex string)   1 encoded-table address   2 arg2
//   3 arg3                            4 arg4                    5 output-buffer address
//   6 expected ground-truth string     7 max steps
//
// Writes <outdir>/emulation.json so the caller gates on an ARTIFACT, never on an exit
// code -- the same rule the Ghidra wrapper was fixed for.

import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;

import ghidra.app.emulator.DefaultEmulator;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;

public class EmulateDecode extends GhidraScript {

    // Scratch stack, far from the image. The research noted 0x7FFE0000 for exactly this.
    private static final long SCRATCH_SP = 0x7FF00000L;

    private String out(String label, String value) {
        println("EMULATION " + label + ": " + value);
        return value;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 8) {
            println("EMULATION ERROR: expected 8 script args, got " + args.length);
            return;
        }

        String fnAddrHex = args[0];
        String tableAddrHex = args[1];
        long a2 = Long.parseLong(args[2]);
        long a3 = Long.parseLong(args[3]);
        long a4 = Long.parseLong(args[4]);
        String outAddrHex = args[5];
        String expected = args[6];
        long maxSteps = Long.parseLong(args[7]);

        Address fnAddr = toAddr(fnAddrHex);
        Address tableAddr = toAddr(tableAddrHex);
        Address outAddr = toAddr(outAddrHex);
        Address fnEnd = currentProgram.getFunctionManager()
                .getFunctionAt(fnAddr).getBody().getMaxAddress();

        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        DefaultEmulator de = new DefaultEmulator(emu);
        long steps = 0;
        String decoded = null;
        String error = null;
        String outHex = null;
        boolean outNonZero = false;

        try {
            // Windows x64: RCX, RDX, R8, R9 carry the first four integer arguments and
            // the FIFTH goes on the stack at [RSP+0x28] -- past the shadow space and the
            // return address. Getting this wrong does not error; it produces a confident
            // wrong answer, which is why the result is checked against ground truth.
            // A real return address on the stack. Without it `ret` pops 0 into RIP and the
            // PC lands at 0, which terminates the loop but tells us nothing about WHERE the
            // function returned -- and makes "did it return normally" indistinguishable from
            // "it ran off the end of the map".
            // writeStackValue(slot, size, value), NOT writeMemoryValue at a raw address.
            // The raw-address form silently faulted: SCRATCH_SP is not in any mapped memory
            // block, the EmulatorHelper fault handler swallowed it, [RSP] stayed 0, and the
            // function's `ret` popped 0 into RIP. That produced "15 steps, halted at PC=0"
            // and looked like the decode had failed rather than like the write never landed.
            emu.writeRegister("RSP", SCRATCH_SP);
            emu.writeStackValue(0, 8, fnEnd.getOffset() + 1);   // return address
            emu.writeRegister("RCX", tableAddr.getOffset());
            emu.writeRegister("RDX", a2);
            emu.writeRegister("R8", a3);
            emu.writeRegister("R9", a4);
            emu.writeStackValue(5, 8, outAddr.getOffset());     // 5th arg, past shadow space

            de.setExecuteAddress(fnAddr.getOffset());

            TaskMonitor mon = monitor;
            while (steps < maxSteps) {
                long pc = de.getPC();
                Address pcAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(pc);
                if (pcAddr.compareTo(fnAddr) < 0 || pcAddr.compareTo(fnEnd) > 0) {
                    break; // returned
                }
                de.executeInstruction(false, mon);
                steps++;
            }

            if (de.getHalt()) {
                error = "emulator halted at PC=0x" + Long.toHexString(de.getPC());
            }

            // Read the output while the emulator is STILL ALIVE. The first version
            // disposed in the finally block and then read the buffer, which returned null
            // and looked like "the decode produced nothing" rather than "we tore down the
            // machine before looking at it".
            decoded = emu.readNullTerminatedString(outAddr, 96);
            if (decoded != null && decoded.isEmpty()) { decoded = null; }
            // Diagnostic: is the buffer empty, or merely not null-terminated? Those are
            // very different failures and "decoded: null" alone cannot tell them apart.
            byte[] raw = emu.readMemory(outAddr, 48);
            StringBuilder hex = new StringBuilder();
            boolean anyNonZero = false;
            for (byte b : raw) { hex.append(String.format("%02x", b)); if (b != 0) { anyNonZero = true; } }
            outHex = hex.toString();
            outNonZero = anyNonZero;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            try { de.dispose(); emu.dispose(); } catch (Exception ignored) { }
        }

        String verdict;
        if (error != null) {
            verdict = "ERROR";
        } else if (decoded == null) {
            verdict = "NO_OUTPUT";
        } else if (decoded.equals(expected)) {
            verdict = "MATCHES_GROUND_TRUTH";
        } else {
            verdict = "MISMATCH";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"schema\": \"ghidra/emulation@1\",\n");
        sb.append("  \"target\": \"").append(currentProgram.getName()).append("\",\n");
        sb.append("  \"function\": \"").append(fnAddrHex).append("\",\n");
        sb.append("  \"table_argument\": \"").append(tableAddrHex).append("\",\n");
        sb.append("  \"arguments\": [").append(a2).append(", ").append(a3).append(", ").append(a4).append("],\n");
        sb.append("  \"steps\": ").append(steps).append(",\n");
        sb.append("  \"pcode_instructions\": ").append(steps).append(",\n");
        sb.append("  \"executed_nothing\": true,\n");
        sb.append("  \"decoded\": ").append(decoded == null ? "null" : "\"" + decoded.replace("\\", "\\\\").replace("\"", "\\\"") + "\"").append(",\n");
        sb.append("  \"expected\": \"").append(expected).append("\",\n");
        sb.append("  \"verdict\": \"").append(verdict).append("\",\n");
        sb.append("  \"output_non_zero\": ").append(outNonZero).append(",\n");
        sb.append("  \"output_head_hex\": \"").append(outHex == null ? "" : outHex).append("\",\n");
        if (error != null) {
            sb.append("  \"error\": \"").append(error.replace("\"", "'")).append("\",\n");
        }
        sb.append("  \"note\": \"p-code was walked inside the analyser; the binary never executed, no process was created, and no debugger attached.\"\n");
        sb.append("}\n");

        String outDir = args.length > 8 ? args[8] : null;
        if (outDir != null) {
            File f = new File(outDir, "emulation.json");
            PrintWriter w = new PrintWriter(f, "UTF-8");
            w.print(sb.toString());
            w.close();
        }

        out("steps", String.valueOf(steps));
        out("decoded", String.valueOf(decoded));
        out("expected", expected);
        out("verdict", verdict);
        out("output_non_zero", String.valueOf(outNonZero));
        out("output_head_hex", outHex);
        if (error != null) { out("error", error); }
    }
}
