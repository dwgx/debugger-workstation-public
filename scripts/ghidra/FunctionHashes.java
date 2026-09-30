// FunctionHashes.java -- one line per function: name, size, body hash.
//
// This is the input DiffPrograms.java consumes, and it is useful on its own: a
// manifest is a function inventory you can diff, sort, grep and check into a
// notes file without shipping a Ghidra project around.
//
//   analyzeHeadless.bat <proj> agent -import x.dll -scriptPath scripts/ghidra \
//       -postScript FunctionHashes.java <outDir>
//
// The hash is MD5 over the function's body bytes, truncated to 8 bytes. It is a
// content address, not a similarity score: identical bytes hash identically, and
// nothing else does. That is a deliberate limit -- a recompile with different
// optimisation moves every hash -- and DiffPrograms reports names as well as
// hashes so a caller can tell "renamed" from "changed".
//@category debugger-workstation
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class FunctionHashes extends GhidraScript {

	private static String bodyHash(AddressSetView body) {
		try {
			long n = body.getNumAddresses();
			if (n <= 0 || n > 4L * 1024 * 1024) {
				return "size" + n;
			}
			byte[] buf = new byte[(int) n];
			currentProgram.getMemory().getBytes(body.getMinAddress(), buf);
			byte[] d = MessageDigest.getInstance("MD5").digest(buf);
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < 8; i++) {
				sb.append(String.format("%02x", d[i]));
			}
			return sb.toString();
		}
		catch (Exception e) {
			return "err";
		}
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String outDir = args.length > 0 ? args[0] : ".";
		new File(outDir).mkdirs();
		File out = new File(outDir, "hashes-" + currentProgram.getName() + ".txt");

		int count = 0;
		StringBuilder sb = new StringBuilder();
		sb.append("# program\t").append(currentProgram.getName()).append('\n');
		sb.append("# language\t").append(currentProgram.getLanguageID()).append('\n');
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		while (it.hasNext()) {
			Function f = it.next();
			sb.append(f.getName()).append('\t')
				.append(f.getBody().getNumAddresses()).append('\t')
				.append(bodyHash(f.getBody())).append('\n');
			count++;
		}

		try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8)) {
			w.write(sb.toString());
		}
		println("HASHES " + count + " functions -> " + out.getAbsolutePath());
	}
}
