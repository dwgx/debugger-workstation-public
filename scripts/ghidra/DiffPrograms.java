// DiffPrograms.java -- cross-binary function diff, from two Ghidra hash manifests.
//
// This is the capability the station's headless surface did not have, and it is
// the one that answers "is this build the same as last week's, and if not, where".
//
// Why manifests instead of opening the second program in-process: Ghidra 12 has
// no framework-level ProgramManager, so a headless script cannot open a sibling
// program from the same project. The hashes therefore come out of two ordinary
// analyzeHeadless runs (FunctionHashes.java) and the comparison happens here, on
// text. The Ghidra-specific part -- "what are this program's functions and what
// are their bytes" -- is still done by Ghidra; only the set arithmetic is not,
// and set arithmetic is the part that should be readable.
//
//   FunctionHashes.java  <outDir>              -> <outDir>/hashes-<program>.txt
//   DiffPrograms.java     <manifestA> <manifestB> <outDir>
//
// Matching is by function name first (exported and named functions survive a
// recompile); a name match with a different hash is a CHANGE, which is the
// interesting cell. Everything is reported and nothing is filtered, so the caller
// decides what noise means.
//@category debugger-workstation
import ghidra.app.script.GhidraScript;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DiffPrograms extends GhidraScript {

	private static final String[] GENERATED_PREFIXES =
		{ "FUN_", "LAB_", "SUB_", "thunk_", "undefined_", "code_", "data_" };

	private static boolean isGenerated(String name) {
		if (name == null) {
			return true;
		}
		for (String p : GENERATED_PREFIXES) {
			if (name.startsWith(p)) {
				return true;
			}
		}
		return false;
	}

	/** name -> "addr:size:hash", from a FunctionHashes.java manifest. */
	private static Map<String, String[]> readManifest(String path) throws Exception {
		Map<String, String[]> m = new LinkedHashMap<>();
		try (BufferedReader r = new BufferedReader(
			new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
			String line;
			while ((line = r.readLine()) != null) {
				if (line.isEmpty() || line.startsWith("#")) {
					continue;
				}
				String[] p = line.split("\t");
				if (p.length >= 3) {
					m.put(p[0], new String[] { p[1], p[2] });
				}
			}
		}
		return m;
	}

	private static String base(String path) {
		File f = new File(path);
		return f.getName();
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			printerr("DiffPrograms: usage <manifestA> <manifestB> [outDir]");
			return;
		}
		String outDir = args.length > 2 ? args[2] : ".";

		Map<String, String[]> a = readManifest(args[0]);
		Map<String, String[]> b = readManifest(args[1]);

		List<String> changed = new ArrayList<>();
		List<String> added = new ArrayList<>();
		List<String> removed = new ArrayList<>();
		int same = 0;

		for (Map.Entry<String, String[]> e : a.entrySet()) {
			String[] other = b.get(e.getKey());
			if (other == null) {
				removed.add(e.getKey() + (isGenerated(e.getKey()) ? "" : "  [named]"));
				continue;
			}
			if (e.getValue()[1].equals(other[1])) {
				same++;
			}
			else {
				changed.add(String.format("CHANGED  %-24s size %s -> %s   %s -> %s",
					e.getKey(), e.getValue()[0], other[0], e.getValue()[1], other[1]));
			}
		}
		for (String k : b.keySet()) {
			if (!a.containsKey(k)) {
				added.add(k + (isGenerated(k) ? "" : "  [named]"));
			}
		}

		StringBuilder sb = new StringBuilder();
		sb.append("DIFF a=").append(base(args[0])).append(" b=").append(base(args[1])).append('\n');
		sb.append("FUNCTIONS a=").append(a.size()).append(" b=").append(b.size())
			.append("  named_a=").append(countNamed(a)).append(" named_b=").append(countNamed(b)).append('\n');
		for (String c : changed) {
			sb.append(c).append('\n');
		}
		sb.append("REMOVED ").append(removed.size())
			.append(removed.isEmpty() ? "" : "  " + String.join(", ", removed)).append('\n');
		sb.append("ADDED   ").append(added.size())
			.append(added.isEmpty() ? "" : "  " + String.join(", ", added)).append('\n');
		sb.append("SUMMARY changed=").append(changed.size())
			.append(" same=").append(same)
			.append(" removed=").append(removed.size())
			.append(" added=").append(added.size()).append('\n');

		new File(outDir).mkdirs();
		File out = new File(outDir, "diff.txt");
		try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8)) {
			w.write(sb.toString());
		}
		println(sb.toString());
		println("DIFF_WRITTEN " + out.getAbsolutePath());
	}

	private static int countNamed(Map<String, String[]> m) {
		int n = 0;
		for (String k : m.keySet()) {
			if (!isGenerated(k)) {
				n++;
			}
		}
		return n;
	}
}
