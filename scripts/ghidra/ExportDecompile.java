// Decompile every function to files (Ghidra headless, no GUI).
//@category debugger-workstation
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ExportDecompile extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("ExportDecompile: no program");
			return;
		}
		String[] args = getScriptArgs();
		if (args == null || args.length < 1 || args[0].isEmpty()) {
			printerr("ExportDecompile: pass outdir as script arg");
			return;
		}
		File outDir = new File(args[0]);
		if (!outDir.exists() && !outDir.mkdirs()) {
			printerr("ExportDecompile: cannot create " + outDir);
			return;
		}
		int maxFn = Integer.MAX_VALUE;
		if (args.length > 1) {
			try {
				maxFn = Integer.parseInt(args[1]);
			}
			catch (NumberFormatException ignored) {
				maxFn = Integer.MAX_VALUE;
			}
		}

		File decompDir = new File(outDir, "decompiled");
		decompDir.mkdirs();

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

		List<String> funcLines = new ArrayList<>();
		int n = 0;
		int decompiled = 0;
		for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
			if (n >= maxFn) {
				break;
			}
			Address entry = fn.getEntryPoint();
			String name = fn.getName();
			funcLines.add(name + " @ " + entry);
			File cf = new File(decompDir, safeName(name, entry) + ".c");
			DecompileResults res = decomp.decompileFunction(fn, 30, mon);
			String body;
			if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
				body = res.getDecompiledFunction().getC();
				decompiled++;
			}
			else {
				body = "// decompile failed; disassembly fallback\n" + disasm(fn);
			}
			writeText(cf, body);
			n++;
		}

		writeLines(new File(outDir, "functions.txt"), funcLines);
		writeLines(new File(outDir, "imports.txt"), imports());
		writeLines(new File(outDir, "exports.txt"), exports());
		writeLines(new File(outDir, "segments.txt"), segments());
		writeLines(new File(outDir, "strings.txt"), strings(4000));

		String summary = "{"
			+ "\"ok\":true,"
			+ "\"tool\":\"ghidra\","
			+ "\"program\":\"" + esc(currentProgram.getName()) + "\","
			+ "\"language\":\"" + esc(currentProgram.getLanguageID().toString()) + "\","
			+ "\"functions\":" + n + ","
			+ "\"decompiled\":" + decompiled + ","
			+ "\"outdir\":\"" + esc(outDir.getAbsolutePath().replace('\\', '/')) + "\""
			+ "}\n";
		writeText(new File(outDir, "summary.json"), summary);
		println("EXPORT_DECOMPILE " + outDir.getAbsolutePath());
		println(summary.trim());
	}

	private String disasm(Function fn) {
		StringBuilder sb = new StringBuilder();
		InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			sb.append(ins.getAddress()).append(": ").append(ins.toString()).append('\n');
		}
		return sb.toString();
	}

	private List<String> imports() {
		List<String> lines = new ArrayList<>();
		for (Symbol s : currentProgram.getSymbolTable().getExternalSymbols()) {
			lines.add(s.getName() + " -> " + s.getAddress());
		}
		return lines;
	}

	private List<String> exports() {
		List<String> lines = new ArrayList<>();
		for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(true)) {
			if (s.isExternalEntryPoint()) {
				lines.add(s.getName() + " -> " + s.getAddress());
			}
		}
		return lines;
	}

	private List<String> segments() {
		List<String> lines = new ArrayList<>();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			lines.add(b.getName() + ": " + b.getStart() + " - " + b.getEnd());
		}
		return lines;
	}

	private List<String> strings(int limit) {
		List<String> lines = new ArrayList<>();
		DataIterator it = currentProgram.getListing().getDefinedData(true);
		while (it.hasNext() && lines.size() < limit) {
			Data d = it.next();
			if (d != null && d.hasStringValue()) {
				Object v = d.getValue();
				lines.add(d.getAddress() + " " + String.valueOf(v));
			}
		}
		return lines;
	}

	private static String safeName(String name, Address addr) {
		String s = name.replaceAll("[^A-Za-z0-9_.-]", "_");
		if (s.length() > 80) {
			s = s.substring(0, 80);
		}
		return s + "_" + addr.toString();
	}

	private static String esc(String s) {
		if (s == null) {
			return "";
		}
		return s.replace("\\", "\\\\").replace("\"", "\\\"");
	}

	private static void writeText(File f, String text) throws Exception {
		try (FileWriter w = new FileWriter(f, StandardCharsets.UTF_8)) {
			w.write(text == null ? "" : text);
		}
	}

	private static void writeLines(File f, List<String> lines) throws Exception {
		try (FileWriter w = new FileWriter(f, StandardCharsets.UTF_8)) {
			for (String line : lines) {
				w.write(line);
				w.write('\n');
			}
		}
	}
}
