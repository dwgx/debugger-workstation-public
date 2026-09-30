// Headless HTTP that speaks LaurieWired GhidraMCP paths (no GUI).
//@category debugger-workstation
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

public class HeadlessMcpHttp extends GhidraScript {

	private HttpServer server;
	private final AtomicBoolean shutdown = new AtomicBoolean(false);

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("HeadlessMcpHttp: no program");
			return;
		}
		int port = 8080;
		String[] args = getScriptArgs();
		if (args != null && args.length > 0 && !args[0].isEmpty()) {
			port = Integer.parseInt(args[0]);
		}
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
		server.createContext("/health", ex -> send(ex, "ok " + currentProgram.getName()));
		server.createContext("/shutdown", ex -> {
			send(ex, "bye");
			shutdown.set(true);
		});
		server.createContext("/methods", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(functionNames(), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/list_functions", ex -> send(ex, listFunctions()));
		server.createContext("/classes", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(classNames(), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/namespaces", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(classNames(), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/segments", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(segments(), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/imports", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(imports(), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/exports", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(exports(), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/data", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(dataItems(), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/strings", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(strings(q.get("filter")), pint(q.get("offset"), 0), pint(q.get("limit"), 2000)));
		});
		server.createContext("/searchFunctions", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(searchFunctions(q.get("query")), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/decompile", ex -> send(ex, decompileByName(body(ex).trim())));
		server.createContext("/decompile_function", ex -> send(ex, decompileByAddress(query(ex).get("address"))));
		server.createContext("/disassemble_function", ex -> send(ex, disassemble(query(ex).get("address"))));
		server.createContext("/get_function_by_address", ex -> send(ex, functionAt(query(ex).get("address"))));
		server.createContext("/get_current_address", ex -> send(ex, entryAddress()));
		server.createContext("/get_current_function", ex -> send(ex, currentFunction()));
		server.createContext("/xrefs_to", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(xrefsTo(q.get("address")), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/xrefs_from", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(xrefsFrom(q.get("address")), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/function_xrefs", ex -> {
			Map<String, String> q = query(ex);
			send(ex, paginate(functionXrefs(q.get("name")), pint(q.get("offset"), 0), pint(q.get("limit"), 100)));
		});
		server.createContext("/renameFunction", ex -> {
			Map<String, String> p = form(ex);
			send(ex, renameFunction(p.get("oldName"), p.get("newName")) ? "Renamed successfully" : "Rename failed");
		});
		server.createContext("/renameData", ex -> {
			Map<String, String> p = form(ex);
			renameData(p.get("address"), p.get("newName"));
			send(ex, "Rename data attempted");
		});
		server.createContext("/rename_function_by_address", ex -> {
			Map<String, String> p = form(ex);
			send(ex, renameFunctionByAddress(p.get("function_address"), p.get("new_name"))
				? "Renamed successfully" : "Rename failed");
		});
		server.createContext("/set_decompiler_comment", ex -> {
			Map<String, String> p = form(ex);
			send(ex, setComment(p.get("address"), p.get("comment"), CodeUnit.PRE_COMMENT)
				? "Comment set" : "Failed");
		});
		server.createContext("/set_disassembly_comment", ex -> {
			Map<String, String> p = form(ex);
			send(ex, setComment(p.get("address"), p.get("comment"), CodeUnit.EOL_COMMENT)
				? "Comment set" : "Failed");
		});
		server.createContext("/renameVariable", ex -> {
			Map<String, String> p = form(ex);
			send(ex, renameVariable(p.get("function") != null ? p.get("function") : p.get("address"),
				p.get("variable"), p.get("new_name"))
					? "Variable renamed" : "renameVariable failed (need function/address, variable, new_name)");
		});
		server.createContext("/set_function_prototype", ex -> {
			Map<String, String> p = form(ex);
			send(ex, setFunctionPrototype(p.get("function") != null ? p.get("function") : p.get("address"),
				p.get("return_type"), p.get("params")));
		});
		server.createContext("/set_local_variable_type", ex -> {
			Map<String, String> p = form(ex);
			send(ex, setLocalVariableType(p.get("function") != null ? p.get("function") : p.get("address"),
				p.get("variable"), p.get("type")));
		});

		// ---- added 2026-09-30: the three capabilities the router backend could
		// not do headlessly before. Each one is a real implementation, not a stub:
		// an agent that calls these gets data it could not get any other way.
		server.createContext("/pcode", ex -> {
			Map<String, String> q = query(ex);
			Function f = functionFor(q.get("address"));
			if (f == null) {
				f = functionByName(q.get("name"));
			}
			if (f == null) {
				send(ex, "No function found -- pass ?address= or ?name=");
				return;
			}
			send(ex, paginate(pcode(f), pint(q.get("offset"), 0), pint(q.get("limit"), 500)));
		});
		server.createContext("/cfg", ex -> {
			Map<String, String> q = query(ex);
			Function f = functionFor(q.get("address"));
			if (f == null) {
				f = functionByName(q.get("name"));
			}
			if (f == null) {
				send(ex, "No function found -- pass ?address= or ?name=");
				return;
			}
			send(ex, paginate(cfg(f), pint(q.get("offset"), 0), pint(q.get("limit"), 500)));
		});
		server.createContext("/create_struct", ex -> {
			Map<String, String> p = form(ex);
			send(ex, createStruct(p.get("name"), p.get("fields"), p.get("apply_to")));
		});
		server.createContext("/list_structs", ex -> send(ex, listStructs()));
		server.createContext("/resolve_type", ex -> {
			Map<String, String> q = query(ex);
			DataType dt = resolveType(q.get("type"));
			send(ex, dt == null ? "unknown type: " + q.get("type")
				: dt.getPathName() + "  (" + dt.getLength() + " bytes)");
		});
		server.setExecutor(null);
		server.start();
		println("HEADLESS_MCP_HTTP 127.0.0.1:" + port + " " + currentProgram.getName());
		while (!monitor.isCancelled() && !shutdown.get()) {
			Thread.sleep(400);
		}
		server.stop(0);
		println("HEADLESS_MCP_HTTP stop");
	}

	private List<String> functionNames() {
		List<String> names = new ArrayList<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			names.add(f.getName());
		}
		return names;
	}

	private String listFunctions() {
		StringBuilder sb = new StringBuilder();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			sb.append(f.getName()).append(" at ").append(f.getEntryPoint()).append('\n');
		}
		return sb.toString();
	}

	private List<String> classNames() {
		Set<String> set = new HashSet<>();
		for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(true)) {
			Namespace ns = s.getParentNamespace();
			if (ns != null && !ns.isGlobal()) {
				set.add(ns.getName());
			}
		}
		List<String> sorted = new ArrayList<>(set);
		Collections.sort(sorted);
		return sorted;
	}

	private List<String> segments() {
		List<String> lines = new ArrayList<>();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			lines.add(String.format("%s: %s - %s", b.getName(), b.getStart(), b.getEnd()));
		}
		return lines;
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
		SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s.isExternalEntryPoint()) {
				lines.add(s.getName() + " -> " + s.getAddress());
			}
		}
		return lines;
	}

	private List<String> dataItems() {
		List<String> lines = new ArrayList<>();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			DataIterator it = currentProgram.getListing().getDefinedData(block.getStart(), true);
			while (it.hasNext()) {
				Data data = it.next();
				if (!block.contains(data.getAddress())) {
					continue;
				}
				String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
				lines.add(data.getAddress() + ": " + label + " = " + data.getDefaultValueRepresentation());
			}
		}
		return lines;
	}

	private List<String> strings(String filter) {
		List<String> lines = new ArrayList<>();
		DataIterator it = currentProgram.getListing().getDefinedData(true);
		while (it.hasNext()) {
			Data d = it.next();
			if (d == null || !d.hasStringValue()) {
				continue;
			}
			String value = String.valueOf(d.getValue());
			if (filter != null && !filter.isEmpty() && !value.toLowerCase().contains(filter.toLowerCase())) {
				continue;
			}
			lines.add(d.getAddress() + ": " + value);
		}
		return lines;
	}

	private List<String> searchFunctions(String term) {
		List<String> matches = new ArrayList<>();
		if (term == null || term.isEmpty()) {
			matches.add("Search term is required");
			return matches;
		}
		String needle = term.toLowerCase();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.getName().toLowerCase().contains(needle)) {
				matches.add(f.getName() + " @ " + f.getEntryPoint());
			}
		}
		Collections.sort(matches);
		if (matches.isEmpty()) {
			matches.add("No functions matching '" + term + "'");
		}
		return matches;
	}

	private String decompileByName(String name) {
		if (name == null || name.isEmpty()) {
			return "Function not found";
		}
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (name.equals(f.getName())) {
				return decompile(f);
			}
		}
		return "Function not found";
	}

	private String decompileByAddress(String addressStr) {
		Function f = functionFor(addressStr);
		if (f == null) {
			return "No function found at or containing address " + addressStr;
		}
		return decompile(f);
	}

	private String decompile(Function f) {
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		DecompileResults res = decomp.decompileFunction(f, 30, new ConsoleTaskMonitor());
		if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
			return res.getDecompiledFunction().getC();
		}
		return "Decompilation failed";
	}

	private String disassemble(String addressStr) {
		Function f = functionFor(addressStr);
		if (f == null) {
			return "No function found at or containing address " + addressStr;
		}
		StringBuilder sb = new StringBuilder();
		Listing listing = currentProgram.getListing();
		Address end = f.getBody().getMaxAddress();
		InstructionIterator it = listing.getInstructions(f.getEntryPoint(), true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			if (ins.getAddress().compareTo(end) > 0) {
				break;
			}
			String comment = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress());
			comment = comment != null ? "; " + comment : "";
			sb.append(ins.getAddress()).append(": ").append(ins.toString()).append(' ').append(comment).append('\n');
		}
		return sb.toString();
	}

	private Function functionFor(String addressStr) {
		if (addressStr == null || addressStr.isEmpty()) {
			return null;
		}
		try {
			Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
			Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
			if (f == null) {
				f = currentProgram.getFunctionManager().getFunctionContaining(addr);
			}
			return f;
		}
		catch (Exception e) {
			return null;
		}
	}

	private String functionAt(String addressStr) {
		Function f = functionFor(addressStr);
		if (f == null) {
			return "No function at " + addressStr;
		}
		return String.format("Function: %s at %s\nSignature: %s", f.getName(), f.getEntryPoint(), f.getSignature());
	}

	private String entryAddress() {
		Function f = currentProgram.getFunctionManager().getFunctionAt(currentProgram.getMinAddress());
		if (f == null) {
			for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
				return fn.getEntryPoint().toString();
			}
			return currentProgram.getMinAddress().toString();
		}
		return f.getEntryPoint().toString();
	}

	private String currentFunction() {
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			return String.format("Function: %s at %s\nSignature: %s", f.getName(), f.getEntryPoint(), f.getSignature());
		}
		return "No function";
	}

	private List<String> xrefsTo(String addressStr) {
		List<String> refs = new ArrayList<>();
		Address addr;
		try {
			addr = currentProgram.getAddressFactory().getAddress(addressStr);
		}
		catch (Exception e) {
			refs.add("Address is required");
			return refs;
		}
		ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(addr);
		while (it.hasNext()) {
			Reference ref = it.next();
			Function from = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
			String info = from != null ? " in " + from.getName() : "";
			refs.add("From " + ref.getFromAddress() + info + " [" + ref.getReferenceType().getName() + "]");
		}
		return refs;
	}

	private List<String> xrefsFrom(String addressStr) {
		List<String> refs = new ArrayList<>();
		Address addr;
		try {
			addr = currentProgram.getAddressFactory().getAddress(addressStr);
		}
		catch (Exception e) {
			refs.add("Address is required");
			return refs;
		}
		ReferenceManager rm = currentProgram.getReferenceManager();
		for (Reference ref : rm.getReferencesFrom(addr)) {
			Address to = ref.getToAddress();
			Function tf = currentProgram.getFunctionManager().getFunctionAt(to);
			String info = tf != null ? " to function " + tf.getName() : "";
			refs.add("To " + to + info + " [" + ref.getReferenceType().getName() + "]");
		}
		return refs;
	}

	private List<String> functionXrefs(String name) {
		List<String> refs = new ArrayList<>();
		if (name == null || name.isEmpty()) {
			refs.add("Function name is required");
			return refs;
		}
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!function.getName().equals(name)) {
				continue;
			}
			ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
			while (it.hasNext()) {
				Reference ref = it.next();
				Function from = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				String info = from != null ? " in " + from.getName() : "";
				refs.add("From " + ref.getFromAddress() + info + " [" + ref.getReferenceType().getName() + "]");
			}
		}
		if (refs.isEmpty()) {
			refs.add("No references found to function: " + name);
		}
		return refs;
	}

	private boolean renameFunction(String oldName, String newName) {
		if (oldName == null || newName == null) {
			return false;
		}
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (oldName.equals(f.getName())) {
				return rename(f, newName);
			}
		}
		return false;
	}

	private boolean renameFunctionByAddress(String addressStr, String newName) {
		Function f = functionFor(addressStr);
		if (f == null || newName == null || newName.isEmpty()) {
			return false;
		}
		return rename(f, newName);
	}

	private boolean rename(Function f, String newName) {
		boolean ok = false;
		int tx = currentProgram.startTransaction("headless rename");
		try {
			f.setName(newName, SourceType.USER_DEFINED);
			ok = true;
		}
		catch (Exception e) {
			printerr("rename: " + e.getMessage());
		}
		finally {
			currentProgram.endTransaction(tx, ok);
		}
		return ok;
	}

	private void renameData(String addressStr, String newName) {
		if (addressStr == null || newName == null) {
			return;
		}
		int tx = currentProgram.startTransaction("headless rename data");
		boolean ok = false;
		try {
			Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
			SymbolTable st = currentProgram.getSymbolTable();
			Symbol symbol = st.getPrimarySymbol(addr);
			if (symbol != null) {
				symbol.setName(newName, SourceType.USER_DEFINED);
			}
			else {
				st.createLabel(addr, newName, SourceType.USER_DEFINED);
			}
			ok = true;
		}
		catch (Exception e) {
			printerr("renameData: " + e.getMessage());
		}
		finally {
			currentProgram.endTransaction(tx, ok);
		}
	}

	private boolean setComment(String addressStr, String comment, int type) {
		if (addressStr == null || comment == null) {
			return false;
		}
		int tx = currentProgram.startTransaction("headless comment");
		boolean ok = false;
		try {
			Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
			currentProgram.getListing().setComment(addr, type, comment);
			ok = true;
		}
		catch (Exception e) {
			printerr("comment: " + e.getMessage());
		}
		finally {
			currentProgram.endTransaction(tx, ok);
		}
		return ok;
	}

	/* ==================================================================
	 * Added 2026-09-30. The three routes above used to answer "not
	 * implemented" and there was no P-code, no CFG and no way to author a
	 * type. These are the implementations, and they are the reason the
	 * headless surface is worth keeping without a third-party MCP server.
	 * ================================================================== */

	private Function functionByName(String name) {
		if (name == null || name.isEmpty()) {
			return null;
		}
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (name.equals(f.getName())) {
				return f;
			}
		}
		return null;
	}

	/** P-code for one function, as produced by the decompiler's own translation. */
	private List<String> pcode(Function f) {
		List<String> out = new ArrayList<>();
		DecompInterface di = new DecompInterface();
		try {
			di.openProgram(currentProgram);
			DecompileResults res = di.decompileFunction(f, 60, new ConsoleTaskMonitor());
			if (res == null || !res.decompileCompleted() || res.getHighFunction() == null) {
				out.add("P-code unavailable: decompilation did not complete");
				return out;
			}
			int n = 0;
			// Ghidra 12 API drift. HighFunction.getPcodeOps() returns
			// Iterator<PcodeOpAST>, not PcodeOp[] -- it moved up to PcodeSyntaxTree and
			// changed shape. A for-each over it does not compile, which is why this whole
			// file never ran. It also means the /pcode tool silently did not exist.
			java.util.Iterator<ghidra.program.model.pcode.PcodeOpAST> ops = res.getHighFunction().getPcodeOps();
			while (ops.hasNext()) {
				PcodeOp op = ops.next();
				String where = op.getSeqnum() != null ? String.valueOf(op.getSeqnum().getTarget()) : "entry";
				out.add(where + "  " + op.getMnemonic() + "  " + op.toString());
				n++;
			}
			out.add("--- " + f.getName() + ": " + n + " p-code ops ---");
		}
		catch (Exception e) {
			out.add("P-code error: " + e.getMessage());
		}
		finally {
			di.dispose();
		}
		return out;
	}

	/**
	 * Basic blocks and edges for one function.
	 *
	 * A block starts at the entry, at any flow target inside the body, and right
	 * after any instruction that does not fall through. Successors are the flow
	 * targets plus the fallthrough, which is what a human means by "where can this
	 * go" and is the thing you cannot reconstruct from a decompiler's output once
	 * it has decided to print an if/else instead.
	 */
	private List<String> cfg(Function f) {
		List<String> out = new ArrayList<>();
		Listing listing = currentProgram.getListing();
		Address entry = f.getEntryPoint();
		Address end = f.getBody().getMaxAddress();
		Set<Address> leaders = new LinkedHashSet<>();
		leaders.add(entry);

		List<Instruction> insns = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(entry, true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			if (ins.getAddress().compareTo(end) > 0) {
				break;
			}
			insns.add(ins);
			for (Address t : ins.getFlows()) {
				if (f.getBody().contains(t)) {
					leaders.add(t);
				}
			}
			if (ins.getFlowType() != FlowType.FALL_THROUGH) {
				Address next = ins.getMaxAddress().next();
				if (f.getBody().contains(next)) {
					leaders.add(next);
				}
			}
		}
		if (insns.isEmpty()) {
			out.add("No instructions in " + f.getName());
			return out;
		}

		out.add("FUNCTION " + f.getName() + " @ " + entry + "  insn=" + insns.size()
			+ "  blocks=" + leaders.size());
		Instruction blockStart = null;
		int size = 0;
		Set<String> succ = new LinkedHashSet<>();
		for (int i = 0; i < insns.size(); i++) {
			Instruction ins = insns.get(i);
			boolean isLeader = leaders.contains(ins.getAddress());
			if (isLeader && blockStart != null) {
				out.add("BLOCK " + blockStart.getAddress() + " size=" + size + " -> " + String.join(",", succ));
				succ = new LinkedHashSet<>();
				size = 0;
			}
			if (blockStart == null) {
				blockStart = ins;
			}
			size++;
			for (Address t : ins.getFlows()) {
				succ.add(t.toString());
			}
			if (ins.getFlowType() == FlowType.FALL_THROUGH && i + 1 < insns.size()) {
				succ.add(insns.get(i + 1).getAddress().toString());
			}
		}
		if (blockStart != null) {
			out.add("BLOCK " + blockStart.getAddress() + " size=" + size + " -> " + String.join(",", succ));
		}
		return out;
	}

	private DataTypeManager dtm() {
		return currentProgram.getDataTypeManager();
	}

	private int pointerSize() {
		// Program.getPointerSize() was removed in Ghidra 12.x; it is getDefaultPointerSize().
		return currentProgram.getDefaultPointerSize();
	}

	/**
	 * Turn a type name into a DataType. Handles the C spellings an analyst types
	 * on the wire (int, uint32, ptr, char*, byte[16]) and then falls back to a
	 * lookup by name, so a type created earlier by /create_struct is usable here
	 * on the next call.
	 */
	private DataType resolveType(String raw) {
		if (raw == null) {
			return null;
		}
		String t = raw.trim();
		if (t.isEmpty()) {
			return null;
		}
		int bracket = t.indexOf('[');
		if (bracket > 0 && t.endsWith("]")) {
			DataType base = resolveType(t.substring(0, bracket));
			if (base == null) {
				return null;
			}
			try {
				int count = Integer.parseInt(t.substring(bracket + 1, t.length() - 1).trim());
				return new ArrayDataType(base, count, base.getLength());
			}
			catch (Exception e) {
				return null;
			}
		}
		if (t.endsWith("*")) {
			DataType base = resolveType(t.substring(0, t.length() - 1));
			if (base == null) {
				return null;
			}
			return new PointerDataType(base, pointerSize(), dtm());
		}
		switch (t.toLowerCase()) {
			case "void": return VoidDataType.dataType;
			case "bool":
			case "byte":
			case "uint8": return ByteDataType.dataType;
			case "char": return CharDataType.dataType;
			case "short":
			case "int16": return ShortDataType.dataType;
			case "ushort":
			case "uint16": return UnsignedShortDataType.dataType;
			case "int":
			case "int32": return IntegerDataType.dataType;
			case "uint":
			case "uint32": return UnsignedIntegerDataType.dataType;
			case "long":
			case "int64": return LongLongDataType.dataType;
			case "ulong":
			case "uint64": return UnsignedLongLongDataType.dataType;
			case "float": return FloatDataType.dataType;
			case "double": return DoubleDataType.dataType;
			case "pointer":
			case "ptr": return new PointerDataType(VoidDataType.dataType, pointerSize(), dtm());
			case "string": return new PointerDataType(CharDataType.dataType, pointerSize(), dtm());
			default: break;
		}
		try {
			DataType found = dtm().getDataType(t);
			return found;
		}
		catch (Exception e) {
			return null;
		}
	}

	/**
	 * Author a structure from a `;`-separated field list and optionally apply it.
	 *
	 * Each field is `offset:length:type[:name]`, or `length:type[:name]` to place
	 * it at the current end. Types may be arrays (`byte[16]`) or pointers. The
	 * `apply_to` step is what turns a description into a fact: after
	 * createData, every access to that address is typed.
	 */
	private String createStruct(String name, String fields, String applyTo) {
		if (name == null || name.isEmpty() || fields == null || fields.isEmpty()) {
			return "create_struct needs name= and fields=";
		}
		List<String> specs = new ArrayList<>();
		for (String f : fields.split(";")) {
			if (!f.trim().isEmpty()) {
				specs.add(f.trim());
			}
		}
		if (specs.isEmpty()) {
			return "create_struct: no fields";
		}
		StructureDataType sdt = new StructureDataType(name, 0);
		int cursor = 0;
		StringBuilder report = new StringBuilder();
		for (String spec : specs) {
			String[] parts = spec.split(":");
			int offset;
			int length;
			String typeText;
			String fieldName;
			if (parts.length >= 3) {
				offset = (int) parseNumber(parts[0]);
				length = (int) parseNumber(parts[1]);
				typeText = parts[2];
				fieldName = parts.length > 3 ? parts[3] : ("field_" + parts[0]);
			}
			else {
				offset = cursor;
				length = (int) parseNumber(parts[0]);
				typeText = parts[1];
				fieldName = parts.length > 2 ? parts[2] : ("field_" + offset);
			}
			DataType dt = resolveType(typeText);
			if (dt == null) {
				return "create_struct: unknown type '" + typeText + "' in field '" + spec + "'";
			}
			if (length <= 0) {
				length = dt.getLength();
			}
			if (offset != cursor) {
				int pad = offset - cursor;
				if (pad > 0) {
					sdt.add(ByteDataType.dataType, pad, "pad_" + cursor, "alignment padding");
				}
			}
			sdt.add(dt, length, fieldName, "");
			cursor = offset + length;
			report.append("  +").append(String.format("0x%02x", offset)).append(' ')
				.append(fieldName).append(" : ").append(dt.getName())
				.append(" [").append(length).append("]\n");
		}

		int tx = currentProgram.startTransaction("headless create struct");
		boolean ok = false;
		String applied = "";
		try {
			DataType added = dtm().addDataType(sdt, DataTypeConflictHandler.REPLACE_HANDLER);
			ok = true;
			if (applyTo != null && !applyTo.isEmpty()) {
				Address addr = currentProgram.getAddressFactory().getAddress(applyTo);
				currentProgram.getListing().createData(addr, added);
				applied = "\nApplied " + added.getName() + " at " + applyTo;
			}
		}
		catch (Exception e) {
			return "create_struct failed: " + e.getMessage();
		}
		finally {
			currentProgram.endTransaction(tx, ok);
		}
		return "Created " + name + " (" + cursor + " bytes):\n" + report + applied;
	}

	private String listStructs() {
		List<String> names = new ArrayList<>();
		java.util.Iterator<DataType> typeIt = dtm().getAllDataTypes();
		while (typeIt.hasNext()) {
			DataType dt = typeIt.next();
			if (dt.getPathName() != null && dt.getPathName().startsWith("/")) {
				names.add(dt.getPathName() + "  " + dt.getLength() + " bytes");
			}
		}
		Collections.sort(names);
		return names.isEmpty() ? "No program types yet -- POST /create_struct first" : String.join("\n", names);
	}

	private boolean renameVariable(String function, String variable, String newName) {
		if (variable == null || newName == null || newName.isEmpty()) {
			return false;
		}
		Function f = functionFor(function);
		if (f == null) {
			f = functionByName(function);
		}
		if (f == null) {
			return false;
		}
		Variable v = findVariable(f, variable);
		if (v == null) {
			return false;
		}
		int tx = currentProgram.startTransaction("headless rename variable");
		boolean ok = false;
		try {
			v.setName(newName, SourceType.USER_DEFINED);
			ok = true;
		}
		catch (Exception e) {
			printerr("renameVariable: " + e.getMessage());
		}
		finally {
			currentProgram.endTransaction(tx, ok);
		}
		return ok;
	}

	private String setFunctionPrototype(String function, String returnType, String params) {
		Function f = functionFor(function);
		if (f == null) {
			f = functionByName(function);
		}
		if (f == null) {
			return "set_function_prototype: no function at or named '" + function + "'";
		}
		DataType rt = resolveType(returnType == null || returnType.isEmpty() ? "void" : returnType);
		if (rt == null) {
			return "set_function_prototype: unknown return type '" + returnType + "'";
		}
		List<Parameter> args = new ArrayList<>();
		int i = 0;
		if (params != null && !params.isEmpty()) {
			for (String spec : params.split("[;,]")) {
				String s = spec.trim();
				if (s.isEmpty()) {
					continue;
				}
				String[] pv = s.split(":");
				DataType dt = resolveType(pv[0]);
				if (dt == null) {
					return "set_function_prototype: unknown parameter type '" + pv[0] + "'";
				}
				String pname = pv.length > 1 && !pv[1].isEmpty() ? pv[1] : ("arg_" + i);
				args.add(new ParameterImpl(pname, dt, currentProgram));
				i++;
			}
		}
		int tx = currentProgram.startTransaction("headless set prototype");
		boolean ok = false;
		try {
			if (args.isEmpty()) {
				f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
					SourceType.USER_DEFINED);
			}
			else {
				f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
					SourceType.USER_DEFINED, args.toArray(new Parameter[0]));
			}
			f.setReturnType(rt, SourceType.USER_DEFINED);
			ok = true;
		}
		catch (Exception e) {
			return "set_function_prototype failed: " + e.getMessage();
		}
		finally {
			currentProgram.endTransaction(tx, ok);
		}
		return ok ? "Prototype set: " + f.getSignature() : "set_function_prototype failed";
	}

	private String setLocalVariableType(String function, String variable, String type) {
		Function f = functionFor(function);
		if (f == null) {
			f = functionByName(function);
		}
		if (f == null) {
			return "set_local_variable_type: no function at or named '" + function + "'";
		}
		DataType dt = resolveType(type);
		if (dt == null) {
			return "set_local_variable_type: unknown type '" + type + "'";
		}
		Variable v = findVariable(f, variable);
		if (v == null) {
			return "set_local_variable_type: no variable '" + variable + "' in " + f.getName();
		}
		int tx = currentProgram.startTransaction("headless set local type");
		boolean ok = false;
		try {
			v.setDataType(dt, SourceType.USER_DEFINED);
			ok = true;
		}
		catch (Exception e) {
			return "set_local_variable_type failed: " + e.getMessage();
		}
		finally {
			currentProgram.endTransaction(tx, ok);
		}
		return ok ? "Local " + v.getName() + " : " + dt.getName() : "setDataType refused " + dt.getName();
	}

	/** Variables of a function by name, then by stack offset, then by index. */
	private Variable findVariable(Function f, String wanted) {
		if (wanted == null || wanted.isEmpty()) {
			return null;
		}
		for (Variable v : f.getLocalVariables()) {
			if (wanted.equals(v.getName()) || wanted.equals(String.valueOf(v.getStackOffset()))) {
				return v;
			}
		}
		try {
			int idx = Integer.parseInt(wanted);
			Variable[] all = f.getAllVariables();
			if (idx >= 0 && idx < all.length) {
				return all[idx];
			}
		}
		catch (NumberFormatException e) {
			// not an index; the name and offset lookups already ran
		}
		return null;
	}

	private static long parseNumber(String s) {
		String t = s.trim().toLowerCase();
		if (t.startsWith("0x")) {
			return Long.parseLong(t.substring(2), 16);
		}
		return Long.parseLong(t);
	}

	private static Map<String, String> query(HttpExchange ex) {
		Map<String, String> map = new HashMap<>();
		String raw = ex.getRequestURI().getRawQuery();
		if (raw == null || raw.isEmpty()) {
			return map;
		}
		for (String pair : raw.split("&")) {
			String[] kv = pair.split("=", 2);
			if (kv.length == 2) {
				map.put(decode(kv[0]), decode(kv[1]));
			}
		}
		return map;
	}

	private static Map<String, String> form(HttpExchange ex) throws IOException {
		Map<String, String> map = new HashMap<>();
		String body = body(ex);
		for (String pair : body.split("&")) {
			String[] kv = pair.split("=", 2);
			if (kv.length == 2) {
				map.put(decode(kv[0]), decode(kv[1]));
			}
		}
		return map;
	}

	private static String body(HttpExchange ex) throws IOException {
		return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
	}

	private static String decode(String s) {
		return URLDecoder.decode(s, StandardCharsets.UTF_8);
	}

	private static int pint(String v, int d) {
		if (v == null) {
			return d;
		}
		try {
			return Integer.parseInt(v);
		}
		catch (NumberFormatException e) {
			return d;
		}
	}

	private static String paginate(List<String> items, int offset, int limit) {
		int start = Math.max(0, offset);
		int end = Math.min(items.size(), start + Math.max(0, limit));
		if (start >= items.size()) {
			return "";
		}
		return String.join("\n", items.subList(start, end));
	}

	private static void send(HttpExchange ex, String response) throws IOException {
		if (response == null) {
			response = "";
		}
		byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
		ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
		ex.sendResponseHeaders(200, bytes.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(bytes);
		}
	}
}
