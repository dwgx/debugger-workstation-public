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
		server.createContext("/renameVariable", ex -> send(ex, "headless: renameVariable not implemented; use batch export"));
		server.createContext("/set_function_prototype", ex -> send(ex, "headless: set_function_prototype not implemented"));
		server.createContext("/set_local_variable_type", ex -> send(ex, "headless: set_local_variable_type not implemented"));
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
