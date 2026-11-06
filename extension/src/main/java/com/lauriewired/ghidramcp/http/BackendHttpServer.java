package com.lauriewired.ghidramcp.http;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.lauriewired.ghidramcp.core.GhidraAnalysisService;
import com.lauriewired.ghidramcp.core.McpException;
import com.lauriewired.ghidramcp.core.ProgramProvider;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * HTTP backend used by the ghidra-mcp Python server. Binds to loopback unless the GUI plugin is
 * configured with another host. Requests are handled one at a time on a dedicated thread.
 */
public final class BackendHttpServer {

	public static final String VERSION = "2.0.0";

	private static final Set<String> ALLOWED_HOSTS = Set.of("127.0.0.1", "localhost", "[::1]");

	@FunctionalInterface
	interface Handler {
		Object handle(Request request, Program program);
	}

	private record Route(String method, boolean needsProgram, Handler handler) {
	}

	private final ProgramProvider provider;
	private final GhidraAnalysisService service;
	private final TriangrRoutes triangr;
	private final Map<String, Route> routes = new LinkedHashMap<>();
	private volatile Set<String> allowedHosts = ALLOWED_HOSTS;
	private volatile long startedAtMillis;
	private volatile long lastRequestMillis;
	private HttpServer server;
	private ExecutorService executor;

	public BackendHttpServer(ProgramProvider provider) {
		this.provider = provider;
		this.service = new GhidraAnalysisService(provider::runWrite, provider::getDataTypeService);
		this.triangr = new TriangrRoutes(provider, service);
		registerRoutes();
	}

	/** Starts listening on 127.0.0.1. Pass port 0 to pick a free port. */
	public synchronized void start(int port) throws IOException {
		start(null, port);
	}

	/**
	 * Starts listening on the given host (null or blank means loopback). Requests must name
	 * either a loopback host or the configured host in their Host header.
	 */
	public synchronized void start(String host, int port) throws IOException {
		stop();
		InetAddress bind = host == null || host.isBlank() ? InetAddress.getLoopbackAddress()
				: InetAddress.getByName(host.trim());
		Set<String> hosts = new HashSet<>(ALLOWED_HOSTS);
		if (host != null && !host.isBlank()) {
			String configured = host.trim().toLowerCase(Locale.ROOT);
			hosts.add(configured.contains(":") && !configured.startsWith("[")
					? "[" + configured + "]"
					: configured);
		}
		allowedHosts = Set.copyOf(hosts);
		server = HttpServer.create(new InetSocketAddress(bind, port), 0);
		server.createContext("/", this::dispatch);
		executor = Executors.newSingleThreadExecutor(r -> {
			Thread t = new Thread(r, "GhidraMCP-HTTP");
			t.setDaemon(true);
			return t;
		});
		server.setExecutor(executor);
		triangr.start();
		server.start();
		startedAtMillis = System.currentTimeMillis();
		lastRequestMillis = startedAtMillis;
		Msg.info(this, "GhidraMCP backend listening on " + bind.getHostAddress() + ":" + getPort());
	}

	public synchronized int getPort() {
		return server != null ? server.getAddress().getPort() : -1;
	}

	public synchronized void stop() {
		if (server != null) {
			server.stop(1);
			server = null;
		}
		if (executor != null) {
			executor.shutdownNow();
			executor = null;
		}
		triangr.stop();
	}

	/** True while the listener and its worker pools are running. */
	synchronized boolean isRunning() {
		return server != null && executor != null && !executor.isShutdown();
	}

	private void registerRoutes() {
		TaskMonitor monitor = TaskMonitor.DUMMY;

		routes.put("/health", new Route("GET", false, (q, p) -> health(p)));
		get("/program_info", (q, p) -> service.getProgramInfo(p));

		get("/functions", (q, p) -> service.listFunctions(p, q.optional("filter"), q.offset(), q.limit(100)));
		get("/classes", (q, p) -> service.listClasses(p, q.offset(), q.limit(100)));
		get("/namespaces", (q, p) -> service.listNamespaces(p, q.offset(), q.limit(100)));
		get("/segments", (q, p) -> service.listSegments(p, q.offset(), q.limit(100)));
		get("/imports", (q, p) -> service.listImports(p, q.offset(), q.limit(100)));
		get("/exports", (q, p) -> service.listExports(p, q.offset(), q.limit(100)));
		get("/data", (q, p) -> service.listDefinedData(p, q.offset(), q.limit(100)));
		get("/strings", (q, p) -> service.listStrings(p, q.optional("filter"), q.offset(), q.limit(200)));

		get("/function", (q, p) -> service.getFunction(p, q.required("address")));
		get("/current_address", (q, p) -> Map.of("address", currentAddress().toString()));
		get("/current_function", (q, p) -> service.getFunctionContaining(p, currentAddress()));
		get("/decompile", (q, p) -> service.decompileByName(p, q.required("name"), monitor));
		get("/decompile_function", (q, p) -> service.decompileByAddress(p, q.required("address"), q.intParam("timeout", GhidraAnalysisService.DECOMPILE_TIMEOUT_SECONDS), monitor));
		get("/disassemble_function", (q, p) -> service.disassemble(p, q.required("address"), q.offset(), q.limit(500)));

		get("/xrefs_to", (q, p) -> service.getXrefsTo(p, q.required("address"), q.offset(), q.limit(100)));
		get("/xrefs_from", (q, p) -> service.getXrefsFrom(p, q.required("address"), q.offset(), q.limit(100)));
		get("/function_xrefs", (q, p) -> service.getFunctionXrefs(p, q.optional("name"), q.optional("address"), q.offset(), q.limit(100)));
		get("/function_calls", (q, p) -> service.getFunctionCalls(p, q.required("address"), q.optional("direction"), q.offset(), q.limit(100)));
		get("/read_memory", (q, p) -> service.readMemory(p, q.required("address"), q.intParam("length", 64)));

		post("/rename_function", (q, p) -> service.renameFunctionByName(p, q.required("old_name"), q.required("new_name")));
		post("/rename_function_by_address", (q, p) -> service.renameFunctionByAddress(p, q.required("function_address"), q.required("new_name")));
		post("/rename_data", (q, p) -> service.renameData(p, q.required("address"), q.required("new_name")));
		post("/rename_variable", (q, p) -> service.renameVariable(p, q.optional("function_name"), q.optional("function_address"), q.required("old_name"), q.required("new_name"), monitor));
		post("/set_decompiler_comment", (q, p) -> service.setComment(p, q.required("address"), q.present("comment"), CommentType.PRE));
		post("/set_disassembly_comment", (q, p) -> service.setComment(p, q.required("address"), q.present("comment"), CommentType.EOL));
		post("/set_function_prototype", (q, p) -> service.setFunctionPrototype(p, q.required("function_address"), q.required("prototype"), provider.getDataTypeService(), monitor));
		post("/set_local_variable_type", (q, p) -> service.setLocalVariableType(p, q.required("function_address"), q.required("variable_name"), q.required("new_type"), monitor));

		triangr.register(this);
	}

	/** Registers a route; used by {@link TriangrRoutes}. */
	void addRoute(String method, String path, boolean needsProgram, Handler handler) {
		if (routes.containsKey(path)) {
			throw new IllegalStateException("Duplicate backend route: " + path);
		}
		routes.put(path, new Route(method, needsProgram, handler));
	}

	private void get(String path, Handler handler) {
		routes.put(path, new Route("GET", true, handler));
	}

	private void post(String path, Handler handler) {
		routes.put(path, new Route("POST", true, handler));
	}

	private Address currentAddress() {
		return provider.getCurrentAddress();
	}

	private Map<String, Object> health(Program program) {
		Map<String, Object> health = new LinkedHashMap<>();
		health.put("status", "ok");
		health.put("version", VERSION);
		health.put("ghidra_version", Application.getApplicationVersion());
		health.put("mode", provider.mode());
		health.put("capabilities", new TreeSet<>(provider.capabilities()));
		if (program != null) {
			Map<String, Object> info = new LinkedHashMap<>();
			info.put("name", program.getName());
			info.put("project_path",
				program.getDomainFile() != null ? program.getDomainFile().getPathname() : null);
			info.put("language_id", program.getLanguageID().toString());
			health.put("program", info);
		}
		else {
			health.put("program", null);
		}
		long now = System.currentTimeMillis();
		boolean running = isRunning();
		health.put("server_running", running);
		health.put("watchdog_healthy", running && triangr.isHealthy());
		health.put("program_loaded", program != null);
		health.put("uptime_ms", startedAtMillis > 0 ? now - startedAtMillis : 0);
		health.put("last_request_ms_ago", lastRequestMillis > 0 ? now - lastRequestMillis : 0);
		health.put("port", getPort());
		health.put("async_tasks", triangr.taskCount());
		return health;
	}

	private void dispatch(HttpExchange exchange) throws IOException {
		if (!exchange.getRequestURI().getPath().startsWith("/health")) {
			// Health probes are excluded so last_request_ms_ago reflects real tool traffic.
			lastRequestMillis = System.currentTimeMillis();
		}
		try {
			// Browsers attach an Origin header and DNS-rebound requests carry a foreign Host.
			if (exchange.getRequestHeaders().containsKey("Origin") || !hostAllowed(exchange)) {
				throw new McpException("FORBIDDEN", 403, "Cross-origin requests are not allowed");
			}
			String path = exchange.getRequestURI().getPath();
			if (path.length() > 1 && path.endsWith("/")) {
				path = path.substring(0, path.length() - 1);
			}
			Route route = routes.get(path);
			if (route == null) {
				throw new McpException("UNKNOWN_ENDPOINT", 404, "Unknown endpoint: " + path);
			}
			if (!route.method().equalsIgnoreCase(exchange.getRequestMethod())) {
				throw new McpException("METHOD_NOT_ALLOWED", 405,
					path + " requires " + route.method());
			}
			Request request = Request.parse(exchange);
			Program program = provider.getProgram();
			if (route.needsProgram() && program == null) {
				throw McpException.noProgram();
			}
			send(exchange, 200, Json.success(route.handler().handle(request, program)));
		}
		catch (McpException e) {
			send(exchange, e.status(), Json.error(e.code(), e.getMessage()));
		}
		catch (Throwable t) {
			Msg.error(this, "GhidraMCP request failed", t);
			String message = t.getMessage() != null ? t.getMessage() : t.getClass().getName();
			send(exchange, 500, Json.error("INTERNAL_ERROR", message));
		}
	}

	private boolean hostAllowed(HttpExchange exchange) {
		String host = exchange.getRequestHeaders().getFirst("Host");
		if (host == null) {
			return true;
		}
		int colon = host.lastIndexOf(':');
		if (colon > 0 && host.indexOf(']') < colon) {
			host = host.substring(0, colon);
		}
		return allowedHosts.contains(host.toLowerCase(Locale.ROOT));
	}

	private static void send(HttpExchange exchange, int status, String json) throws IOException {
		byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(status, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}
}
