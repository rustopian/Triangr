package com.lauriewired.ghidramcp.http;

import com.lauriewired.ghidramcp.core.GhidraAnalysisService;
import com.lauriewired.ghidramcp.core.ProgramProvider;
import com.lauriewired.ghidramcp.core.TriangrService;

/**
 * Backend routes that Triangr adds to the upstream GhidraMCP backend, kept apart from
 * {@link BackendHttpServer} so upstream changes merge cleanly. Owns the async decompilation
 * pool, which starts and stops with the server.
 */
final class TriangrRoutes {

	private final TriangrService triangr;
	private final AsyncDecompileTasks tasks;

	TriangrRoutes(ProgramProvider provider, GhidraAnalysisService service) {
		this.triangr = new TriangrService(provider::runWrite, service);
		this.tasks = new AsyncDecompileTasks(service);
	}

	void register(BackendHttpServer server) {
		get(server, "/get_comment",
			(q, p) -> triangr.getComment(p, q.required("address"), q.optional("kind")));

		// Structures
		get(server, "/list_structures",
			(q, p) -> triangr.listStructures(p, q.offset(), q.limit(100)));
		get(server, "/get_structure", (q, p) -> triangr.getStructure(p, q.required("name")));
		post(server, "/create_structure",
			(q, p) -> triangr.createStructure(p, q.required("name"), q.intParam("size", 0)));
		post(server, "/add_structure_field",
			(q, p) -> triangr.addStructureField(p, q.required("struct_name"),
				q.required("field_name"), q.required("field_type"), optionalInt(q, "offset")));
		post(server, "/rename_structure_field",
			(q, p) -> triangr.renameStructureField(p, q.required("struct_name"),
				q.required("old_field_name"), q.required("new_field_name")));
		post(server, "/delete_structure_field",
			(q, p) -> triangr.deleteStructureField(p, q.required("struct_name"),
				q.required("field_name")));
		post(server, "/set_field_type",
			(q, p) -> triangr.setStructureFieldType(p, q.required("struct_name"),
				q.required("field_name"), q.required("new_type"), optionalInt(q, "length")));
		post(server, "/resize_structure_field",
			(q, p) -> triangr.resizeStructureField(p, q.required("struct_name"),
				q.required("field_name"), requiredInt(q, "new_length")));
		post(server, "/rename_structure",
			(q, p) -> triangr.renameStructure(p, q.required("old_name"), q.required("new_name")));
		post(server, "/delete_structure", (q, p) -> triangr.deleteStructure(p, q.required("name")));
		post(server, "/create_structure_pointer",
			(q, p) -> triangr.createStructurePointer(p, q.required("struct_name"),
				q.optional("pointer_name")));

		// Functions and bytes
		post(server, "/create_function",
			(q, p) -> triangr.createFunction(p, q.required("address"), q.optional("name")));
		get(server, "/read_bytes",
			(q, p) -> triangr.readBytes(p, q.required("address"), q.intParam("length", 32)));
		post(server, "/write_bytes",
			(q, p) -> triangr.writeBytes(p, q.required("address"), q.required("bytes")));

		// Async decompilation. Status and results outlive the program they came from.
		post(server, "/decompile_async", (q, p) -> tasks.submit(p, q.required("address"),
			q.intParam("timeout", GhidraAnalysisService.DECOMPILE_TIMEOUT_SECONDS)));
		server.addRoute("GET", "/task_status", false,
			(q, p) -> tasks.status(q.required("task_id")));
		server.addRoute("GET", "/task_result", false,
			(q, p) -> tasks.result(q.required("task_id")));
	}

	void start() {
		tasks.start();
	}

	void stop() {
		tasks.stop();
	}

	boolean isHealthy() {
		return tasks.isHealthy();
	}

	int taskCount() {
		return tasks.size();
	}

	private static void get(BackendHttpServer server, String path,
			BackendHttpServer.Handler handler) {
		server.addRoute("GET", path, true, handler);
	}

	private static void post(BackendHttpServer server, String path,
			BackendHttpServer.Handler handler) {
		server.addRoute("POST", path, true, handler);
	}

	private static Integer optionalInt(Request q, String name) {
		String value = q.optional(name);
		return value == null || value.isEmpty() ? null : q.intParam(name, 0);
	}

	private static int requiredInt(Request q, String name) {
		q.required(name);
		return q.intParam(name, 0);
	}
}
