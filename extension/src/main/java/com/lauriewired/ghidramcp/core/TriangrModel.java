package com.lauriewired.ghidramcp.core;

import java.util.List;

/**
 * Result types returned by {@link TriangrService}, the Triangr additions to the upstream
 * backend. Serialized to JSON with snake_case names.
 */
public final class TriangrModel {

	private TriangrModel() {
	}

	public record CommentRead(String address, String kind, boolean exists, String comment) {
	}

	public record StructureSummary(String name, String path, int size, int fieldCount) {
	}

	public record StructureField(int offset, String name, String type, int length,
			String comment) {
	}

	public record StructureInfo(String name, String path, int size, List<StructureField> fields) {
	}

	/**
	 * A change to one field. {@code field} is the field after the change (null when it was
	 * deleted) and {@code previous} the field before it (null when it was added).
	 */
	public record StructureFieldChange(String structure, int structureSize, StructureField field,
			StructureField previous) {
	}

	public record StructureRenamed(String oldName, String newName, String path) {
	}

	public record StructureDeleted(String name, String path) {
	}

	public record PointerTypeCreated(String structure, String pointerType, String typedef) {
	}

	public record BytesRead(String address, int length, String hex) {
	}

	public record BytesWritten(String address, String end, int length, boolean disassembled,
			String warning) {
	}

	public record AsyncTask(String taskId, String status, String address, long elapsedMs,
			String error) {
	}
}
