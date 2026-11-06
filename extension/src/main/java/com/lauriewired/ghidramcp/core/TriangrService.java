package com.lauriewired.ghidramcp.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

import com.lauriewired.ghidramcp.core.GhidraAnalysisService.WriteExecutor;
import com.lauriewired.ghidramcp.core.Model.FunctionInfo;
import com.lauriewired.ghidramcp.core.TriangrModel.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Triangr additions to the upstream backend: comment reads, structure editing, function
 * creation, and raw byte reads and patches. Like {@link GhidraAnalysisService}, it has no GUI
 * dependency, so it works in both GUI and headless mode.
 */
public class TriangrService {

	public static final int MAX_BYTES = 1024 * 1024;

	@FunctionalInterface
	private interface WriteAction<T> {
		T run() throws Exception;
	}

	private final WriteExecutor writeExecutor;
	private final GhidraAnalysisService analysis;

	public TriangrService(WriteExecutor writeExecutor, GhidraAnalysisService analysis) {
		this.writeExecutor = writeExecutor;
		this.analysis = analysis;
	}

	// ------------------------------------------------------------------------------------------
	// Comments
	// ------------------------------------------------------------------------------------------

	/**
	 * Reads the comment that set_disasm_comment ("disasm", end-of-line) or set_decomp_comment
	 * ("decomp", pre-comment) would replace.
	 */
	public CommentRead getComment(Program program, String address, String kind) {
		String k = kind == null || kind.isEmpty() ? "disasm" : kind.toLowerCase(Locale.ROOT);
		CommentType type = switch (k) {
			case "disasm" -> CommentType.EOL;
			case "decomp" -> CommentType.PRE;
			default -> throw McpException.invalidParameter(
				"kind must be 'disasm' or 'decomp' (got '" + kind + "')");
		};
		Address addr = GhidraAnalysisService.parseAddress(program, address);
		String comment = program.getListing().getComment(type, addr);
		return new CommentRead(addr.toString(), k, comment != null, comment);
	}

	// ------------------------------------------------------------------------------------------
	// Structures
	// ------------------------------------------------------------------------------------------

	public Page<StructureSummary> listStructures(Program program, int offset, int limit) {
		List<Structure> all = new ArrayList<>();
		program.getDataTypeManager().getAllStructures().forEachRemaining(all::add);
		all.sort(Comparator.comparing(Structure::getPathName));
		Page.Builder<StructureSummary> page = new Page.Builder<>(offset, limit);
		for (Structure s : all) {
			page.offer(() -> summary(s));
		}
		return page.build();
	}

	public StructureInfo getStructure(Program program, String name) {
		Structure struct = findStructure(program.getDataTypeManager(), name);
		List<StructureField> fields = new ArrayList<>();
		for (DataTypeComponent c : struct.getComponents()) {
			fields.add(field(c));
		}
		return new StructureInfo(struct.getName(), struct.getPathName(), size(struct),
			fields);
	}

	/**
	 * Creates a structure in the root category. Size 0 creates an empty structure; a positive
	 * size reserves that many undefined bytes. Either way it grows as fields are appended.
	 */
	public StructureSummary createStructure(Program program, String name, int size) {
		requireNonEmpty(name, "name");
		if (size < 0) {
			throw McpException.invalidParameter("size must be >= 0 (got " + size + ")");
		}
		DataTypeManager dtm = program.getDataTypeManager();
		return write(program, "Create structure " + name, () -> {
			DataType clash = findAnyByName(dtm, name);
			if (clash != null) {
				throw McpException.conflict(
					"A data type named '" + name + "' already exists at " + clash.getPathName());
			}
			DataType added = dtm.addDataType(
				new StructureDataType(CategoryPath.ROOT, name, size, dtm),
				DataTypeConflictHandler.DEFAULT_HANDLER);
			return summary((Structure) added);
		});
	}

	/** Appends a field, or inserts it at a byte offset when {@code offset} is not null. */
	public StructureFieldChange addStructureField(Program program, String structName,
			String fieldName, String fieldType, Integer offset) {
		requireNonEmpty(structName, "struct_name");
		requireNonEmpty(fieldName, "field_name");
		requireNonEmpty(fieldType, "field_type");
		if (offset != null && offset < 0) {
			throw McpException.invalidParameter("offset must be >= 0 (got " + offset + ")");
		}
		DataType type = analysis.resolveType(program, fieldType);
		if (offset != null && type.getLength() <= 0) {
			throw McpException.invalidParameter("Type '" + type.getName() + "' has no fixed " +
				"length, which inserting at an offset requires. Append it (omit offset) or use " +
				"a sized type.");
		}
		return write(program, "Add field to " + structName, () -> {
			Structure struct = findStructure(program.getDataTypeManager(), structName);
			DataTypeComponent added = offset == null ? struct.add(type, fieldName, null)
					: struct.insertAtOffset(offset, type, type.getLength(), fieldName, null);
			return new StructureFieldChange(struct.getPathName(), size(struct),
				field(added), null);
		});
	}

	/** Renames a field; default names such as "field_0x4" identify unnamed fields. */
	public StructureFieldChange renameStructureField(Program program, String structName,
			String oldFieldName, String newFieldName) {
		requireNonEmpty(structName, "struct_name");
		requireNonEmpty(oldFieldName, "old_field_name");
		requireNonEmpty(newFieldName, "new_field_name");
		return write(program, "Rename field in " + structName, () -> {
			Structure struct = findStructure(program.getDataTypeManager(), structName);
			DataTypeComponent target = findField(struct, oldFieldName);
			for (DataTypeComponent c : struct.getComponents()) {
				if (c.getOrdinal() != target.getOrdinal() && newFieldName.equals(fieldName(c))) {
					throw McpException.conflict("A field named '" + newFieldName +
						"' already exists in " + struct.getPathName());
				}
			}
			StructureField before = field(target);
			target.setFieldName(newFieldName);
			return new StructureFieldChange(struct.getPathName(), size(struct),
				field(struct.getComponent(target.getOrdinal())), before);
		});
	}

	public StructureFieldChange deleteStructureField(Program program, String structName,
			String fieldName) {
		requireNonEmpty(structName, "struct_name");
		requireNonEmpty(fieldName, "field_name");
		return write(program, "Delete field from " + structName, () -> {
			Structure struct = findStructure(program.getDataTypeManager(), structName);
			DataTypeComponent target = findField(struct, fieldName);
			StructureField before = field(target);
			struct.delete(target.getOrdinal());
			return new StructureFieldChange(struct.getPathName(), size(struct), null,
				before);
		});
	}

	/**
	 * Changes a field's type. A larger type absorbs the following components; a smaller one
	 * leaves undefined bytes. {@code length} overrides the type's natural length and is required
	 * for types without a fixed length.
	 */
	public StructureFieldChange setStructureFieldType(Program program, String structName,
			String fieldName, String newType, Integer length) {
		requireNonEmpty(structName, "struct_name");
		requireNonEmpty(fieldName, "field_name");
		requireNonEmpty(newType, "new_type");
		DataType type = analysis.resolveType(program, newType);
		int effectiveLength = length != null ? length : type.getLength();
		if (effectiveLength <= 0) {
			throw McpException.invalidParameter("Type '" + type.getName() + "' has no fixed " +
				"length; pass an explicit positive length");
		}
		return write(program, "Set type of " + structName + "." + fieldName, () -> {
			Structure struct = findStructure(program.getDataTypeManager(), structName);
			DataTypeComponent target = findField(struct, fieldName);
			StructureField before = field(target);
			DataTypeComponent replaced = struct.replaceAtOffset(target.getOffset(), type,
				effectiveLength, target.getFieldName(), target.getComment());
			return new StructureFieldChange(struct.getPathName(), size(struct),
				field(replaced), before);
		});
	}

	/** Changes a field's length while keeping its type, e.g. to adjust an array bound. */
	public StructureFieldChange resizeStructureField(Program program, String structName,
			String fieldName, int newLength) {
		requireNonEmpty(structName, "struct_name");
		requireNonEmpty(fieldName, "field_name");
		if (newLength <= 0) {
			throw McpException.invalidParameter("new_length must be > 0 (got " + newLength + ")");
		}
		return write(program, "Resize " + structName + "." + fieldName, () -> {
			Structure struct = findStructure(program.getDataTypeManager(), structName);
			DataTypeComponent target = findField(struct, fieldName);
			StructureField before = field(target);
			if (target.getLength() == newLength) {
				return new StructureFieldChange(struct.getPathName(), size(struct), before,
					before);
			}
			DataTypeComponent resized = struct.replaceAtOffset(target.getOffset(),
				target.getDataType(), newLength, target.getFieldName(), target.getComment());
			return new StructureFieldChange(struct.getPathName(), size(struct),
				field(resized), before);
		});
	}

	/**
	 * Renames a structure; references to it update automatically. Runs on the calling thread,
	 * not the write executor: dispatching this data type manager change to the Swing thread has
	 * deadlocked in the GUI.
	 */
	public StructureRenamed renameStructure(Program program, String oldName, String newName) {
		requireNonEmpty(oldName, "old_name");
		requireNonEmpty(newName, "new_name");
		DataTypeManager dtm = program.getDataTypeManager();
		return writeOnCallingThread(program, "Rename structure " + oldName, () -> {
			Structure struct = findStructure(dtm, oldName);
			DataType clash = findAnyByName(dtm, newName);
			if (clash != null && !clash.getDataTypePath().equals(struct.getDataTypePath())) {
				throw McpException.conflict("A data type named '" + newName +
					"' already exists at " + clash.getPathName());
			}
			String old = struct.getName();
			struct.setName(newName);
			return new StructureRenamed(old, struct.getName(), struct.getPathName());
		});
	}

	/**
	 * Deletes a structure; fields, parameters and variables that used it become undefined.
	 * Runs on the calling thread for the same reason as {@link #renameStructure}.
	 */
	public StructureDeleted deleteStructure(Program program, String name) {
		requireNonEmpty(name, "name");
		DataTypeManager dtm = program.getDataTypeManager();
		return writeOnCallingThread(program, "Delete structure " + name, () -> {
			Structure struct = findStructure(dtm, name);
			String structName = struct.getName();
			String path = struct.getPathName();
			if (!dtm.remove(struct)) {
				throw McpException.failed("The data type manager refused to remove " + path);
			}
			return new StructureDeleted(structName, path);
		});
	}

	/**
	 * Adds a pointer type for a structure and, when {@code pointerName} is given, a typedef
	 * with that name (e.g. "PMyStruct" for "MyStruct *").
	 */
	public PointerTypeCreated createStructurePointer(Program program, String structName,
			String pointerName) {
		requireNonEmpty(structName, "struct_name");
		boolean named = pointerName != null && !pointerName.isEmpty();
		DataTypeManager dtm = program.getDataTypeManager();
		return write(program, "Create pointer to " + structName, () -> {
			Structure struct = findStructure(dtm, structName);
			if (named) {
				DataType clash = findAnyByName(dtm, pointerName);
				if (clash != null) {
					throw McpException.conflict("A data type named '" + pointerName +
						"' already exists at " + clash.getPathName());
				}
			}
			DataType pointer = dtm.addDataType(new PointerDataType(struct, dtm),
				DataTypeConflictHandler.DEFAULT_HANDLER);
			String typedef = null;
			if (named) {
				typedef = dtm.addDataType(
					new TypedefDataType(CategoryPath.ROOT, pointerName, pointer, dtm),
					DataTypeConflictHandler.DEFAULT_HANDLER).getPathName();
			}
			return new PointerTypeCreated(struct.getPathName(), pointer.getPathName(), typedef);
		});
	}

	// ------------------------------------------------------------------------------------------
	// Functions
	// ------------------------------------------------------------------------------------------

	/**
	 * Creates a function at an entry address with Ghidra's CreateFunctionCmd, the same path as
	 * the "Create Function" action. A null or empty name gets Ghidra's default name.
	 */
	public FunctionInfo createFunction(Program program, String address, String name) {
		Address entry = GhidraAnalysisService.parseAddress(program, address);
		String functionName = name == null || name.isEmpty() ? null : name;
		return write(program, "Create function at " + entry, () -> {
			Function existing = program.getFunctionManager().getFunctionAt(entry);
			if (existing != null) {
				throw new McpException("ALREADY_EXISTS", 409, "A function already exists at " +
					entry + " (" + existing.getName(true) + ")");
			}
			CreateFunctionCmd cmd =
				new CreateFunctionCmd(functionName, entry, null, SourceType.USER_DEFINED);
			if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
				throw McpException.failed("Could not create function: " + cmd.getStatusMsg());
			}
			Function created = program.getFunctionManager().getFunctionAt(entry);
			if (created == null) {
				throw McpException.failed("CreateFunctionCmd succeeded but no function exists at " +
					entry);
			}
			return GhidraAnalysisService.info(created);
		});
	}

	// ------------------------------------------------------------------------------------------
	// Bytes
	// ------------------------------------------------------------------------------------------

	/** Reads up to {@link #MAX_BYTES} bytes as space-separated hex. */
	public BytesRead readBytes(Program program, String address, int length) {
		if (length < 1 || length > MAX_BYTES) {
			throw McpException.invalidParameter(
				"length must be between 1 and " + MAX_BYTES + " (got " + length + ")");
		}
		Address start = GhidraAnalysisService.parseAddress(program, address);
		byte[] buffer = new byte[length];
		int read;
		try {
			read = program.getMemory().getBytes(start, buffer);
		}
		catch (MemoryAccessException e) {
			throw new McpException("MEMORY_ERROR", 400,
				"Cannot read memory at " + start + ": " + e.getMessage());
		}
		return new BytesRead(start.toString(), read, hex(buffer, read));
	}

	/**
	 * Writes space-separated hex bytes. The write is committed in its own transaction. If the
	 * range held instructions, it is then re-disassembled in a separate, best-effort
	 * transaction, so a disassembly failure cannot roll back the patch.
	 */
	public BytesWritten writeBytes(Program program, String address, String bytesHex) {
		byte[] bytes = parseHexBytes(bytesHex);
		Address start = GhidraAnalysisService.parseAddress(program, address);
		Address end;
		try {
			end = start.addNoWrap(bytes.length - 1);
		}
		catch (AddressOverflowException e) {
			throw McpException.invalidParameter("Write of " + bytes.length + " bytes at " + start +
				" runs past the end of the address space");
		}
		Memory memory = program.getMemory();
		if (!memory.contains(start) || !memory.contains(end)) {
			throw McpException.invalidParameter(
				"Range " + start + " - " + end + " is not mapped in program memory");
		}
		Listing listing = program.getListing();
		Instruction first = firstInstruction(listing, start, end);
		boolean hadCode = first != null;
		Address disassembleFrom = hadCode ? first.getMinAddress() : start;

		Address last = end;
		write(program, "Write bytes", () -> {
			// Data definitions stay in place over patched bytes; only stale instructions are
			// cleared, and only code is re-disassembled.
			if (hadCode) {
				listing.clearCodeUnits(start, last, false);
			}
			memory.setBytes(start, bytes);
			return null;
		});

		boolean disassembled = false;
		String warning = null;
		if (hadCode) {
			try {
				write(program, "Disassemble after write", () -> {
					Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null)
							.disassemble(disassembleFrom, null);
					return null;
				});
				disassembled = true;
			}
			catch (McpException e) {
				warning = "Bytes were written but re-disassembly failed: " + e.getMessage();
				Msg.warn(this, warning, e);
			}
		}
		return new BytesWritten(start.toString(), end.toString(), bytes.length, disassembled,
			warning);
	}

	/** The instruction containing {@code start}, else the first one inside the range. */
	private static Instruction firstInstruction(Listing listing, Address start, Address end) {
		Instruction containing = listing.getInstructionContaining(start);
		if (containing != null) {
			return containing;
		}
		InstructionIterator it = listing.getInstructions(new AddressSet(start, end), true);
		return it.hasNext() ? it.next() : null;
	}

	private static byte[] parseHexBytes(String text) {
		if (text == null || text.isBlank()) {
			throw McpException.invalidParameter("bytes must contain at least one hex byte");
		}
		String[] tokens = text.trim().split("\\s+");
		if (tokens.length > MAX_BYTES) {
			throw McpException.invalidParameter("A write may be at most " + MAX_BYTES + " bytes");
		}
		byte[] bytes = new byte[tokens.length];
		for (int i = 0; i < tokens.length; i++) {
			int value;
			try {
				value = Integer.parseInt(tokens[i], 16);
			}
			catch (NumberFormatException e) {
				throw McpException.invalidParameter(
					"Invalid hex byte at index " + i + ": '" + tokens[i] + "'");
			}
			if (value < 0 || value > 0xff) {
				throw McpException.invalidParameter(
					"Hex byte at index " + i + " is out of range 00..ff: '" + tokens[i] + "'");
			}
			bytes[i] = (byte) value;
		}
		return bytes;
	}

	// ------------------------------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------------------------------

	/**
	 * Finds a structure by full path ("/category/Name") or by name: an exact match first, then a
	 * case-insensitive one.
	 */
	private static Structure findStructure(DataTypeManager dtm, String name) {
		requireNonEmpty(name, "struct_name");
		if (name.startsWith("/")) {
			DataType dt = dtm.getDataType(name);
			if (dt instanceof Structure s) {
				return s;
			}
			if (dt != null) {
				throw McpException.invalidParameter("'" + name + "' is not a structure");
			}
			throw McpException.notFound("Structure not found: " + name);
		}
		List<Structure> exact = new ArrayList<>();
		Structure caseInsensitive = null;
		Iterator<Structure> it = dtm.getAllStructures();
		while (it.hasNext()) {
			Structure s = it.next();
			if (s.getName().equals(name)) {
				exact.add(s);
			}
			else if (caseInsensitive == null && s.getName().equalsIgnoreCase(name)) {
				caseInsensitive = s;
			}
		}
		if (exact.size() == 1) {
			return exact.get(0);
		}
		if (exact.size() > 1) {
			List<String> paths = new ArrayList<>();
			for (Structure s : exact) {
				paths.add(s.getPathName());
			}
			throw McpException.ambiguous("'" + name + "' matches " + exact.size() +
				" structures; pass the full path instead: " + String.join(", ", paths));
		}
		if (caseInsensitive != null) {
			return caseInsensitive;
		}
		DataType other = findAnyByName(dtm, name);
		if (other != null) {
			throw McpException.invalidParameter(
				"'" + name + "' is a " + other.getClass().getSimpleName() + ", not a structure");
		}
		throw McpException.notFound("Structure not found: " + name);
	}

	/** Any data type with this name, preferring an exact match over a case-insensitive one. */
	private static DataType findAnyByName(DataTypeManager dtm, String name) {
		DataType caseInsensitive = null;
		Iterator<DataType> it = dtm.getAllDataTypes();
		while (it.hasNext()) {
			DataType dt = it.next();
			if (dt.getName().equals(name)) {
				return dt;
			}
			if (caseInsensitive == null && dt.getName().equalsIgnoreCase(name)) {
				caseInsensitive = dt;
			}
		}
		return caseInsensitive;
	}

	/** A field by explicit name, or by Ghidra's default name (e.g. "field_0x4"). */
	private static DataTypeComponent findField(Structure struct, String fieldName) {
		for (DataTypeComponent c : struct.getComponents()) {
			if (fieldName.equals(fieldName(c))) {
				return c;
			}
		}
		throw McpException.notFound(
			"Field '" + fieldName + "' not found in " + struct.getPathName());
	}

	private static String fieldName(DataTypeComponent c) {
		return c.getFieldName() != null ? c.getFieldName() : c.getDefaultFieldName();
	}

	private static StructureField field(DataTypeComponent c) {
		return c == null ? null
				: new StructureField(c.getOffset(), fieldName(c), c.getDataType().getDisplayName(),
					c.getLength(), c.getComment());
	}

	private static StructureSummary summary(Structure s) {
		return new StructureSummary(s.getName(), s.getPathName(), size(s), s.getNumComponents());
	}

	/** Ghidra reports an empty structure's length as 1; report 0 instead. */
	private static int size(Structure s) {
		return s.isZeroLength() ? 0 : s.getLength();
	}

	private static String hex(byte[] bytes, int length) {
		StringBuilder sb = new StringBuilder(length * 3);
		for (int i = 0; i < length; i++) {
			if (i > 0) {
				sb.append(' ');
			}
			sb.append(String.format("%02x", bytes[i] & 0xff));
		}
		return sb.toString();
	}

	private static void requireNonEmpty(String value, String name) {
		if (value == null || value.isEmpty()) {
			throw McpException.missingParameter(name);
		}
	}

	private <T> T write(Program program, String transactionName, WriteAction<T> action) {
		return writeExecutor.execute(() -> inTransaction(program, transactionName, action));
	}

	private static <T> T writeOnCallingThread(Program program, String transactionName,
			WriteAction<T> action) {
		return inTransaction(program, transactionName, action);
	}

	private static <T> T inTransaction(Program program, String transactionName,
			WriteAction<T> action) {
		int tx = program.startTransaction(transactionName);
		boolean commit = false;
		try {
			T result = action.run();
			commit = true;
			return result;
		}
		catch (McpException e) {
			throw e;
		}
		catch (DuplicateNameException e) {
			throw McpException.conflict(e.getMessage());
		}
		catch (InvalidInputException | IllegalArgumentException e) {
			throw McpException.invalidParameter(e.getMessage());
		}
		catch (Exception e) {
			throw McpException.failed(transactionName + " failed: " + e.getMessage(), e);
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}
}
