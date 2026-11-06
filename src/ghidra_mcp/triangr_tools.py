"""MCP tools that Triangr adds to the upstream ghidra-mcp server.

They are registered from `create_server` but live here so upstream changes to server.py merge
cleanly. The angr/AngryGhidra tools are in `angr_tools`.
"""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from ghidra_mcp.angr_tools import AngrTools, register_angr_tools
from ghidra_mcp.backend import BackendError, GhidraBackend

DECOMPILE_TIMEOUT_MIN = 10
DECOMPILE_TIMEOUT_MAX = 1800
# Extra HTTP read time beyond the decompiler deadline, so the backend's reply can still arrive.
DECOMPILE_READ_MARGIN = 30
HEALTH_TIMEOUT = 5.0

Result = dict[str, Any]


def clamp_decompile_timeout(timeout: int) -> int:
    return max(DECOMPILE_TIMEOUT_MIN, min(int(timeout), DECOMPILE_TIMEOUT_MAX))


def register_triangr_tools(mcp: FastMCP, backend: GhidraBackend) -> None:
    def call(method: str, endpoint: str, _read_timeout: float | None = None, **params: Any) -> Any:
        try:
            return backend.request(method, endpoint, params, read_timeout=_read_timeout)
        except BackendError as e:
            raise ToolError(str(e)) from e

    def get(endpoint: str, _read_timeout: float | None = None, **params: Any) -> Any:
        return call("GET", endpoint, _read_timeout, **params)

    def post(endpoint: str, _read_timeout: float | None = None, **params: Any) -> Any:
        return call("POST", endpoint, _read_timeout, **params)

    # ---- Health ----------------------------------------------------------------------------

    @mcp.tool()
    def check_server_health() -> Result:
        """Probe the Ghidra backend: status, Ghidra version, mode (gui or headless), loaded
        program, uptime, time since the last tool request, and async task count. Reports
        status "unreachable" instead of failing when the backend cannot be reached."""
        try:
            data = backend.request("GET", "health", read_timeout=HEALTH_TIMEOUT)
        except BackendError as e:
            result: Result = {"status": "unreachable", "error": str(e)}
            loading = getattr(backend, "status", None)
            if loading:
                result["headless_status"] = loading
            result["backend_url"] = backend.base_url
            return result
        return {**data, "backend_url": backend.base_url}

    # ---- Comments --------------------------------------------------------------------------

    @mcp.tool()
    def get_comment(address: str, kind: Literal["disasm", "decomp"] = "disasm") -> Result:
        """Read the comment that set_disasm_comment ("disasm", end-of-line) or
        set_decomp_comment ("decomp", pre-comment) would replace."""
        return get("get_comment", address=address, kind=kind)

    # ---- Async decompilation ---------------------------------------------------------------

    @mcp.tool()
    def decompile_function_async(address: str, timeout: int = 300) -> Result:
        """Start decompiling the function at or containing an address in the background and
        return a task_id at once. Poll get_task_status, then fetch the code with
        get_task_result. timeout is the decompiler deadline in seconds (10-1800)."""
        return post("decompile_async", address=address, timeout=clamp_decompile_timeout(timeout))

    @mcp.tool()
    def get_task_status(task_id: str) -> Result:
        """Status of an async decompilation: pending, running, completed or failed, with the
        elapsed time and any error."""
        return get("task_status", task_id=task_id)

    @mcp.tool()
    def get_task_result(task_id: str) -> Result:
        """Decompiled code of a completed async task, in the same shape as decompile_by_addr.
        The task is forgotten once its result has been read."""
        return get("task_result", task_id=task_id)

    # ---- Functions -------------------------------------------------------------------------

    @mcp.tool()
    def create_function(address: str, name: str = "") -> Result:
        """Create a function at an entry address with Ghidra's CreateFunctionCmd, which
        disassembles and computes the body like the "Create Function" action. Without a name,
        Ghidra assigns its default FUN_<addr> name."""
        return post("create_function", address=address, name=name or None)

    # ---- Structures ------------------------------------------------------------------------

    @mcp.tool()
    def list_structures(offset: int = 0, limit: int = 100) -> Result:
        """List structure data types (name, category path, size, component count)."""
        return get("list_structures", offset=offset, limit=limit)

    @mcp.tool()
    def get_structure(name: str) -> Result:
        """Get a structure's field layout (offset, name, type, length, comment). name may be a
        plain name or a full path such as "/MyCategory/MyStruct"."""
        return get("get_structure", name=name)

    @mcp.tool()
    def create_structure(name: str, size: int = 0) -> Result:
        """Create a structure. size 0 creates an empty structure that grows as fields are
        appended; a positive size reserves that many bytes up front. The name must not collide
        with an existing data type."""
        return post("create_structure", name=name, size=size)

    @mcp.tool()
    def add_structure_field(
        struct_name: str, field_name: str, field_type: str, offset: int = -1
    ) -> Result:
        """Add a field to a structure. field_type accepts built-ins ("int", "uint"), existing
        types ("MyStruct"), C syntax ("MyStruct *", "char[16]", "uint32_t"), and Windows-style
        "PMyStruct". offset -1 appends; otherwise the field is inserted at that byte offset."""
        return post(
            "add_structure_field",
            struct_name=struct_name,
            field_name=field_name,
            field_type=field_type,
            offset=offset if offset >= 0 else None,
        )

    @mcp.tool()
    def rename_structure(old_name: str, new_name: str) -> Result:
        """Rename a structure. References to it update automatically."""
        return post("rename_structure", old_name=old_name, new_name=new_name)

    @mcp.tool()
    def delete_structure(name: str) -> Result:
        """Delete a structure. Fields, parameters and variables that used it become
        undefined."""
        return post("delete_structure", name=name)

    @mcp.tool()
    def rename_structure_field(struct_name: str, old_field_name: str, new_field_name: str) -> Result:
        """Rename a structure field. Default names such as "field_0x4" identify unnamed
        fields."""
        return post(
            "rename_structure_field",
            struct_name=struct_name,
            old_field_name=old_field_name,
            new_field_name=new_field_name,
        )

    @mcp.tool()
    def set_field_type(struct_name: str, field_name: str, new_type: str, length: int = 0) -> Result:
        """Change a structure field's type. A larger type absorbs the following components; a
        smaller one leaves undefined bytes. Use it to collapse several slots into one composite
        field. length 0 uses the type's natural length; types without a fixed length need an
        explicit one."""
        return post(
            "set_field_type",
            struct_name=struct_name,
            field_name=field_name,
            new_type=new_type,
            length=length if length > 0 else None,
        )

    @mcp.tool()
    def resize_structure_field(struct_name: str, field_name: str, new_length: int) -> Result:
        """Change a field's length in bytes, keeping its type. Growing absorbs the following
        components; shrinking leaves undefined bytes."""
        return post(
            "resize_structure_field",
            struct_name=struct_name,
            field_name=field_name,
            new_length=new_length,
        )

    @mcp.tool()
    def delete_structure_field(struct_name: str, field_name: str) -> Result:
        """Delete a structure field. Default names such as "field_0x4" identify unnamed
        fields."""
        return post("delete_structure_field", struct_name=struct_name, field_name=field_name)

    @mcp.tool()
    def create_structure_pointer(struct_name: str, pointer_name: str = "") -> Result:
        """Add the pointer type "<struct_name> *" and, if pointer_name is given, a typedef with
        that name (e.g. "PMyStruct")."""
        return post(
            "create_structure_pointer", struct_name=struct_name, pointer_name=pointer_name or None
        )

    # ---- Bytes -----------------------------------------------------------------------------

    @mcp.tool()
    def read_bytes(address: str, length: int = 32) -> Result:
        """Read up to 1 MiB of raw bytes as space-separated hex (e.g. "55 8b ec"). Fails if the
        start address is not readable; use read_memory for small reads that show gaps."""
        return get("read_bytes", address=address, length=length)

    @mcp.tool()
    def write_bytes(address: str, bytes_hex: str) -> Result:
        """Patch program memory with space-separated hex bytes (e.g. "90 90 90 90"), up to 1
        MiB. Instructions in the range are cleared and re-disassembled; defined data keeps its
        type. A failed re-disassembly is reported as a warning and does not undo the write."""
        return post("write_bytes", address=address, bytes=bytes_hex)

    register_angr_tools(mcp, AngrTools(backend))
