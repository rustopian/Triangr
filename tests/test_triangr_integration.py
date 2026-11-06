"""End-to-end tests of the Triangr additions against a real headless Ghidra.

Skipped unless GHIDRA_INSTALL_DIR is set and the extension jar is built; see
test_headless_integration.py. Changes are made in a temporary project and discarded.
"""

import asyncio
import json
import os
import re
import time
from pathlib import Path

import pytest
from mcp.server.fastmcp.exceptions import ToolError

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_x86_64.elf"
GHIDRA = os.environ.get("GHIDRA_INSTALL_DIR")
JAR = Path(os.environ.get("GHIDRA_MCP_EXTENSION_JAR", ROOT / "extension/build/libs/GhidraMCP.jar"))

pytestmark = [
    pytest.mark.ghidra,
    pytest.mark.skipif(not GHIDRA, reason="GHIDRA_INSTALL_DIR not set"),
    pytest.mark.skipif(not JAR.is_file(), reason=f"extension jar not built: {JAR}"),
]


@pytest.fixture(scope="module")
def headless():
    pytest.importorskip("pyghidra")
    from ghidra_mcp.backend import DeferredBackend
    from ghidra_mcp.headless import HeadlessOptions, HeadlessSession
    from ghidra_mcp.server import create_server

    backend = DeferredBackend(5, 120, wait_timeout=1)
    session = HeadlessSession(
        HeadlessOptions(binary=FIXTURE, ghidra_install_dir=Path(GHIDRA), extension_jar=JAR),
        backend,
    )
    session.start()
    session.load()
    try:
        yield backend, create_server(backend, capabilities=set())
    finally:
        session.close()


@pytest.fixture(scope="module")
def mcp(headless):
    return headless[1]


def call(mcp, tool, **args):
    result = asyncio.run(mcp.call_tool(tool, args))
    if isinstance(result, tuple):
        return result[1]
    return json.loads(result[0].text)


def call_error(mcp, tool, match, **args):
    with pytest.raises(ToolError, match=match):
        asyncio.run(mcp.call_tool(tool, args))


def functions(mcp) -> dict[str, str]:
    page = call(mcp, "list_functions", limit=2000)
    return {f["name"]: f["address"] for f in page["items"]}


def test_fork_tool_names_are_exposed(mcp):
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert {
        "get_func_by_addr", "decompile_by_addr", "rename_func_by_addr", "set_func_prototype",
        "set_lvar_type", "set_decomp_comment", "set_disasm_comment", "search_functions",
        "get_comment", "decompile_function_async", "get_task_status", "get_task_result",
        "create_function", "read_bytes", "write_bytes", "check_server_health",
        "list_structures", "create_structure", "angr_symbolic_find", "angr_decompile_function",
    } <= names
    assert not {"decompile_function_by_address", "get_function_by_address"} & names


def test_health_reports_backend_details(mcp):
    health = call(mcp, "check_server_health")
    assert health["status"] == "ok"
    assert health["mode"] == "headless"
    assert health["server_running"] is True
    assert health["watchdog_healthy"] is True
    assert health["program_loaded"] is True
    assert health["program"]["name"] == FIXTURE.name
    assert health["port"] > 0
    assert health["uptime_ms"] >= 0
    assert health["async_tasks"] >= 0
    assert health["backend_url"].startswith("http://127.0.0.1:")


def test_decompile_by_addr_accepts_timeout(mcp):
    fns = functions(mcp)
    result = call(mcp, "decompile_by_addr", address=fns["compute"], timeout=15)
    assert "add_numbers" in result["code"]


def test_async_decompile_round_trip(mcp):
    fns = functions(mcp)
    task = call(mcp, "decompile_function_async", address=fns["compute"], timeout=30)
    assert task["status"] in {"pending", "running", "completed"}
    deadline = time.time() + 60
    status = task
    while status["status"] not in {"completed", "failed"} and time.time() < deadline:
        time.sleep(0.2)
        status = call(mcp, "get_task_status", task_id=task["task_id"])
    assert status["status"] == "completed", status
    result = call(mcp, "get_task_result", task_id=task["task_id"])
    assert result["code"] == call(mcp, "decompile_by_addr", address=fns["compute"])["code"]
    call_error(mcp, "get_task_result", "NOT_FOUND", task_id=task["task_id"])
    call_error(mcp, "decompile_function_async", "BAD_ADDRESS", address="not-an-address")


def test_get_comment_reads_what_set_comment_wrote(mcp):
    address = functions(mcp)["mul_numbers"]
    assert call(mcp, "get_comment", address=address)["exists"] is False
    call(mcp, "set_disasm_comment", address=address, comment="eol note")
    call(mcp, "set_decomp_comment", address=address, comment="pre note")
    assert call(mcp, "get_comment", address=address)["comment"] == "eol note"
    decomp = call(mcp, "get_comment", address=address, kind="decomp")
    assert decomp == {"address": decomp["address"], "kind": "decomp", "exists": True,
                      "comment": "pre note"}
    call(mcp, "set_disasm_comment", address=address, comment="")
    call(mcp, "set_decomp_comment", address=address, comment="")
    assert call(mcp, "get_comment", address=address)["comment"] is None


def test_structure_crud(mcp):
    created = call(mcp, "create_structure", name="TriangrPoint")
    assert created == {"name": "TriangrPoint", "path": "/TriangrPoint", "size": 0, "field_count": 0}
    call_error(mcp, "create_structure", "NAME_CONFLICT", name="TriangrPoint")

    x = call(mcp, "add_structure_field", struct_name="TriangrPoint", field_name="x",
             field_type="int")
    assert x["field"]["offset"] == 0 and x["structure_size"] == 4
    y = call(mcp, "add_structure_field", struct_name="TriangrPoint", field_name="y",
             field_type="int")
    assert y["field"]["offset"] == 4 and y["structure_size"] == 8
    tag = call(mcp, "add_structure_field", struct_name="TriangrPoint", field_name="tag",
               field_type="char", offset=0)
    assert tag["field"] == {"offset": 0, "name": "tag", "type": "char", "length": 1,
                            "comment": None}
    layout = call(mcp, "get_structure", name="TriangrPoint")
    assert [(f["name"], f["offset"]) for f in layout["fields"]] == [("tag", 0), ("x", 1), ("y", 5)]

    renamed = call(mcp, "rename_structure_field", struct_name="TriangrPoint",
                   old_field_name="y", new_field_name="yy")
    assert renamed["previous"]["name"] == "y" and renamed["field"]["name"] == "yy"
    call_error(mcp, "rename_structure_field", "NAME_CONFLICT", struct_name="TriangrPoint",
               old_field_name="yy", new_field_name="x")

    retyped = call(mcp, "set_field_type", struct_name="TriangrPoint", field_name="yy",
                   new_type="short")
    assert retyped["previous"]["type"] == "int"
    assert (retyped["field"]["type"], retyped["field"]["length"]) == ("short", 2)
    same = call(mcp, "resize_structure_field", struct_name="TriangrPoint", field_name="yy",
                new_length=2)
    assert same["field"] == same["previous"]

    deleted = call(mcp, "delete_structure_field", struct_name="TriangrPoint", field_name="tag")
    assert deleted["field"] is None and deleted["previous"]["name"] == "tag"
    call_error(mcp, "delete_structure_field", "NOT_FOUND", struct_name="TriangrPoint",
               field_name="tag")

    pointer = call(mcp, "create_structure_pointer", struct_name="TriangrPoint",
                   pointer_name="PTriangrPoint")
    assert pointer == {"structure": "/TriangrPoint", "pointer_type": "/TriangrPoint *",
                       "typedef": "/PTriangrPoint"}
    listed = call(mcp, "list_structures", limit=2000)["items"]
    assert "/TriangrPoint" in {s["path"] for s in listed}

    moved = call(mcp, "rename_structure", old_name="TriangrPoint", new_name="TriangrPoint2")
    assert moved == {"old_name": "TriangrPoint", "new_name": "TriangrPoint2",
                     "path": "/TriangrPoint2"}
    call_error(mcp, "get_structure", "NOT_FOUND", name="TriangrPoint")
    call_error(mcp, "get_structure", "INVALID_PARAMETER", name="PTriangrPoint")

    fns = functions(mcp)
    typed = call(mcp, "set_lvar_type", function_address=fns["checksum"],
                 variable_name="param_1", new_type="TriangrPoint2 *")
    assert typed["new_type"] == "TriangrPoint2 *"

    assert call(mcp, "delete_structure", name="TriangrPoint2")["path"] == "/TriangrPoint2"
    call_error(mcp, "get_structure", "NOT_FOUND", name="TriangrPoint2")


def test_overlong_type_expression_is_rejected(mcp):
    fns = functions(mcp)
    call_error(mcp, "set_lvar_type", "INVALID_PARAMETER", function_address=fns["checksum"],
               variable_name="param_2", new_type="int" + "[2147483647]" * 60)


def test_rename_decompiler_generated_local(mcp):
    fns = functions(mcp)
    code = call(mcp, "decompile_by_addr", address=fns["checksum"])["code"]
    generated = re.findall(r"\b([a-z]Var\d+|local_[0-9a-f]+)\b", code)
    if not generated:
        pytest.skip("checksum has no decompiler-generated locals in this build")
    renamed = call(mcp, "rename_variable", function_address=fns["checksum"],
                   old_name=generated[0], new_name="triangr_local")
    assert renamed["new_name"] == "triangr_local"
    code = call(mcp, "decompile_by_addr", address=fns["checksum"])["code"]
    assert "triangr_local" in code


def test_read_and_write_bytes(mcp):
    secret = call(mcp, "list_strings", filter="fixture-secret")["items"][0]
    read = call(mcp, "read_bytes", address=secret["address"], length=9)
    assert read["length"] == 9
    assert bytes.fromhex(read["hex"]) == b"GhidraMCP"

    # Patching defined data keeps the data definition.
    written = call(mcp, "write_bytes", address=secret["address"], bytes_hex="67")
    assert written == {"address": read["address"], "end": read["address"], "length": 1,
                       "disassembled": False, "warning": None}
    assert call(mcp, "read_bytes", address=secret["address"], length=1)["hex"] == "67"
    assert call(mcp, "list_strings", filter="ghidraMCP-fixture")["items"][0]["address"] == \
        secret["address"]
    call(mcp, "write_bytes", address=secret["address"], bytes_hex="47")

    # Patching code re-disassembles it.
    fns = functions(mcp)
    first = call(mcp, "disassemble_function", address=fns["add_numbers"])["items"][0]
    patch = " ".join(first["bytes"][i:i + 2] for i in range(0, len(first["bytes"]), 2))
    written = call(mcp, "write_bytes", address=first["address"], bytes_hex=patch)
    assert written["disassembled"] is True and written["warning"] is None
    again = call(mcp, "disassemble_function", address=fns["add_numbers"])["items"][0]
    assert again["instruction"] == first["instruction"]

    call_error(mcp, "write_bytes", "INVALID_PARAMETER", address=first["address"], bytes_hex="zz")
    call_error(mcp, "write_bytes", "INVALID_PARAMETER", address="0x0", bytes_hex="90")
    call_error(mcp, "read_bytes", "INVALID_PARAMETER", address=first["address"], length=0)
    call_error(mcp, "read_bytes", "INVALID_PARAMETER", address=first["address"],
               length=2 * 1024 * 1024)


def test_angr_defaults_come_from_program_info(headless):
    from ghidra_mcp.angr_tools import AngrTools, normalize_ghidra_address

    backend, _ = headless
    tools = AngrTools(backend)
    binary, pcode = tools.resolve_angr_defaults()
    assert Path(binary).name == FIXTURE.name
    assert pcode == ""
    assert normalize_ghidra_address(tools.program_info()["min_address"]).startswith("0x")


def test_create_function(mcp):
    # Runs last: it splits `compute`, which other tests decompile.
    fns = functions(mcp)
    call_error(mcp, "create_function", "ALREADY_EXISTS", address=fns["compute"])
    inner = call(mcp, "disassemble_function", address=fns["compute"])["items"][1]["address"]
    created = call(mcp, "create_function", address=inner, name="triangr_inner")
    assert (created["name"], created["address"]) == ("triangr_inner", inner)
    assert call(mcp, "get_func_by_addr", address=inner)["name"] == "triangr_inner"
