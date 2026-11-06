"""Contract tests for the Triangr MCP tools: each one calls the right backend endpoint with the
right method and parameters and passes the structured result through."""

import asyncio
import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from ghidra_mcp.angr_tools import TOOL_NAMES as ANGR_TOOL_NAMES
from ghidra_mcp.backend import GhidraBackend
from ghidra_mcp.server import create_server

RENAMED_TOOLS = {
    "get_func_by_addr": "get_function_by_address",
    "decompile_by_addr": "decompile_function_by_address",
    "rename_func_by_addr": "rename_function_by_address",
    "set_func_prototype": "set_function_prototype",
    "set_lvar_type": "set_local_variable_type",
    "set_decomp_comment": "set_decompiler_comment",
    "set_disasm_comment": "set_disassembly_comment",
    "search_functions": "search_functions_by_name",
}


def call(mcp, tool, **args):
    result = asyncio.run(mcp.call_tool(tool, args))
    if isinstance(result, tuple):
        return result[1]
    return json.loads(result[0].text)


@pytest.fixture
def server(fake_backend):
    return create_server(GhidraBackend(fake_backend.url))


def last_request(fake_backend):
    return fake_backend.requests[-1]


def test_short_tool_names_replace_upstream_names(server):
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert set(RENAMED_TOOLS) <= names
    assert not set(RENAMED_TOOLS.values()) & names
    assert set(ANGR_TOOL_NAMES) <= names
    assert all(len(name) <= 30 for name in names)


@pytest.mark.parametrize(
    "tool, args, method, endpoint, sent",
    [
        ("get_comment", {"address": "0x10"}, "GET", "/get_comment",
         {"address": "0x10", "kind": "disasm"}),
        ("get_comment", {"address": "0x10", "kind": "decomp"}, "GET", "/get_comment",
         {"address": "0x10", "kind": "decomp"}),
        ("get_task_status", {"task_id": "t1"}, "GET", "/task_status", {"task_id": "t1"}),
        ("get_task_result", {"task_id": "t1"}, "GET", "/task_result", {"task_id": "t1"}),
        ("create_function", {"address": "0x10"}, "POST", "/create_function", {"address": "0x10"}),
        ("create_function", {"address": "0x10", "name": "f"}, "POST", "/create_function",
         {"address": "0x10", "name": "f"}),
        ("list_structures", {}, "GET", "/list_structures", {"offset": "0", "limit": "100"}),
        ("get_structure", {"name": "S"}, "GET", "/get_structure", {"name": "S"}),
        ("create_structure", {"name": "S"}, "POST", "/create_structure",
         {"name": "S", "size": "0"}),
        ("create_structure", {"name": "S", "size": 16}, "POST", "/create_structure",
         {"name": "S", "size": "16"}),
        ("add_structure_field", {"struct_name": "S", "field_name": "f", "field_type": "int"},
         "POST", "/add_structure_field", {"struct_name": "S", "field_name": "f",
                                          "field_type": "int"}),
        ("add_structure_field", {"struct_name": "S", "field_name": "f", "field_type": "int",
                                 "offset": 8},
         "POST", "/add_structure_field", {"struct_name": "S", "field_name": "f",
                                          "field_type": "int", "offset": "8"}),
        ("rename_structure", {"old_name": "A", "new_name": "B"}, "POST", "/rename_structure",
         {"old_name": "A", "new_name": "B"}),
        ("delete_structure", {"name": "S"}, "POST", "/delete_structure", {"name": "S"}),
        ("rename_structure_field", {"struct_name": "S", "old_field_name": "a",
                                    "new_field_name": "b"},
         "POST", "/rename_structure_field", {"struct_name": "S", "old_field_name": "a",
                                             "new_field_name": "b"}),
        ("set_field_type", {"struct_name": "S", "field_name": "f", "new_type": "char *"},
         "POST", "/set_field_type", {"struct_name": "S", "field_name": "f",
                                     "new_type": "char *"}),
        ("set_field_type", {"struct_name": "S", "field_name": "f", "new_type": "string",
                            "length": 12},
         "POST", "/set_field_type", {"struct_name": "S", "field_name": "f",
                                     "new_type": "string", "length": "12"}),
        ("resize_structure_field", {"struct_name": "S", "field_name": "f", "new_length": 4},
         "POST", "/resize_structure_field", {"struct_name": "S", "field_name": "f",
                                             "new_length": "4"}),
        ("delete_structure_field", {"struct_name": "S", "field_name": "f"}, "POST",
         "/delete_structure_field", {"struct_name": "S", "field_name": "f"}),
        ("create_structure_pointer", {"struct_name": "S"}, "POST", "/create_structure_pointer",
         {"struct_name": "S"}),
        ("create_structure_pointer", {"struct_name": "S", "pointer_name": "PS"}, "POST",
         "/create_structure_pointer", {"struct_name": "S", "pointer_name": "PS"}),
        ("read_bytes", {"address": "0x10"}, "GET", "/read_bytes",
         {"address": "0x10", "length": "32"}),
        ("write_bytes", {"address": "0x10", "bytes_hex": "90 90"}, "POST", "/write_bytes",
         {"address": "0x10", "bytes": "90 90"}),
    ],
)
def test_tool_calls_backend(server, fake_backend, tool, args, method, endpoint, sent):
    data = {"echo": endpoint}
    fake_backend.ok(endpoint, data)
    assert call(server, tool, **args) == data
    assert last_request(fake_backend) == (method, endpoint, sent)


@pytest.mark.parametrize("requested, sent", [(120, "120"), (1, "10"), (99999, "1800")])
def test_decompile_by_addr_clamps_and_sends_timeout(server, fake_backend, requested, sent):
    fake_backend.ok("/decompile_function", {"function": {}, "code": "int f(void)", "truncated": False})
    call(server, "decompile_by_addr", address="0x10", timeout=requested)
    assert last_request(fake_backend) == ("GET", "/decompile_function",
                                          {"address": "0x10", "timeout": sent})


def test_decompile_by_addr_waits_beyond_the_default_read_timeout(fake_backend):
    import time

    def slow(_params):
        time.sleep(0.6)
        return {"success": True, "data": {"code": "slow"}}

    fake_backend.routes["/decompile_function"] = (200, slow)
    server = create_server(GhidraBackend(fake_backend.url, read_timeout=0.2))
    assert call(server, "decompile_by_addr", address="0x10")["code"] == "slow"


@pytest.mark.parametrize("requested, sent", [(300, "300"), (0, "10"), (5000, "1800")])
def test_decompile_function_async_clamps_timeout(server, fake_backend, requested, sent):
    fake_backend.ok("/decompile_async", {"task_id": "t1", "status": "pending"})
    assert call(server, "decompile_function_async", address="0x10", timeout=requested)["task_id"] == "t1"
    assert last_request(fake_backend) == ("POST", "/decompile_async",
                                          {"address": "0x10", "timeout": sent})


def test_backend_errors_become_tool_errors(server, fake_backend):
    fake_backend.fail("/create_structure", 409, "NAME_CONFLICT", "A data type named 'S' exists")
    with pytest.raises(ToolError, match="NAME_CONFLICT"):
        asyncio.run(server.call_tool("create_structure", {"name": "S"}))


def test_get_comment_rejects_unknown_kind(server):
    with pytest.raises(ToolError):
        asyncio.run(server.call_tool("get_comment", {"address": "0x1", "kind": "plate"}))


def test_check_server_health_passes_details_through(server, fake_backend):
    health = {"status": "ok", "mode": "gui", "server_running": True, "watchdog_healthy": True,
              "program_loaded": True, "uptime_ms": 10, "last_request_ms_ago": 5, "port": 8080}
    fake_backend.ok("/health", health)
    assert call(server, "check_server_health") == {**health, "backend_url": fake_backend.url}


def test_check_server_health_reports_unreachable():
    server = create_server(GhidraBackend("http://127.0.0.1:1/", connect_timeout=0.5,
                                         connect_retries=0))
    result = call(server, "check_server_health")
    assert result["status"] == "unreachable"
    assert "BACKEND_UNAVAILABLE" in result["error"]
    assert result["backend_url"] == "http://127.0.0.1:1/"


def test_descriptions_only_mention_registered_tool_names(server):
    """Upstream docstrings that point at a renamed tool would send the model to a missing tool."""
    tools = asyncio.run(server.list_tools())
    for tool in tools:
        for old in RENAMED_TOOLS.values():
            assert old not in (tool.description or ""), (tool.name, old)
