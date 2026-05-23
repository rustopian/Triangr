"""
Contract tests for every MCP tool exposed by bridge_mcp_ghidra.py.

These tests do NOT talk to a real Ghidra. They use pytest-httpx to mock the
plugin's HTTP server. For each tool we assert:

  * the request goes to the right endpoint, with the right HTTP method
  * the right query / form parameters are encoded
  * the response body is parsed into the right Python shape

The mocked response bodies use shapes captured from a real Ghidra
instance running this fork's plugin (a Solana .so), so the assertions
exercise realistic parsing paths — not just "got a string back".
"""

import pytest

BASE_URL = "http://127.0.0.1:8080/"


def _url(endpoint: str) -> str:
    return BASE_URL + endpoint


# ---------------------------------------------------------------------------
# Listing endpoints (GET ?offset=&limit=)
# ---------------------------------------------------------------------------

class TestListings:
    """All paginated GET endpoints; verify offset+limit propagation and that
    the newline-delimited body is split into a list."""

    def test_list_methods(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("methods?offset=0&limit=100"),
            text="entrypoint\nkernel_internal_panic_shim_strips_line_col")
        assert bridge_module.list_methods() == [
            "entrypoint",
            "kernel_internal_panic_shim_strips_line_col",
        ]

    def test_list_methods_pagination(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("methods?offset=50&limit=10"), text="foo")
        assert bridge_module.list_methods(offset=50, limit=10) == ["foo"]

    def test_list_classes(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("classes?offset=0&limit=100"), text="<EXTERNAL>")
        assert bridge_module.list_classes() == ["<EXTERNAL>"]

    def test_list_segments(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("segments?offset=0&limit=100"),
            text=".text: ram:00000120 - ram:00220d97\n"
                 ".rodata: ram:00220d98 - ram:002325d8")
        out = bridge_module.list_segments()
        assert len(out) == 2
        assert out[0].startswith(".text:")

    def test_list_imports(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("imports?offset=0&limit=100"),
            text="abort -> EXTERNAL:00000001")
        assert bridge_module.list_imports() == ["abort -> EXTERNAL:00000001"]

    def test_list_exports(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("exports?offset=0&limit=100"),
            text="entrypoint -> ram:00000120\nSECURITY_TXT -> ram:00232688")
        out = bridge_module.list_exports()
        assert out == ["entrypoint -> ram:00000120",
                       "SECURITY_TXT -> ram:00232688"]

    def test_list_namespaces(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("namespaces?offset=0&limit=100"), text="<EXTERNAL>")
        assert bridge_module.list_namespaces() == ["<EXTERNAL>"]

    def test_list_data_items(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("data?offset=0&limit=100"),
            text='ram:00220d98: s_src/entrypoint... = "src/entrypoint..."')
        out = bridge_module.list_data_items()
        assert len(out) == 1
        assert out[0].startswith("ram:00220d98:")

    def test_list_functions(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("list_functions"),
            text="entrypoint at ram:00000120\n"
                 "kernel_internal_panic_shim_strips_line_col at ram:000011d0")
        out = bridge_module.list_functions()
        assert out[0] == "entrypoint at ram:00000120"

    def test_search_functions(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("searchFunctions?query=panic&offset=0&limit=100"),
            text="alloc_or_panic_capacity_overflow @ ram:00001408")
        out = bridge_module.search_functions(query="panic")
        assert out == ["alloc_or_panic_capacity_overflow @ ram:00001408"]

    def test_search_functions_empty_query_returns_error(
            self, bridge_module, httpx_mock):
        # Local-side validation — no HTTP call should happen.
        out = bridge_module.search_functions(query="")
        assert out == ["Error: query string is required"]

    def test_list_strings_no_filter(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("strings?offset=0&limit=2000"),
            text='ram:00220dd6: "Phoenix: Eternal"')
        out = bridge_module.list_strings()
        assert "Phoenix" in out[0]

    def test_list_strings_with_filter(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("strings?offset=0&limit=10&filter=phoenix"),
            text='ram:00220dd6: "Phoenix: Eternal"')
        out = bridge_module.list_strings(limit=10, filter="phoenix")
        assert len(out) == 1


# ---------------------------------------------------------------------------
# Function-by-address / current-selection accessors
# ---------------------------------------------------------------------------

class TestFunctionAccessors:

    def test_get_func_by_addr(self, bridge_module, httpx_mock):
        body = ("Function: entrypoint at ram:00000120\n"
                "Signature: ulonglong __fastcall entrypoint(ulonglong * param_1)\n"
                "Entry: ram:00000120\n"
                "Body: ram:00000120 - ram:000011cf")
        httpx_mock.add_response(
            url=_url("get_function_by_address?address=0x00000120"), text=body)
        out = bridge_module.get_func_by_addr("0x00000120")
        assert out.startswith("Function: entrypoint")
        assert "Signature:" in out

    def test_get_func_by_addr_not_found_passes_error_through(
            self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("get_function_by_address?address=0xdeadbeef"),
            text="No function found at address 0xdeadbeef")
        assert bridge_module.get_func_by_addr("0xdeadbeef").startswith(
            "No function found")

    def test_get_current_address(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("get_current_address"), text="ram:000a7558")
        assert bridge_module.get_current_address() == "ram:000a7558"

    def test_get_current_function(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("get_current_function"),
            text="No function at current location: ram:000a7558")
        assert "No function" in bridge_module.get_current_function()

    def test_get_program_info(self, bridge_module, httpx_mock):
        body = (
            "name: eternal.so\n"
            "executable_path: /tmp/eternal.so\n"
            "language_id: eBPF:LE:64:default\n"
            "image_base: 0x0")
        httpx_mock.add_response(url=_url("program_info"), text=body)
        out = bridge_module.get_program_info()
        assert "executable_path: /tmp/eternal.so" in out
        assert "language_id: eBPF:LE:64:default" in out


# ---------------------------------------------------------------------------
# Decompile / disassemble
# ---------------------------------------------------------------------------

class TestDecompile:

    def test_decompile_function_by_name(self, bridge_module, httpx_mock):
        # POST body is the raw function name
        httpx_mock.add_response(
            method="POST", url=_url("decompile"),
            match_content=b"entrypoint",
            text="ulonglong entrypoint(ulonglong *param_1)\n{\n  return 0;\n}")
        out = bridge_module.decompile_function("entrypoint")
        assert "entrypoint" in out

    def test_decompile_by_addr_sends_timeout_query_param(
            self, bridge_module, httpx_mock):
        # Verifies the Fix #7 plumbing: the bridge MUST forward the timeout
        # as a query param, not just as the httpx socket timeout.
        httpx_mock.add_response(
            url=_url("decompile_function?address=0x120&timeout=200"),
            text="ulonglong entrypoint(...)")
        out = bridge_module.decompile_by_addr("0x120", timeout=200)
        assert "entrypoint" in out

    def test_decompile_by_addr_clamps_low(self, bridge_module, httpx_mock):
        # min(timeout, MAX) → max(10, ...) → 10
        httpx_mock.add_response(
            url=_url("decompile_function?address=0x120&timeout=10"), text="x")
        bridge_module.decompile_by_addr("0x120", timeout=1)

    def test_decompile_by_addr_clamps_high(self, bridge_module, httpx_mock):
        # Clamped to TIMEOUT_DECOMPILE_MAX = 1800
        httpx_mock.add_response(
            url=_url("decompile_function?address=0x120&timeout=1800"), text="x")
        bridge_module.decompile_by_addr("0x120", timeout=99999)

    def test_disassemble_function(self, bridge_module, httpx_mock):
        body = ("ram:00000120: MOV R2,R1 \n"
                "ram:00000128: ADD R2,0x8 \n"
                "ram:00000130: LDXDW R4,[R1 + 0x0] ")
        httpx_mock.add_response(
            url=_url("disassemble_function?address=0x120"), text=body)
        out = bridge_module.disassemble_function("0x120")
        assert len(out) == 3
        assert out[0].startswith("ram:00000120:")


# ---------------------------------------------------------------------------
# Optional angr / AngryGhidra integrations (1.6.0)
# ---------------------------------------------------------------------------

class TestAngrIntegrations:

    def test_angr_decompile_uses_program_info_defaults(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/eternal.so\n"
                 "language_id: eBPF:LE:64:default")
        calls = {}

        def fake_run(args, timeout):
            calls["args"] = args
            calls["timeout"] = timeout
            return "oxidized"

        monkeypatch.setattr(bridge_module, "run_angr_helper", fake_run)
        out = bridge_module.angr_decompile_function("0x120", timeout=77)

        assert out == "oxidized"
        assert calls["timeout"] == 77
        assert calls["args"] == [
            "--binary", "/tmp/eternal.so",
            "--address", "0x120",
            "--rust",
            "--skip-rust-setup",
            "--pcode-language", "eBPF:LE:64:default",
        ]

    def test_angr_check_setup_with_explicit_binary(
            self, bridge_module, monkeypatch):
        calls = {}

        def fake_run(args, timeout):
            calls["args"] = args
            calls["timeout"] = timeout
            return "ok"

        monkeypatch.setattr(bridge_module, "run_angr_helper", fake_run)
        out = bridge_module.angr_check_setup(
            binary_path="/tmp/a.out",
            pcode_language="eBPF:LE:64:default")

        assert out == "ok"
        assert calls["timeout"] == 30
        assert calls["args"] == [
            "--check",
            "--binary", "/tmp/a.out",
            "--pcode-language", "eBPF:LE:64:default",
        ]

    def test_angr_symbolic_find_falls_back_to_core_when_angryghidra_cannot_represent_request(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/eternal.so\n"
                 "language_id: eBPF:LE:64:default")
        calls = {}

        def fake_run(args, timeout):
            calls["args"] = args
            calls["timeout"] = timeout
            return "found: true"

        monkeypatch.setattr(bridge_module, "run_angr_helper", fake_run)
        out = bridge_module.angr_symbolic_find(
            find_address="ram:00000180",
            start_address="ram:00000120",
            avoid_addresses="ram:00000140,0x160",
            stdin_bytes=8,
            symbolic_memory_json='{"0x2000": 32}',
            registers_json='{"r1": "sv8", "r2": "0x10"}',
            timeout=55,
            max_steps=123)

        assert out == "engine: core angr\nfound: true"
        assert calls["timeout"] == 55
        assert calls["args"] == [
            "--binary", "/tmp/eternal.so",
            "--symbolic-find", "0x180",
            "--max-steps", "123",
            "--start-address", "0x120",
            "--avoid-address", "0x140,0x160",
            "--pcode-language", "eBPF:LE:64:default",
            "--stdin-bytes", "8",
            "--symbolic-memory-json", '{"0x2000": 32}',
            "--registers-json", '{"r1": "sv8", "r2": "0x10"}',
        ]

    def test_angr_symbolic_find_prefers_angryghidra_when_available(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/a.out\n"
                 "language_id: x86:LE:64:default\n"
                 "min_address: 0x400000")
        monkeypatch.setattr(bridge_module, "find_angryghidra_script", lambda: "/opt/angryghidra.py")
        calls = {}

        def fake_run(options, timeout):
            calls["options"] = options
            calls["timeout"] = timeout
            return "t:0x401000\nt:0x401020\nargv[1] = b'ok'"

        monkeypatch.setattr(bridge_module, "run_angryghidra_options", fake_run)
        out = bridge_module.angr_symbolic_find(
            find_address="0x401020",
            start_address="0x401000",
            argv_bytes="4",
            symbolic_memory_json='{"0x404000": 8}',
            memory_json='{"0x405000": "0x41"}',
            registers_json='{"rax": "sv8"}',
            timeout=44)

        assert out.startswith("engine: AngryGhidra\n")
        assert calls["timeout"] == 44
        assert calls["options"] == {
            "binary_file": "/tmp/a.out",
            "base_address": "0x400000",
            "find_address": "0x401020",
            "auto_load_libs": False,
            "blank_state": "0x401000",
            "arguments": {"1": "4"},
            "vectors": {"0x404000": "8"},
            "mem_store": {"0x405000": "0x41"},
            "regs_vals": {"rax": "sv8"},
        }

    def test_angr_symbolic_find_forced_angryghidra_missing_is_clear(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/a.out\n"
                 "language_id: x86:LE:64:default\n"
                 "min_address: 0x400000")
        monkeypatch.setattr(bridge_module, "find_angryghidra_script", lambda: "")

        out = bridge_module.angr_symbolic_find(
            find_address="0x401020",
            engine="angryghidra")

        assert "AngryGhidra is not installed or configured" in out

    def test_angr_annotate_symbolic_path_writes_trace_comments(
            self, bridge_module, httpx_mock, monkeypatch):
        monkeypatch.setattr(
            bridge_module,
            "angr_symbolic_find",
            lambda **_kwargs: "engine: AngryGhidra\nt:0x401000\nt:0x401020")
        httpx_mock.add_response(
            method="POST",
            url=_url("set_disassembly_comment"),
            match_content=(
                b"address=0x401000&comment=angr+symbolic+path%3A+step+1%2F2+"
                b"toward+0x401020"
            ),
            text="Comment set successfully")
        httpx_mock.add_response(
            method="POST",
            url=_url("set_disassembly_comment"),
            match_content=(
                b"address=0x401020&comment=angr+symbolic+path%3A+step+2%2F2+"
                b"toward+0x401020"
            ),
            text="Comment set successfully")

        out = bridge_module.angr_annotate_symbolic_path(
            find_address="0x401020",
            comment_kind="disasm")

        assert "Annotated 2 trace address(es)" in out
        assert "set_disassembly_comment 0x401000: Comment set successfully" in out

    def test_angr_solve_constraints_at_builds_rich_solver_args(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/eternal.so\n"
                 "language_id: eBPF:LE:64:default")
        calls = {}

        def fake_run(args, timeout):
            calls["args"] = args
            calls["timeout"] = timeout
            return "satisfiable: true"

        monkeypatch.setattr(bridge_module, "run_angr_helper", fake_run)
        out = bridge_module.angr_solve_constraints_at(
            address="ram:00000180",
            start_address="ram:00000120",
            constraints_json='[{"type":"reg","name":"r1","op":"==","value":"0x10"}]',
            eval_registers="r0,r1",
            eval_memory_json='{"0x3000": 8}',
            timeout=88,
            max_steps=44)

        assert out == "satisfiable: true"
        assert calls["timeout"] == 88
        assert calls["args"] == [
            "--binary", "/tmp/eternal.so",
            "--solve-at", "0x180",
            "--max-steps", "44",
            "--start-address", "0x120",
            "--pcode-language", "eBPF:LE:64:default",
            "--constraints-json", '[{"type": "reg", "name": "r1", "op": "==", "value": "0x10"}]',
            "--eval-memory-json", '{"0x3000": 8}',
            "--eval-registers", "r0,r1",
        ]

    def test_angr_reachability_builds_cfg_args(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/eternal.so\n"
                 "language_id: eBPF:LE:64:default")
        calls = {}
        def fake_run(args, timeout):
            calls["data"] = (args, timeout)
            return "reachable: true"

        monkeypatch.setattr(bridge_module, "run_angr_helper", fake_run)

        out = bridge_module.angr_reachability(
            "ram:00000120",
            "ram:00000180",
            complete_cfg=True,
            include_path=False,
            summary_limit=7,
            timeout=99)

        assert out == "reachable: true"
        args, timeout = calls["data"]
        assert timeout == 99
        assert args == [
            "--binary", "/tmp/eternal.so",
            "--reachability-from", "0x120",
            "--reachability-to", "0x180",
            "--summary-limit", "7",
            "--pcode-language", "eBPF:LE:64:default",
            "--complete-cfg",
        ]

    def test_angr_cfg_summary_builds_function_args(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/eternal.so\n"
                 "language_id: eBPF:LE:64:default")
        calls = {}
        def fake_run(args, timeout):
            calls["data"] = (args, timeout)
            return "cfg"

        monkeypatch.setattr(bridge_module, "run_angr_helper", fake_run)

        out = bridge_module.angr_cfg_summary(
            function_address="ram:00000120",
            summary_limit=5,
            timeout=66)

        assert out == "cfg"
        args, timeout = calls["data"]
        assert timeout == 66
        assert args == [
            "--binary", "/tmp/eternal.so",
            "--cfg-summary",
            "--summary-limit", "5",
            "--pcode-language", "eBPF:LE:64:default",
            "--function-address", "0x120",
        ]

    def test_angr_callgraph_summary_builds_args(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/eternal.so\n"
                 "language_id: eBPF:LE:64:default")
        calls = {}
        def fake_run(args, timeout):
            calls["data"] = (args, timeout)
            return "callgraph"

        monkeypatch.setattr(bridge_module, "run_angr_helper", fake_run)

        out = bridge_module.angr_callgraph_summary(summary_limit=3, timeout=77)

        assert out == "callgraph"
        args, timeout = calls["data"]
        assert timeout == 77
        assert args == [
            "--binary", "/tmp/eternal.so",
            "--callgraph-summary",
            "--summary-limit", "3",
            "--pcode-language", "eBPF:LE:64:default",
        ]

    def test_angr_lift_block_builds_args(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/eternal.so\n"
                 "language_id: eBPF:LE:64:default")
        calls = {}
        def fake_run(args, timeout):
            calls["data"] = (args, timeout)
            return "AIL"

        monkeypatch.setattr(bridge_module, "run_angr_helper", fake_run)

        out = bridge_module.angr_lift_block(
            "ram:00000120",
            lift_format="ail",
            num_inst=4,
            timeout=33)

        assert out == "AIL"
        args, timeout = calls["data"]
        assert timeout == 33
        assert args == [
            "--binary", "/tmp/eternal.so",
            "--lift-block", "0x120",
            "--lift-format", "ail",
            "--pcode-language", "eBPF:LE:64:default",
            "--num-inst", "4",
        ]

    def test_angr_compare_decompilers_batches_ghidra_and_oxidizer(
            self, bridge_module, httpx_mock, monkeypatch):
        httpx_mock.add_response(
            url=_url("program_info"),
            text="executable_path: /tmp/eternal.so\n"
                 "language_id: eBPF:LE:64:default")
        httpx_mock.add_response(
            url=_url("decompile_function?address=0x120&timeout=12"),
            text="ghidra one")
        httpx_mock.add_response(
            url=_url("decompile_function?address=0x180&timeout=12"),
            text="ghidra two")
        calls = []

        def fake_run(args, timeout):
            calls.append((args, timeout))
            return "oxidizer"

        monkeypatch.setattr(bridge_module, "run_angr_helper", fake_run)
        out = bridge_module.angr_compare_decompilers(
            "ram:00000120, ram:00000180",
            timeout_per_function=12,
            max_functions=2)

        assert "ghidra one" in out
        assert "ghidra two" in out
        assert len(calls) == 2
        assert calls[0] == ([
            "--binary", "/tmp/eternal.so",
            "--address", "0x120",
            "--rust",
            "--skip-rust-setup",
            "--pcode-language", "eBPF:LE:64:default",
        ], 12)

    def test_angryghidra_check_setup_missing_is_clear(
            self, bridge_module, monkeypatch):
        monkeypatch.setattr(bridge_module, "find_angryghidra_script", lambda: "")
        out = bridge_module.angryghidra_check_setup()
        assert "AngryGhidra is not installed or configured" in out
        assert "Non-AngryGhidra MCP tools are unaffected" in out

    def test_angryghidra_symbolic_execute_missing_is_clear(
            self, bridge_module, monkeypatch):
        monkeypatch.setattr(bridge_module, "find_angryghidra_script", lambda: "")
        out = bridge_module.angryghidra_symbolic_execute(find_address="0x120")
        assert "AngryGhidra is not installed or configured" in out


# ---------------------------------------------------------------------------
# Async decompile (PR #124)
# ---------------------------------------------------------------------------

class TestAsyncDecompile:

    def test_decompile_function_async_returns_task_id(
            self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("decompile_async?address=0x120&timeout=300"),
            text='{"task_id":"abc-123","status":"pending"}')
        out = bridge_module.decompile_function_async("0x120")
        assert out == {"task_id": "abc-123", "status": "pending"}

    def test_decompile_function_async_clamps_timeout(
            self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("decompile_async?address=0x120&timeout=1800"),
            text='{"task_id":"x","status":"pending"}')
        bridge_module.decompile_function_async("0x120", timeout=999999)

    def test_decompile_function_async_returns_error_dict_on_bad_json(
            self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("decompile_async?address=0x120&timeout=300"),
            text="not json")
        out = bridge_module.decompile_function_async("0x120")
        assert "error" in out

    def test_get_task_status(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("task_status?task_id=abc"),
            text='{"task_id":"abc","status":"completed","elapsed_ms":1234}')
        out = bridge_module.get_task_status("abc")
        assert out["status"] == "completed"
        assert out["elapsed_ms"] == 1234

    def test_get_task_result(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("task_result?task_id=abc"),
            text="int main() { return 0; }")
        out = bridge_module.get_task_result("abc")
        assert "main" in out


# ---------------------------------------------------------------------------
# Comments + symbol renames (POST)
# ---------------------------------------------------------------------------

class TestMutations:

    def test_rename_function(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("renameFunction"),
            match_content=b"oldName=foo&newName=bar",
            text="Renamed successfully")
        assert bridge_module.rename_function("foo", "bar") == "Renamed successfully"

    def test_rename_data(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("renameData"),
            match_content=b"address=0x200&newName=foo",
            text="Rename data attempted")
        bridge_module.rename_data("0x200", "foo")

    def test_rename_variable(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("renameVariable"),
            match_content=b"functionName=entrypoint&oldName=uVar1&newName=count",
            text="Variable renamed")
        assert bridge_module.rename_variable(
            "entrypoint", "uVar1", "count") == "Variable renamed"

    def test_rename_func_by_addr(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("rename_function_by_address"),
            match_content=b"function_address=0x120&new_name=main",
            text="Function renamed successfully")
        bridge_module.rename_func_by_addr("0x120", "main")

    def test_set_decomp_comment(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("set_decompiler_comment"),
            match_content=b"address=0x120&comment=hello",
            text="Comment set successfully")
        bridge_module.set_decomp_comment("0x120", "hello")

    def test_set_disasm_comment(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("set_disassembly_comment"),
            match_content=b"address=0x120&comment=note",
            text="Comment set successfully")
        bridge_module.set_disasm_comment("0x120", "note")

    def test_set_func_prototype(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("set_function_prototype"),
            text="Function prototype set successfully")
        bridge_module.set_func_prototype("0x120", "int main(int)")

    def test_set_lvar_type(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("set_local_variable_type"),
            text="Variable type set successfully")
        bridge_module.set_lvar_type("0x120", "uVar1", "int")


# ---------------------------------------------------------------------------
# Xrefs
# ---------------------------------------------------------------------------

class TestXrefs:

    def test_xrefs_to(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("xrefs_to?address=0x120&offset=0&limit=100"),
            text="From _elfProgramHeaders::00000010 [DATA]\n"
                 "From Entry Point [EXTERNAL]")
        out = bridge_module.get_xrefs_to("0x120")
        assert len(out) == 2
        assert "elfProgramHeaders" in out[0]

    def test_xrefs_from_empty_body(self, bridge_module, httpx_mock):
        # The live server returns an empty body when an address has no
        # outgoing references; splitlines("") is [].
        httpx_mock.add_response(
            url=_url("xrefs_from?address=0x120&offset=0&limit=100"), text="")
        assert bridge_module.get_xrefs_from("0x120") == []

    def test_xrefs_from_with_results(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("xrefs_from?address=0x120&offset=0&limit=100"),
            text="To ram:00000400 to function foo [UNCONDITIONAL_CALL]")
        out = bridge_module.get_xrefs_from("0x120")
        assert len(out) == 1
        assert "UNCONDITIONAL_CALL" in out[0]

    def test_function_xrefs(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("function_xrefs?name=entrypoint&offset=0&limit=100"),
            text="From _elfProgramHeaders::00000010 [DATA]")
        out = bridge_module.get_function_xrefs("entrypoint")
        assert "elfProgramHeaders" in out[0]


# ---------------------------------------------------------------------------
# Structure CRUD (this fork's PR #1) + later fixes
# ---------------------------------------------------------------------------

class TestStructures:

    def test_create_structure_default_size(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("create_structure"),
            match_content=b"name=MyStruct&size=0",
            text="Created structure '/MyStruct' (size=0)")
        out = bridge_module.create_structure("MyStruct")
        assert out.startswith("Created structure")

    def test_create_structure_with_size(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("create_structure"),
            match_content=b"name=Header&size=16",
            text="Created structure '/Header' (size=16)")
        bridge_module.create_structure("Header", size=16)

    def test_list_structures(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("list_structures?offset=0&limit=100"),
            text="/AccountInfo (size=88)\n/AssetFlags (size=1)")
        out = bridge_module.list_structures()
        assert "/AccountInfo (size=88)" in out

    def test_get_structure(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("get_structure?name=AssetFlags"),
            text="/AssetFlags (size=1)\n  +0x0: byte bits (size=1)")
        out = bridge_module.get_structure("AssetFlags")
        # The bridge joins lines on '\n' so the structure should be returned
        # multi-line, intact.
        assert "/AssetFlags" in out
        assert "byte bits" in out

    def test_add_structure_field_append(self, bridge_module, httpx_mock):
        # No offset → bridge omits the 'offset' key entirely
        httpx_mock.add_response(
            method="POST", url=_url("add_structure_field"),
            match_content=b"struct_name=MyStruct&field_name=magic&field_type=uint",
            text="Appended field 'magic' to /MyStruct (new size=4)")
        bridge_module.add_structure_field("MyStruct", "magic", "uint")

    def test_add_structure_field_at_offset(self, bridge_module, httpx_mock):
        # offset >= 0 → bridge includes 'offset' in the form
        httpx_mock.add_response(
            method="POST", url=_url("add_structure_field"),
            match_content=b"struct_name=MyStruct&field_name=tail&"
                          b"field_type=int&offset=12",
            text="Inserted field 'tail' at offset 12 in /MyStruct")
        bridge_module.add_structure_field("MyStruct", "tail", "int", offset=12)

    def test_rename_structure(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("rename_structure"),
            match_content=b"old_name=A&new_name=B",
            text="Renamed structure 'A' to '/B'")
        bridge_module.rename_structure("A", "B")

    def test_delete_structure(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("delete_structure"),
            match_content=b"name=Doomed",
            text="Deleted structure '/Doomed'")
        bridge_module.delete_structure("Doomed")

    def test_rename_structure_field(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("rename_structure_field"),
            match_content=b"struct_name=S&old_field_name=field_0x4&"
                          b"new_field_name=count",
            text="Renamed field 'field_0x4' to 'count'")
        bridge_module.rename_structure_field("S", "field_0x4", "count")

    def test_delete_structure_field(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("delete_structure_field"),
            match_content=b"struct_name=S&field_name=garbage",
            text="Deleted field 'garbage' from /S")
        bridge_module.delete_structure_field("S", "garbage")

    def test_set_field_type_default_length(self, bridge_module, httpx_mock):
        # length=0 default → bridge omits 'length' key (server uses natural)
        httpx_mock.add_response(
            method="POST", url=_url("set_field_type"),
            match_content=b"struct_name=S&field_name=quad&new_type=Pubkey",
            text="Set field 'quad' to type Pubkey")
        bridge_module.set_field_type("S", "quad", "Pubkey")

    def test_set_field_type_explicit_length(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("set_field_type"),
            match_content=b"struct_name=S&field_name=buf&new_type=char&length=32",
            text="Set field 'buf' to type char (length=32)")
        bridge_module.set_field_type("S", "buf", "char", length=32)

    def test_resize_structure_field(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("resize_structure_field"),
            match_content=b"struct_name=S&field_name=f&new_length=8",
            text="Resized field 'f' from 4 to 8 bytes")
        bridge_module.resize_structure_field("S", "f", 8)

    def test_create_structure_pointer_default(self, bridge_module, httpx_mock):
        # pointer_name="" → bridge omits 'pointer_name' key
        httpx_mock.add_response(
            method="POST", url=_url("create_structure_pointer"),
            match_content=b"struct_name=S",
            text="Created pointer type '/S *'")
        bridge_module.create_structure_pointer("S")

    def test_create_structure_pointer_named_typedef(
            self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("create_structure_pointer"),
            match_content=b"struct_name=S&pointer_name=PS",
            text="Created typedef '/PS' for S *")
        bridge_module.create_structure_pointer("S", "PS")


# ---------------------------------------------------------------------------
# create_function (this fork's PR #1)
# ---------------------------------------------------------------------------

class TestCreateFunction:

    def test_create_function_without_name(self, bridge_module, httpx_mock):
        # name="" → bridge omits 'name' key entirely
        httpx_mock.add_response(
            method="POST", url=_url("create_function"),
            match_content=b"address=0x1000",
            text="Created function 'FUN_00001000' at 0x1000")
        out = bridge_module.create_function("0x1000")
        assert "Created function" in out

    def test_create_function_with_name(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("create_function"),
            match_content=b"address=0x1000&name=main",
            text="Created function 'main' at 0x1000")
        bridge_module.create_function("0x1000", "main")


# ---------------------------------------------------------------------------
# Memory read/write (PR #57) + health (PR #149)
# ---------------------------------------------------------------------------

class TestMemoryAndHealth:

    def test_read_bytes_default_length(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("read_bytes?address=0x120&length=32"),
            text="55 8b ec ...")
        out = bridge_module.read_bytes("0x120")
        assert "55 8b ec" in out[0]

    def test_read_bytes_explicit_length(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("read_bytes?address=0x120&length=8"),
            text="55 8b ec 90 90 90 90 90")
        bridge_module.read_bytes("0x120", length=8)

    def test_write_bytes(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("write_bytes"),
            match_content=b"address=0x120&bytes=90+90+90",
            text="Bytes written successfully")
        # Note: httpx URL-encodes spaces as '+' in form bodies, hence the
        # match_content above; the caller still passes a space-separated str.
        out = bridge_module.write_bytes("0x120", "90 90 90")
        assert "written" in out

    def test_check_server_health_ok(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("health"),
            json={
                "status": "OK",
                "server_running": True,
                "watchdog_healthy": True,
                "program_loaded": True,
                "uptime_ms": 1234,
                "last_request_ms_ago": 12,
                "port": 8080,
            })
        out = bridge_module.check_server_health()
        assert out.startswith("OK")
        assert "Port: 8080" in out

    def test_check_server_health_unhealthy(self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("health"),
            json={"status": "ERROR", "server_running": False})
        out = bridge_module.check_server_health()
        assert "ERROR" in out


# ---------------------------------------------------------------------------
# Error-path behavior of safe_get / safe_post
# ---------------------------------------------------------------------------

class TestErrorPaths:

    def test_safe_get_returns_status_string_on_404(
            self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            url=_url("methods?offset=0&limit=100"),
            status_code=404, text="No context")
        out = bridge_module.list_methods()
        assert out == ["Error 404: No context"]

    def test_safe_post_returns_status_string_on_500(
            self, bridge_module, httpx_mock):
        httpx_mock.add_response(
            method="POST", url=_url("renameFunction"),
            status_code=500, text="boom")
        out = bridge_module.rename_function("a", "b")
        assert out == "Error 500: boom"
