"""Tests for the angr/AngryGhidra tools. angr itself is never run: the helper subprocess is
replaced, and Ghidra is a FakeBackend."""

import pytest

from ghidra_mcp import angr_tools
from ghidra_mcp.angr_tools import AngrTools, normalize_ghidra_address
from ghidra_mcp.backend import GhidraBackend

EBPF_PROGRAM = {"executable_path": "/tmp/sample.bin", "language_id": "eBPF:LE:64:default"}
X86_PROGRAM = {
    "executable_path": "/tmp/a.out",
    "language_id": "x86:LE:64:default",
    "min_address": "00400000",
}


@pytest.fixture
def tools(fake_backend):
    return AngrTools(GhidraBackend(fake_backend.url))


@pytest.fixture
def helper_calls(monkeypatch):
    """Replaces the angr helper subprocess and records (args, timeout) per call."""
    calls = []

    def install(output="ok"):
        def fake_run(args, timeout):
            calls.append((args, timeout))
            return output

        monkeypatch.setattr(angr_tools, "run_angr_helper", fake_run)
        return calls

    return install


def preview_token(output: str) -> str:
    for line in output.splitlines():
        if line.startswith("preview_token: "):
            return line.split(": ", 1)[1]
    raise AssertionError("preview_token not found")


def serve_comments(fake_backend, *comment_sequences):
    """Serves /get_comment from per-address sequences of comments; the last one repeats."""
    queues = {address: list(comments) for address, comments in comment_sequences}

    def respond(params):
        queue = queues[params["address"]]
        comment = queue.pop(0) if len(queue) > 1 else queue[0]
        return {"success": True, "data": {"address": params["address"], "kind": params["kind"],
                                          "exists": comment is not None, "comment": comment}}

    fake_backend.routes["/get_comment"] = (200, respond)


@pytest.mark.parametrize(
    "address, expected",
    [
        ("0x401000", "0x401000"),
        ("ram:00000180", "0x180"),
        ("0xram:00000180", "0x180"),
        ("00401000", "0x401000"),
        ("0000", "0x0"),
        ("", ""),
        ("main", "main"),
    ],
)
def test_normalize_ghidra_address(address, expected):
    assert normalize_ghidra_address(address) == expected


def test_default_angr_python_prefers_triangr_home(tmp_path, monkeypatch):
    python_path = tmp_path / "triangr" / "venv" / "bin" / "python"
    python_path.parent.mkdir(parents=True)
    python_path.write_text("")
    monkeypatch.setenv("TRIANGR_HOME", str(tmp_path / "triangr"))
    assert angr_tools.default_angr_python() == str(python_path)


def test_default_angr_python_checks_default_install_without_relative_probe(monkeypatch):
    checked = []
    monkeypatch.delenv("TRIANGR_HOME", raising=False)
    monkeypatch.setattr(
        angr_tools, "DEFAULT_TRIANGR_ANGR_PYTHON", "/home/user/.local/share/triangr/venv/bin/python"
    )

    def fake_isfile(path):
        checked.append(path)
        return False

    monkeypatch.setattr(angr_tools.os.path, "isfile", fake_isfile)
    assert angr_tools.default_angr_python() == angr_tools.sys.executable
    assert "venv/bin/python" not in checked
    assert "/home/user/.local/share/triangr/venv/bin/python" in checked


def test_find_angryghidra_script_uses_triangr_home(tmp_path, monkeypatch):
    script = tmp_path / "triangr" / "AngryGhidra" / "angryghidra_script" / "angryghidra.py"
    script.parent.mkdir(parents=True)
    script.write_text("# test")
    monkeypatch.setenv("TRIANGR_HOME", str(tmp_path / "triangr"))
    monkeypatch.delenv("ANGRYGHIDRA_SCRIPT", raising=False)
    monkeypatch.delenv("ANGRYGHIDRA_HOME", raising=False)
    monkeypatch.setattr(angr_tools.glob, "glob", lambda _pattern: [])
    assert angr_tools.find_angryghidra_script() == str(script)


def test_helper_script_is_packaged():
    assert angr_tools.DEFAULT_ANGR_HELPER.endswith("helpers/angr_decompile.py")
    assert angr_tools.os.path.isfile(angr_tools.DEFAULT_ANGR_HELPER)


def test_run_limited_subprocess_does_not_share_stdin(tmp_path):
    script = tmp_path / "read_stdin.py"
    script.write_text("import sys; print(repr(sys.stdin.read()))")
    code, out, _err, error = angr_tools.run_limited_subprocess(
        [angr_tools.sys.executable, str(script)], "probe", 30
    )
    assert (code, out, error) == (0, "''", "")


def test_angr_decompile_uses_program_info_defaults(tools, fake_backend, helper_calls):
    fake_backend.ok("/program_info", EBPF_PROGRAM)
    calls = helper_calls("oxidized")
    assert tools.angr_decompile_function("0x120", timeout=77) == "oxidized"
    assert calls == [([
        "--binary", "/tmp/sample.bin",
        "--address", "0x120",
        "--rust",
        "--skip-rust-setup",
        "--pcode-language", "eBPF:LE:64:default",
    ], 77)]


def test_angr_decompile_without_program_or_binary_is_clear(tools, fake_backend):
    fake_backend.fail("/program_info", 409, "NO_PROGRAM", "No program is open")
    assert "No binary_path provided" in tools.angr_decompile_function("0x120")


def test_angr_check_setup_with_explicit_binary(tools, helper_calls):
    calls = helper_calls("ok")
    out = tools.angr_check_setup(binary_path="/tmp/a.out", pcode_language="eBPF:LE:64:default")
    assert out == "ok"
    assert calls == [(["--check", "--binary", "/tmp/a.out", "--pcode-language",
                       "eBPF:LE:64:default"], 30)]


def test_angr_symbolic_find_falls_back_to_core_when_angryghidra_cannot_represent_request(
        tools, fake_backend, helper_calls):
    fake_backend.ok("/program_info", EBPF_PROGRAM)
    calls = helper_calls("found: true")
    out = tools.angr_symbolic_find(
        find_address="ram:00000180",
        start_address="ram:00000120",
        avoid_addresses="ram:00000140,0x160",
        stdin_bytes=8,
        symbolic_memory_json='{"0x2000": 32}',
        registers_json='{"r1": "sv8", "r2": "0x10"}',
        timeout=55,
        max_steps=123,
    )
    assert out == "engine: core angr\nfound: true"
    assert calls == [([
        "--binary", "/tmp/sample.bin",
        "--symbolic-find", "0x180",
        "--max-steps", "123",
        "--start-address", "0x120",
        "--avoid-address", "0x140,0x160",
        "--pcode-language", "eBPF:LE:64:default",
        "--stdin-bytes", "8",
        "--symbolic-memory-json", '{"0x2000": 32}',
        "--registers-json", '{"r1": "sv8", "r2": "0x10"}',
    ], 55)]


def test_angr_symbolic_find_core_uses_program_base_address(tools, fake_backend, helper_calls,
                                                           monkeypatch):
    fake_backend.ok("/program_info", X86_PROGRAM)
    monkeypatch.setattr(angr_tools, "find_angryghidra_script", lambda: "")
    calls = helper_calls("found: true")
    tools.angr_symbolic_find(find_address="00401020")
    args, _timeout = calls[0]
    assert args[args.index("--symbolic-find") + 1] == "0x401020"
    assert args[args.index("--base-address") + 1] == "0x400000"


def test_angr_symbolic_find_prefers_angryghidra_when_available(tools, fake_backend, monkeypatch):
    fake_backend.ok("/program_info", X86_PROGRAM)
    monkeypatch.setattr(angr_tools, "find_angryghidra_script", lambda: "/opt/angryghidra.py")
    calls = {}

    def fake_run(options, timeout):
        calls.update(options=options, timeout=timeout)
        return "t:0x401000\nt:0x401020\nargv[1] = b'ok'"

    monkeypatch.setattr(angr_tools, "run_angryghidra_options", fake_run)
    out = tools.angr_symbolic_find(
        find_address="0x401020",
        start_address="0x401000",
        argv_bytes="4",
        symbolic_memory_json='{"0x404000": 8}',
        memory_json='{"0x405000": "0x41"}',
        registers_json='{"rax": "sv8"}',
        timeout=44,
    )
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


def test_angr_symbolic_find_forced_angryghidra_missing_is_clear(tools, fake_backend, monkeypatch):
    fake_backend.ok("/program_info", X86_PROGRAM)
    monkeypatch.setattr(angr_tools, "find_angryghidra_script", lambda: "")
    out = tools.angr_symbolic_find(find_address="0x401020", engine="angryghidra")
    assert "AngryGhidra is not installed or configured" in out


def test_angr_symbolic_find_rejects_unbounded_max_steps(tools):
    out = tools.angr_symbolic_find(find_address="0x401020", binary_path="/tmp/a.out", max_steps=0)
    assert "max_steps must be between 1" in out


def test_angr_symbolic_find_rejects_huge_symbolic_stdin(tools):
    out = tools.angr_symbolic_find(
        find_address="0x401020", binary_path="/tmp/a.out", stdin_bytes=999999
    )
    assert "stdin_bytes must be between 0 and 4096" in out


def test_angr_symbolic_find_rejects_unknown_engine(tools):
    out = tools.angr_symbolic_find(find_address="0x1", engine="z3")
    assert out.startswith("engine must be one of")


def test_annotate_previews_by_default(tools, fake_backend, monkeypatch):
    monkeypatch.setattr(
        tools, "angr_symbolic_find", lambda **_: "engine: AngryGhidra\nt:0x401000\nt:0x401020"
    )
    serve_comments(fake_backend, ("0x401000", ["existing branch note"]), ("0x401020", [None]))
    out = tools.angr_annotate_symbolic_path(find_address="0x401020")
    assert "Preview only: 2 trace comment(s) would be written" in out
    assert "preview_token: " in out
    assert "- disasm 0x401000" in out
    assert "current: existing branch note" in out
    assert "pending: angr symbolic path: step 1/2 toward 0x401020" in out
    assert "- disasm 0x401020" in out
    assert "current: <none>" in out
    assert not [r for r in fake_backend.requests if r[0] == "POST"]


def test_annotate_requires_overwrite_confirmation(tools, monkeypatch):
    monkeypatch.setattr(tools, "angr_symbolic_find", lambda **_: "engine: AngryGhidra\nt:0x401000")
    out = tools.angr_annotate_symbolic_path(find_address="0x401020", apply=True)
    assert "Refusing to write comments" in out
    assert "overwrite_existing=True" in out


def test_annotate_requires_matching_preview_token(tools, monkeypatch):
    monkeypatch.setattr(tools, "angr_symbolic_find", lambda **_: "engine: AngryGhidra\nt:0x401000")
    out = tools.angr_annotate_symbolic_path(
        find_address="0x401020", apply=True, overwrite_existing=True
    )
    assert "no matching preview token" in out
    assert "First call angr_annotate_symbolic_path" in out


def test_annotate_rejects_changed_call_after_preview(tools, fake_backend, monkeypatch):
    monkeypatch.setattr(tools, "angr_symbolic_find", lambda **_: "engine: AngryGhidra\nt:0x401000")
    serve_comments(fake_backend, ("0x401000", [None]))
    token = preview_token(
        tools.angr_annotate_symbolic_path(find_address="0x401020", comment_prefix="previewed path")
    )
    out = tools.angr_annotate_symbolic_path(
        find_address="0x401020",
        comment_prefix="changed path",
        apply=True,
        overwrite_existing=True,
        preview_token=token,
    )
    assert "preview_token does not match this exact annotation request" in out


def test_annotate_rejects_changed_current_comment(tools, fake_backend, monkeypatch):
    monkeypatch.setattr(tools, "angr_symbolic_find", lambda **_: "engine: AngryGhidra\nt:0x401000")
    serve_comments(fake_backend, ("0x401000", ["old", "changed"]))
    token = preview_token(tools.angr_annotate_symbolic_path(find_address="0x401020"))
    out = tools.angr_annotate_symbolic_path(
        find_address="0x401020", apply=True, overwrite_existing=True, preview_token=token
    )
    assert "preview_token does not match this exact annotation request" in out


def test_annotate_requires_comment_read_before_token(tools, fake_backend, monkeypatch):
    monkeypatch.setattr(tools, "angr_symbolic_find", lambda **_: "engine: AngryGhidra\nt:0x401000")
    fake_backend.fail("/get_comment", 404, "UNKNOWN_ENDPOINT", "Unknown endpoint: /get_comment")
    out = tools.angr_annotate_symbolic_path(find_address="0x401020")
    assert "could not be read" in out
    assert "preview_token:" not in out


def test_annotate_token_is_single_use(tools, fake_backend, monkeypatch):
    monkeypatch.setattr(tools, "angr_symbolic_find", lambda **_: "engine: AngryGhidra\nt:0x401000")
    serve_comments(fake_backend, ("0x401000", [None]))
    fake_backend.ok("/set_disassembly_comment", {"address": "00401000", "comment_type": "EOL",
                                                 "comment": "x"})
    token = preview_token(tools.angr_annotate_symbolic_path(find_address="0x401020"))
    kwargs = dict(find_address="0x401020", apply=True, overwrite_existing=True,
                  preview_token=token)
    assert "Annotated 1 trace address(es)" in tools.angr_annotate_symbolic_path(**kwargs)
    assert "no recent preview was found" in tools.angr_annotate_symbolic_path(**kwargs)


def test_annotate_writes_trace_comments_with_confirmation(tools, fake_backend, monkeypatch):
    monkeypatch.setattr(
        tools, "angr_symbolic_find", lambda **_: "engine: AngryGhidra\nt:0x401000\nt:0x401020"
    )
    serve_comments(fake_backend, ("0x401000", ["existing branch note"]), ("0x401020", [None]))
    fake_backend.ok("/set_disassembly_comment", {"address": "x", "comment_type": "EOL",
                                                 "comment": "x"})
    token = preview_token(
        tools.angr_annotate_symbolic_path(find_address="0x401020", comment_kind="disasm")
    )
    out = tools.angr_annotate_symbolic_path(
        find_address="0x401020",
        comment_kind="disasm",
        apply=True,
        overwrite_existing=True,
        preview_token=token,
    )
    assert "Annotated 2 trace address(es)" in out
    assert "set_disassembly_comment 0x401000: comment set" in out
    writes = [r for r in fake_backend.requests if r[0] == "POST"]
    assert [(path, params) for _, path, params in writes] == [
        ("/set_disassembly_comment",
         {"address": "0x401000", "comment": "angr symbolic path: step 1/2 toward 0x401020"}),
        ("/set_disassembly_comment",
         {"address": "0x401020", "comment": "angr symbolic path: step 2/2 toward 0x401020"}),
    ]


def test_angr_solve_constraints_at_builds_rich_solver_args(tools, fake_backend, helper_calls):
    fake_backend.ok("/program_info", EBPF_PROGRAM)
    calls = helper_calls("satisfiable: true")
    out = tools.angr_solve_constraints_at(
        address="ram:00000180",
        start_address="ram:00000120",
        constraints_json='[{"type":"reg","name":"r1","op":"==","value":"0x10"}]',
        eval_registers="r0,r1",
        eval_memory_json='{"0x3000": 8}',
        timeout=88,
        max_steps=44,
    )
    assert out == "satisfiable: true"
    assert calls == [([
        "--binary", "/tmp/sample.bin",
        "--solve-at", "0x180",
        "--max-steps", "44",
        "--start-address", "0x120",
        "--pcode-language", "eBPF:LE:64:default",
        "--constraints-json", '[{"type": "reg", "name": "r1", "op": "==", "value": "0x10"}]',
        "--eval-memory-json", '{"0x3000": 8}',
        "--eval-registers", "r0,r1",
    ], 88)]


def test_angr_reachability_builds_cfg_args(tools, fake_backend, helper_calls):
    fake_backend.ok("/program_info", EBPF_PROGRAM)
    calls = helper_calls("reachable: true")
    out = tools.angr_reachability(
        "ram:00000120", "ram:00000180", complete_cfg=True, include_path=False, summary_limit=7,
        timeout=99,
    )
    assert out == "reachable: true"
    assert calls == [([
        "--binary", "/tmp/sample.bin",
        "--reachability-from", "0x120",
        "--reachability-to", "0x180",
        "--summary-limit", "7",
        "--pcode-language", "eBPF:LE:64:default",
        "--complete-cfg",
    ], 99)]


def test_angr_cfg_summary_builds_function_args(tools, fake_backend, helper_calls):
    fake_backend.ok("/program_info", EBPF_PROGRAM)
    calls = helper_calls("cfg")
    assert tools.angr_cfg_summary(function_address="ram:00000120", summary_limit=5,
                                  timeout=66) == "cfg"
    assert calls == [([
        "--binary", "/tmp/sample.bin",
        "--cfg-summary",
        "--summary-limit", "5",
        "--pcode-language", "eBPF:LE:64:default",
        "--function-address", "0x120",
    ], 66)]


def test_angr_callgraph_summary_builds_args(tools, fake_backend, helper_calls):
    fake_backend.ok("/program_info", EBPF_PROGRAM)
    calls = helper_calls("callgraph")
    assert tools.angr_callgraph_summary(summary_limit=3, timeout=77) == "callgraph"
    assert calls == [([
        "--binary", "/tmp/sample.bin",
        "--callgraph-summary",
        "--summary-limit", "3",
        "--pcode-language", "eBPF:LE:64:default",
    ], 77)]


def test_angr_lift_block_builds_args(tools, fake_backend, helper_calls):
    fake_backend.ok("/program_info", EBPF_PROGRAM)
    calls = helper_calls("AIL")
    assert tools.angr_lift_block("ram:00000120", lift_format="ail", num_inst=4, timeout=33) == "AIL"
    assert calls == [([
        "--binary", "/tmp/sample.bin",
        "--lift-block", "0x120",
        "--lift-format", "ail",
        "--pcode-language", "eBPF:LE:64:default",
        "--num-inst", "4",
    ], 33)]


def test_angr_lift_block_rejects_unknown_format(tools):
    assert "lift_format must be one of" in tools.angr_lift_block("0x1", binary_path="/x",
                                                                 lift_format="llvm")


def test_angr_compare_decompilers_batches_ghidra_and_oxidizer(tools, fake_backend, helper_calls):
    fake_backend.ok("/program_info", EBPF_PROGRAM)
    fake_backend.routes["/decompile_function"] = (200, lambda params: {
        "success": True,
        "data": {"function": {"name": "f", "address": params["address"]},
                 "code": f"ghidra {params['address']} timeout={params['timeout']}",
                 "truncated": False},
    })
    calls = helper_calls("oxidizer")
    out = tools.angr_compare_decompilers(
        "ram:00000120, ram:00000180", timeout_per_function=12, max_functions=2
    )
    assert "ghidra 0x120 timeout=12" in out
    assert "ghidra 0x180 timeout=12" in out
    assert out.count("### angr/Oxidizer\noxidizer") == 2
    assert calls[0] == ([
        "--binary", "/tmp/sample.bin",
        "--address", "0x120",
        "--rust",
        "--skip-rust-setup",
        "--pcode-language", "eBPF:LE:64:default",
    ], 12)


def test_angr_compare_decompilers_reports_ghidra_errors_inline(tools, fake_backend, helper_calls):
    fake_backend.ok("/program_info", EBPF_PROGRAM)
    fake_backend.fail("/decompile_function", 404, "FUNCTION_NOT_FOUND", "No function at 0x120")
    helper_calls("oxidizer")
    out = tools.angr_compare_decompilers("0x120")
    assert "Ghidra decompilation failed: [FUNCTION_NOT_FOUND]" in out


def test_angr_compare_decompilers_rejects_excessive_batch(tools):
    out = tools.angr_compare_decompilers("0x120", binary_path="/tmp/sample.bin", max_functions=999)
    assert "max_functions must be between 1 and 25" in out


def test_angryghidra_check_setup_missing_is_clear(tools, monkeypatch):
    monkeypatch.setattr(angr_tools, "find_angryghidra_script", lambda: "")
    out = tools.angryghidra_check_setup()
    assert "AngryGhidra is not installed or configured" in out
    assert "Non-AngryGhidra MCP tools are unaffected" in out


def test_angryghidra_symbolic_execute_missing_is_clear(tools, monkeypatch):
    monkeypatch.setattr(angr_tools, "find_angryghidra_script", lambda: "")
    out = tools.angryghidra_symbolic_execute(find_address="0x120")
    assert "AngryGhidra is not installed or configured" in out


def test_angryghidra_options_are_capped():
    error = angr_tools.validate_angryghidra_options({"vectors": {"0x1": 999999}})
    assert "must be between 1 and 4096 bytes" in error
