#!/usr/bin/env python3
import argparse
import io
import json
import os
import sys
import traceback
from collections import deque
from contextlib import redirect_stderr
from itertools import islice

BRIDGE_DIR = os.path.dirname(os.path.abspath(__file__))


os.environ.setdefault("XDG_CACHE_HOME", os.path.join(BRIDGE_DIR, ".angr-cache"))

MAX_JSON_INPUT_CHARS = 100_000
MAX_SYMBOLIC_BYTES = 4096
MAX_TOTAL_SYMBOLIC_BYTES = 16_384
MAX_SYMBOLIC_ARGS = 16
MAX_SYMBOLIC_REGIONS = 64
MAX_SYMBOLIC_REGISTER_BYTES = 64
MAX_CONSTRAINTS = 128
MAX_STEPS = 100_000
MAX_SUMMARY_LIMIT = 500
MAX_BLOCK_SIZE = 4096
MAX_NUM_INST = 256


def parse_address(value: str) -> int:
    if value.startswith("0x") and ":" in value:
        value = value[2:]
    if ":" in value:
        value = "0x" + value.rsplit(":", 1)[1]
    return int(value, 0)


def patch_elf_pcode_loader(pcode_language: str) -> None:
    if not pcode_language:
        return

    import archinfo
    from cle.backends.elf.elf import ELF
    from cle.errors import CLECompatibilityError

    pcode_arch = archinfo.ArchPcode(pcode_language)
    original_extract_arch = ELF.extract_arch

    def extract_arch_with_pcode_fallback(reader):
        try:
            return original_extract_arch(reader)
        except CLECompatibilityError as exc:
            # Some BPF ELFs use e_machine 263, while upstream pypcode's eBPF
            # opinion currently only matches Linux eBPF e_machine 247.
            if "263" in str(exc) and pcode_language.startswith("eBPF:"):
                return pcode_arch
            raise

    ELF.extract_arch = staticmethod(extract_arch_with_pcode_fallback)


def make_project(
    binary_path: str,
    pcode_language: str,
    rust: bool,
    base_address: str = "",
    auto_load_libs: bool = False,
):
    import angr
    import archinfo

    kwargs = {"auto_load_libs": auto_load_libs}
    main_opts = {}
    if pcode_language:
        patch_elf_pcode_loader(pcode_language)
        main_opts["arch"] = archinfo.ArchPcode(pcode_language)
    if base_address:
        main_opts["base_addr"] = parse_address(base_address)
    if main_opts:
        kwargs["main_opts"] = main_opts

    project = angr.Project(binary_path, **kwargs)
    if rust:
        # angr detects Rust from symbols when possible. Many stripped or p-code
        # targets need this nudge to enable Rust-oriented decompiler passes.
        project._languages = ["rust"]  # pylint: disable=protected-access
    return project


def parse_json_map(value: str, field_name: str) -> dict:
    if not value:
        return {}
    if len(value) > MAX_JSON_INPUT_CHARS:
        raise ValueError(f"{field_name} exceeds {MAX_JSON_INPUT_CHARS} characters")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field_name} must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    return parsed


def checked_int(value, field_name: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(str(value), 0)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{field_name} must be between {minimum} and {maximum}")
    return parsed


def parse_csv_ints(
    value: str,
    field_name: str,
    max_items: int,
    max_value: int,
) -> list[int]:
    if not value:
        return []
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if len(parts) > max_items:
        raise ValueError(f"{field_name} may contain at most {max_items} entries")
    return [
        checked_int(part, f"{field_name} entry", 1, max_value)
        for part in parts
    ]


def parse_csv_strings(value: str) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def hex_addr(value: int) -> str:
    return f"0x{value:x}"


def build_cfg(project, args, function_starts: list[int] | None = None):
    cfg_kwargs = {
        "normalize": True,
        "force_complete_scan": args.complete_cfg,
    }
    if function_starts:
        cfg_kwargs["function_starts"] = function_starts
        cfg_kwargs["force_complete_scan"] = False
    return project.analyses.CFGFast(**cfg_kwargs)


def get_cfg_node(cfg, address: int):
    return cfg.model.get_any_node(address, anyaddr=True)


def function_label(project, address: int | None) -> str:
    if address is None:
        return "unknown"
    func = project.kb.functions.get_by_addr(address)
    if func is None:
        return hex_addr(address)
    return f"{func.name} @ {hex_addr(func.addr)}"


def normalize_register_name(project, reg_name: str) -> str:
    if reg_name in project.arch.registers:
        return reg_name
    lowered = reg_name.lower()
    if lowered in project.arch.registers:
        return lowered
    uppered = reg_name.upper()
    if uppered in project.arch.registers:
        return uppered
    return reg_name


def make_block(project, address: int, block_size: int = 0, num_inst: int = 0):
    kwargs = {}
    if block_size > 0:
        block_size = checked_int(block_size, "block_size", 1, MAX_BLOCK_SIZE)
        kwargs["size"] = block_size
    if num_inst > 0:
        num_inst = checked_int(num_inst, "num_inst", 1, MAX_NUM_INST)
        kwargs["num_inst"] = num_inst
    return project.factory.block(address, **kwargs)


def setup_symbolic_execution(args: argparse.Namespace, target_value: str):
    import claripy

    target_addr = parse_address(target_value)
    avoid = [parse_address(value) for value in args.avoid_address.split(",") if value.strip()]
    project = make_project(
        args.binary,
        args.pcode_language,
        rust=False,
        base_address=args.base_address,
        auto_load_libs=args.auto_load_libs,
    )

    argv = [args.binary]
    symbolic_argv = []
    total_symbolic = 0
    argv_lengths = parse_csv_ints(
        args.argv_bytes,
        "argv_bytes",
        MAX_SYMBOLIC_ARGS,
        MAX_SYMBOLIC_BYTES,
    )
    for index, length in enumerate(argv_lengths, start=1):
        sym_arg = claripy.BVS(f"argv{index}", length * 8)
        symbolic_argv.append((index, length, sym_arg))
        argv.append(sym_arg)
        total_symbolic += length

    symbolic_stdin = None
    stdin = None
    if args.stdin_bytes > 0:
        args.stdin_bytes = checked_int(args.stdin_bytes, "stdin_bytes", 1, MAX_SYMBOLIC_BYTES)
        symbolic_stdin = claripy.BVS("stdin", args.stdin_bytes * 8)
        stdin = symbolic_stdin
        total_symbolic += args.stdin_bytes

    if args.start_address:
        state_kwargs = {}
        if stdin is not None:
            state_kwargs["stdin"] = stdin
        state = project.factory.blank_state(addr=parse_address(args.start_address), **state_kwargs)
    else:
        state_kwargs = {}
        if len(argv) > 1:
            state_kwargs["args"] = argv
        if stdin is not None:
            state_kwargs["stdin"] = stdin
        state = project.factory.entry_state(**state_kwargs)

    symbolic_memory = {}
    symbolic_memory_map = parse_json_map(args.symbolic_memory_json, "symbolic_memory_json")
    if len(symbolic_memory_map) > MAX_SYMBOLIC_REGIONS:
        raise ValueError(f"symbolic_memory_json may contain at most {MAX_SYMBOLIC_REGIONS} entries")
    for addr, length in symbolic_memory_map.items():
        mem_addr = parse_address(str(addr))
        mem_len = checked_int(
            length,
            f"symbolic_memory_json[{addr!r}]",
            1,
            MAX_SYMBOLIC_BYTES,
        )
        sym_mem = claripy.BVS(f"mem_{mem_addr:x}", mem_len * 8)
        symbolic_memory[mem_addr] = (mem_len, sym_mem)
        state.memory.store(mem_addr, sym_mem)
        total_symbolic += mem_len

    memory_map = parse_json_map(args.memory_json, "memory_json")
    if len(memory_map) > MAX_SYMBOLIC_REGIONS:
        raise ValueError(f"memory_json may contain at most {MAX_SYMBOLIC_REGIONS} entries")
    for addr, value in memory_map.items():
        mem_addr = parse_address(str(addr))
        if isinstance(value, str):
            concrete = int(value, 0)
        else:
            concrete = int(value)
        if concrete < 0:
            raise ValueError(f"memory_json[{addr!r}] must be non-negative")
        byte_len = max(1, (concrete.bit_length() + 7) // 8)
        if byte_len > MAX_SYMBOLIC_BYTES:
            raise ValueError(f"memory_json[{addr!r}] may contain at most {MAX_SYMBOLIC_BYTES} bytes")
        state.memory.store(mem_addr, concrete, size=byte_len)

    symbolic_registers = {}
    registers = parse_json_map(args.registers_json, "registers_json")
    if len(registers) > MAX_SYMBOLIC_REGIONS:
        raise ValueError(f"registers_json may contain at most {MAX_SYMBOLIC_REGIONS} entries")
    for reg_name, value in registers.items():
        reg_name = normalize_register_name(project, reg_name)
        if isinstance(value, str) and value.startswith("sv"):
            byte_len = checked_int(
                value[2:],
                f"registers_json[{reg_name!r}]",
                1,
                MAX_SYMBOLIC_REGISTER_BYTES,
            )
            sym_reg = claripy.BVS(f"reg_{reg_name}", byte_len * 8)
            symbolic_registers[reg_name] = (byte_len, sym_reg)
            setattr(state.regs, reg_name, sym_reg)
            total_symbolic += byte_len
        else:
            setattr(state.regs, reg_name, int(str(value), 0))

    if total_symbolic > MAX_TOTAL_SYMBOLIC_BYTES:
        raise ValueError(f"total symbolic input may not exceed {MAX_TOTAL_SYMBOLIC_BYTES} bytes")

    symbols = {
        "stdin": (args.stdin_bytes, symbolic_stdin),
        "argv": symbolic_argv,
        "memory": symbolic_memory,
        "registers": symbolic_registers,
    }
    return project, state, symbols, target_addr, avoid


def run_explorer(project, state, target_addr: int, avoid: list[int], max_steps: int):
    import angr

    max_steps = checked_int(max_steps, "max_steps", 1, MAX_STEPS)
    simgr = project.factory.simulation_manager(state)
    explorer_kwargs = {"find": target_addr}
    if avoid:
        explorer_kwargs["avoid"] = avoid
    simgr.use_technique(angr.exploration_techniques.Explorer(**explorer_kwargs))

    simgr.run(n=max_steps)
    return simgr


def describe_symbolic_solution(found, symbols) -> list[str]:
    lines = []
    stdin_len, symbolic_stdin = symbols["stdin"]
    if symbolic_stdin is not None:
        lines.append(f"stdin = {found.solver.eval(symbolic_stdin, cast_to=bytes)!r}")
    for index, _length, sym_arg in symbols["argv"]:
        lines.append(f"argv[{index}] = {found.solver.eval(sym_arg, cast_to=bytes)!r}")
    for mem_addr, (mem_len, sym_mem) in symbols["memory"].items():
        lines.append(f"mem[{hex_addr(mem_addr)}:{mem_len}] = {found.solver.eval(sym_mem, cast_to=bytes)!r}")
    for reg_name, (_byte_len, sym_reg) in symbols["registers"].items():
        lines.append(f"reg[{reg_name}] = {found.solver.eval(sym_reg):#x}")
    return lines


def get_symbolic_ast(state, symbols, item: dict):
    target_type = item.get("type")
    if target_type == "reg":
        reg_name = normalize_register_name(state.project, item["name"])
        return getattr(state.regs, reg_name)
    if target_type == "mem":
        mem_len = checked_int(item["length"], "constraint memory length", 1, MAX_SYMBOLIC_BYTES)
        return state.memory.load(parse_address(str(item["address"])), mem_len)
    if target_type == "stdin":
        _length, symbolic_stdin = symbols["stdin"]
        if symbolic_stdin is None:
            raise ValueError("constraint references stdin, but stdin is not symbolic")
        return symbolic_stdin
    if target_type == "argv":
        index = int(str(item["index"]), 0)
        for arg_index, _length, sym_arg in symbols["argv"]:
            if arg_index == index:
                return sym_arg
        raise ValueError(f"constraint references argv[{index}], but it is not symbolic")
    raise ValueError(f"unsupported constraint type: {target_type!r}")


def concrete_bvv(state, item: dict, bits: int):
    import claripy

    if "value_hex" in item:
        raw = bytes.fromhex(str(item["value_hex"]).removeprefix("0x"))
        if len(raw) * 8 != bits:
            raise ValueError(f"value_hex is {len(raw) * 8} bits, expected {bits}")
        return claripy.BVV(raw)
    if "value_bytes" in item:
        raw = str(item["value_bytes"]).encode()
        if len(raw) * 8 != bits:
            raise ValueError(f"value_bytes is {len(raw) * 8} bits, expected {bits}")
        return claripy.BVV(raw)
    if "value" not in item:
        raise ValueError("constraint is missing value, value_hex, or value_bytes")
    return claripy.BVV(int(str(item["value"]), 0), bits)


def constraint_expr(state, symbols, item: dict):
    ast = get_symbolic_ast(state, symbols, item)
    value = concrete_bvv(state, item, ast.size())
    op = item.get("op", "==")
    if op in {"==", "eq"}:
        return ast == value
    if op in {"!=", "ne"}:
        return ast != value
    if op in {"<", "ult"}:
        return ast < value
    if op in {"<=", "ule"}:
        return ast <= value
    if op in {">", "ugt"}:
        return ast > value
    if op in {">=", "uge"}:
        return ast >= value
    if op == "slt":
        return ast.SLT(value)
    if op == "sle":
        return ast.SLE(value)
    if op == "sgt":
        return ast.SGT(value)
    if op == "sge":
        return ast.SGE(value)
    raise ValueError(f"unsupported constraint op: {op!r}")


def run_check(args: argparse.Namespace) -> int:
    import angr

    print(f"python: {sys.executable}")
    print(f"angr: {angr.__version__}")
    if args.binary:
        project = make_project(
            args.binary,
            args.pcode_language,
            rust=False,
            base_address=args.base_address,
            auto_load_libs=args.auto_load_libs,
        )
        print(f"binary: {args.binary}")
        print(f"arch: {project.arch}")
        print(f"min_addr: {project.loader.main_object.min_addr:#x}")
        print(f"max_addr: {project.loader.main_object.max_addr:#x}")
    return 0


def run_symbolic_find(args: argparse.Namespace) -> int:
    project, state, symbols, target_addr, avoid = setup_symbolic_execution(args, args.symbolic_find)
    simgr = run_explorer(project, state, target_addr, avoid, args.max_steps)

    print(f"binary: {args.binary}")
    print(f"arch: {project.arch}")
    print(f"target: {target_addr:#x}")
    if args.start_address:
        print(f"start: {parse_address(args.start_address):#x}")
    if avoid:
        print("avoid: " + ", ".join(f"{addr:#x}" for addr in avoid))
    print(f"max_steps: {args.max_steps}")

    if not simgr.found:
        print("found: false")
        print(f"active_states: {len(simgr.active)}")
        print(f"deadended_states: {len(simgr.deadended)}")
        print(f"avoid_states: {len(simgr.avoid)}")
        return 2

    found = simgr.found[0]
    print("found: true")
    print("path:")
    for addr in found.history.bbl_addrs.hardcopy:
        print(f"  {addr:#x}")

    for line in describe_symbolic_solution(found, symbols):
        print(line)

    return 0


def run_solve_at(args: argparse.Namespace) -> int:
    project, state, symbols, target_addr, avoid = setup_symbolic_execution(args, args.solve_at)
    simgr = run_explorer(project, state, target_addr, avoid, args.max_steps)

    print(f"binary: {args.binary}")
    print(f"arch: {project.arch}")
    print(f"target: {target_addr:#x}")
    print(f"max_steps: {args.max_steps}")

    if not simgr.found:
        print("found: false")
        print(f"active_states: {len(simgr.active)}")
        print(f"deadended_states: {len(simgr.deadended)}")
        print(f"avoid_states: {len(simgr.avoid)}")
        return 2

    found = simgr.found[0]
    print("found: true")

    if not args.constraints_json:
        parsed_constraints = []
    else:
        if len(args.constraints_json) > MAX_JSON_INPUT_CHARS:
            raise ValueError(f"constraints_json exceeds {MAX_JSON_INPUT_CHARS} characters")
        decoded_constraints = json.loads(args.constraints_json)
        if isinstance(decoded_constraints, dict):
            parsed_constraints = decoded_constraints.get("constraints", [])
        else:
            parsed_constraints = decoded_constraints
    if not isinstance(parsed_constraints, list):
        raise ValueError("constraints_json constraints must be a list")
    if len(parsed_constraints) > MAX_CONSTRAINTS:
        raise ValueError(f"constraints_json may contain at most {MAX_CONSTRAINTS} entries")

    for item in parsed_constraints:
        if not isinstance(item, dict):
            raise ValueError("each constraint must be a JSON object")
        found.add_constraints(constraint_expr(found, symbols, item))

    satisfiable = found.solver.satisfiable()
    print(f"satisfiable: {str(satisfiable).lower()}")
    if not satisfiable:
        return 3

    for line in describe_symbolic_solution(found, symbols):
        print(line)

    eval_registers = parse_csv_strings(args.eval_registers)
    for reg_name in eval_registers:
        reg_name = normalize_register_name(project, reg_name)
        print(f"eval_reg[{reg_name}] = {found.solver.eval(getattr(found.regs, reg_name)):#x}")

    eval_memory = parse_json_map(args.eval_memory_json, "eval_memory_json")
    if len(eval_memory) > MAX_SYMBOLIC_REGIONS:
        raise ValueError(f"eval_memory_json may contain at most {MAX_SYMBOLIC_REGIONS} entries")
    for addr, length in eval_memory.items():
        mem_addr = parse_address(str(addr))
        mem_len = checked_int(length, f"eval_memory_json[{addr!r}]", 1, MAX_SYMBOLIC_BYTES)
        value = found.solver.eval(found.memory.load(mem_addr, mem_len), cast_to=bytes)
        print(f"eval_mem[{hex_addr(mem_addr)}:{mem_len}] = {value!r}")

    if args.eval_stdin_bytes > 0:
        args.eval_stdin_bytes = checked_int(
            args.eval_stdin_bytes,
            "eval_stdin_bytes",
            1,
            MAX_SYMBOLIC_BYTES,
        )
        stdin_len, symbolic_stdin = symbols["stdin"]
        if symbolic_stdin is None:
            print("eval_stdin = <stdin is not symbolic>")
        else:
            byte_len = min(stdin_len, args.eval_stdin_bytes)
            print(f"eval_stdin[{byte_len}] = {found.solver.eval(symbolic_stdin, cast_to=bytes)[:byte_len]!r}")

    return 0


def run_reachability(args: argparse.Namespace) -> int:
    args.summary_limit = checked_int(args.summary_limit, "summary_limit", 1, MAX_SUMMARY_LIMIT)
    source = parse_address(args.reachability_from)
    target = parse_address(args.reachability_to)
    project = make_project(
        args.binary,
        args.pcode_language,
        rust=False,
        base_address=args.base_address,
        auto_load_libs=args.auto_load_libs,
    )
    cfg = build_cfg(project, args, function_starts=None if args.complete_cfg else [source])
    source_node = get_cfg_node(cfg, source)
    target_node = get_cfg_node(cfg, target)

    print(f"binary: {args.binary}")
    print(f"arch: {project.arch}")
    print(f"source: {source:#x}")
    print(f"target: {target:#x}")
    print(f"cfg_nodes: {cfg.graph.number_of_nodes()}")
    print(f"cfg_edges: {cfg.graph.number_of_edges()}")

    if source_node is None:
        print("reachable: false")
        print("reason: source node not found")
        return 2
    if target_node is None:
        print("reachable: false")
        print("reason: target node not found")
        return 2

    queue = deque([source_node])
    predecessor = {source_node: None}
    while queue:
        node = queue.popleft()
        if node == target_node:
            break
        for successor in cfg.graph.successors(node):
            if successor not in predecessor:
                predecessor[successor] = node
                queue.append(successor)

    if target_node not in predecessor:
        print("reachable: false")
        return 0

    path = []
    node = target_node
    while node is not None:
        path.append(node)
        node = predecessor[node]
    path.reverse()

    print("reachable: true")
    print(f"path_length: {len(path)}")
    if args.include_path:
        print("path:")
        for node in path[: args.summary_limit]:
            print(f"  {node.addr:#x}")
        if len(path) > args.summary_limit:
            print(f"  ... {len(path) - args.summary_limit} more nodes")
    return 0


def run_cfg_summary(args: argparse.Namespace) -> int:
    args.summary_limit = checked_int(args.summary_limit, "summary_limit", 1, MAX_SUMMARY_LIMIT)
    project = make_project(
        args.binary,
        args.pcode_language,
        rust=False,
        base_address=args.base_address,
        auto_load_libs=args.auto_load_libs,
    )
    function_addr = parse_address(args.function_address) if args.function_address else None
    cfg = build_cfg(project, args, function_starts=[function_addr] if function_addr is not None else None)

    print(f"binary: {args.binary}")
    print(f"arch: {project.arch}")
    print(f"cfg_nodes: {cfg.graph.number_of_nodes()}")
    print(f"cfg_edges: {cfg.graph.number_of_edges()}")
    print(f"functions: {len(project.kb.functions)}")

    if function_addr is not None:
        func = project.kb.functions.get_by_addr(function_addr)
        if func is None:
            print(f"function: not found @ {function_addr:#x}")
            return 2
        print(f"function: {func.name} @ {func.addr:#x}")
        block_addrs = sorted(func.block_addrs_set)
        print(f"blocks: {len(block_addrs)}")
        print("block_addresses:")
        for addr in block_addrs[: args.summary_limit]:
            print(f"  {addr:#x}")
        if len(block_addrs) > args.summary_limit:
            print(f"  ... {len(block_addrs) - args.summary_limit} more blocks")
        call_sites = list(func.get_call_sites())
        print(f"call_sites: {len(call_sites)}")
        for site in call_sites[: args.summary_limit]:
            target = func.get_call_target(site)
            print(f"  {site:#x} -> {function_label(project, target)}")
        return 0

    print("functions_sample:")
    for func in islice(project.kb.functions.values(), args.summary_limit):
        print(f"  {func.addr:#x} {func.name} blocks={len(func.block_addrs_set)}")
    return 0


def run_callgraph_summary(args: argparse.Namespace) -> int:
    args.summary_limit = checked_int(args.summary_limit, "summary_limit", 1, MAX_SUMMARY_LIMIT)
    project = make_project(
        args.binary,
        args.pcode_language,
        rust=False,
        base_address=args.base_address,
        auto_load_libs=args.auto_load_libs,
    )
    build_cfg(project, args)
    callgraph = project.kb.functions.callgraph
    print(f"binary: {args.binary}")
    print(f"arch: {project.arch}")
    print(f"functions: {callgraph.number_of_nodes()}")
    print(f"calls: {callgraph.number_of_edges()}")

    edge_count = callgraph.number_of_edges()
    print("edges:")
    for src, dst in islice(callgraph.edges(), args.summary_limit):
        print(f"  {function_label(project, src)} -> {function_label(project, dst)}")
    if edge_count > args.summary_limit:
        print(f"  ... {edge_count - args.summary_limit} more edges")
    return 0


def run_lift_block(args: argparse.Namespace) -> int:
    from angr import ailment
    from angr.ailment.manager import Manager

    address = parse_address(args.lift_block)
    project = make_project(
        args.binary,
        args.pcode_language,
        rust=False,
        base_address=args.base_address,
        auto_load_libs=args.auto_load_libs,
    )
    block = make_block(project, address, args.block_size, args.num_inst)

    print(f"binary: {args.binary}")
    print(f"arch: {project.arch}")
    print(f"block: {address:#x}")
    print(f"size: {block.size}")
    print(f"instruction_addresses: {', '.join(hex_addr(addr) for addr in block.instruction_addrs)}")

    if args.lift_format in {"vex", "both"}:
        print()
        print("VEX:")
        print(block.vex)

    if args.lift_format in {"ail", "both"}:
        print()
        print("AIL:")
        manager = Manager(arch=project.arch)
        ail_block = ailment.IRSBConverter.convert(block.vex, manager)
        print(ail_block.dbg_repr().rstrip())
    return 0


def run_decompile(args: argparse.Namespace) -> int:
    import angr  # noqa: F401

    target_addr = parse_address(args.address)
    project = make_project(
        args.binary,
        args.pcode_language,
        args.rust,
        base_address=args.base_address,
        auto_load_libs=args.auto_load_libs,
    )

    cfg_kwargs = {
        "normalize": True,
        "function_starts": [target_addr],
        "force_complete_scan": False,
    }
    project.analyses.CFGFast(**cfg_kwargs)

    setup_notes = []
    if args.rust and not args.skip_rust_setup:
        try:
            project.analyses.CompleteCallingConventions(recover_variables=False)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            setup_notes.append(f"CompleteCallingConventions skipped: {type(exc).__name__}: {exc}")
        try:
            project.analyses.RustSymbolRecovery()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            setup_notes.append(f"RustSymbolRecovery skipped: {type(exc).__name__}: {exc}")
        try:
            project.analyses.TypeDBLoader()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            setup_notes.append(f"TypeDBLoader skipped: {type(exc).__name__}: {exc}")

    func = project.kb.functions.get_by_addr(target_addr)
    if func is None:
        print(f"No function recovered at {target_addr:#x}")
        return 2

    decompiler = project.analyses.Decompiler(func)
    codegen = getattr(decompiler, "codegen", None)
    if codegen is None or not getattr(codegen, "text", None):
        print(f"Decompiler produced no code for {func.name} at {target_addr:#x}")
        return 3

    print(f"binary: {args.binary}")
    print(f"arch: {project.arch}")
    print(f"function: {func.name} @ {target_addr:#x}")
    print(f"rust_mode: {args.rust}")
    if args.pcode_language:
        print(f"pcode_language: {args.pcode_language}")
    for note in setup_notes:
        print(f"note: {note}")
    print()
    print(codegen.text)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run angr/Oxidizer decompilation for GhidraMCP.")
    parser.add_argument("--binary", help="Path to binary to load")
    parser.add_argument("--address", help="Function entry address")
    parser.add_argument("--pcode-language", default="", help="Optional pypcode language id")
    parser.add_argument("--base-address", default="", help="Optional image base for raw/blob-style loads")
    parser.add_argument("--auto-load-libs", action="store_true", help="Ask angr to load imported libraries")
    parser.add_argument("--skip-rust-setup", action="store_true", help="Skip Rust recovery setup analyses")
    parser.add_argument("--check", action="store_true", help="Only verify angr imports and optional binary load")
    parser.add_argument("--symbolic-find", help="Find an execution path to this address")
    parser.add_argument("--start-address", default="", help="Optional blank_state start address for symbolic path search")
    parser.add_argument("--avoid-address", default="", help="Comma-separated addresses to avoid during symbolic path search")
    parser.add_argument("--stdin-bytes", type=int, default=0, help="Make stdin symbolic with this byte length")
    parser.add_argument("--argv-bytes", default="", help="Comma-separated symbolic argv byte lengths")
    parser.add_argument("--symbolic-memory-json", default="", help="JSON object mapping address to symbolic byte length")
    parser.add_argument("--memory-json", default="", help="JSON object mapping address to concrete integer/hex value")
    parser.add_argument("--registers-json", default="", help='JSON object mapping register names to values or "svN" symbolic byte lengths')
    parser.add_argument("--max-steps", type=int, default=10000, help=f"Maximum symbolic execution steps, 1-{MAX_STEPS}")
    parser.add_argument("--solve-at", help="Find an address and solve/evaluate requested constraints there")
    parser.add_argument("--constraints-json", default="", help="JSON list of constraints, or object with a constraints list")
    parser.add_argument("--eval-registers", default="", help="Comma-separated register names to evaluate after solve-at")
    parser.add_argument("--eval-memory-json", default="", help="JSON object mapping address to byte length to evaluate after solve-at")
    parser.add_argument("--eval-stdin-bytes", type=int, default=0, help="Evaluate this many symbolic stdin bytes after solve-at")
    parser.add_argument("--reachability-from", help="Source address for static CFG reachability")
    parser.add_argument("--reachability-to", help="Target address for static CFG reachability")
    parser.add_argument("--cfg-summary", action="store_true", help="Summarize angr CFGFast output")
    parser.add_argument("--callgraph-summary", action="store_true", help="Summarize angr's recovered callgraph")
    parser.add_argument("--function-address", default="", help="Optional function address for CFG summaries")
    parser.add_argument("--complete-cfg", action="store_true", help="Force complete CFG scan instead of targeted/default scan")
    parser.add_argument("--summary-limit", type=int, default=50, help="Maximum items to print in summaries")
    parser.add_argument("--include-path", action="store_true", help="Include a static reachability path when found")
    parser.add_argument("--lift-block", help="Lift a basic block at this address")
    parser.add_argument("--lift-format", choices=["vex", "ail", "both"], default="both", help="IR format to print for --lift-block")
    parser.add_argument("--block-size", type=int, default=0, help="Optional block size for lifting")
    parser.add_argument("--num-inst", type=int, default=0, help="Optional instruction count for lifting")
    rust_group = parser.add_mutually_exclusive_group()
    rust_group.add_argument("--rust", dest="rust", action="store_true", default=True)
    rust_group.add_argument("--no-rust", dest="rust", action="store_false")
    args = parser.parse_args()
    args.max_steps = checked_int(args.max_steps, "max_steps", 1, MAX_STEPS)
    args.stdin_bytes = checked_int(args.stdin_bytes, "stdin_bytes", 0, MAX_SYMBOLIC_BYTES)
    args.eval_stdin_bytes = checked_int(args.eval_stdin_bytes, "eval_stdin_bytes", 0, MAX_SYMBOLIC_BYTES)
    args.summary_limit = checked_int(args.summary_limit, "summary_limit", 1, MAX_SUMMARY_LIMIT)
    if args.block_size < 0:
        raise ValueError("block_size must be non-negative")
    if args.num_inst < 0:
        raise ValueError("num_inst must be non-negative")

    if args.check:
        if not args.binary:
            import angr

            print(f"python: {sys.executable}")
            print(f"angr: {angr.__version__}")
            return 0
        return run_check(args)

    if args.symbolic_find:
        if not args.binary:
            parser.error("--binary is required with --symbolic-find")
        return run_symbolic_find(args)

    if args.solve_at:
        if not args.binary:
            parser.error("--binary is required with --solve-at")
        return run_solve_at(args)

    if args.reachability_from or args.reachability_to:
        if not args.binary or not args.reachability_from or not args.reachability_to:
            parser.error("--binary, --reachability-from, and --reachability-to are required together")
        return run_reachability(args)

    if args.cfg_summary:
        if not args.binary:
            parser.error("--binary is required with --cfg-summary")
        return run_cfg_summary(args)

    if args.callgraph_summary:
        if not args.binary:
            parser.error("--binary is required with --callgraph-summary")
        return run_callgraph_summary(args)

    if args.lift_block:
        if not args.binary:
            parser.error("--binary is required with --lift-block")
        return run_lift_block(args)

    if not args.binary or not args.address:
        parser.error("--binary and --address are required unless --check is used")

    return run_decompile(args)


if __name__ == "__main__":
    stderr = io.StringIO()
    try:
        with redirect_stderr(stderr):
            exit_code = main()
    except ValueError as exc:
        captured = stderr.getvalue().strip()
        if captured:
            print(captured, file=sys.stderr)
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        captured = stderr.getvalue().strip()
        if captured:
            print(captured, file=sys.stderr)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        sys.exit(1)

    captured = stderr.getvalue().strip()
    if captured:
        print(captured, file=sys.stderr)
    sys.exit(exit_code)
