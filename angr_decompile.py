#!/usr/bin/env python3
import argparse
import io
import json
import os
import sys
import traceback
from contextlib import redirect_stderr

BRIDGE_DIR = os.path.dirname(os.path.abspath(__file__))


os.environ.setdefault("XDG_CACHE_HOME", os.path.join(BRIDGE_DIR, ".angr-cache"))


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
            # Solana BPF ELFs use e_machine 263, while upstream pypcode's eBPF
            # opinion currently only matches Linux eBPF e_machine 247.
            if "263" in str(exc) and pcode_language.startswith("eBPF:"):
                return pcode_arch
            raise

    ELF.extract_arch = staticmethod(extract_arch_with_pcode_fallback)


def make_project(binary_path: str, pcode_language: str, rust: bool, base_address: str = ""):
    import angr
    import archinfo

    kwargs = {"auto_load_libs": False}
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
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field_name} must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    return parsed


def parse_csv_ints(value: str) -> list[int]:
    if not value:
        return []
    return [int(part.strip(), 0) for part in value.split(",") if part.strip()]


def run_check(args: argparse.Namespace) -> int:
    import angr

    print(f"python: {sys.executable}")
    print(f"angr: {angr.__version__}")
    if args.binary:
        project = make_project(args.binary, args.pcode_language, rust=False, base_address=args.base_address)
        print(f"binary: {args.binary}")
        print(f"arch: {project.arch}")
        print(f"min_addr: {project.loader.main_object.min_addr:#x}")
        print(f"max_addr: {project.loader.main_object.max_addr:#x}")
    return 0


def run_symbolic_find(args: argparse.Namespace) -> int:
    import angr
    import claripy

    target_addr = parse_address(args.symbolic_find)
    avoid = [parse_address(value) for value in args.avoid_address.split(",") if value.strip()]
    project = make_project(args.binary, args.pcode_language, rust=False, base_address=args.base_address)

    argv = [args.binary]
    symbolic_argv = []
    for index, length in enumerate(parse_csv_ints(args.argv_bytes), start=1):
        sym_arg = claripy.BVS(f"argv{index}", length * 8)
        symbolic_argv.append((index, sym_arg))
        argv.append(sym_arg)

    symbolic_stdin = None
    stdin = None
    if args.stdin_bytes > 0:
        symbolic_stdin = claripy.BVS("stdin", args.stdin_bytes * 8)
        stdin = symbolic_stdin

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
    for addr, length in parse_json_map(args.symbolic_memory_json, "symbolic_memory_json").items():
        mem_addr = parse_address(str(addr))
        mem_len = int(str(length), 0)
        sym_mem = claripy.BVS(f"mem_{mem_addr:x}", mem_len * 8)
        symbolic_memory[mem_addr] = (mem_len, sym_mem)
        state.memory.store(mem_addr, sym_mem)

    for addr, value in parse_json_map(args.memory_json, "memory_json").items():
        mem_addr = parse_address(str(addr))
        if isinstance(value, str):
            concrete = int(value, 0)
            byte_len = max(1, (concrete.bit_length() + 7) // 8)
        else:
            concrete = int(value)
            byte_len = max(1, (concrete.bit_length() + 7) // 8)
        state.memory.store(mem_addr, concrete, size=byte_len)

    symbolic_registers = {}
    registers = parse_json_map(args.registers_json, "registers_json")
    for reg_name, value in registers.items():
        if isinstance(value, str) and value.startswith("sv"):
            byte_len = int(value[2:], 0)
            sym_reg = claripy.BVS(f"reg_{reg_name}", byte_len * 8)
            symbolic_registers[reg_name] = sym_reg
            setattr(state.regs, reg_name, sym_reg)
        else:
            setattr(state.regs, reg_name, int(str(value), 0))

    simgr = project.factory.simulation_manager(state)
    explorer_kwargs = {"find": target_addr}
    if avoid:
        explorer_kwargs["avoid"] = avoid
    simgr.use_technique(angr.exploration_techniques.Explorer(**explorer_kwargs))

    if args.max_steps > 0:
        simgr.run(n=args.max_steps)
    else:
        simgr.run()

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

    if symbolic_stdin is not None:
        print(f"stdin = {found.solver.eval(symbolic_stdin, cast_to=bytes)!r}")
    for index, sym_arg in symbolic_argv:
        print(f"argv[{index}] = {found.solver.eval(sym_arg, cast_to=bytes)!r}")
    for mem_addr, (mem_len, sym_mem) in symbolic_memory.items():
        print(f"mem[{mem_addr:#x}:{mem_len}] = {found.solver.eval(sym_mem, cast_to=bytes)!r}")
    for reg_name, sym_reg in symbolic_registers.items():
        print(f"reg[{reg_name}] = {found.solver.eval(sym_reg):#x}")

    return 0


def run_decompile(args: argparse.Namespace) -> int:
    import angr  # noqa: F401

    target_addr = parse_address(args.address)
    project = make_project(args.binary, args.pcode_language, args.rust, base_address=args.base_address)

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
    parser.add_argument("--max-steps", type=int, default=10000, help="Maximum symbolic execution steps, or 0 for unbounded")
    rust_group = parser.add_mutually_exclusive_group()
    rust_group.add_argument("--rust", dest="rust", action="store_true", default=True)
    rust_group.add_argument("--no-rust", dest="rust", action="store_false")
    args = parser.parse_args()

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

    if not args.binary or not args.address:
        parser.error("--binary and --address are required unless --check is used")

    return run_decompile(args)


if __name__ == "__main__":
    stderr = io.StringIO()
    try:
        with redirect_stderr(stderr):
            exit_code = main()
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
