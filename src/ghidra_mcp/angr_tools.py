"""Optional angr/Oxidizer and AngryGhidra tools.

angr runs in a separate Python process (the helper script in `helpers/`), so the MCP server
does not depend on angr. Every tool defaults its binary path, p-code language and base address
from the program open in Ghidra.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import string
import subprocess
import sys
import tempfile
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from ghidra_mcp.backend import BackendError, GhidraBackend

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
# The checkout root when running from source; harmless when installed as a wheel.
REPO_ROOT = os.path.dirname(os.path.dirname(PACKAGE_DIR))
DEFAULT_ANGR_HELPER = os.path.join(PACKAGE_DIR, "helpers", "angr_decompile.py")
DEFAULT_ANGRYGHIDRA_SCRIPT = os.path.join(
    REPO_ROOT,
    "AngryGhidra",
    "angryghidra_script",
    "angryghidra.py",
)
DEFAULT_TRIANGR_HOME = os.path.expanduser("~/.local/share/triangr")
DEFAULT_TRIANGR_ANGR_PYTHON = os.path.join(DEFAULT_TRIANGR_HOME, "venv", "bin", "python")
DEFAULT_TRIANGR_ANGRYGHIDRA_SCRIPT = os.path.join(
    DEFAULT_TRIANGR_HOME,
    "AngryGhidra",
    "angryghidra_script",
    "angryghidra.py",
)
PARENT_ANGRYGHIDRA_SCRIPT = os.path.join(
    os.path.dirname(REPO_ROOT),
    "AngryGhidra",
    "angryghidra_script",
    "angryghidra.py",
)

TIMEOUT_MAX = 1800
GHIDRA_DECOMPILE_TIMEOUT_MIN = 10
GHIDRA_DECOMPILE_READ_MARGIN = 30
ANGR_HELPER_OUTPUT_MAX_CHARS = 200_000
ANGR_JSON_INPUT_MAX_CHARS = 100_000
ANGR_OPTIONS_JSON_MAX_CHARS = 100_000
ANGR_MAX_SYMBOLIC_BYTES = 4096
ANGR_MAX_TOTAL_SYMBOLIC_BYTES = 16_384
ANGR_MAX_SYMBOLIC_ARGS = 16
ANGR_MAX_SYMBOLIC_REGIONS = 64
ANGR_MAX_SYMBOLIC_REGISTER_BYTES = 64
ANGR_MAX_HOOKS = 64
ANGR_MAX_STEPS = 100_000
ANGR_MAX_SUMMARY_LIMIT = 500
ANGR_MAX_BLOCK_SIZE = 4096
ANGR_MAX_NUM_INST = 256
ANGR_MAX_COMPARE_FUNCTIONS = 25
ANGR_MAX_COMMENTS = 100
ANGR_MAX_COMMENT_PREFIX_CHARS = 200
ANGR_PREVIEW_CONFIRMATION_TTL_SECONDS = 600
ANGR_PREVIEW_CONFIRMATION_MAX_ENTRIES = 128

COMMENT_KINDS = {
    "set_disassembly_comment": "disasm",
    "set_decompiler_comment": "decomp",
}


# ---- Environment discovery -----------------------------------------------------------------


def default_angr_python() -> str:
    candidates = [
        DEFAULT_TRIANGR_ANGR_PYTHON,
        os.path.join(REPO_ROOT, ".venv", "bin", "python"),
        sys.executable,
    ]
    triangr_home = os.environ.get("TRIANGR_HOME")
    if triangr_home:
        candidates.insert(0, os.path.join(triangr_home, "venv", "bin", "python"))
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return sys.executable


def angryghidra_python() -> str:
    return (
        os.environ.get("ANGRYGHIDRA_PYTHON")
        or os.environ.get("GHIDRA_MCP_ANGR_PYTHON")
        or default_angr_python()
    )


def find_angryghidra_script() -> str:
    candidates = [
        os.environ.get("ANGRYGHIDRA_SCRIPT", ""),
        os.path.join(os.environ.get("ANGRYGHIDRA_HOME", ""), "angryghidra_script", "angryghidra.py"),
        DEFAULT_TRIANGR_ANGRYGHIDRA_SCRIPT,
        DEFAULT_ANGRYGHIDRA_SCRIPT,
        PARENT_ANGRYGHIDRA_SCRIPT,
    ]
    triangr_home = os.environ.get("TRIANGR_HOME")
    if triangr_home:
        candidates.insert(
            2,
            os.path.join(triangr_home, "AngryGhidra", "angryghidra_script", "angryghidra.py"),
        )
    candidates.extend(
        glob.glob(
            os.path.expanduser(
                "~/Library/ghidra/*/Extensions/AngryGhidra/angryghidra_script/angryghidra.py"
            )
        )
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return ""


def angryghidra_missing_message() -> str:
    return (
        "AngryGhidra is not installed or configured. Install it next to this bridge "
        f"at {os.path.dirname(DEFAULT_ANGRYGHIDRA_SCRIPT)} or set ANGRYGHIDRA_HOME "
        "or ANGRYGHIDRA_SCRIPT. Non-AngryGhidra MCP tools are unaffected."
    )


def infer_pcode_language(language_id: str | None) -> str:
    if not language_id:
        return ""
    if language_id in {"eBPF:LE:64:default", "eBPF:BE:64:default", "BPF:LE:32:default"}:
        return language_id
    lowered = language_id.lower()
    if "ebpf" in lowered or "bpf" in lowered or "solana" in lowered:
        return "eBPF:LE:64:default"
    return ""


def normalize_ghidra_address(address: str) -> str:
    """Converts a Ghidra address ("00401000", "ram:00401000", "0x401000") to 0x-prefixed hex.

    Ghidra prints addresses as hex without a prefix, so bare digits are read as hex, as Ghidra
    itself does.
    """
    value = (address or "").strip()
    if not value:
        return value
    if value.lower().startswith("0x") and ":" in value:
        value = value[2:]
    if ":" in value:
        value = value.rsplit(":", 1)[1]
        return f"0x{value.lstrip('0') or '0'}"
    if value.lower().startswith("0x"):
        return value
    if all(c in string.hexdigits for c in value):
        return f"0x{value.lstrip('0') or '0'}"
    return value


# ---- Input validation ----------------------------------------------------------------------


def parse_optional_json(value: str, field_name: str):
    if not value:
        return None
    if len(value) > ANGR_JSON_INPUT_MAX_CHARS:
        raise ValueError(f"{field_name} exceeds {ANGR_JSON_INPUT_MAX_CHARS} characters")
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        raise ValueError(f"{field_name} must be valid JSON: {e}") from e


def bounded_int(value: int, field_name: str, minimum: int, maximum: int) -> tuple[int, str]:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return minimum, f"{field_name} must be an integer"
    if parsed < minimum or parsed > maximum:
        return parsed, f"{field_name} must be between {minimum} and {maximum}"
    return parsed, ""


def parse_capped_csv_ints(
    value: str, field_name: str, max_items: int, max_value: int
) -> tuple[list[int], str]:
    if not value:
        return [], ""
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if len(parts) > max_items:
        return [], f"{field_name} may contain at most {max_items} entries"
    result = []
    for part in parts:
        try:
            parsed = int(part, 0)
        except ValueError:
            return [], f"{field_name} entry {part!r} is not an integer"
        if parsed < 1 or parsed > max_value:
            return [], f"{field_name} entries must be between 1 and {max_value}"
        result.append(parsed)
    return result, ""


def parse_capped_json_map(value: str, field_name: str, max_items: int) -> tuple[dict, str]:
    try:
        parsed = parse_optional_json(value, field_name)
    except ValueError as e:
        return {}, str(e)
    if parsed is None:
        return {}, ""
    if not isinstance(parsed, dict):
        return {}, f"{field_name} must be a JSON object"
    if len(parsed) > max_items:
        return {}, f"{field_name} may contain at most {max_items} entries"
    return parsed, ""


def symbolic_length(
    value, field_name: str, max_value: int = ANGR_MAX_SYMBOLIC_BYTES
) -> tuple[int, str]:
    try:
        parsed = int(str(value), 0)
    except ValueError:
        return 0, f"{field_name} must be an integer byte length"
    if parsed < 1 or parsed > max_value:
        return parsed, f"{field_name} must be between 1 and {max_value} bytes"
    return parsed, ""


def validate_symbolic_input_caps(
    stdin_bytes: int = 0,
    argv_bytes: str = "",
    symbolic_memory_json: str = "",
    memory_json: str = "",
    registers_json: str = "",
) -> str:
    if stdin_bytes:
        _stdin_bytes, error = bounded_int(stdin_bytes, "stdin_bytes", 0, ANGR_MAX_SYMBOLIC_BYTES)
        if error:
            return error
    argv_lengths, error = parse_capped_csv_ints(
        argv_bytes,
        "argv_bytes",
        ANGR_MAX_SYMBOLIC_ARGS,
        ANGR_MAX_SYMBOLIC_BYTES,
    )
    if error:
        return error
    total_symbolic = sum(argv_lengths) + max(0, int(stdin_bytes or 0))

    symbolic_memory, error = parse_capped_json_map(
        symbolic_memory_json,
        "symbolic_memory_json",
        ANGR_MAX_SYMBOLIC_REGIONS,
    )
    if error:
        return error
    for addr, length in symbolic_memory.items():
        byte_len, error = symbolic_length(length, f"symbolic_memory_json[{addr!r}]")
        if error:
            return error
        total_symbolic += byte_len

    memory, error = parse_capped_json_map(memory_json, "memory_json", ANGR_MAX_SYMBOLIC_REGIONS)
    if error:
        return error
    for addr, value in memory.items():
        try:
            concrete = int(str(value), 0)
        except ValueError:
            return f"memory_json[{addr!r}] must be an integer or hex string"
        if concrete < 0:
            return f"memory_json[{addr!r}] must be non-negative"
        byte_len = max(1, (concrete.bit_length() + 7) // 8)
        if byte_len > ANGR_MAX_SYMBOLIC_BYTES:
            return f"memory_json[{addr!r}] may contain at most {ANGR_MAX_SYMBOLIC_BYTES} bytes"

    registers, error = parse_capped_json_map(
        registers_json,
        "registers_json",
        ANGR_MAX_SYMBOLIC_REGIONS,
    )
    if error:
        return error
    for reg_name, value in registers.items():
        if isinstance(value, str) and value.startswith("sv"):
            byte_len, error = symbolic_length(
                value[2:],
                f"registers_json[{reg_name!r}]",
                ANGR_MAX_SYMBOLIC_REGISTER_BYTES,
            )
            if error:
                return error
            total_symbolic += byte_len

    if total_symbolic > ANGR_MAX_TOTAL_SYMBOLIC_BYTES:
        return f"total symbolic input may not exceed {ANGR_MAX_TOTAL_SYMBOLIC_BYTES} bytes"
    return ""


def validate_solver_caps(
    constraints_json: str = "",
    eval_memory_json: str = "",
    eval_stdin_bytes: int = 0,
) -> str:
    try:
        constraints = parse_optional_json(constraints_json, "constraints_json")
    except ValueError as e:
        return str(e)
    if isinstance(constraints, dict):
        constraints = constraints.get("constraints", [])
    if constraints is None:
        constraints = []
    if not isinstance(constraints, list):
        return "constraints_json constraints must be a list"
    if len(constraints) > ANGR_MAX_SYMBOLIC_REGIONS * 2:
        return f"constraints_json may contain at most {ANGR_MAX_SYMBOLIC_REGIONS * 2} entries"

    eval_memory, error = parse_capped_json_map(
        eval_memory_json,
        "eval_memory_json",
        ANGR_MAX_SYMBOLIC_REGIONS,
    )
    if error:
        return error
    for addr, length in eval_memory.items():
        _byte_len, error = symbolic_length(length, f"eval_memory_json[{addr!r}]")
        if error:
            return error

    if eval_stdin_bytes:
        _eval_stdin_bytes, error = bounded_int(
            eval_stdin_bytes,
            "eval_stdin_bytes",
            0,
            ANGR_MAX_SYMBOLIC_BYTES,
        )
        if error:
            return error
    return ""


def validate_angryghidra_options(options: dict) -> str:
    encoded = json.dumps(options)
    if len(encoded) > ANGR_OPTIONS_JSON_MAX_CHARS:
        return f"AngryGhidra options exceed {ANGR_OPTIONS_JSON_MAX_CHARS} characters"

    arguments = options.get("arguments", {})
    if arguments and not isinstance(arguments, dict):
        return "AngryGhidra arguments must be a JSON object"
    if len(arguments) > ANGR_MAX_SYMBOLIC_ARGS:
        return f"AngryGhidra arguments may contain at most {ANGR_MAX_SYMBOLIC_ARGS} entries"
    total_symbolic = 0
    for key, value in arguments.items():
        byte_len, error = symbolic_length(value, f"arguments[{key!r}]")
        if error:
            return error
        total_symbolic += byte_len

    vectors = options.get("vectors", {})
    if vectors and not isinstance(vectors, dict):
        return "AngryGhidra vectors must be a JSON object"
    if len(vectors) > ANGR_MAX_SYMBOLIC_REGIONS:
        return f"AngryGhidra vectors may contain at most {ANGR_MAX_SYMBOLIC_REGIONS} entries"
    for addr, length in vectors.items():
        byte_len, error = symbolic_length(length, f"vectors[{addr!r}]")
        if error:
            return error
        total_symbolic += byte_len

    mem_store = options.get("mem_store", {})
    if mem_store and not isinstance(mem_store, dict):
        return "AngryGhidra mem_store must be a JSON object"
    if len(mem_store) > ANGR_MAX_SYMBOLIC_REGIONS:
        return f"AngryGhidra mem_store may contain at most {ANGR_MAX_SYMBOLIC_REGIONS} entries"
    for addr, value in mem_store.items():
        text_value = str(value)
        if len(text_value.removeprefix("0x")) > ANGR_MAX_SYMBOLIC_BYTES * 2:
            return f"mem_store[{addr!r}] may contain at most {ANGR_MAX_SYMBOLIC_BYTES} bytes"

    regs_vals = options.get("regs_vals", {})
    if regs_vals and not isinstance(regs_vals, dict):
        return "AngryGhidra regs_vals must be a JSON object"
    if len(regs_vals) > ANGR_MAX_SYMBOLIC_REGIONS:
        return f"AngryGhidra regs_vals may contain at most {ANGR_MAX_SYMBOLIC_REGIONS} entries"
    for reg_name, value in regs_vals.items():
        if isinstance(value, str) and value.startswith("sv"):
            byte_len, error = symbolic_length(
                value[2:],
                f"regs_vals[{reg_name!r}]",
                ANGR_MAX_SYMBOLIC_REGISTER_BYTES,
            )
            if error:
                return error
            total_symbolic += byte_len

    hooks = options.get("hooks", [])
    if hooks and not isinstance(hooks, list):
        return "AngryGhidra hooks must be a JSON array"
    if len(hooks) > ANGR_MAX_HOOKS:
        return f"AngryGhidra hooks may contain at most {ANGR_MAX_HOOKS} entries"
    for index, hook in enumerate(hooks):
        if not isinstance(hook, dict):
            return f"AngryGhidra hooks[{index}] must be a JSON object"
        for _address, register_updates in hook.items():
            if not isinstance(register_updates, dict):
                return f"AngryGhidra hooks[{index}] values must be JSON objects"
            for reg_name, value in register_updates.items():
                if isinstance(value, str) and value.startswith("sv"):
                    byte_len, error = symbolic_length(
                        value[2:],
                        f"hooks[{index}][{reg_name!r}]",
                        ANGR_MAX_SYMBOLIC_REGISTER_BYTES,
                    )
                    if error:
                        return error
                    total_symbolic += byte_len

    if total_symbolic > ANGR_MAX_TOTAL_SYMBOLIC_BYTES:
        return (
            f"total AngryGhidra symbolic input may not exceed {ANGR_MAX_TOTAL_SYMBOLIC_BYTES} bytes"
        )
    return ""


# ---- Subprocesses --------------------------------------------------------------------------


def read_limited_stream(stream, limit: int) -> tuple[str, bool]:
    stream.seek(0)
    text = stream.read(limit + 1)
    if len(text) > limit:
        return text[:limit], True
    return text, False


def truncation_note(label: str, limit: int) -> str:
    return f"\n\n[{label} truncated after {limit} characters]"


def run_limited_subprocess(
    cmd: list[str], label: str, timeout: int
) -> tuple[int | None, str, str, str]:
    effective_timeout = max(1, min(timeout, TIMEOUT_MAX))
    try:
        with tempfile.TemporaryFile(
            "w+", encoding="utf-8", errors="replace"
        ) as stdout_file, tempfile.TemporaryFile(
            "w+", encoding="utf-8", errors="replace"
        ) as stderr_file:
            completed = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=effective_timeout,
                check=False,
            )
            output, output_truncated = read_limited_stream(stdout_file, ANGR_HELPER_OUTPUT_MAX_CHARS)
            errors, errors_truncated = read_limited_stream(stderr_file, ANGR_HELPER_OUTPUT_MAX_CHARS)
    except FileNotFoundError as e:
        return None, "", "", f"Failed to start {label}: {e}"
    except subprocess.TimeoutExpired:
        return None, "", "", f"{label} timed out after {effective_timeout} seconds"

    output = output.strip()
    errors = errors.strip()
    if output_truncated:
        output += truncation_note(f"{label} stdout", ANGR_HELPER_OUTPUT_MAX_CHARS)
    if errors_truncated:
        errors += truncation_note(f"{label} stderr", ANGR_HELPER_OUTPUT_MAX_CHARS)
    return completed.returncode, output, errors, ""


def run_angr_helper(args: list[str], timeout: int) -> str:
    helper = os.environ.get("GHIDRA_MCP_ANGR_HELPER", DEFAULT_ANGR_HELPER)
    python = os.environ.get("GHIDRA_MCP_ANGR_PYTHON", default_angr_python())
    returncode, output, errors, error = run_limited_subprocess(
        [python, helper, *args], "angr helper", timeout
    )
    if error:
        return error
    if returncode == 0:
        return output if output else "(angr returned no output)"
    details = output
    if errors:
        details = f"{details}\n\nstderr:\n{errors}" if details else f"stderr:\n{errors}"
    return f"angr helper failed with exit code {returncode}\n\n{details}".strip()


def run_angryghidra_options(options: dict, timeout: int) -> str:
    script = find_angryghidra_script()
    if not script:
        return angryghidra_missing_message()
    validation_error = validate_angryghidra_options(options)
    if validation_error:
        return validation_error

    options_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix="-angryghidra.json", delete=False
        ) as options_file:
            json.dump(options, options_file)
            options_path = options_file.name
        returncode, output, errors, error = run_limited_subprocess(
            [angryghidra_python(), script, options_path],
            "AngryGhidra",
            timeout,
        )
    finally:
        if options_path:
            try:
                os.unlink(options_path)
            except OSError:
                pass

    if error:
        return error
    if returncode == 0:
        return output if output else "(AngryGhidra returned no solution)"
    details = output
    if errors:
        details = f"{details}\n\nstderr:\n{errors}" if details else f"stderr:\n{errors}"
    return f"AngryGhidra failed with exit code {returncode}\n\n{details}".strip()


# ---- Argument building ---------------------------------------------------------------------


def require_binary_path(binary_path: str) -> str:
    if not binary_path:
        return "No binary_path provided and Ghidra did not return an executable_path"
    return ""


def normalize_address_list(addresses: str) -> str:
    return ",".join(
        normalize_ghidra_address(address) for address in addresses.split(",") if address.strip()
    )


def append_common_angr_args(args: list[str], pcode_language: str = "", base_address: str = "") -> None:
    if pcode_language:
        args.extend(["--pcode-language", pcode_language])
    if base_address:
        args.extend(["--base-address", normalize_ghidra_address(base_address)])


def append_json_arg(args: list[str], option: str, value: str, field_name: str) -> str:
    try:
        parsed = parse_optional_json(value, field_name)
    except ValueError as e:
        return str(e)
    if parsed is not None:
        args.extend([option, json.dumps(parsed)])
    return ""


def append_rust_args(args: list[str], rust: bool, run_rust_setup: bool) -> None:
    if rust:
        args.append("--rust")
        if not run_rust_setup:
            args.append("--skip-rust-setup")
    else:
        args.append("--no-rust")


def split_addresses(addresses: str, max_addresses: int) -> list[str]:
    normalized = addresses.replace("\n", ",").replace(" ", ",")
    result = [
        normalize_ghidra_address(address) for address in normalized.split(",") if address.strip()
    ]
    return result[: max(1, max_addresses)]


def normalize_angryghidra_map_values(
    parsed: dict,
    symbolic_prefix_ok: bool = False,
    integers_as_hex: bool = False,
) -> dict:
    normalized = {}
    for key, value in parsed.items():
        if isinstance(value, int) and integers_as_hex:
            normalized[str(key)] = hex(value)
        elif symbolic_prefix_ok and isinstance(value, str) and value.startswith("sv"):
            normalized[str(key)] = value
        else:
            normalized[str(key)] = str(value)
    return normalized


def make_angryghidra_arguments(argv_bytes: str) -> dict:
    arguments = {}
    for index, length in enumerate((part.strip() for part in argv_bytes.split(",")), start=1):
        if length:
            arguments[str(index)] = length
    return arguments


def angryghidra_symbolic_unsupported_reason(
    stdin_bytes: int,
    pcode_language: str = "",
    raw_binary_arch: str = "",
) -> str:
    unsupported = []
    if stdin_bytes > 0:
        unsupported.append("symbolic stdin is not supported by AngryGhidra's native script")
    if pcode_language and not raw_binary_arch:
        unsupported.append(
            "p-code language loading requires the core angr helper unless raw_binary_arch is provided"
        )
    return "; ".join(unsupported)


def extract_trace_addresses(output: str) -> list[str]:
    addresses = []
    in_core_path = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "path:":
            in_core_path = True
            continue
        if stripped.startswith("t:"):
            addresses.append(normalize_ghidra_address(stripped[2:]))
            in_core_path = False
            continue
        if in_core_path and stripped.startswith("0x"):
            addresses.append(normalize_ghidra_address(stripped.split()[0]))
            continue
        if in_core_path and stripped and not stripped.startswith("..."):
            in_core_path = False
    deduped = []
    seen = set()
    for address in addresses:
        if address not in seen:
            deduped.append(address)
            seen.add(address)
    return deduped


# ---- Annotation previews -------------------------------------------------------------------


def annotation_preview_token(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]


def missing_annotation_preview_message() -> str:
    return (
        "Refusing to write comments because no matching preview token was provided. "
        "First call angr_annotate_symbolic_path with the same arguments and "
        "apply=False, overwrite_existing=False. Review the preview, then retry "
        "with apply=True, overwrite_existing=True, and the preview_token from that response."
    )


def format_preview_comment(value: str) -> str:
    if not value:
        return "<none>"
    return value.replace("\n", "\n    ")


def format_planned_comment_preview(planned_writes: list[dict]) -> str:
    lines = ["Planned comment writes:"]
    for planned_write in planned_writes:
        kind = COMMENT_KINDS.get(planned_write["endpoint"], planned_write["endpoint"])
        lines.append(f"- {kind} {planned_write['address']}")
        lines.append(f"  current: {format_preview_comment(planned_write.get('current_comment', ''))}")
        lines.append(f"  pending: {format_preview_comment(planned_write['comment'])}")
    return "\n".join(lines)


class AnnotationPreviews:
    """Short-lived tokens that tie an annotation write to the exact preview the caller saw."""

    def __init__(self) -> None:
        self._issued: dict[str, float] = {}

    def clear(self) -> None:
        self._issued.clear()

    def prune(self, now: float | None = None) -> None:
        if now is None:
            now = time.time()
        expired = [
            token
            for token, issued in self._issued.items()
            if now - issued > ANGR_PREVIEW_CONFIRMATION_TTL_SECONDS
        ]
        for token in expired:
            self._issued.pop(token, None)
        while len(self._issued) > ANGR_PREVIEW_CONFIRMATION_MAX_ENTRIES:
            oldest = min(self._issued, key=self._issued.get)
            self._issued.pop(oldest, None)

    def remember(self, payload: dict) -> str:
        now = time.time()
        self.prune(now)
        token = annotation_preview_token(payload)
        self._issued[token] = now
        return token

    def validate(self, payload: dict, preview_token: str) -> str:
        """Returns an error message, or "" after consuming the matching token."""
        self.prune()
        expected_token = annotation_preview_token(payload)
        if not preview_token:
            return missing_annotation_preview_message()
        if preview_token != expected_token:
            return (
                "Refusing to write comments because preview_token does not match this exact "
                "annotation request. Re-run the preview with the same arguments you want to "
                "apply, then use the preview_token from that response."
            )
        if expected_token not in self._issued:
            return (
                "Refusing to write comments because no recent preview was found for this exact "
                "annotation request. Preview confirmations expire after "
                f"{ANGR_PREVIEW_CONFIRMATION_TTL_SECONDS // 60} minutes; re-run the preview "
                "and retry with the new preview_token."
            )
        self._issued.pop(expected_token, None)
        return ""


# ---- Tools ---------------------------------------------------------------------------------


class AngrTools:
    """The angr tool implementations. Each returns text, including validation errors."""

    def __init__(self, backend: GhidraBackend):
        self.backend = backend
        self.previews = AnnotationPreviews()

    # -- Ghidra context --

    def program_info(self) -> dict[str, Any]:
        """The open program's /program_info, or {} if Ghidra cannot provide it."""
        try:
            info = self.backend.get("program_info")
        except BackendError:
            return {}
        return info if isinstance(info, dict) else {}

    def resolve_angr_defaults(self, binary_path: str = "", pcode_language: str = "") -> tuple[str, str]:
        program_info = {}
        if not binary_path or not pcode_language:
            program_info = self.program_info()
        if not binary_path:
            binary_path = program_info.get("executable_path") or ""
        if not pcode_language:
            pcode_language = infer_pcode_language(program_info.get("language_id"))
        return binary_path, pcode_language

    def read_current_comment(self, address: str, endpoint: str) -> tuple[str, str]:
        kind = COMMENT_KINDS.get(endpoint)
        if not kind:
            return "", f"Cannot read current comment for unsupported endpoint {endpoint!r}"
        try:
            response = self.backend.request(
                "GET", "get_comment", {"address": address, "kind": kind}, read_timeout=10.0
            )
        except BackendError as e:
            return "", str(e)
        return str((response or {}).get("comment") or ""), ""

    def attach_current_comments(self, planned_writes: list[dict]) -> str:
        for planned_write in planned_writes:
            current_comment, error = self.read_current_comment(
                planned_write["address"],
                planned_write["endpoint"],
            )
            if error:
                return error
            planned_write["current_comment"] = current_comment
        return ""

    def ghidra_decompile(self, address: str, timeout: int) -> str:
        try:
            result = self.backend.request(
                "GET",
                "decompile_function",
                {"address": address, "timeout": max(GHIDRA_DECOMPILE_TIMEOUT_MIN, timeout)},
                read_timeout=timeout + GHIDRA_DECOMPILE_READ_MARGIN,
            )
        except BackendError as e:
            return f"Ghidra decompilation failed: {e}"
        code = (result or {}).get("code", "")
        if (result or {}).get("truncated"):
            code += "\n\n[Ghidra output truncated]"
        return code

    # -- Tools --

    def angr_decompile_function(
        self,
        address: str,
        binary_path: str = "",
        rust: bool = True,
        run_rust_setup: bool = False,
        pcode_language: str = "",
        timeout: int = 120,
    ) -> str:
        """
        Decompile a function with angr/Oxidizer.

        If binary_path is omitted, the current Ghidra program's executable path is
        used. For p-code targets, the helper falls back to angr's p-code engine
        using the Ghidra language id when possible.

        Args:
            address: Function entry address in hex (e.g. "0x1400010a0").
            binary_path: Optional path to the binary. Defaults to current Ghidra
                         program executable path.
            rust: Enable angr's Rust-oriented decompiler/codegen path.
            run_rust_setup: Run slower Rust setup analyses that may try to download
                            FLIRT signatures if angr has not cached them yet.
            pcode_language: Optional pypcode language id, such as
                            "eBPF:LE:64:default".
            timeout: Maximum helper runtime in seconds.
        """
        binary_path, pcode_language = self.resolve_angr_defaults(binary_path, pcode_language)
        missing = require_binary_path(binary_path)
        if missing:
            return missing

        args = ["--binary", binary_path, "--address", normalize_ghidra_address(address)]
        append_rust_args(args, rust, run_rust_setup)
        if pcode_language:
            args.extend(["--pcode-language", pcode_language])
        return run_angr_helper(args, max(1, timeout))

    def angr_check_setup(self, binary_path: str = "", pcode_language: str = "") -> str:
        """
        Verify the bridge can import angr and optionally load the current binary.
        """
        binary_path, pcode_language = self.resolve_angr_defaults(binary_path, pcode_language)
        args = ["--check"]
        if binary_path:
            args.extend(["--binary", binary_path])
        if pcode_language:
            args.extend(["--pcode-language", pcode_language])
        return run_angr_helper(args, 30)

    def angr_symbolic_find(
        self,
        find_address: str,
        binary_path: str = "",
        start_address: str = "",
        avoid_addresses: str = "",
        pcode_language: str = "",
        base_address: str = "",
        raw_binary_arch: str = "",
        auto_load_libs: bool = False,
        stdin_bytes: int = 0,
        argv_bytes: str = "",
        symbolic_memory_json: str = "",
        memory_json: str = "",
        registers_json: str = "",
        engine: str = "auto",
        timeout: int = 120,
        max_steps: int = 10000,
    ) -> str:
        """
        Find a symbolic execution path to an address.

        engine="auto" prefers AngryGhidra when it is installed and the request fits
        AngryGhidra's native script, then falls back to the core angr helper. Use
        engine="angryghidra" to require AngryGhidra, or engine="core" to force the
        bridge's direct angr helper.

        Args:
            find_address: Address to reach.
            binary_path: Optional binary path. Defaults to the current Ghidra
                         program executable path.
            start_address: Optional blank-state start address. If omitted, angr
                           starts from the binary entry point.
            avoid_addresses: Optional comma-separated addresses to avoid.
            pcode_language: Optional pypcode language id.
            base_address: Optional loader base address. Defaults to the Ghidra
                          program's minimum address.
            raw_binary_arch: Optional AngryGhidra raw blob architecture.
            auto_load_libs: Whether AngryGhidra/core angr should load shared libs.
            stdin_bytes: Symbolic stdin length in bytes.
            argv_bytes: Comma-separated symbolic argv byte lengths, e.g. "8,16".
            symbolic_memory_json: JSON object mapping address to symbolic byte
                                  length, e.g. {"0x1000": 32}.
            memory_json: JSON object mapping address to concrete integer/hex value.
            registers_json: JSON object mapping register names to values or "svN"
                            for an N-byte symbolic register.
            engine: "auto", "angryghidra", or "core".
            timeout: Maximum helper runtime in seconds.
            max_steps: Maximum core-helper symbolic execution steps. AngryGhidra's
                       native script runs until it finds a path or the timeout hits.
        """
        requested_engine = engine.lower().strip()
        if requested_engine not in {"auto", "angryghidra", "core"}:
            return 'engine must be one of: "auto", "angryghidra", "core"'
        max_steps, error = bounded_int(max_steps, "max_steps", 1, ANGR_MAX_STEPS)
        if error:
            return error
        error = validate_symbolic_input_caps(
            stdin_bytes=stdin_bytes,
            argv_bytes=argv_bytes,
            symbolic_memory_json=symbolic_memory_json,
            memory_json=memory_json,
            registers_json=registers_json,
        )
        if error:
            return error

        program_info = {}
        if not binary_path or not pcode_language or not base_address:
            program_info = self.program_info()
        if not binary_path:
            binary_path = program_info.get("executable_path") or ""
        if not binary_path:
            return require_binary_path(binary_path)
        if not pcode_language:
            pcode_language = infer_pcode_language(program_info.get("language_id"))
        if not base_address:
            base_address = program_info.get("min_address") or ""

        if requested_engine in {"auto", "angryghidra"}:
            script = find_angryghidra_script()
            unsupported = angryghidra_symbolic_unsupported_reason(
                stdin_bytes,
                pcode_language,
                raw_binary_arch,
            )
            if script and not unsupported:
                options, error = self.build_angryghidra_symbolic_options(
                    find_address=find_address,
                    binary_path=binary_path,
                    start_address=start_address,
                    avoid_addresses=avoid_addresses,
                    base_address=base_address,
                    raw_binary_arch=raw_binary_arch,
                    auto_load_libs=auto_load_libs,
                    argv_bytes=argv_bytes,
                    symbolic_memory_json=symbolic_memory_json,
                    memory_json=memory_json,
                    registers_json=registers_json,
                )
                if error:
                    return error
                return "engine: AngryGhidra\n" + run_angryghidra_options(options, timeout)
            if requested_engine == "angryghidra":
                if not script:
                    return angryghidra_missing_message()
                return f"AngryGhidra cannot run this request: {unsupported}"

        args = [
            "--binary", binary_path,
            "--symbolic-find", normalize_ghidra_address(find_address),
            "--max-steps", str(max_steps),
        ]
        if start_address:
            args.extend(["--start-address", normalize_ghidra_address(start_address)])
        if avoid_addresses:
            args.extend(["--avoid-address", normalize_address_list(avoid_addresses)])
        append_common_angr_args(args, pcode_language, base_address)
        if auto_load_libs:
            args.append("--auto-load-libs")
        if stdin_bytes > 0:
            args.extend(["--stdin-bytes", str(stdin_bytes)])
        if argv_bytes:
            args.extend(["--argv-bytes", argv_bytes])
        for option, value, field_name in [
            ("--symbolic-memory-json", symbolic_memory_json, "symbolic_memory_json"),
            ("--memory-json", memory_json, "memory_json"),
            ("--registers-json", registers_json, "registers_json"),
        ]:
            error = append_json_arg(args, option, value, field_name)
            if error:
                return error

        return "engine: core angr\n" + run_angr_helper(args, max(1, timeout))

    def build_angryghidra_symbolic_options(
        self,
        find_address: str,
        binary_path: str,
        start_address: str = "",
        avoid_addresses: str = "",
        base_address: str = "",
        raw_binary_arch: str = "",
        auto_load_libs: bool = False,
        argv_bytes: str = "",
        symbolic_memory_json: str = "",
        memory_json: str = "",
        registers_json: str = "",
    ) -> tuple[dict | None, str]:
        if not binary_path:
            return None, require_binary_path(binary_path)
        if not base_address:
            base_address = self.program_info().get("min_address") or "0x0"

        try:
            options = {
                "binary_file": binary_path,
                "base_address": normalize_ghidra_address(base_address),
                "find_address": normalize_ghidra_address(find_address),
                "auto_load_libs": auto_load_libs,
            }
            if start_address:
                options["blank_state"] = normalize_ghidra_address(start_address)
            if avoid_addresses:
                options["avoid_address"] = normalize_address_list(avoid_addresses)
            if raw_binary_arch:
                options["raw_binary_arch"] = raw_binary_arch
            arguments = make_angryghidra_arguments(argv_bytes)
            if arguments:
                options["arguments"] = arguments
            for key, value, field_name, symbolic_prefix_ok, integers_as_hex in [
                ("vectors", symbolic_memory_json, "symbolic_memory_json", False, False),
                ("mem_store", memory_json, "memory_json", False, True),
                ("regs_vals", registers_json, "registers_json", True, True),
            ]:
                parsed = parse_optional_json(value, field_name)
                if parsed is not None:
                    if not isinstance(parsed, dict):
                        return None, f"{field_name} must be a JSON object"
                    options[key] = normalize_angryghidra_map_values(
                        parsed,
                        symbolic_prefix_ok,
                        integers_as_hex,
                    )
        except ValueError as e:
            return None, str(e)

        return options, ""

    def angr_annotate_symbolic_path(
        self,
        find_address: str,
        binary_path: str = "",
        start_address: str = "",
        avoid_addresses: str = "",
        pcode_language: str = "",
        base_address: str = "",
        raw_binary_arch: str = "",
        auto_load_libs: bool = False,
        stdin_bytes: int = 0,
        argv_bytes: str = "",
        symbolic_memory_json: str = "",
        memory_json: str = "",
        registers_json: str = "",
        engine: str = "auto",
        comment_kind: str = "disasm",
        comment_prefix: str = "angr symbolic path",
        max_comments: int = 100,
        apply: bool = False,
        overwrite_existing: bool = False,
        preview_token: str = "",
        timeout: int = 120,
        max_steps: int = 10000,
    ) -> str:
        """
        Run a symbolic path search and write path comments into the Ghidra program.

        This endpoint previews by default. To write comments, first review a preview
        response, then call again with the same arguments, apply=True,
        overwrite_existing=True, and the preview_token from that preview. The token
        check is required because the current Ghidra comment endpoints replace
        existing comments. comment_kind may be "disasm", "decomp", or "both";
        comments are applied only when a trace/path is found.
        """
        if comment_kind not in {"disasm", "decomp", "both"}:
            return 'comment_kind must be one of: "disasm", "decomp", "both"'
        max_comments, error = bounded_int(max_comments, "max_comments", 1, ANGR_MAX_COMMENTS)
        if error:
            return error
        if len(comment_prefix) > ANGR_MAX_COMMENT_PREFIX_CHARS:
            return f"comment_prefix may contain at most {ANGR_MAX_COMMENT_PREFIX_CHARS} characters"
        if apply and not overwrite_existing:
            return (
                "Refusing to write comments because Ghidra's comment endpoints replace existing "
                "comments. Call with overwrite_existing=True to confirm after reviewing a preview."
            )
        if apply and overwrite_existing and not preview_token:
            return missing_annotation_preview_message()

        result = self.angr_symbolic_find(
            find_address=find_address,
            binary_path=binary_path,
            start_address=start_address,
            avoid_addresses=avoid_addresses,
            pcode_language=pcode_language,
            base_address=base_address,
            raw_binary_arch=raw_binary_arch,
            auto_load_libs=auto_load_libs,
            stdin_bytes=stdin_bytes,
            argv_bytes=argv_bytes,
            symbolic_memory_json=symbolic_memory_json,
            memory_json=memory_json,
            registers_json=registers_json,
            engine=engine,
            timeout=timeout,
            max_steps=max_steps,
        )

        trace_addresses = extract_trace_addresses(result)[: max(1, max_comments)]
        if not trace_addresses:
            return f"{result}\n\nNo trace addresses found; no comments were written."

        total = len(trace_addresses)
        normalized_target = normalize_ghidra_address(find_address)
        endpoints = []
        if comment_kind in {"disasm", "both"}:
            endpoints.append("set_disassembly_comment")
        if comment_kind in {"decomp", "both"}:
            endpoints.append("set_decompiler_comment")
        planned_writes = [
            {
                "endpoint": endpoint,
                "address": address,
                "comment": f"{comment_prefix}: step {index}/{total} toward {normalized_target}",
            }
            for index, address in enumerate(trace_addresses, start=1)
            for endpoint in endpoints
        ]
        current_comment_error = self.attach_current_comments(planned_writes)
        if current_comment_error:
            return (
                f"{result}\n\n"
                "Refusing to create an annotation preview token because the current "
                "comments that would be overwritten could not be read. Update and "
                f"restart the Triangr extension, then retry. Details: {current_comment_error}"
            )
        preview_payload = {
            "tool": "angr_annotate_symbolic_path",
            "request": {
                "find_address": normalized_target,
                "binary_path": binary_path,
                "start_address": normalize_ghidra_address(start_address),
                "avoid_addresses": normalize_address_list(avoid_addresses),
                "pcode_language": pcode_language,
                "base_address": normalize_ghidra_address(base_address),
                "raw_binary_arch": raw_binary_arch,
                "auto_load_libs": auto_load_libs,
                "stdin_bytes": stdin_bytes,
                "argv_bytes": argv_bytes,
                "symbolic_memory_json": symbolic_memory_json,
                "memory_json": memory_json,
                "registers_json": registers_json,
                "engine": engine,
                "comment_kind": comment_kind,
                "comment_prefix": comment_prefix,
                "max_comments": max_comments,
                "timeout": max(1, timeout),
                "max_steps": max_steps,
            },
            "trace_addresses": trace_addresses,
            "planned_writes": planned_writes,
        }

        if not apply:
            token = self.previews.remember(preview_payload)
            return (
                f"{result}\n\n"
                f"Preview only: {len(trace_addresses)} trace comment(s) would be written. "
                "Review the preview, then call with the same arguments, apply=True, "
                f"overwrite_existing=True, and preview_token=\"{token}\" to write them. "
                f"Preview tokens expire after {ANGR_PREVIEW_CONFIRMATION_TTL_SECONDS // 60} minutes.\n"
                f"preview_token: {token}\n" + format_planned_comment_preview(planned_writes)
            )
        preview_error = self.previews.validate(preview_payload, preview_token)
        if preview_error:
            return f"{result}\n\n{preview_error}"

        writes = []
        for planned_write in planned_writes:
            try:
                self.backend.post(
                    planned_write["endpoint"],
                    address=planned_write["address"],
                    comment=planned_write["comment"],
                )
                status = "comment set"
            except BackendError as e:
                status = f"failed: {e}"
            writes.append(f"{planned_write['endpoint']} {planned_write['address']}: {status}")

        return (
            f"{result}\n\n"
            f"Annotated {len(trace_addresses)} trace address(es) with {len(writes)} comment write(s).\n"
            + "\n".join(writes)
        )

    def angr_solve_constraints_at(
        self,
        address: str,
        binary_path: str = "",
        start_address: str = "",
        avoid_addresses: str = "",
        pcode_language: str = "",
        base_address: str = "",
        stdin_bytes: int = 0,
        argv_bytes: str = "",
        symbolic_memory_json: str = "",
        memory_json: str = "",
        registers_json: str = "",
        constraints_json: str = "",
        eval_registers: str = "",
        eval_memory_json: str = "",
        eval_stdin_bytes: int = 0,
        timeout: int = 120,
        max_steps: int = 10000,
    ) -> str:
        """
        Find an execution path to an address, add constraints, and solve values.

        constraints_json accepts a JSON list (or {"constraints": [...]}) of objects
        like {"type":"reg","name":"r1","op":"==","value":"0x10"} or
        {"type":"mem","address":"0x2000","length":4,"op":"!=","value_hex":"00000000"}.
        Supported types are reg, mem, stdin, and argv.
        """
        binary_path, pcode_language = self.resolve_angr_defaults(binary_path, pcode_language)
        missing = require_binary_path(binary_path)
        if missing:
            return missing
        max_steps, error = bounded_int(max_steps, "max_steps", 1, ANGR_MAX_STEPS)
        if error:
            return error
        error = validate_symbolic_input_caps(
            stdin_bytes=stdin_bytes,
            argv_bytes=argv_bytes,
            symbolic_memory_json=symbolic_memory_json,
            memory_json=memory_json,
            registers_json=registers_json,
        )
        if error:
            return error
        error = validate_solver_caps(
            constraints_json=constraints_json,
            eval_memory_json=eval_memory_json,
            eval_stdin_bytes=eval_stdin_bytes,
        )
        if error:
            return error

        args = [
            "--binary", binary_path,
            "--solve-at", normalize_ghidra_address(address),
            "--max-steps", str(max_steps),
        ]
        if start_address:
            args.extend(["--start-address", normalize_ghidra_address(start_address)])
        if avoid_addresses:
            args.extend(["--avoid-address", normalize_address_list(avoid_addresses)])
        append_common_angr_args(args, pcode_language, base_address)
        if stdin_bytes > 0:
            args.extend(["--stdin-bytes", str(stdin_bytes)])
        if argv_bytes:
            args.extend(["--argv-bytes", argv_bytes])
        for option, value, field_name in [
            ("--symbolic-memory-json", symbolic_memory_json, "symbolic_memory_json"),
            ("--memory-json", memory_json, "memory_json"),
            ("--registers-json", registers_json, "registers_json"),
            ("--constraints-json", constraints_json, "constraints_json"),
            ("--eval-memory-json", eval_memory_json, "eval_memory_json"),
        ]:
            error = append_json_arg(args, option, value, field_name)
            if error:
                return error
        if eval_registers:
            args.extend(["--eval-registers", eval_registers])
        if eval_stdin_bytes > 0:
            args.extend(["--eval-stdin-bytes", str(eval_stdin_bytes)])

        return run_angr_helper(args, max(1, timeout))

    def angr_reachability(
        self,
        source_address: str,
        target_address: str,
        binary_path: str = "",
        pcode_language: str = "",
        base_address: str = "",
        complete_cfg: bool = False,
        include_path: bool = True,
        summary_limit: int = 50,
        timeout: int = 120,
    ) -> str:
        """
        Use angr CFGFast to check static reachability from one address to another.
        """
        binary_path, pcode_language = self.resolve_angr_defaults(binary_path, pcode_language)
        missing = require_binary_path(binary_path)
        if missing:
            return missing
        summary_limit, error = bounded_int(summary_limit, "summary_limit", 1, ANGR_MAX_SUMMARY_LIMIT)
        if error:
            return error

        args = [
            "--binary", binary_path,
            "--reachability-from", normalize_ghidra_address(source_address),
            "--reachability-to", normalize_ghidra_address(target_address),
            "--summary-limit", str(summary_limit),
        ]
        append_common_angr_args(args, pcode_language, base_address)
        if complete_cfg:
            args.append("--complete-cfg")
        if include_path:
            args.append("--include-path")
        return run_angr_helper(args, max(1, timeout))

    def angr_cfg_summary(
        self,
        binary_path: str = "",
        function_address: str = "",
        pcode_language: str = "",
        base_address: str = "",
        complete_cfg: bool = False,
        summary_limit: int = 50,
        timeout: int = 120,
    ) -> str:
        """
        Summarize angr CFGFast output for the whole binary or a single function.
        """
        binary_path, pcode_language = self.resolve_angr_defaults(binary_path, pcode_language)
        missing = require_binary_path(binary_path)
        if missing:
            return missing
        summary_limit, error = bounded_int(summary_limit, "summary_limit", 1, ANGR_MAX_SUMMARY_LIMIT)
        if error:
            return error

        args = [
            "--binary", binary_path,
            "--cfg-summary",
            "--summary-limit", str(summary_limit),
        ]
        append_common_angr_args(args, pcode_language, base_address)
        if function_address:
            args.extend(["--function-address", normalize_ghidra_address(function_address)])
        if complete_cfg:
            args.append("--complete-cfg")
        return run_angr_helper(args, max(1, timeout))

    def angr_callgraph_summary(
        self,
        binary_path: str = "",
        pcode_language: str = "",
        base_address: str = "",
        complete_cfg: bool = False,
        summary_limit: int = 100,
        timeout: int = 180,
    ) -> str:
        """
        Summarize angr's recovered callgraph edges.
        """
        binary_path, pcode_language = self.resolve_angr_defaults(binary_path, pcode_language)
        missing = require_binary_path(binary_path)
        if missing:
            return missing
        summary_limit, error = bounded_int(summary_limit, "summary_limit", 1, ANGR_MAX_SUMMARY_LIMIT)
        if error:
            return error

        args = [
            "--binary", binary_path,
            "--callgraph-summary",
            "--summary-limit", str(summary_limit),
        ]
        append_common_angr_args(args, pcode_language, base_address)
        if complete_cfg:
            args.append("--complete-cfg")
        return run_angr_helper(args, max(1, timeout))

    def angr_lift_block(
        self,
        address: str,
        binary_path: str = "",
        pcode_language: str = "",
        base_address: str = "",
        lift_format: str = "both",
        block_size: int = 0,
        num_inst: int = 0,
        timeout: int = 60,
    ) -> str:
        """
        Lift a basic block to VEX, AIL, or both.
        """
        binary_path, pcode_language = self.resolve_angr_defaults(binary_path, pcode_language)
        missing = require_binary_path(binary_path)
        if missing:
            return missing
        if lift_format not in {"vex", "ail", "both"}:
            return "lift_format must be one of: vex, ail, both"
        if block_size:
            block_size, error = bounded_int(block_size, "block_size", 1, ANGR_MAX_BLOCK_SIZE)
            if error:
                return error
        if num_inst:
            num_inst, error = bounded_int(num_inst, "num_inst", 1, ANGR_MAX_NUM_INST)
            if error:
                return error

        args = [
            "--binary", binary_path,
            "--lift-block", normalize_ghidra_address(address),
            "--lift-format", lift_format,
        ]
        append_common_angr_args(args, pcode_language, base_address)
        if block_size > 0:
            args.extend(["--block-size", str(block_size)])
        if num_inst > 0:
            args.extend(["--num-inst", str(num_inst)])
        return run_angr_helper(args, max(1, timeout))

    def angr_compare_decompilers(
        self,
        addresses: str,
        binary_path: str = "",
        pcode_language: str = "",
        rust: bool = True,
        run_rust_setup: bool = False,
        timeout_per_function: int = 120,
        max_functions: int = 10,
    ) -> str:
        """
        Batch-compare Ghidra decompiler output with angr/Oxidizer output.

        addresses accepts comma, space, or newline-separated function entry
        addresses. Results are returned in side-by-side text sections.
        """
        binary_path, pcode_language = self.resolve_angr_defaults(binary_path, pcode_language)
        missing = require_binary_path(binary_path)
        if missing:
            return missing
        max_functions, error = bounded_int(
            max_functions, "max_functions", 1, ANGR_MAX_COMPARE_FUNCTIONS
        )
        if error:
            return error

        selected_addresses = split_addresses(addresses, max_functions)
        if not selected_addresses:
            return "No addresses provided"

        sections = []
        per_function_timeout = max(1, min(timeout_per_function, TIMEOUT_MAX))
        for address in selected_addresses:
            ghidra_output = self.ghidra_decompile(address, per_function_timeout)
            angr_args = ["--binary", binary_path, "--address", address]
            append_rust_args(angr_args, rust, run_rust_setup)
            if pcode_language:
                angr_args.extend(["--pcode-language", pcode_language])
            oxidizer_output = run_angr_helper(angr_args, per_function_timeout)
            sections.append(
                f"## {address}\n\n"
                f"### Ghidra\n{ghidra_output}\n\n"
                f"### angr/Oxidizer\n{oxidizer_output}"
            )

        return "\n\n".join(sections)

    def angryghidra_check_setup(self) -> str:
        """
        Check whether the optional AngryGhidra script is installed and callable.
        """
        script = find_angryghidra_script()
        if not script:
            return angryghidra_missing_message()
        return f"AngryGhidra script: {script}\nPython: {angryghidra_python()}"

    def angryghidra_symbolic_execute(
        self,
        find_address: str,
        binary_path: str = "",
        start_address: str = "",
        avoid_addresses: str = "",
        base_address: str = "",
        raw_binary_arch: str = "",
        auto_load_libs: bool = False,
        arguments_json: str = "",
        vectors_json: str = "",
        mem_store_json: str = "",
        regs_vals_json: str = "",
        hooks_json: str = "",
        timeout: int = 120,
    ) -> str:
        """
        Run the optional AngryGhidra symbolic-execution script.

        JSON fields should use AngryGhidra's native option shapes. If AngryGhidra is
        not installed, this returns a clear error and leaves all other bridge tools
        working normally.
        """
        if not find_angryghidra_script():
            return angryghidra_missing_message()

        program_info = {}
        if not binary_path or not base_address:
            program_info = self.program_info()
        if not binary_path:
            binary_path = program_info.get("executable_path") or ""
        if not binary_path:
            return require_binary_path(binary_path)
        if not base_address:
            base_address = program_info.get("min_address") or "0x0"

        try:
            options = {
                "binary_file": binary_path,
                "base_address": normalize_ghidra_address(base_address),
                "find_address": normalize_ghidra_address(find_address),
                "auto_load_libs": auto_load_libs,
            }
            if start_address:
                options["blank_state"] = normalize_ghidra_address(start_address)
            if avoid_addresses:
                options["avoid_address"] = normalize_address_list(avoid_addresses)
            if raw_binary_arch:
                options["raw_binary_arch"] = raw_binary_arch
            for key, value in {
                "arguments": arguments_json,
                "vectors": vectors_json,
                "mem_store": mem_store_json,
                "regs_vals": regs_vals_json,
                "hooks": hooks_json,
            }.items():
                parsed = parse_optional_json(value, key)
                if parsed is not None:
                    options[key] = parsed
        except ValueError as e:
            return str(e)

        return run_angryghidra_options(options, timeout)


TOOL_NAMES = (
    "angr_decompile_function",
    "angr_check_setup",
    "angr_symbolic_find",
    "angr_annotate_symbolic_path",
    "angr_solve_constraints_at",
    "angr_reachability",
    "angr_cfg_summary",
    "angr_callgraph_summary",
    "angr_lift_block",
    "angr_compare_decompilers",
    "angryghidra_check_setup",
    "angryghidra_symbolic_execute",
)


def register_angr_tools(mcp: FastMCP, tools: AngrTools) -> None:
    for name in TOOL_NAMES:
        mcp.add_tool(getattr(tools, name), name=name)
