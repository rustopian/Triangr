# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "httpx>=0.27.0",
#     "tenacity>=8.2.0",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import os
import json
import glob
import httpx
import argparse
import logging
import subprocess
import tempfile
from urllib.parse import urljoin
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
BRIDGE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ANGR_HELPER = os.path.join(BRIDGE_DIR, "angr_decompile.py")
DEFAULT_ANGRYGHIDRA_SCRIPT = os.path.join(
    BRIDGE_DIR,
    "AngryGhidra",
    "angryghidra_script",
    "angryghidra.py",
)
PARENT_ANGRYGHIDRA_SCRIPT = os.path.join(
    os.path.dirname(BRIDGE_DIR),
    "AngryGhidra",
    "angryghidra_script",
    "angryghidra.py",
)

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

# HTTP client with connection pooling
_http_client = None

# Configurable timeouts (in seconds)
TIMEOUT_DECOMPILE_MAX = 1800  # Maximum decompilation timeout (30 minutes)
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

def get_http_client():
    global _http_client
    if _http_client is None:
        _http_client = httpx.Client(
            timeout=30.0,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )
    return _http_client

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((httpx.ConnectError, httpx.ConnectTimeout)),
    reraise=True,
)
def safe_get(endpoint: str, params: dict = None, timeout: float = 30.0) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = get_http_client().get(url, params=params, timeout=timeout)
        response.encoding = 'utf-8'
        if response.status_code == 200:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((httpx.ConnectError, httpx.ConnectTimeout)),
    reraise=True,
)
def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = get_http_client().post(url, data=data)
        else:
            response = get_http_client().post(url, content=data.encode("utf-8"))
        response.encoding = 'utf-8'
        if response.status_code == 200:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def parse_key_value_lines(lines: list) -> dict:
    result = {}
    for line in lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            result[key.strip()] = value.strip()
    return result

def default_angr_python() -> str:
    candidates = [
        os.path.join(BRIDGE_DIR, ".venv", "bin", "python"),
        os.path.join(BRIDGE_DIR, "GhidraMCP-fork", ".venv", "bin", "python"),
        sys.executable,
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return sys.executable

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
    value = (address or "").strip()
    if not value:
        return value
    if value.startswith("0x") and ":" in value:
        value = value[2:]
    if ":" in value:
        value = value.rsplit(":", 1)[1]
        return f"0x{value.lstrip('0') or '0'}"
    return value

def run_angr_helper(args: list[str], timeout: int) -> str:
    helper = os.environ.get("GHIDRA_MCP_ANGR_HELPER", DEFAULT_ANGR_HELPER)
    python = os.environ.get("GHIDRA_MCP_ANGR_PYTHON", default_angr_python())
    cmd = [python, helper, *args]
    effective_timeout = max(1, min(timeout, TIMEOUT_DECOMPILE_MAX))
    try:
        with tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace") as stdout_file, \
                tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace") as stderr_file:
            completed = subprocess.run(
                cmd,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=effective_timeout,
                check=False,
            )
            output, output_truncated = read_limited_stream(stdout_file, ANGR_HELPER_OUTPUT_MAX_CHARS)
            errors, errors_truncated = read_limited_stream(stderr_file, ANGR_HELPER_OUTPUT_MAX_CHARS)
    except FileNotFoundError as e:
        return f"Failed to start angr helper: {e}"
    except subprocess.TimeoutExpired:
        return f"angr helper timed out after {effective_timeout} seconds"

    errors = errors.strip()
    output = output.strip()
    if output_truncated:
        output += truncation_note("angr stdout", ANGR_HELPER_OUTPUT_MAX_CHARS)
    if errors_truncated:
        errors += truncation_note("angr stderr", ANGR_HELPER_OUTPUT_MAX_CHARS)
    if completed.returncode == 0:
        return output if output else "(angr returned no output)"

    details = output
    if errors:
        details = f"{details}\n\nstderr:\n{errors}" if details else f"stderr:\n{errors}"
    return f"angr helper failed with exit code {completed.returncode}\n\n{details}".strip()

def find_angryghidra_script() -> str:
    candidates = [
        os.environ.get("ANGRYGHIDRA_SCRIPT", ""),
        os.path.join(os.environ.get("ANGRYGHIDRA_HOME", ""), "angryghidra_script", "angryghidra.py"),
        DEFAULT_ANGRYGHIDRA_SCRIPT,
        PARENT_ANGRYGHIDRA_SCRIPT,
    ]
    candidates.extend(glob.glob(os.path.expanduser(
        "~/Library/ghidra/*/Extensions/AngryGhidra/angryghidra_script/angryghidra.py"
    )))
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

def read_limited_stream(stream, limit: int) -> tuple[str, bool]:
    stream.seek(0)
    text = stream.read(limit + 1)
    if len(text) > limit:
        return text[:limit], True
    return text, False

def truncation_note(label: str, limit: int) -> str:
    return f"\n\n[{label} truncated after {limit} characters]"

def parse_capped_csv_ints(value: str, field_name: str, max_items: int, max_value: int) -> tuple[list[int], str]:
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

def symbolic_length(value, field_name: str, max_value: int = ANGR_MAX_SYMBOLIC_BYTES) -> tuple[int, str]:
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

    memory, error = parse_capped_json_map(
        memory_json,
        "memory_json",
        ANGR_MAX_SYMBOLIC_REGIONS,
    )
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
        return f"total AngryGhidra symbolic input may not exceed {ANGR_MAX_TOTAL_SYMBOLIC_BYTES} bytes"
    return ""

def resolve_angr_defaults(binary_path: str = "", pcode_language: str = "") -> tuple[str, str]:
    program_info = {}
    if not binary_path or not pcode_language:
        program_info = parse_key_value_lines(safe_get("program_info"))
    if not binary_path:
        binary_path = program_info.get("executable_path", "")
    if not pcode_language:
        pcode_language = infer_pcode_language(program_info.get("language_id"))
    return binary_path, pcode_language

def require_binary_path(binary_path: str) -> str:
    if not binary_path:
        return "No binary_path provided and Ghidra did not return an executable_path"
    return ""

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

def split_addresses(addresses: str, max_addresses: int) -> list[str]:
    normalized = addresses.replace("\n", ",").replace(" ", ",")
    result = [
        normalize_ghidra_address(address)
        for address in normalized.split(",")
        if address.strip()
    ]
    return result[:max(1, max_addresses)]

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

def run_angryghidra_options(options: dict, timeout: int) -> str:
    script = find_angryghidra_script()
    if not script:
        return angryghidra_missing_message()
    validation_error = validate_angryghidra_options(options)
    if validation_error:
        return validation_error

    python = os.environ.get("ANGRYGHIDRA_PYTHON") or os.environ.get("GHIDRA_MCP_ANGR_PYTHON") or default_angr_python()
    options_path = ""
    effective_timeout = max(1, min(timeout, TIMEOUT_DECOMPILE_MAX))
    try:
        with tempfile.NamedTemporaryFile("w", suffix="-angryghidra.json", delete=False) as options_file:
            json.dump(options, options_file)
            options_path = options_file.name
        with tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace") as stdout_file, \
                tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace") as stderr_file:
            completed = subprocess.run(
                [python, script, options_path],
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=effective_timeout,
                check=False,
            )
            output, output_truncated = read_limited_stream(stdout_file, ANGR_HELPER_OUTPUT_MAX_CHARS)
            errors, errors_truncated = read_limited_stream(stderr_file, ANGR_HELPER_OUTPUT_MAX_CHARS)
    except FileNotFoundError as e:
        return f"Failed to start AngryGhidra: {e}"
    except subprocess.TimeoutExpired:
        return f"AngryGhidra timed out after {effective_timeout} seconds"
    finally:
        if options_path:
            try:
                os.unlink(options_path)
            except OSError:
                pass

    output = output.strip()
    errors = errors.strip()
    if output_truncated:
        output += truncation_note("AngryGhidra stdout", ANGR_HELPER_OUTPUT_MAX_CHARS)
    if errors_truncated:
        errors += truncation_note("AngryGhidra stderr", ANGR_HELPER_OUTPUT_MAX_CHARS)
    if completed.returncode == 0:
        return output if output else "(AngryGhidra returned no solution)"

    details = output
    if errors:
        details = f"{details}\n\nstderr:\n{errors}" if details else f"stderr:\n{errors}"
    return f"AngryGhidra failed with exit code {completed.returncode}\n\n{details}".strip()

def build_angryghidra_symbolic_options(
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
        return None, "No binary_path provided and Ghidra did not return an executable_path"
    if not base_address:
        program_info = parse_key_value_lines(safe_get("program_info"))
        base_address = program_info.get("min_address", "0x0")

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
            options["avoid_address"] = ",".join(
                normalize_ghidra_address(address)
                for address in avoid_addresses.split(",")
                if address.strip()
            )
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

def angryghidra_symbolic_unsupported_reason(
    stdin_bytes: int,
    pcode_language: str = "",
    raw_binary_arch: str = "",
) -> str:
    unsupported = []
    if stdin_bytes > 0:
        unsupported.append("symbolic stdin is not supported by AngryGhidra's native script")
    if pcode_language and not raw_binary_arch:
        unsupported.append("p-code language loading requires the core angr helper unless raw_binary_arch is provided")
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

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_func_by_addr(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def get_program_info() -> str:
    """
    Get metadata for the current Ghidra program, including executable path,
    language id, compiler spec, image base, and address range.
    """
    return "\n".join(safe_get("program_info"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def angr_decompile_function(
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
    used. For Ghidra/Solana eBPF programs, the helper falls back to angr's
    p-code engine using the Ghidra language id when possible.

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
    program_info = {}
    if not binary_path or not pcode_language:
        program_info = parse_key_value_lines(safe_get("program_info"))
    if not binary_path:
        binary_path = program_info.get("executable_path", "")
    if not binary_path:
        return "No binary_path provided and Ghidra did not return an executable_path"
    if not pcode_language:
        pcode_language = infer_pcode_language(program_info.get("language_id"))

    args = ["--binary", binary_path, "--address", normalize_ghidra_address(address)]
    if rust:
        args.append("--rust")
        if not run_rust_setup:
            args.append("--skip-rust-setup")
    else:
        args.append("--no-rust")
    if pcode_language:
        args.extend(["--pcode-language", pcode_language])
    return run_angr_helper(args, max(1, timeout))

@mcp.tool()
def angr_check_setup(binary_path: str = "", pcode_language: str = "") -> str:
    """
    Verify the bridge can import angr and optionally load the current binary.
    """
    program_info = {}
    if not binary_path or not pcode_language:
        program_info = parse_key_value_lines(safe_get("program_info"))
    if not binary_path:
        binary_path = program_info.get("executable_path", "")
    if not pcode_language:
        pcode_language = infer_pcode_language(program_info.get("language_id"))

    args = ["--check"]
    if binary_path:
        args.extend(["--binary", binary_path])
    if pcode_language:
        args.extend(["--pcode-language", pcode_language])
    return run_angr_helper(args, 30)

@mcp.tool()
def angr_symbolic_find(
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
        base_address: Optional loader base address.
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
    _max_steps, error = bounded_int(max_steps, "max_steps", 1, ANGR_MAX_STEPS)
    if error:
        return error
    max_steps = _max_steps
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
        program_info = parse_key_value_lines(safe_get("program_info"))
    if not binary_path:
        binary_path = program_info.get("executable_path", "")
    if not binary_path:
        return "No binary_path provided and Ghidra did not return an executable_path"
    if not pcode_language:
        pcode_language = infer_pcode_language(program_info.get("language_id"))
    if not base_address:
        base_address = program_info.get("min_address", "")

    if requested_engine in {"auto", "angryghidra"}:
        script = find_angryghidra_script()
        unsupported = angryghidra_symbolic_unsupported_reason(
            stdin_bytes,
            pcode_language,
            raw_binary_arch,
        )
        if script and not unsupported:
            options, error = build_angryghidra_symbolic_options(
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
        normalized_avoid = ",".join(
            normalize_ghidra_address(address)
            for address in avoid_addresses.split(",")
        )
        args.extend(["--avoid-address", normalized_avoid])
    if pcode_language:
        args.extend(["--pcode-language", pcode_language])
    if base_address:
        args.extend(["--base-address", normalize_ghidra_address(base_address)])
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
        parsed = parse_optional_json(value, field_name)
        if parsed is not None:
            args.extend([option, json.dumps(parsed)])

    return "engine: core angr\n" + run_angr_helper(args, max(1, timeout))

@mcp.tool()
def angr_annotate_symbolic_path(
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
    timeout: int = 120,
    max_steps: int = 10000,
) -> str:
    """
    Run a symbolic path search and write path comments into the Ghidra program.

    This endpoint previews by default. Set apply=True and
    overwrite_existing=True to write comments, because the current Ghidra
    comment endpoints replace existing comments. comment_kind may be "disasm",
    "decomp", or "both"; comments are applied only when a trace/path is found.
    """
    if comment_kind not in {"disasm", "decomp", "both"}:
        return 'comment_kind must be one of: "disasm", "decomp", "both"'
    _max_comments, error = bounded_int(max_comments, "max_comments", 1, ANGR_MAX_COMMENTS)
    if error:
        return error
    max_comments = _max_comments
    if len(comment_prefix) > ANGR_MAX_COMMENT_PREFIX_CHARS:
        return f"comment_prefix may contain at most {ANGR_MAX_COMMENT_PREFIX_CHARS} characters"

    result = angr_symbolic_find(
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
    preview = [
        f"{address}: {comment_prefix}: step {index}/{total} toward {normalized_target}"
        for index, address in enumerate(trace_addresses, start=1)
    ]

    if not apply:
        return (
            f"{result}\n\n"
            f"Preview only: {len(trace_addresses)} trace comment(s) would be written. "
            "Call with apply=True and overwrite_existing=True to write them.\n"
            + "\n".join(preview)
        )
    if not overwrite_existing:
        return (
            f"{result}\n\n"
            "Refusing to write comments because Ghidra's comment endpoints replace existing comments. "
            "Call with overwrite_existing=True to confirm."
        )

    endpoints = []
    if comment_kind in {"disasm", "both"}:
        endpoints.append("set_disassembly_comment")
    if comment_kind in {"decomp", "both"}:
        endpoints.append("set_decompiler_comment")

    writes = []
    for index, address in enumerate(trace_addresses, start=1):
        comment = f"{comment_prefix}: step {index}/{total} toward {normalized_target}"
        for endpoint in endpoints:
            response = safe_post(endpoint, {"address": address, "comment": comment})
            writes.append(f"{endpoint} {address}: {response}")

    return (
        f"{result}\n\n"
        f"Annotated {len(trace_addresses)} trace address(es) with {len(writes)} comment write(s).\n"
        + "\n".join(writes)
    )

@mcp.tool()
def angr_solve_constraints_at(
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
    binary_path, pcode_language = resolve_angr_defaults(binary_path, pcode_language)
    missing = require_binary_path(binary_path)
    if missing:
        return missing
    _max_steps, error = bounded_int(max_steps, "max_steps", 1, ANGR_MAX_STEPS)
    if error:
        return error
    max_steps = _max_steps
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
        normalized_avoid = ",".join(
            normalize_ghidra_address(address_part)
            for address_part in avoid_addresses.split(",")
        )
        args.extend(["--avoid-address", normalized_avoid])
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

@mcp.tool()
def angr_reachability(
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
    binary_path, pcode_language = resolve_angr_defaults(binary_path, pcode_language)
    missing = require_binary_path(binary_path)
    if missing:
        return missing
    _summary_limit, error = bounded_int(summary_limit, "summary_limit", 1, ANGR_MAX_SUMMARY_LIMIT)
    if error:
        return error
    summary_limit = _summary_limit

    args = [
        "--binary", binary_path,
        "--reachability-from", normalize_ghidra_address(source_address),
        "--reachability-to", normalize_ghidra_address(target_address),
        "--summary-limit", str(max(1, summary_limit)),
    ]
    append_common_angr_args(args, pcode_language, base_address)
    if complete_cfg:
        args.append("--complete-cfg")
    if include_path:
        args.append("--include-path")
    return run_angr_helper(args, max(1, timeout))

@mcp.tool()
def angr_cfg_summary(
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
    binary_path, pcode_language = resolve_angr_defaults(binary_path, pcode_language)
    missing = require_binary_path(binary_path)
    if missing:
        return missing
    _summary_limit, error = bounded_int(summary_limit, "summary_limit", 1, ANGR_MAX_SUMMARY_LIMIT)
    if error:
        return error
    summary_limit = _summary_limit

    args = [
        "--binary", binary_path,
        "--cfg-summary",
        "--summary-limit", str(max(1, summary_limit)),
    ]
    append_common_angr_args(args, pcode_language, base_address)
    if function_address:
        args.extend(["--function-address", normalize_ghidra_address(function_address)])
    if complete_cfg:
        args.append("--complete-cfg")
    return run_angr_helper(args, max(1, timeout))

@mcp.tool()
def angr_callgraph_summary(
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
    binary_path, pcode_language = resolve_angr_defaults(binary_path, pcode_language)
    missing = require_binary_path(binary_path)
    if missing:
        return missing
    _summary_limit, error = bounded_int(summary_limit, "summary_limit", 1, ANGR_MAX_SUMMARY_LIMIT)
    if error:
        return error
    summary_limit = _summary_limit

    args = [
        "--binary", binary_path,
        "--callgraph-summary",
        "--summary-limit", str(max(1, summary_limit)),
    ]
    append_common_angr_args(args, pcode_language, base_address)
    if complete_cfg:
        args.append("--complete-cfg")
    return run_angr_helper(args, max(1, timeout))

@mcp.tool()
def angr_lift_block(
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
    binary_path, pcode_language = resolve_angr_defaults(binary_path, pcode_language)
    missing = require_binary_path(binary_path)
    if missing:
        return missing
    if lift_format not in {"vex", "ail", "both"}:
        return "lift_format must be one of: vex, ail, both"
    if block_size:
        _block_size, error = bounded_int(block_size, "block_size", 1, ANGR_MAX_BLOCK_SIZE)
        if error:
            return error
        block_size = _block_size
    if num_inst:
        _num_inst, error = bounded_int(num_inst, "num_inst", 1, ANGR_MAX_NUM_INST)
        if error:
            return error
        num_inst = _num_inst

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

@mcp.tool()
def angr_compare_decompilers(
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
    binary_path, pcode_language = resolve_angr_defaults(binary_path, pcode_language)
    missing = require_binary_path(binary_path)
    if missing:
        return missing
    _max_functions, error = bounded_int(max_functions, "max_functions", 1, ANGR_MAX_COMPARE_FUNCTIONS)
    if error:
        return error
    max_functions = _max_functions

    selected_addresses = split_addresses(addresses, max_functions)
    if not selected_addresses:
        return "No addresses provided"

    sections = []
    per_function_timeout = max(1, min(timeout_per_function, TIMEOUT_DECOMPILE_MAX))
    for address in selected_addresses:
        ghidra_output = "\n".join(safe_get(
            "decompile_function",
            {"address": address, "timeout": per_function_timeout},
            timeout=float(per_function_timeout),
        ))
        angr_args = ["--binary", binary_path, "--address", address]
        if rust:
            angr_args.append("--rust")
            if not run_rust_setup:
                angr_args.append("--skip-rust-setup")
        else:
            angr_args.append("--no-rust")
        if pcode_language:
            angr_args.extend(["--pcode-language", pcode_language])
        oxidizer_output = run_angr_helper(angr_args, per_function_timeout)
        sections.append(
            f"## {address}\n\n"
            f"### Ghidra\n{ghidra_output}\n\n"
            f"### angr/Oxidizer\n{oxidizer_output}"
        )

    return "\n\n".join(sections)

@mcp.tool()
def angryghidra_check_setup() -> str:
    """
    Check whether the optional AngryGhidra script is installed and callable.
    """
    script = find_angryghidra_script()
    if not script:
        return angryghidra_missing_message()
    python = os.environ.get("ANGRYGHIDRA_PYTHON") or os.environ.get("GHIDRA_MCP_ANGR_PYTHON") or default_angr_python()
    return f"AngryGhidra script: {script}\nPython: {python}"

@mcp.tool()
def angryghidra_symbolic_execute(
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
        program_info = parse_key_value_lines(safe_get("program_info"))
    if not binary_path:
        binary_path = program_info.get("executable_path", "")
    if not binary_path:
        return "No binary_path provided and Ghidra did not return an executable_path"
    if not base_address:
        base_address = program_info.get("min_address", "0x0")
    base_address = normalize_ghidra_address(base_address)
    find_address = normalize_ghidra_address(find_address)

    try:
        options = {
            "binary_file": binary_path,
            "base_address": base_address,
            "find_address": find_address,
            "auto_load_libs": auto_load_libs,
        }
        if start_address:
            options["blank_state"] = normalize_ghidra_address(start_address)
        if avoid_addresses:
            options["avoid_address"] = ",".join(
                normalize_ghidra_address(address)
                for address in avoid_addresses.split(",")
            )
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

@mcp.tool()
def decompile_by_addr(address: str, timeout: int = 120) -> str:
    """
    Decompile a function at the given address.

    Args:
        address: Function address in hex format (e.g. "0x1400010a0")
        timeout: Decompilation timeout in seconds (default: 120, max: 1800).
                 Increase for large/complex functions.
    """
    # Clamp timeout to valid range
    timeout = max(10, min(timeout, TIMEOUT_DECOMPILE_MAX))
    # Pass timeout both as a query parameter (so the Ghidra server honors it on
    # DecompInterface.decompileFunction) and as the HTTP read deadline (so the
    # bridge does not give up before the server can answer).
    return "\n".join(safe_get(
        "decompile_function",
        {"address": address, "timeout": timeout},
        timeout=float(timeout)))

@mcp.tool()
def decompile_function_async(address: str, timeout: int = 300) -> dict:
    """
    Start async decompilation of a function. Returns immediately with a task_id.
    Use get_task_status() to poll for completion, then get_task_result() to get output.
    
    Args:
        address: Function address in hex format (e.g. "0x1400010a0")
        timeout: Decompilation timeout in seconds (default: 300, max: 600)
    
    Returns:
        Dict with task_id and initial status
    """
    import json
    timeout = max(10, min(timeout, TIMEOUT_DECOMPILE_MAX))
    result = safe_get("decompile_async", {"address": address, "timeout": timeout}, timeout=10.0)
    try:
        return json.loads("\n".join(result))
    except:
        return {"error": "\n".join(result)}

@mcp.tool()
def get_task_status(task_id: str) -> dict:
    """
    Check the status of an async decompilation task.
    
    Args:
        task_id: Task ID from decompile_function_async()
    
    Returns:
        Dict with status, progress, elapsed_ms, and error (if failed)
    """
    import json
    result = safe_get("task_status", {"task_id": task_id}, timeout=5.0)
    try:
        return json.loads("\n".join(result))
    except:
        return {"error": "\n".join(result)}

@mcp.tool()
def get_task_result(task_id: str) -> str:
    """
    Get the result of a completed async decompilation task.
    
    Args:
        task_id: Task ID from decompile_function_async()
    
    Returns:
        Decompiled C code or error message
    """
    return "\n".join(safe_get("task_result", {"task_id": task_id}, timeout=10.0))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decomp_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disasm_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_func_by_addr(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_func_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_lvar_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def create_function(address: str, name: str = "") -> str:
    """
    Create a new function at the given entry address.

    Uses Ghidra's CreateFunctionCmd, so disassembly and body computation happen
    automatically (the same path as the "Create Function" UI action).

    Args:
        address: Entry-point address in hex (e.g. "0x1400010a0").
        name: Optional function name. If omitted, Ghidra assigns the default
              FUN_<addr> name.
    """
    data = {"address": address}
    if name:
        data["name"] = name
    return safe_post("create_function", data)

@mcp.tool()
def create_structure(name: str, size: int = 0) -> str:
    """
    Create a new structure data type in the program's data type manager.

    Args:
        name: Name for the new structure (must not collide with an existing type).
        size: Initial size in bytes. 0 (default) creates an empty structure that
              grows as fields are appended; a positive value reserves that many
              bytes up front (additional fields still grow the structure).
    """
    return safe_post("create_structure", {"name": name, "size": size})

@mcp.tool()
def add_structure_field(struct_name: str, field_name: str, field_type: str, offset: int = -1) -> str:
    """
    Add a field to an existing structure.

    Args:
        struct_name: Name of the existing structure to modify.
        field_name: Field name to assign.
        field_type: Field type. Accepts built-ins ("int", "uint", ...), existing
                    data type names ("MyStruct"), and pointer syntax
                    ("MyStruct *", "void **", or the Windows-style "PMyStruct").
        offset: Byte offset to insert at. -1 (default) appends to the end.
    """
    data = {
        "struct_name": struct_name,
        "field_name": field_name,
        "field_type": field_type,
    }
    if offset >= 0:
        data["offset"] = offset
    return safe_post("add_structure_field", data)

@mcp.tool()
def rename_structure(old_name: str, new_name: str) -> str:
    """
    Rename an existing structure data type.

    Args:
        old_name: Current structure name.
        new_name: New structure name. Must not collide with another data type.
    """
    return safe_post("rename_structure", {"old_name": old_name, "new_name": new_name})

@mcp.tool()
def delete_structure(name: str) -> str:
    """
    Delete a structure data type from the program's data type manager.

    References to the structure elsewhere in the program (struct fields, function
    parameters, local variables) will be replaced with undefined types.
    """
    return safe_post("delete_structure", {"name": name})

@mcp.tool()
def rename_structure_field(struct_name: str, old_field_name: str, new_field_name: str) -> str:
    """
    Rename a field in an existing structure.

    Args:
        struct_name: Name of the existing structure.
        old_field_name: Current field name. Default-generated names like "field_0x4"
                        are valid identifiers for unnamed fields.
        new_field_name: New field name. Must not collide with an existing field name
                        in the same structure.
    """
    return safe_post("rename_structure_field", {
        "struct_name": struct_name,
        "old_field_name": old_field_name,
        "new_field_name": new_field_name,
    })

@mcp.tool()
def set_field_type(struct_name: str, field_name: str, new_type: str, length: int = 0) -> str:
    """
    Change the data type of a structure field.

    If the new type is larger than the current field, subsequent components in
    the structure are absorbed; if smaller, the freed bytes become undefined.
    This is the right tool for collapsing several scalar slots into a single
    composite field (e.g. "convert four consecutive qwords into one Pubkey").

    Args:
        struct_name: Existing structure name.
        field_name: Field whose type should be replaced.
        new_type: New type. Accepts built-ins, existing data types, and pointer
                  syntax ("MyType *").
        length: Explicit byte length override. 0 (default) uses the type's
                natural length. Required for types with dynamic size.
    """
    data = {
        "struct_name": struct_name,
        "field_name": field_name,
        "new_type": new_type,
    }
    if length > 0:
        data["length"] = length
    return safe_post("set_field_type", data)

@mcp.tool()
def resize_structure_field(struct_name: str, field_name: str, new_length: int) -> str:
    """
    Change a field's length in bytes while preserving its data type.

    Growing absorbs subsequent components; shrinking turns the freed bytes into
    undefined slots.

    Args:
        struct_name: Existing structure name.
        field_name: Field to resize.
        new_length: New length in bytes (must be > 0).
    """
    return safe_post("resize_structure_field", {
        "struct_name": struct_name,
        "field_name": field_name,
        "new_length": new_length,
    })

@mcp.tool()
def delete_structure_field(struct_name: str, field_name: str) -> str:
    """
    Delete a field from an existing structure.

    Args:
        struct_name: Name of the existing structure.
        field_name: Field name to remove. Default-generated names like "field_0x4"
                    are valid identifiers for unnamed fields.
    """
    return safe_post("delete_structure_field", {
        "struct_name": struct_name,
        "field_name": field_name,
    })

@mcp.tool()
def create_structure_pointer(struct_name: str, pointer_name: str = "") -> str:
    """
    Register a pointer type for an existing structure.

    Args:
        struct_name: Name of the existing structure.
        pointer_name: Optional name for a typedef pointing at "<struct_name> *"
                      (e.g. "PMyStruct"). When empty, the bare "<struct_name> *"
                      pointer type is added to the data type manager.
    """
    data = {"struct_name": struct_name}
    if pointer_name:
        data["pointer_name"] = pointer_name
    return safe_post("create_structure_pointer", data)

@mcp.tool()
def list_structures(offset: int = 0, limit: int = 100) -> list:
    """
    List all structure data types defined in the program.
    """
    return safe_get("list_structures", {"offset": offset, "limit": limit})

@mcp.tool()
def get_structure(name: str) -> str:
    """
    Get the field layout of a structure by name.
    """
    return "\n".join(safe_get("get_structure", {"name": name}))

@mcp.tool()
def check_server_health() -> str:
    """
    Probe the GhidraMCP HTTP server's /health endpoint and summarize the
    response. Useful for diagnosing whether the Ghidra plugin is loaded and
    responding.
    """
    import json

    url = urljoin(ghidra_server_url, "health")
    try:
        response = get_http_client().get(url, timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            status = data.get("status", "UNKNOWN")
            if status == "OK":
                return (
                    f"OK - Server healthy\n"
                    f"Running: {data.get('server_running')}\n"
                    f"Watchdog: {data.get('watchdog_healthy')}\n"
                    f"Program: {data.get('program_loaded')}\n"
                    f"Uptime: {data.get('uptime_ms')}ms\n"
                    f"Last request: {data.get('last_request_ms_ago')}ms ago\n"
                    f"Port: {data.get('port')}"
                )
            return f"ERROR - Server unhealthy"
        return f"ERROR - Server returned status {response.status_code}"
    except Exception as e:
        return f"ERROR - Server unreachable: {str(e)}"

@mcp.tool()
def read_bytes(address: str, length: int = 32) -> str:
    """
    Read raw bytes from memory at the given address.

    Args:
        address: Starting address in hex (e.g. "0x00401000")
        length: Number of bytes to read (default: 32)

    Returns:
        Hex string of the bytes, space-separated (e.g. "55 8b ec ...")
    """
    return safe_get("read_bytes", {"address": address, "length": length})

@mcp.tool()
def write_bytes(address: str, bytes_hex: str) -> str:
    """
    Writes a sequence of bytes to the specified address in the program's memory.

    Args:
        address: Destination address (e.g., "0x140001000")
        bytes_hex: Sequence of space-separated bytes in hexadecimal format (e.g., "90 90 90 90")

    Returns:
        Result of the operation (e.g., "Bytes written successfully" or a detailed error)
    """
    return safe_post("write_bytes", {"address": address, "bytes": bytes_hex})

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()
