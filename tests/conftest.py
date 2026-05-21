"""
Test harness for the GhidraMCP Python bridge.

The bridge is a single-file script (`bridge_mcp_ghidra.py`) at the repo root,
not an installable package. We load it as a module here so tests can call its
MCP tool functions directly.

The bridge keeps a module-level `_http_client` singleton; we reset it before
every test so each test starts with a fresh httpx Client whose transport
pytest-httpx can intercept cleanly.
"""

import importlib.util
import pathlib
import sys

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_BRIDGE_PATH = _REPO_ROOT / "bridge_mcp_ghidra.py"


def _load_bridge():
    spec = importlib.util.spec_from_file_location("bridge", _BRIDGE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["bridge"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def bridge_module():
    """Module-scoped: load once."""
    return _load_bridge()


@pytest.fixture(autouse=True)
def _reset_http_client(bridge_module):
    """
    Per-test: clear the cached singleton so pytest-httpx intercepts cleanly.
    """
    bridge_module._http_client = None
    yield
    if bridge_module._http_client is not None:
        try:
            bridge_module._http_client.close()
        except Exception:
            pass
        bridge_module._http_client = None
