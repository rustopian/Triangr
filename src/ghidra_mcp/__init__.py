"""MCP server for Ghidra."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ghidramcp")
except PackageNotFoundError:  # running from a source checkout that is not installed
    __version__ = "0.0"
