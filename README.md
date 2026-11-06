# Triangr MCP
## Complete AI Binary Analysis and Reverse Engineering Plugin
## angr/Oxidizer decompilation + Ghidra project context + MCP

Triangr turns a binary into an agent-ready reverse engineering workbench.

Use it to analyze executables and smart contracts in depth, providing
tools that keep AI agents from wasting tokens and presenting unsubtantiated
guesses.

This is the maintained, hardened, feature-extended fork of
[LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP).
`Ghidra` keeps the project context, `angr` answers program-analysis questions,
and MCP lets AI tools drive the workflow.

Your agents can inspect binary, compare Ghidra & Oxidizer decompilation, trace how
to reach a branch, solve constraints at an address, lift blocks to VEX or AIL,
summarize CFGs and callgraphs, rename functions and variables, edit structures,
annotate paths, and patch bytes from the same MCP bridge.

Since structures, function and variable names, and annotations are made directly
into Ghidra projects, knowledge about the binary grows from one run to the next.
Triangr works with the Ghidra GUI or fully headless, with no GUI running.

This fork preserves credit for the original work, design, and naming by
LaurieWired. New endpoints, hardening, and incorporated pull requests are listed
in [CHANGELOG.md](CHANGELOG.md).

[![CI](https://github.com/rustopian/Triangr/actions/workflows/build.yml/badge.svg)](https://github.com/rustopian/Triangr/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/rustopian/Triangr?label=release)](https://github.com/rustopian/Triangr/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://github.com/rustopian/Triangr/blob/main/pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Quick Start

Install Triangr and its local toolchain:

```bash
git clone https://github.com/rustopian/Triangr.git triangr
cd triangr
./scripts/install.sh --install-deps --yes
```

Start Ghidra and enable the plugin:

```bash
source ~/.local/share/triangr/env.sh
"$GHIDRA_HOME/ghidraRun"
```

Create or open a Ghidra project, import a binary, and open it for analysis.
When the main analysis window appears, enable `Triangr` under `File` ->
`Configure` -> `Developer`. The plugin starts a localhost HTTP server at
`http://127.0.0.1:8080/`; verify it with:

```bash
curl http://127.0.0.1:8080/health
```

Add the MCP server to your AI tool's MCP JSON config, using the wrapper written
by the installer:

```json
{
  "mcpServers": {
    "triangr": {
      "command": "/ABSOLUTE/PATH/TO/.local/share/triangr/bin/triangr-mcp",
      "args": [
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Or skip the GUI and let Triangr import and analyze the binary itself (see
[Headless Mode](#headless-mode)):

```json
{
  "mcpServers": {
    "triangr": {
      "command": "/ABSOLUTE/PATH/TO/.local/share/triangr/bin/triangr-mcp",
      "args": ["--headless", "--binary", "/path/to/target", "--project", "/path/to/projects"]
    }
  }
}
```

Sample supported tasks:

- "Summarize the loaded binary and list all entrypoints, public and hidden."
- "Decompile auth check functions in Ghidra and Oxidizer and make a Rust prototype."
- "Find paths that can reach this address and explain the constraints."
- "Make the code more readable analyzing and naming the 10 most common structures."

## MCP

Triangr works with Claude Code, Codex, Claude Desktop, VS Code, Cline, 5ire, and
other MCP-capable AI tools.

Ghidra tools return structured JSON: list tools are paginated (`offset`/`limit`,
check `has_more`), and failures are MCP tool errors with a stable code such as
`[FUNCTION_NOT_FOUND]` or `[AMBIGUOUS_NAME]`. Addresses are hex strings, with or
without `0x`.

## Ghidra Capabilities

Triangr exposes the Ghidra project as structured AI tool context:

- Identify the program (format, language, compiler, image base, entry points,
  hashes), and list or filter functions, classes, namespaces, segments, imports,
  exports, strings, data, and xrefs.
- Walk the call graph one level at a time with callers and callees, including
  indirect calls through pointers.
- Decompile and disassemble by function or address, including async
  decompilation with task polling and configurable timeouts for large functions.
- Rename functions, data, and local variables, set function prototypes, set local
  variable types, and preserve first-attempt variable rename reliability.
- Create, list, inspect, and edit structures, and apply them as variable types,
  using Ghidra's built-in data type parser for complex C-style type expressions.
- Read memory (with unmapped gaps marked) or raw bytes, write bytes, create
  functions, and force re-disassembly after code patches.
- Read and set disassembly and decompiler comments, including preview-token guarded
  overwrite flows so agents see the current comment and pending replacement
  before applying destructive annotation writes.
- Check backend health, mode, uptime, and activity during long analysis sessions.

## angr/Oxidizer Capabilities

angr gives the bridge executable reasoning beyond static project inspection:

- Decompile functions through angr's Oxidizer decompiler and compare Oxidizer
  output against Ghidra decompiler output.
- Find symbolic paths to a target address, optionally avoiding addresses.
- Add JSON-described constraints at a found state and evaluate requested values.
- Check static reachability between addresses.
- Recover and summarize CFG and callgraph structure.
- Lift blocks to VEX or AIL for lower-level IR inspection.
- Use p-code support for targets such as eBPF, including Ghidra language
  inference when available.
- Use AngryGhidra when installed for compatible symbolic execution workflows,
  while falling back to the core angr helper when appropriate.

The angr tools need the optional `angr` extra (Python 3.12+), which the
installer includes.

## Headless Mode

`triangr-mcp --headless` (or `ghidra-mcp --headless`) imports and analyzes a
binary with [PyGhidra](https://pypi.org/project/pyghidra/), with no Ghidra GUI
running, and serves it through the same tools. GUI-only tools such as
`get_current_address` are hidden in this mode.

```bash
~/.local/share/triangr/bin/triangr-mcp --headless --binary /path/to/target --project ~/triangr-projects
```

- `--project DIR` keeps the Ghidra project between runs and saves changes on
  exit. Without it, a temporary project is used and changes are discarded.
- `--no-analyze`, `--language`, and `--compiler` control import and analysis;
  `--extension-jar` uses a specific `GhidraMCP.jar` instead of the installed
  extension.
- Headless mode needs Python 3.10–3.13, the `headless` extra (installed by the
  installer), the Triangr extension installed in Ghidra, and `GHIDRA_INSTALL_DIR`
  (set by the installer's `env.sh`).
- On macOS, build Ghidra's decompiler once with `support/gradle/gradlew buildNatives`
  from the Ghidra directory if your Ghidra build has no native decompiler for your
  platform.

## Install Script

### Prerequisites

The installer supports Linux, WSL2, and macOS. It can install common packages
when a supported package manager is available:

- Linux: `apt`, `dnf`, or `pacman`
- macOS: Homebrew
- WSL2: Linux package managers, with WSLg or another X server for the Ghidra GUI

If you skip package-manager installation, install these yourself first:
Python 3.10+ (3.12+ for angr), `git`, `curl` or `wget`, `unzip`, and JDK 21. For
Ghidra extension builds, the installer uses a Gradle version Ghidra supports,
downloading it when needed, and runs it on JDK 21.

### Using the Script

```bash
git clone https://github.com/rustopian/Triangr.git triangr
cd triangr
./scripts/install.sh
```

For a non-interactive install that also attempts system dependencies:

```bash
./scripts/install.sh --install-deps --yes
```

Useful options:

```bash
./scripts/install.sh --help
./scripts/install.sh --prefix ~/.local/share/triangr
./scripts/install.sh --no-angryghidra
./scripts/install.sh --no-extension
```

### What It Does

The script defaults to user-owned paths under `~/.local/share/triangr` and can
be re-run safely. It:

- Detects Linux, WSL2, or macOS.
- Prompts before using a package manager unless `--install-deps` or `--yes` is
  supplied.
- Downloads Ghidra 12.0.4 by default.
- Creates a dedicated Python virtual environment.
- Installs the bridge runtime dependencies, including angr/Oxidizer and PyGhidra.
- Installs the current checkout into that environment.
- Builds the Triangr Ghidra extension with Gradle, otherwise falls back to a
  release asset built for the same Ghidra version.
- Installs the extension into the downloaded Ghidra tree.
- Moves any existing extension folder aside with a `.old.<timestamp>` suffix
  before replacing it.
- Clones AngryGhidra when requested and builds it with a Ghidra-compatible
  Gradle, downloading that Gradle when needed.
- Writes `env.sh` with `GHIDRA_HOME`, `GHIDRA_INSTALL_DIR`,
  `GHIDRA_MCP_ANGR_PYTHON`, `ANGRYGHIDRA_HOME`, `ANGRYGHIDRA_SCRIPT`, and related
  paths.
- Writes `bin/triangr-mcp`, a wrapper suitable for MCP client configs.

The script does not edit Claude, Codex, Cline, or other MCP client configs.

### Verification

After installation:

```bash
source ~/.local/share/triangr/env.sh
ghidra-mcp --help
~/.local/share/triangr/bin/triangr-mcp --help
python -c "import angr; print(angr.__version__)"
"$GHIDRA_HOME/ghidraRun"
```

In Ghidra:

1. Restart Ghidra if it was already open.
2. Create or open a project, import a binary, and open it for analysis.
3. Enable the Triangr plugin under `File` -> `Configure` -> `Developer`.
4. Optional: enable AngryGhidra under `File` -> `Configure` -> `Miscellaneous`.
5. Check the bridge:

```bash
curl http://127.0.0.1:8080/health
```

## Manual Installation

Download the latest [release](https://github.com/rustopian/Triangr/releases)
from this repository. It contains the Ghidra plugin and Python MCP client.

1. Run Ghidra.
2. Select `File` -> `Install Extensions`.
3. Click the `+` button.
4. Select the `ghidra_<version>_PUBLIC_<date>_GhidraMCP.zip` extension archive
   that matches your Ghidra version. The `GhidraMCP` name is retained for
   compatibility with existing installs.
5. Restart Ghidra.
6. Create or open a project, import a binary, and open it for analysis.
7. Make sure the Triangr plugin is enabled in `File` -> `Configure` ->
   `Developer`.
8. Optional: configure host and port under `Edit` -> `Tool Options` ->
   `Triangr HTTP Server`. A host other than `127.0.0.1` exposes the program to
   the network without authentication.

The Python MCP client can be installed from this repository:

```bash
pipx install "ghidramcp[angr,headless] @ git+https://github.com/rustopian/Triangr.git"
uv tool install "ghidramcp[angr,headless] @ git+https://github.com/rustopian/Triangr.git"
```

Both install the `ghidra-mcp` command and the `bridge_mcp_ghidra` alias. Drop
the extras you do not need.

Or directly from a checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[angr,headless]"
```

## MCP Clients

Any MCP client should work with Triangr. If you used the installer, prefer the
generated wrapper at `~/.local/share/triangr/bin/triangr-mcp`. It loads the
right angr, AngryGhidra, and Ghidra environment automatically. The server IP and
port default to `127.0.0.1:8080` and should point at the target Ghidra instance.

### Claude Desktop

Go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` ->
`claude_desktop_config.json` and add:

```json
{
  "mcpServers": {
    "triangr": {
      "command": "/Users/YOUR_USER/.local/share/triangr/bin/triangr-mcp",
      "args": [
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

If you are running from a checkout rather than an installed console script, use:

```json
{
  "mcpServers": {
    "triangr": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

### Claude Code

```bash
claude mcp add triangr -- ~/.local/share/triangr/bin/triangr-mcp --ghidra-server http://127.0.0.1:8080/
```

### VS Code

Run `MCP: Add Server` from the Command Palette, or add the following to
`.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "triangr": {
      "type": "stdio",
      "command": "/Users/YOUR_USER/.local/share/triangr/bin/triangr-mcp",
      "args": ["--ghidra-server", "http://127.0.0.1:8080/"]
    }
  }
}
```

### Clients That Connect to a URL (Cline and Others)

Run the MCP server over Streamable HTTP:

```bash
~/.local/share/triangr/bin/triangr-mcp --transport streamable-http --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

Then add `http://127.0.0.1:8081/mcp` as a remote server in your client (in Cline:
Server Name `Triangr`, Server URL `http://127.0.0.1:8081/mcp`). The older
`--transport sse` (URL `http://127.0.0.1:8081/sse`) still works but is
deprecated.

### 5ire

Open 5ire and go to `Tools` -> `New`:

1. Tool Key: `triangr`
2. Name: `Triangr`
3. Command: `/Users/YOUR_USER/.local/share/triangr/bin/triangr-mcp`

Use `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py` instead if running from a
checkout.

## Building from Source

1. Set `GHIDRA_INSTALL_DIR` to your Ghidra directory (12.0.4 and 12.1.4 are tested).
2. Build the extension with Gradle on JDK 21:

```bash
cd extension && "$GHIDRA_INSTALL_DIR/support/gradle/gradlew" buildExtension
```

The generated zip in `extension/dist/` includes the built Ghidra plugin and the
resources Ghidra needs to recognize the extension:

- `lib/GhidraMCP.jar`, retained as the compatibility artifact name
- `extension.properties`
- `Module.manifest`

The Python MCP server runs from a checkout with `uv run ghidra-mcp` and is tested
with `uv run pytest`. With `GHIDRA_INSTALL_DIR` set and the extension built,
`uv run --extra headless pytest` also runs the end-to-end tests against a real
headless Ghidra.

## Repository Layout

- `extension/`: the Ghidra extension. `core/` holds the GUI-independent analysis
  services, `http/` the local backend server, and `gui/` and `headless/` the two
  ways a program is supplied. Triangr's additions live in `TriangrService`,
  `TriangrModel`, `TriangrRoutes`, and `AsyncDecompileTasks`.
- `src/ghidra_mcp/`: the Python MCP server. Triangr's tools live in
  `triangr_tools.py` and `angr_tools.py`; `helpers/angr_decompile.py` runs inside
  the angr Python environment.
- `scripts/install.sh`: the installer.
