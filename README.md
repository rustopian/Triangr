# Triangr

**angr/Oxidizer decompilation + Ghidra project context + AI analysis**

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

Sample supported tasks:

- "Summarize the loaded binary and list all entrypoints, public and hidden."
- "Decompile auth check functions in Ghidra and Oxidizer and make a Rust prototype."
- "Find paths that can reach this address and explain the constraints."
- "Make the code more readable analyzing and naming the 10 most common structures."

## MCP

Triangr works with Claude Code, Codex, Claude Desktop, Cline, 5ire, and other
MCP-capable AI tools.

## Ghidra Capabilities

Triangr exposes the Ghidra project as structured AI tool context:

- List and search functions, classes, imports, exports, strings, data, and xrefs.
- Decompile and disassemble by function or address, including async
  decompilation with task polling and configurable timeouts for large functions.
- Rename functions and local variables, set function prototypes, set local
  variable types, and preserve first-attempt variable rename reliability.
- Create, list, inspect, edit, and apply structures and enums using Ghidra's
  built-in data type parser for complex C-style type expressions.
- Read bytes, write bytes, create functions, and force re-disassembly after
  patches where possible.
- Set disassembly and decompiler comments, including preview-token guarded
  overwrite flows so agents see the current comment and pending replacement
  before applying destructive annotation writes.
- Check bridge health and watchdog status during long analysis sessions.

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

## Install Script

### Prerequisites

The installer supports Linux, WSL2, and macOS. It can install common packages
when a supported package manager is available:

- Linux: `apt`, `dnf`, or `pacman`
- macOS: Homebrew
- WSL2: Linux package managers, with WSLg or another X server for the Ghidra GUI

If you skip package-manager installation, install these yourself first:
Python 3.10+, `git`, `curl` or `wget`, `unzip`, JDK 21, and Maven. For Ghidra
extension builds, the installer uses the required Gradle version, not system.

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
- Installs the bridge runtime dependencies, including angr/Oxidizer.
- Installs the current checkout into that environment.
- Builds the Triangr Ghidra extension when Maven is available, otherwise falls
  back to the latest release asset.
- Installs the extension into the downloaded Ghidra tree.
- Moves any existing extension folder aside with a `.old.<timestamp>` suffix
  before replacing it.
- Clones AngryGhidra when requested and builds it with a Ghidra-compatible
  Gradle, downloading that Gradle when needed.
- Writes `env.sh` with `GHIDRA_HOME`, `GHIDRA_MCP_ANGR_PYTHON`,
  `ANGRYGHIDRA_HOME`, `ANGRYGHIDRA_SCRIPT`, and related paths.
- Writes `bin/triangr-mcp`, a wrapper suitable for MCP client configs.

The script does not edit Claude, Codex, Cline, or other MCP client configs.

### Verification

After installation:

```bash
source ~/.local/share/triangr/env.sh
bridge_mcp_ghidra --help
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
4. Select the `GhidraMCP-<version>.zip` extension archive. The archive name is
   retained for compatibility during the Triangr rebrand.
5. Restart Ghidra.
6. Create or open a project, import a binary, and open it for analysis.
7. Make sure the Triangr plugin is enabled in `File` -> `Configure` ->
   `Developer`.
8. Optional: configure host and port under `Edit` -> `Tool Options` ->
   `Triangr HTTP Server`.

The Python MCP client can be installed from this repository:

```bash
pipx install git+https://github.com/rustopian/Triangr.git
uv tool install git+https://github.com/rustopian/Triangr.git
```

Or directly from a checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e .
```

## MCP Clients

Any MCP client should work with Triangr. If you used the installer, prefer the
generated wrapper at `~/.local/share/triangr/bin/triangr-mcp`. It loads the
right angr and AngryGhidra environment automatically.

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

### Cline

Run the MCP bridge over SSE:

```bash
bridge_mcp_ghidra --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

Or, with the installer wrapper:

```bash
~/.local/share/triangr/bin/triangr-mcp --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

Then add a remote server in Cline:

1. Server Name: `Triangr`
2. Server URL: `http://127.0.0.1:8081/sse`

### 5ire

Open 5ire and go to `Tools` -> `New`:

1. Tool Key: `triangr`
2. Name: `Triangr`
3. Command: `/Users/YOUR_USER/.local/share/triangr/bin/triangr-mcp`

Use `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py` instead if running from a
checkout.

## Building from Source

Copy the following files from your Ghidra directory to this project's `lib/`
directory:

- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`

Build with Maven:

```bash
mvn clean package assembly:single
```

The generated zip file includes the built Ghidra plugin and resources required
for Ghidra to recognize the extension:

- `lib/GhidraMCP.jar`, retained as the compatibility artifact name
- `extension.properties`
- `Module.manifest`
