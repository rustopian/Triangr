# Triangr

**angr/Oxidizer decompilation + Ghidra project context + AI analysis**

Triangr turns a live Ghidra project into an agent-ready reverse engineering
workbench. It is the maintained, hardened fork of
[LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP), expanded
from "LLM can ask Ghidra for decompiler text" into a three-way analysis loop:
Ghidra keeps the project context, angr answers program-analysis questions, and
MCP lets AI tools drive the workflow.

Use it to inspect a binary, compare Ghidra and Oxidizer decompilation, trace how
to reach a branch, solve constraints at an address, lift blocks to VEX or AIL,
summarize CFGs and callgraphs, rename functions and variables, edit structures,
annotate paths, and patch bytes from the same MCP bridge. Optional parts stay
optional: Ghidra-only workflows do not require angr, core angr workflows do not
require AngryGhidra, and missing optional components return clear setup errors
instead of breaking the bridge.

This fork preserves credit for the original work, design, and naming by
LaurieWired. New endpoints, hardening, and incorporated pull requests are listed
in [CHANGELOG.md](CHANGELOG.md).

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/rustopian/GhidraMCP)](https://github.com/rustopian/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/rustopian/GhidraMCP)](https://github.com/rustopian/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/rustopian/GhidraMCP)](https://github.com/rustopian/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/rustopian/GhidraMCP)](https://github.com/rustopian/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9

## MCP

Triangr is a Model Context Protocol server and Ghidra plugin. It works with MCP
clients that can launch a stdio server or connect to an SSE server, including
Claude Code, Codex, Claude Desktop, Cline, 5ire, and other MCP-capable AI tools.

The Python bridge entrypoint remains `bridge_mcp_ghidra` for compatibility. The
installer also creates `~/.local/share/triangr/bin/triangr-mcp`, a wrapper that
loads the Triangr environment before starting the bridge, so GUI MCP clients do
not need hand-written `ANGRYGHIDRA_PYTHON` paths. The bridge speaks MCP on one
side and Ghidra's local HTTP plugin on the other, defaulting to
`http://127.0.0.1:8080/`. The Ghidra plugin binds to localhost by default, has a
configurable host and port, exposes a `/health` endpoint, and supports both
interactive and long-running decompilation workflows.

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
- Use p-code support for targets such as Solana/eBPF, including Ghidra language
  inference when available.
- Use AngryGhidra when installed for compatible symbolic execution workflows,
  while falling back to the core angr helper when appropriate.

The bridge looks for angr through `GHIDRA_MCP_ANGR_PYTHON`, the default
installer venv at `~/.local/share/triangr/venv`, local virtual environments,
then the Python running the MCP bridge. AngryGhidra support is detected through
`ANGRYGHIDRA_SCRIPT`, `ANGRYGHIDRA_HOME`, the default installer checkout under
`~/.local/share/triangr/AngryGhidra`, or a sibling `AngryGhidra` checkout.

## Install Script

### Prerequisites

The installer supports Linux, WSL2, and macOS. It can install common packages
when a supported package manager is available:

- Linux: `apt`, `dnf`, or `pacman`
- macOS: Homebrew
- WSL2: Linux package managers, with WSLg or another X server for the Ghidra GUI

If you skip package-manager installation, install these yourself first:
Python 3.10+, `git`, `curl` or `wget`, `unzip`, JDK 21, and Maven. For Ghidra
extension builds, the installer uses the Gradle version required by the
downloaded Ghidra release rather than relying on an arbitrary system Gradle.

### Using It

```bash
git clone https://github.com/rustopian/GhidraMCP.git triangr
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
./scripts/install.sh --require-angryghidra-build
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
2. Open a program in CodeBrowser.
3. Enable the Triangr plugin under `File` -> `Configure` -> `Developer`.
4. Optional: enable AngryGhidra under `File` -> `Configure` -> `Miscellaneous`.
5. Check the bridge:

```bash
curl http://127.0.0.1:8080/health
```

## Manual Installation

Download the latest [release](https://github.com/rustopian/GhidraMCP/releases)
from this repository. It contains the Ghidra plugin and Python MCP client.

1. Run Ghidra.
2. Select `File` -> `Install Extensions`.
3. Click the `+` button.
4. Select the `GhidraMCP-<version>.zip` extension archive. The archive name is
   retained for compatibility during the Triangr rebrand.
5. Restart Ghidra.
6. Open a program in CodeBrowser.
7. Make sure the Triangr plugin is enabled in `File` -> `Configure` ->
   `Developer`.
8. Optional: configure host and port under `Edit` -> `Tool Options` ->
   `Triangr HTTP Server`.

The Python MCP client can be installed from this repository:

```bash
pipx install git+https://github.com/rustopian/GhidraMCP.git
uv tool install git+https://github.com/rustopian/GhidraMCP.git
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
