#!/usr/bin/env bash
set -euo pipefail

GHIDRA_VERSION="12.0.4"
GHIDRA_DATE="20260303"
GHIDRA_URL=""
GHIDRA_REPO="NationalSecurityAgency/ghidra"
FORK_REPO_URL="https://github.com/rustopian/GhidraMCP.git"
FORK_REPO_REF="main"
ANGRYGHIDRA_REPO="https://github.com/Nalen98/AngryGhidra.git"

PREFIX="${HOME}/.local/share/triangr"
REPO_DIR=""
INSTALL_DEPS="ask"
INSTALL_ANGRYGHIDRA="yes"
INSTALL_TRIANGR_EXTENSION="yes"
DRY_RUN="no"
YES="no"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd || pwd)"
SCRIPT_REPO_DIR=""
if [[ -f "${SCRIPT_DIR}/../bridge_mcp_ghidra.py" ]]; then
  SCRIPT_REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi

usage() {
  cat <<EOF
Usage: $0 [options]

Install Triangr prerequisites, Ghidra, the Triangr Ghidra extension,
Python bridge dependencies, angr/Oxidizer, and optional AngryGhidra.

Options:
  --prefix PATH            Install root. Default: ${PREFIX}
  --repo-dir PATH          Existing checkout to use
  --repo-url URL           Repo to clone when no checkout exists. Default: ${FORK_REPO_URL}
  --repo-ref REF           Git ref to clone. Default: ${FORK_REPO_REF}
  --ghidra-version X       Supported Ghidra version. Default: ${GHIDRA_VERSION}
  --ghidra-date YYYYMMDD   Ghidra build date. Default: ${GHIDRA_DATE}
  --ghidra-url URL         Override Ghidra release ZIP URL
  --install-deps           Install OS packages when a supported manager exists
  --no-install-deps        Do not install OS packages
  --no-extension           Skip installing the Triangr Ghidra extension
  --no-angryghidra         Skip cloning/building AngryGhidra
  --dry-run                Print the install plan without making changes
  -y, --yes                Non-interactive yes for prompts
  -h, --help               Show this help

Environment written to:
  ${PREFIX}/env.sh
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --repo-dir) REPO_DIR="$2"; shift 2 ;;
    --repo-url) FORK_REPO_URL="$2"; shift 2 ;;
    --repo-ref) FORK_REPO_REF="$2"; shift 2 ;;
    --ghidra-version) GHIDRA_VERSION="$2"; shift 2 ;;
    --ghidra-date) GHIDRA_DATE="$2"; shift 2 ;;
    --ghidra-url) GHIDRA_URL="$2"; shift 2 ;;
    --install-deps) INSTALL_DEPS="yes"; shift ;;
    --no-install-deps) INSTALL_DEPS="no"; shift ;;
    --no-extension) INSTALL_TRIANGR_EXTENSION="no"; shift ;;
    --no-angryghidra) INSTALL_ANGRYGHIDRA="no"; shift ;;
    --dry-run) DRY_RUN="yes"; shift ;;
    -y|--yes) YES="yes"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$REPO_DIR" ]]; then
  if [[ -n "$SCRIPT_REPO_DIR" ]]; then
    REPO_DIR="$SCRIPT_REPO_DIR"
  else
    REPO_DIR="$PREFIX/source/Triangr"
  fi
fi

GHIDRA_ZIP="ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
if [[ -z "$GHIDRA_URL" ]]; then
  GHIDRA_URL="https://github.com/${GHIDRA_REPO}/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}"
fi

confirm() {
  local prompt="$1"
  if [[ "$YES" == "yes" ]]; then
    return 0
  fi
  read -r -p "${prompt} [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]]
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

detect_os() {
  local uname_s
  uname_s="$(uname -s)"
  if [[ "$uname_s" == "Darwin" ]]; then
    echo "macos"
  elif [[ "$uname_s" == "Linux" ]]; then
    if grep -qi microsoft /proc/version 2>/dev/null; then
      echo "wsl2"
    else
      echo "linux"
    fi
  else
    echo "unsupported"
  fi
}

install_os_deps() {
  local os="$1"
  if [[ "$INSTALL_DEPS" == "ask" ]] && ! confirm "Install common prerequisites with the system package manager?"; then
    INSTALL_DEPS="no"
  fi
  [[ "$INSTALL_DEPS" == "yes" ]] || return 0

  if [[ "$os" == "macos" ]]; then
    if ! need_cmd brew; then
      echo "Homebrew is not installed. Install Homebrew first or re-run with --no-install-deps." >&2
      return 1
    fi
    brew install python git curl unzip openjdk@21 maven gradle
  elif need_cmd apt-get; then
    run_sudo apt-get update
    run_sudo apt-get install -y python3 python3-venv python3-pip git curl unzip openjdk-21-jdk maven gradle build-essential
  elif need_cmd dnf; then
    run_sudo dnf install -y python3 python3-pip git curl unzip java-21-openjdk-devel maven gradle gcc gcc-c++ make
  elif need_cmd pacman; then
    run_sudo pacman -Sy --needed python python-pip git curl unzip jdk21-openjdk maven gradle base-devel
  else
    echo "No supported package manager found. Install Python 3.10+, git, curl, unzip, JDK 21, Maven, and Gradle manually." >&2
  fi
}

download() {
  local url="$1"
  local output="$2"
  if need_cmd curl; then
    curl -L --fail --retry 3 -o "$output" "$url"
  elif need_cmd wget; then
    wget -O "$output" "$url"
  else
    echo "curl or wget is required to download ${url}" >&2
    return 1
  fi
}

github_latest_asset_url() {
  local repo="$1"
  local pattern="$2"
  python3 - "$repo" "$pattern" <<'PY'
import json
import re
import sys
import urllib.request

repo, pattern = sys.argv[1], sys.argv[2]
url = f"https://api.github.com/repos/{repo}/releases/latest"
req = urllib.request.Request(url, headers={"User-Agent": "triangr-installer"})
with urllib.request.urlopen(req, timeout=30) as response:
    release = json.load(response)
for asset in release.get("assets", []):
    name = asset.get("name", "")
    if re.search(pattern, name):
        print(asset["browser_download_url"])
        break
else:
    raise SystemExit(f"No release asset matched {pattern!r} in {repo}")
PY
}

ensure_repo_checkout() {
  if [[ -f "$REPO_DIR/bridge_mcp_ghidra.py" ]]; then
    echo "Using Triangr checkout at $REPO_DIR"
    return 0
  fi

  if [[ -e "$REPO_DIR" ]]; then
    echo "$REPO_DIR exists but does not look like this MCP fork. Use --repo-dir or move it aside." >&2
    return 1
  fi

  mkdir -p "$(dirname "$REPO_DIR")"
  echo "Cloning Triangr source from $FORK_REPO_URL"
  git clone --depth 1 --branch "$FORK_REPO_REF" "$FORK_REPO_URL" "$REPO_DIR"
}

install_ghidra() {
  local tools_dir="$PREFIX/tools"
  local ghidra_dir="$tools_dir/ghidra_${GHIDRA_VERSION}_PUBLIC"
  local zip_path="$tools_dir/$GHIDRA_ZIP"
  mkdir -p "$tools_dir"

  if [[ -x "$ghidra_dir/ghidraRun" ]]; then
    echo "Ghidra already installed at $ghidra_dir"
    return 0
  fi

  echo "Downloading Ghidra ${GHIDRA_VERSION}"
  download "$GHIDRA_URL" "$zip_path"
  unzip -q "$zip_path" -d "$tools_dir"
}

install_python_env() {
  local venv="$PREFIX/venv"
  if [[ ! -x "$venv/bin/python" ]]; then
    python3 -m venv "$venv"
  fi
  "$venv/bin/python" -m pip install --upgrade pip wheel setuptools
  "$venv/bin/python" -m pip install -r "$REPO_DIR/requirements.txt"
  "$venv/bin/python" -m pip install -e "$REPO_DIR"
}

copy_ghidra_libs_for_build() {
  local ghidra_home="$PREFIX/tools/ghidra_${GHIDRA_VERSION}_PUBLIC"
  local libs=(
    "Features/Base/lib/Base.jar"
    "Features/Decompiler/lib/Decompiler.jar"
    "Framework/Docking/lib/Docking.jar"
    "Framework/Generic/lib/Generic.jar"
    "Framework/Project/lib/Project.jar"
    "Framework/SoftwareModeling/lib/SoftwareModeling.jar"
    "Framework/Utility/lib/Utility.jar"
    "Framework/Gui/lib/Gui.jar"
  )

  mkdir -p "$REPO_DIR/lib"
  for lib in "${libs[@]}"; do
    cp "$ghidra_home/Ghidra/$lib" "$REPO_DIR/lib/"
  done
}

find_extension_zip() {
  local search_root="$1"
  find "$search_root" -type f -name 'GhidraMCP-*.zip' | sort | tail -n 1
}

build_triangr_extension() {
  if ! need_cmd mvn; then
    return 1
  fi
  copy_ghidra_libs_for_build
  mvn -q -f "$REPO_DIR/pom.xml" clean package assembly:single
}

download_triangr_extension() {
  local downloads_dir="$PREFIX/downloads"
  local output="$downloads_dir/triangr-extension.zip"
  local asset_url
  mkdir -p "$downloads_dir"
  asset_url="$(github_latest_asset_url "rustopian/GhidraMCP" 'GhidraMCP.*\.zip$')"
  download "$asset_url" "$output"
  echo "$output"
}

install_extension_zip() {
  local zip_path="$1"
  local extension_dir_name="$2"
  local ghidra_home="$PREFIX/tools/ghidra_${GHIDRA_VERSION}_PUBLIC"
  local extensions_dir="$ghidra_home/Ghidra/Extensions"
  local dest="$extensions_dir/$extension_dir_name"
  local tmp="$PREFIX/tmp/install-${extension_dir_name}-$$"
  local source_dir=""
  local props_file=""
  local inner_zip=""

  rm -rf "$tmp"
  mkdir -p "$tmp" "$extensions_dir"
  unzip -q "$zip_path" -d "$tmp"

  if [[ -f "$tmp/$extension_dir_name/extension.properties" ]]; then
    source_dir="$tmp/$extension_dir_name"
  else
    props_file="$(find "$tmp" -type f -name extension.properties -print -quit || true)"
    if [[ -n "$props_file" ]]; then
      source_dir="$(dirname "$props_file")"
    fi
  fi

  if [[ -z "$source_dir" ]]; then
    inner_zip="$(find "$tmp" -type f -name '*.zip' -print -quit || true)"
    if [[ -n "$inner_zip" ]]; then
      rm -rf "$tmp/inner"
      mkdir -p "$tmp/inner"
      unzip -q "$inner_zip" -d "$tmp/inner"
      if [[ -f "$tmp/inner/$extension_dir_name/extension.properties" ]]; then
        source_dir="$tmp/inner/$extension_dir_name"
      else
        props_file="$(find "$tmp/inner" -type f -name extension.properties -print -quit || true)"
        if [[ -n "$props_file" ]]; then
          source_dir="$(dirname "$props_file")"
        fi
      fi
    fi
  fi

  if [[ -z "$source_dir" || ! -f "$source_dir/extension.properties" ]]; then
    echo "Could not find a Ghidra extension layout inside $zip_path" >&2
    return 1
  fi

  if [[ -e "$dest" ]]; then
    local backup="${dest}.old.$(date +%Y%m%d%H%M%S)"
    echo "Existing $extension_dir_name extension found. Moving it to $backup"
    mv "$dest" "$backup"
  fi

  cp -R "$source_dir" "$dest"
  echo "Installed $extension_dir_name extension into $dest"
}

install_triangr_extension() {
  [[ "$INSTALL_TRIANGR_EXTENSION" == "yes" ]] || return 0
  local zip_path=""

  echo "Building Triangr extension from this checkout"
  if build_triangr_extension; then
    zip_path="$(find_extension_zip "$REPO_DIR/target")"
  fi

  if [[ -z "$zip_path" ]]; then
    zip_path="$(find_extension_zip "$REPO_DIR/target" || true)"
  fi

  if [[ -z "$zip_path" ]]; then
    echo "No local extension ZIP found. Downloading the latest release asset."
    zip_path="$(download_triangr_extension)"
  fi

  install_extension_zip "$zip_path" "GhidraMCP"
}

install_angryghidra() {
  [[ "$INSTALL_ANGRYGHIDRA" == "yes" ]] || return 0
  local dest="$PREFIX/AngryGhidra"
  local ghidra_home="$PREFIX/tools/ghidra_${GHIDRA_VERSION}_PUBLIC"
  local zip_path=""

  if [[ -d "$dest/.git" ]]; then
    if [[ -z "$(git -C "$dest" status --short)" ]]; then
      git -C "$dest" pull --ff-only || echo "Could not fast-forward AngryGhidra. Leaving existing checkout in place." >&2
    else
      echo "AngryGhidra checkout has local changes. Leaving it untouched at $dest"
    fi
  else
    git clone "$ANGRYGHIDRA_REPO" "$dest"
  fi

  if ! need_cmd gradle; then
    echo "Gradle is not installed, so AngryGhidra was cloned but not built." >&2
    return 0
  fi

  echo "Building AngryGhidra extension"
  if (cd "$dest" && GHIDRA_INSTALL_DIR="$ghidra_home" gradle --quiet); then
    zip_path="$(find "$dest" -type f -name '*AngryGhidra*.zip' | sort | tail -n 1)"
    if [[ -n "$zip_path" ]]; then
      install_extension_zip "$zip_path" "AngryGhidra"
    else
      echo "AngryGhidra built, but no extension ZIP was found under $dest." >&2
    fi
  else
    echo "AngryGhidra build failed. The source checkout remains at $dest." >&2
  fi
}

write_env() {
  local env_file="$PREFIX/env.sh"
  local ghidra_home="$PREFIX/tools/ghidra_${GHIDRA_VERSION}_PUBLIC"
  mkdir -p "$PREFIX"
  cat > "$env_file" <<EOF
export TRIANGR_HOME="$PREFIX"
export GHIDRA_HOME="$ghidra_home"
export GHIDRA_INSTALL_DIR="$ghidra_home"
export GHIDRA_MCP_REPO="$REPO_DIR"
export GHIDRA_MCP_ANGR_PYTHON="$PREFIX/venv/bin/python"
export ANGRYGHIDRA_HOME="$PREFIX/AngryGhidra"
export ANGRYGHIDRA_SCRIPT="$PREFIX/AngryGhidra/angryghidra_script/angryghidra.py"
export ANGRYGHIDRA_PYTHON="$PREFIX/venv/bin/python"
export PATH="$PREFIX/venv/bin:$ghidra_home:\$PATH"
EOF
  echo "Wrote $env_file"
}

main() {
  local os
  os="$(detect_os)"
  if [[ "$os" == "unsupported" ]]; then
    echo "Unsupported OS: $(uname -s). This script supports Linux, WSL2, and macOS." >&2
    exit 1
  fi

  if [[ "$DRY_RUN" == "yes" ]]; then
    cat <<EOF
Triangr installer dry run
  os: $os
  prefix: $PREFIX
  repo dir: $REPO_DIR
  repo url: $FORK_REPO_URL
  repo ref: $FORK_REPO_REF
  ghidra url: $GHIDRA_URL
  install deps: $INSTALL_DEPS
  install Triangr extension: $INSTALL_TRIANGR_EXTENSION
  install AngryGhidra: $INSTALL_ANGRYGHIDRA
EOF
    exit 0
  fi

  mkdir -p "$PREFIX"
  install_os_deps "$os"
  ensure_repo_checkout
  install_ghidra
  install_python_env
  install_triangr_extension
  install_angryghidra
  write_env

  cat <<EOF

Triangr local environment is ready.

Next steps:
  source "$PREFIX/env.sh"
  "$PREFIX/tools/ghidra_${GHIDRA_VERSION}_PUBLIC/ghidraRun"

In Ghidra:
  1. Restart Ghidra if it was already open.
  2. Open a program in CodeBrowser.
  3. Enable the Triangr plugin under File -> Configure -> Developer.
  4. Enable AngryGhidra under File -> Configure -> Miscellaneous if you want its UI.

MCP bridge:
  $REPO_DIR/bridge_mcp_ghidra.py

Useful environment:
  $PREFIX/env.sh
EOF
}

main "$@"
