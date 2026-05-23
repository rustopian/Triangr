# Changelog

All notable changes in this fork. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/spec/v2.0.0.html).

This is a fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP).
The "Unreleased" section accumulates changes since the upstream `v1-4` release
(commit `27f316f`).

## [1.6.0] - 2026-05-23

### Added
- **Optional angr/Oxidizer bridge support**: `angr_decompile_function` and
  `angr_check_setup` MCP tools call a packaged `angr_decompile.py` helper.
  The helper supports angr's Rust-oriented decompiler path and can load
  Solana/eBPF ELFs through angr's p-code engine.
- **Core angr symbolic path finding**: `angr_symbolic_find` can search for a
  path to a target branch/address, avoid addresses, and solve symbolic
  stdin/argv, memory regions, and registers without requiring AngryGhidra.
- **Optional AngryGhidra bridge support**: `angryghidra_check_setup` and
  `angryghidra_symbolic_execute` discover a local AngryGhidra install when
  present, but return a clear configuration error when it is absent. Existing
  Ghidra MCP tools do not require AngryGhidra.
- **`/program_info` Java endpoint and `get_program_info` MCP tool**: exposes
  current-program metadata such as executable path, language id, compiler spec,
  image base, and address range so optional external analyzers can default to
  the active Ghidra program.

### Changed
- The Python package now includes `angr_decompile.py` and exposes an optional
  `angr` extra instead of making angr a hard dependency for normal bridge use.

## [1.5.1] - 2026-05-21

Hardening pass driven by a post-merge review of every PR landed in 1.5.0,
plus the build pipeline fixes that surfaced when CI finally ran, plus the
first test coverage this project has ever had.

### Security
- **#12 `resolveDataType` input cap**: rejects type expressions longer
  than 512 chars. Closes a Ghidra-OOM DoS via huge array syntax like
  `char[2147483647][2147483647]`. The listener is localhost-only so
  this was never remotely exploitable, but it's tightened anyway.

### Fixed
- **#9 `pyproject.toml` deps no longer claim `requests`**: aligned to
  `httpx>=0.27,<1` + `tenacity>=8.2,<10` to match the script's imports.
  A `pip install` of 1.5.0 would have failed at first import.
- **#8 async-decompile lifecycle**: replaced `newCachedThreadPool` with
  a fixed-size pool (host CPUs, min 2) + named daemon `ThreadFactory`;
  capped the `asyncTasks` map at 256 entries with oldest-first eviction
  on submission; `dispose()` now `shutdownNow()` + `awaitTermination` +
  clears the map so plugin reloads don't leak threads.
- **#12 `add_structure_field` at-offset** refuses dynamic
  (length ≤ 0) types up front with a clear error instead of bubbling
  `IllegalArgumentException`.
- **#7 decompile timeout is now effective**: the `timeout` parameter on
  `decompile_by_addr` and `decompile_function_async` is plumbed through
  to `DecompInterface.decompileFunction(func, N, monitor)`. Previously
  only the HTTP socket honored it; the server gave up at the hardcoded
  30 s and the bridge kept the socket open silently.
- **#11 `write_bytes` preserves the write on disasm failure**: the byte
  write now commits in its own transaction; re-disassembly runs in a
  separate best-effort transaction so a flow-following failure no
  longer silently rolls back the patch. Added `WRITE_BYTES_MAX = 1 MiB`
  cap mirroring `READ_BYTES_MAX`.
- **Ghidra 11.3.2 compatibility for `DataTypeManager.remove`**: use the
  deprecated-in-12.x two-arg `remove(DataType, TaskMonitor)` form, since
  the single-arg `remove(DataType)` only exists in Ghidra 12.x. The CI
  matrix exposed this immediately.

### Build pipeline
- **`hatch-vcs` tag pattern accepts the `v` prefix**, so the release
  workflow can derive the version from `v1.5.1` (previously: "tag
  'v1.5.1' no version found" → wheel build aborted).
- **Build `assemble` step matches any pom version**, not just
  `*-SNAPSHOT.zip`. With the pom version bumped from `1.0-SNAPSHOT` to
  `1.5.1`, the Maven assembly produces `GhidraMCP-1.5.1.zip` and the
  old glob was missing it.

### Added
- **Tier 1 pytest contract tests for the Python bridge**
  (`tests/test_bridge.py`, 63 tests): every MCP tool the bridge exposes
  is exercised against a mocked Ghidra HTTP server (`pytest-httpx`).
  Tests assert the right endpoint, method, encoded params, and response
  parsing for listings, function accessors, decompile (sync + async),
  comments, renames, xrefs, structure CRUD, `create_function`, memory
  R/W, health, and error paths.
- **`python-tests` CI job** runs alongside the Maven matrix; pure
  Python, no Ghidra download, finishes in <15 s. The Maven matrix
  itself continues to build the plugin against Ghidra 11.3.2 and 12.0.4.

## [1.5.0] - 2026-05-21

### Added (this fork)
- **Structure data type CRUD over MCP**: `create_structure`, `rename_structure`,
  `delete_structure`, `list_structures`, `get_structure`, `add_structure_field`,
  `rename_structure_field`, `delete_structure_field`, `set_field_type`,
  `resize_structure_field`, `create_structure_pointer`.
- **`create_function`** endpoint: create a new function at an arbitrary entry
  address (delegates to Ghidra's `CreateFunctionCmd`).

### Fixed (this fork)
- `rename_structure` and `delete_structure` no longer hang: DataTypeManager
  mutations now run on the HTTP worker thread instead of being dispatched to the
  Swing EDT, avoiding a listener-chain deadlock observed during `setName` /
  `remove`.

### Integrated from upstream pull requests
- [#56](https://github.com/LaurieWired/GhidraMCP/pull/56) (@Vesemir):
  decompiler now respects `setRespectReadOnly(true)`, surfacing more constants
  to the LLM.
- [#57](https://github.com/LaurieWired/GhidraMCP/pull/57) (@Jegghins):
  `read_bytes` / `write_bytes` memory primitives, plus forced disassembly after
  writes so the listing doesn't show `??`. Hardened in a follow-up commit:
  `/read_bytes` length capped at 1 MiB; `/write_bytes` rejects empty bodies and
  invalid hex tokens with HTTP 400 rather than 500.
- [#67](https://github.com/LaurieWired/GhidraMCP/pull/67) (@roya41, partial):
  `resolveDataType` now delegates to Ghidra's built-in `DataTypeParser`, so
  field/parameter types accept full C-style syntax (`MyStruct *`, `int [16]`,
  function-pointer signatures, `uint32_t`/`dword` aliases, etc.).
- [#108](https://github.com/LaurieWired/GhidraMCP/pull/108) (@nightlark):
  `pyproject.toml` and a release-workflow that builds the Python wheel on
  tag-push. The publish-to-PyPI step is intentionally disabled in this fork
  (`if: false`) — the `ghidramcp` PyPI namespace belongs to upstream.
- [#110](https://github.com/LaurieWired/GhidraMCP/pull/110) (@blinkysc,
  partial): `rename_variable` now calls
  `HighFunctionDBUtil.commitLocalNamesToDatabase` first, so renames of
  decompiler-generated names like `uVar1` succeed on the first attempt.
- [#116](https://github.com/LaurieWired/GhidraMCP/pull/116) (@jeFF0Falltrades):
  eight long-named MCP tools shortened to fit OpenAI's 64-char tool-name limit
  (`get_function_by_address` → `get_func_by_addr`, etc.). **Breaking** for any
  caller relying on the old names.
- [#119](https://github.com/LaurieWired/GhidraMCP/pull/119) (@le-jordon):
  configurable bind host via a new tool option, defaulting to `127.0.0.1`.
  Subsumes the hardcoded-bind fix proposed in #126.
- [#121](https://github.com/LaurieWired/GhidraMCP/pull/121) (@jethac):
  Python bridge switched from `requests` to `httpx` with connection pooling
  and `tenacity` exponential-backoff retry.
- [#123](https://github.com/LaurieWired/GhidraMCP/pull/123) (@jethac):
  `decompile_by_addr` accepts a `timeout` parameter (capped at 1800 s).
- [#124](https://github.com/LaurieWired/GhidraMCP/pull/124) (@jethac):
  async decompilation — `decompile_function_async` / `get_task_status` /
  `get_task_result` MCP tools backed by `/decompile_async`, `/task_status`,
  `/task_result` endpoints. Server keeps an in-memory task registry keyed by
  UUID.
- [#132](https://github.com/LaurieWired/GhidraMCP/pull/132) (@ozymand-AI-s):
  CI now builds against a Ghidra version matrix (`11.3.2` + `12.0.4`); pom
  dependency versions and `extension.properties` follow suit. The version was
  bumped 12.0.3 → 12.0.4 in a follow-up commit to match the current release.
- [#149](https://github.com/LaurieWired/GhidraMCP/pull/149) (@daedalus):
  `/health` JSON endpoint + watchdog thread; `check_server_health()` MCP tool.

### Deferred upstream PRs
The following upstream PRs were evaluated and **not** merged in this release;
each has an open thread tracking it.
- [#67](https://github.com/LaurieWired/GhidraMCP/pull/67) (struct-management
  tools — duplicate of this fork's CRUD set; only the parser improvement was
  taken).
- [#110](https://github.com/LaurieWired/GhidraMCP/pull/110) (enum management +
  `apply_struct_at_address` — useful, scoped for a follow-up release).
- [#111](https://github.com/LaurieWired/GhidraMCP/pull/111) (LLM tool
  annotations — would only annotate a subset of current tools; needs a fresh
  pass covering everything added since).
- [#122](https://github.com/LaurieWired/GhidraMCP/pull/122) (multi-instance
  port scanning — threads a `target_binary` parameter through every tool;
  needs a rebase against current main).
- [#126](https://github.com/LaurieWired/GhidraMCP/pull/126) (hardcoded 127.0.0.1
  bind — subsumed by #119).
- [#139](https://github.com/LaurieWired/GhidraMCP/pull/139) (data-manipulation
  + batch ops — the data-manipulation subset is worth taking; scoped for a
  follow-up release).

### Maintenance
- Established fork identity: added `NOTICE`, fork banner in `README.md`,
  this `CHANGELOG.md`, and a fork version (`1.5.0`).
- Build/release CI workflows pulled in from #108 and #132.
