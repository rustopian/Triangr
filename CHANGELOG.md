# Changelog

All notable changes in this fork. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/spec/v2.0.0.html).

This is a fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP).
The "Unreleased" section accumulates changes since the upstream `v1-4` release
(commit `27f316f`).

## [Unreleased]

### Added
- **Structure data type CRUD over MCP**: `create_structure`, `rename_structure`,
  `delete_structure`, `list_structures`, `get_structure`, `add_structure_field`,
  `rename_structure_field`, `delete_structure_field`, `set_field_type`,
  `resize_structure_field`, `create_structure_pointer`.
- **`create_function`** endpoint: create a new function at an arbitrary entry
  address (delegates to Ghidra's `CreateFunctionCmd`).
- `<TypeName> *` / `<TypeName>**` pointer syntax accepted by `resolveDataType`
  alongside the existing Windows-style `PXXX` form.

### Fixed
- `rename_structure` and `delete_structure` no longer hang: DataTypeManager
  mutations now run on the HTTP worker thread instead of being dispatched to the
  Swing EDT, avoiding a listener-chain deadlock observed during `setName` /
  `remove`.

### Maintenance
- Established fork identity: added `NOTICE`, fork banner in `README.md`,
  this `CHANGELOG.md`, and a fork version (`1.5.0`).
