# Changelog — Mod Inspector Implementation

## [0.1.0] - 2026-10-31

### Initial MVP Delivery

#### Architecture & Design Decisions
1. **Separation from Upstream Clones**: Implemented as an independent Rust library and CLI in `development/mod-inspector/`. Upstream repositories under `repositories/*` remain strictly untouched per ecosystem governance rules.
2. **Library-First Core**: Created `horizon-inspector` as a clean, reusable library crate providing strongly-typed inspection models, with `horizon-inspect` as a CLI binary frontend. This enables future Hub ingestion worker pipelines and backend API services to consume inspection logic without CLI wrapper overhead.
3. **Security-First Model**:
   - Explicitly categorized package security tiers (`SandboxedContent`, `UnsandboxedNative`, `ConfigurationOnly`, `VisualShader`, `AssetOnly`).
   - Implemented mandatory security warnings for native mods (`.hnmod`), marking them as unsandboxed code running with full user OS privileges.
   - Enforced rejection of legacy WebAssembly components (`mod.wasm`) in `.hmod` content mods, reflecting Horizon's migration of code mods to native mixins.
4. **Resilient Archive Protection**:
   - Built in-memory ZipArchive validation defending against Zip-Slip path traversals (`..`), absolute paths, colon drive references, non-regular files, duplicate paths, and zip bomb expansion limits.
5. **Warning vs. Error Categorization**:
   - Packages with non-fatal issues (missing descriptions/authors, unpinned native hook API level, experimental capabilities) remain valid (`is_valid = true`) while generating structured warnings.
   - Fatal structural issues, security hazards, checksum mismatches, and syntax errors mark the package as invalid (`is_valid = false`).
6. **Integrity & Verification**:
   - Integrated streaming SHA-256 calculation and Minisign Ed25519 signature verification (`minisign-verify`).
   - Added validation against caller-specified `--expected-sha256` and `--expected-size`.
7. **Standards Compliance**:
   - Designed formal JSON Schema (`schema/inspection-report-v1.schema.json`) for machine-readable integration.
   - Provided formatted terminal output for human developer workflows.

#### Capabilities Implemented
- Content Mod (`.hmod`) manifest & content validation.
- Native Mod (`.hnmod`) bundle structure, pinned Horizon/Mixins revision validation, and hook API checks.
- Modpack (`.hpack`) dependency list and override checks.
- Shader Pack (`.hshader`) manifest and WGSL pipeline validation (`naga`).
- Resource Pack (`.zip`) `pack.mcmeta` and path validation.
- Automated test suite with 14 comprehensive unit and integration tests.

---

## Remaining Limitations & Recommended Next Steps

### Current Limitations
1. **Native Source Static Analysis**:
   - While the inspector validates that `.hnmod` archives contain only permitted Rust source files and pinned git revisions, it does not perform AST/pattern-based static analysis of Rust code (e.g. checking for suspicious syscalls, raw pointer manipulations, or network socket attempts).
2. **WASM Bytecode Decompilation**:
   - Legacy WASM files in `.hmod` are rejected on sight per current Horizon specifications. Detailed decompilation or export analysis is not performed.
3. **Loose Directory Inspection**:
   - Current implementation expects zipped package files. Unpacked directory workspaces (e.g. `assets/` and `data/` on disk before packaging) are not yet directly inspected without packaging.
4. **Remote Registry Index Cross-Verification**:
   - The inspector checks packages locally. It does not yet query live remote HTTP registries or revocation lists (`revoked.toml`) over the network (designed offline-first).

### Recommended Next Steps for Phase 2
1. **Directory / Workspace Inspection Mode**:
   - Add support for `horizon-inspect <dir>` to inspect source workspaces before building packages.
2. **Offline Revocation List Mirror**:
   - Add optional `--revocation-list <revoked.toml>` or embedded revocation cache to check against known taken-down hashes.
3. **Ecosystem API Integration**:
   - Package the `horizon-inspector` crate into a containerized ingestion microservice or Supabase Edge Function worker for the upcoming Horizon Hub mod upload pipeline.
4. **Developer Mod Toolkit Integration**:
   - Expose the inspector directly as a pre-commit check and `cargo-horizon-mod` companion workflow.
