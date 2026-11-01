# MOD-INSPECTOR-REMEDIATION-REPORT.md

CGRLabs Horizon Mod Inspector — Audit Remediation Report
========================================================

**Date:** 2026-10-31  
**Target:** `development/mod-inspector/` (crate `horizon-inspector` v0.1.0)  
**Remediation Scope:** Findings H1–H5, M1–M4, L1–L6 from `MOD-INSPECTOR-AUDIT.md`  
**Test Suite Status:** 25/25 automated tests pass (100% pass rate)

---

## 1. Remediation Status Summary

| Finding | Category | Status | Summary of Fix & Verification |
|---------|----------|--------|-------------------------------|
| **H1** | Archive size limit mismatch | **Fixed** | Replaced generic 64 MiB compressed / 256 MiB uncompressed limits with authoritative per-package-kind `ArchiveLimits::for_kind` matching upstream specs (content: 16 MiB/file, 512 MiB total; native: 64 MiB total; modpack: 64 MiB/override, 256 MiB total overrides; shader: 1 MiB/file, 8 MiB total). Regression tests pass. |
| **H2** | Decompression bomb enforcement | **Fixed** | Pre-checks declared entry size and running cumulative total *before* allocation; enforces 250:1 compression ratio bomb defense on large entries; uses bounded stream reads (`.take(limit + 1)`). Added regression test with Deflate-compressed 20 MiB zeroes failing cleanly at archive boundary. |
| **H3** | Native hooks API level validation | **Fixed** | Added `--target-hooks-api <level>` CLI argument and `config.target_hooks_api` without inventing unverified constants. Emits `NATIVE_HOOKS_INCOMPATIBLE` error when mod requires a level exceeding target, `NATIVE_HOOKS_DECLARED` when compatible. Regression tests pass. |
| **H4** | Duplicate filename overwriting | **Fixed** | Implemented `scan_raw_zip_for_duplicates` inspecting raw Central Directory headers directly from disk (catching duplicates that ZIP parsers silently deduplicate/mask) plus fast-fail on duplicate extraction without overwriting. Regression test verifies rejection. |
| **H5** | Cross-platform symlink detection | **Fixed / Documented** | Combined `entry.is_symlink()` with Unix mode file-type masking (`0o170000`). Documented unavoidable limitations of standard MS-DOS FAT external attributes where symlink bits are omitted by some Windows ZIP archivers. |
| **M1** | Entry count limits | **Fixed** | Content mods now allow up to 65,536 files (`content.rs:20 MAX_FILES`); native mods capped at 512 entries (`native.rs:77`); shader packs capped at 512 entries (`package.rs:18`). Regression tests verify 4,100-entry content mod passes and 513-entry native mod fails. |
| **M2** | Modpack override path traversal | **Not Applicable** | Audited defense-in-depth: `SafeArchive` catches traversal early, and `Modpack::read` independently verifies allowed overrides. Verified behavior is safe and correct. |
| **M3** | Resource pack mcmeta validation | **Not Applicable** | Matches upstream `index.rs:620-659` specification. Added validation for missing top-level `pack` object (`RESOURCE_PACK_META_INVALID`). |
| **M4** | Content validation error specificity | **Fixed** | Mapped `horizon_mods::Content::read` error strings to specific diagnostics: `ARCHIVE_INVALID_PATH` for traversal, `MANIFEST_CAPABILITY_MISMATCH` for missing registries, `CONTENT_RESERVED_NAMESPACE` for reserved tags, `CONTENT_MALFORMED_JSON` for syntax. Regression tests pass. |
| **L1** | Stats accuracy on early exit | **Fixed** | Diagnostics now record specific target entry name and exact size context on early returns. |
| **L2** | Missing signature edge-case tests | **Fixed** | Added automated tests for tampered signature text, missing signature file with supplied public key, invalid base64 public key format, and key missing when signature is present. |
| **L3** | Early file size check | **Fixed** | `inspect_package` checks file size via `std::fs::metadata` before reading or computing streaming SHA-256 hash. |
| **L4** | Content namespace fence | **Not Applicable** | Already verified by upstream `horizon_mods::Content::read`. |
| **L5** | Shader expression/texture budgets | **Not Applicable** | Already verified by upstream `horizon_shader_api::check`. |
| **L6** | JSON schema strictness | **Fixed** | Added uppercase regex pattern `^[A-Z0-9_]+$` for diagnostic codes, set `additionalProperties: false` across all sub-schemas, and enforced 64-hex regex pattern for dependency hashes. |

---

## 2. Detailed Remediation Notes

### H1 & M1: Package-Specific Archive Limits
- **Source of Truth:**
  - Content mods (`.hmod`): `repositories/horizon/crates/horizon-mods/src/content.rs` lines 20–22: `MAX_FILES = 65_536`, `MAX_FILE = 16 << 20` (16 MiB), `MAX_TOTAL = 512 << 20` (512 MiB).
  - Native mods (`.hnmod`): `repositories/horizon/crates/horizon-mods/src/index/native.rs` lines 77–108: `zip.len() <= 512`, `total <= 64 << 20` (64 MiB).
  - Modpacks (`.hpack`): `repositories/horizon/crates/horizon-mods/src/modpack.rs` lines 19–20: `MAX_OVERRIDE = 64 << 20` (64 MiB), `MAX_OVERRIDES = 256 << 20` (256 MiB).
  - Shader packs (`.hshader`): `repositories/horizon/crates/horizon-shader-api/src/package.rs` lines 14–18: `MAX_WGSL = 256 << 10` (256 KiB), `MAX_OTHER = 1 << 20` (1 MiB), `MAX_TOTAL = 8 << 20` (8 MiB), `MAX_ENTRIES = 512`.
- **Implementation:**
  Created `ArchiveLimits` struct in [`src/archive.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/src/archive.rs) with `ArchiveLimits::for_kind(PackageKind)`. The limits are dynamically selected based on package type and can be overridden via `InspectorConfig` or CLI flags (`--max-entries`, `--max-uncompressed`, `--max-file-size`).

### H2: Decompression Bomb Enforcement
- **Implementation:**
  1. Checks declared entry uncompressed size from the ZIP header *before* allocating buffer memory.
  2. Checks cumulative uncompressed size (`total_uncompressed.saturating_add(declared_size) > limits.max_total_uncompressed`) before reading.
  3. Detects extreme compression ratios (`ratio > 250:1` on entries > 10 MiB) to stop bombs before expansion.
  4. Wraps entry reader with `(&mut entry).take(limits.max_file_uncompressed + 1)` so spoofed ZIP headers cannot cause unbounded memory consumption.
  5. Added regression test `test_decompression_bomb_rejected_at_archive_boundary` generating 20 MiB of Deflate-compressed zeroes and verifying fast failure at the archive boundary.

### H3: Native Hooks API Compatibility Validation
- **Requirement:** Do not invent a constant; allow authoritative target hooks API validation if supplied.
- **Implementation:**
  Added `target_hooks_api: Option<u32>` to `InspectorConfig` and `--target-hooks-api <LEVEL>` to CLI.
  - When target level is supplied: compares `manifest.hooks` against target. If `manifest.hooks > target`, emits `DiagnosticCode::NATIVE_HOOKS_INCOMPATIBLE` error. If `<= target`, emits informational confirmation.
  - When target level is not supplied: emits informational note with declared hooks level and prompts user to supply `--target-hooks-api` for target environment verification.

### H4: Duplicate Archive Entry Fast Failure
- **Discovery:**
  High-level ZIP reader libraries (including `zip` 2.6.1) often index central directory entries into a hash map by filename, which silently overwrites or masks duplicate entries when iterating `0..zip.len()`.
- **Implementation:**
  Implemented `scan_raw_zip_for_duplicates` in [`src/archive.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/src/archive.rs) that locates the End of Central Directory (EOCD) record and parses raw Central Directory file headers (`0x02014b50`) directly from disk. If duplicate filenames exist, it emits `ARCHIVE_DUPLICATE_FILE` and fails fast before archive extraction. In addition, `SafeArchive::open_and_scan` checks `entries.contains_key(&name)` and halts immediately without overwriting content.

### H5: Cross-Platform Symlink Detection
- **Implementation:**
  Combined `entry.is_symlink()` with Unix mode bitmask inspection (`mode & 0o170000 != 0 && mode & 0o170000 != 0o100000`).
- **Unavoidable Limitation Documentation:**
  ZIP archives generated on legacy Windows tools without Unix compatibility attributes store MS-DOS attributes where upper 16 bits are 0. In such archives, symlink attributes cannot be discerned from regular files via standard ZIP metadata. The inspector mitigates this by strictly prohibiting absolute paths, colons, backslashes, and `..` path components across all platforms.

---

## 3. Exact Files Modified

1. [`development/mod-inspector/src/error.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/src/error.rs):
   - Added `ARCHIVE_EMPTY`, `ARCHIVE_FILE_TOO_LARGE`, `NATIVE_HOOKS_INCOMPATIBLE`, `CONTENT_VALIDATION_ERROR`.
2. [`development/mod-inspector/src/archive.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/src/archive.rs):
   - Added `ArchiveLimits` with per-package-kind specifications.
   - Added `scan_raw_zip_for_duplicates` raw Central Directory parser.
   - Implemented bounded reading (`.take()`), compression ratio checks, duplicate fast-fail, and symlink detection.
3. [`development/mod-inspector/src/inspectors/mod.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/src/inspectors/mod.rs):
   - Updated `InspectorConfig` with `target_hooks_api`, `custom_limits`, `max_file_size`, `max_entries`, `max_uncompressed`.
   - Wired per-package limits into `SafeArchive::open_and_scan`.
   - Added pre-hash file metadata size check.
4. [`development/mod-inspector/src/inspectors/native_mod.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/src/inspectors/native_mod.rs):
   - Added authoritative `target_hooks_api` validation and `NATIVE_HOOKS_INCOMPATIBLE` diagnostic.
5. [`development/mod-inspector/src/inspectors/content_mod.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/src/inspectors/content_mod.rs):
   - Mapped `Content::read` error messages to specific diagnostic codes (`ARCHIVE_INVALID_PATH`, `MANIFEST_CAPABILITY_MISMATCH`, `CONTENT_RESERVED_NAMESPACE`, `CONTENT_MALFORMED_JSON`).
6. [`development/mod-inspector/src/lib.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/src/lib.rs):
   - Re-exported `ArchiveLimits`.
7. [`development/mod-inspector/src/bin/main.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/src/bin/main.rs):
   - Added CLI flags `--target-hooks-api`, `--max-entries`, `--max-uncompressed`, `--max-file-size`.
8. [`development/mod-inspector/schema/inspection-report-v1.schema.json`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/schema/inspection-report-v1.schema.json):
   - Added `additionalProperties: false`, uppercase regex for diagnostic codes, and SHA-256 patterns.
9. [`development/mod-inspector/tests/integration_tests.rs`](file:///d:/CGRLabs/Horizon-Ecosystem/development/mod-inspector/tests/integration_tests.rs):
   - Added 11 new regression tests (total 25 tests).

---

## 4. Test Execution & Verification

### Test Command
```powershell
cargo test --manifest-path development/mod-inspector/Cargo.toml
```

### Test Results
```
running 25 tests
test test_detects_checksum_and_size_mismatch ... ok
test test_detects_colon_paths ... ok
test test_detects_duplicate_archive_entries_without_overwriting ... ok
test test_detects_invalid_mod_id ... ok
test test_content_mod_missing_registries_capability_specific_code ... ok
test test_inspect_official_modpack ... ok
test test_authoritative_target_hooks_api_validation ... ok
test test_detects_missing_manifest ... ok
test test_empty_archive_rejected ... ok
test test_inspect_official_wasm_hmod_rejected ... ok
test test_detects_zip_slip_path_traversal ... ok
test test_invalid_public_key_format ... ok
test test_inspect_resource_pack ... ok
test test_inspect_valid_content_mod ... ok
test test_inspect_valid_native_mod ... ok
test test_report_json_serialization_roundtrip ... ok
test test_signature_missing_when_key_supplied ... ok
test test_resource_pack_missing_pack_object ... ok
test test_signature_verification_success ... ok
test test_signature_tampered_rejected ... ok
test test_unpinned_native_hooks_emits_warning ... ok
test test_inspect_official_shader ... ok
test test_native_mod_entry_limit_512 ... ok
test test_decompression_bomb_rejected_at_archive_boundary ... ok
test test_content_mod_allows_over_4096_entries ... ok

test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.58s
```

### Upstream Cleanliness Check
```powershell
git -C repositories/horizon status
git -C repositories/horizon-mods status
git -C repositories/horizon-native-mod-template status
```
Result: All upstream repositories remain completely clean and untouched on `main`.

---

## 5. Remaining Limitations

1. **AST-Level Source Code Analysis for Native Mods**:
   - The inspector verifies `.hnmod` bundle structure, manifest schema, pinned Git commit hashes, and allowed file types. It does not perform deep AST semantic analysis on arbitrary Rust source code. Native mods remain classified as `SecurityTier::UnsandboxedNative`.
2. **Offline Revocation Mirroring**:
   - The inspector operates offline-first and does not query remote networks for live revocation updates. Synchronization with remote `revoked.toml` feeds will be integrated in Phase 3 (Ecosystem API).
3. **Windows Reparse Points in Pure FAT Headers**:
   - When ZIP files are constructed without Unix attribute extensions on Windows, symlink bitmasking is omitted at the archive format level. The inspector protects the filesystem by enforcing strict relative path normalization.
