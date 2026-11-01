# Horizon Mod Inspector (`horizon-inspector`)

CGRLabs Horizon Ecosystem — Phase 1 Implementation

Independent package inspection, validation, and security analysis engine for the Horizon game ecosystem (Rust rewrite of Minecraft Java Edition 26.3).

---

## 1. Capabilities

- **Offline-First & Standalone**: Operates locally without external network dependencies.
- **Multi-Format Support**:
  - Content Mods (`.hmod`)
  - Native Mods (`.hnmod`)
  - Modpacks (`.hpack`)
  - Horizon Shaders (`.hshader`)
  - Minecraft Resource Packs (`.zip`)
- **Zero Code Execution**: Statically inspects package structure, manifests, and metadata. Never loads or executes mod code during inspection.
- **Security Tier Classification**:
  - Explicitly tags native mods (`.hnmod`) as **unsandboxed executable code** running with full OS account permissions.
  - Verifies content mods (`.hmod`) are purely sandboxed data/assets, rejecting discontinued WebAssembly binaries (`mod.wasm`).
- **Archive Defense**:
  - Defends against Zip-Slip path traversal attacks (`..`, absolute paths, colon drives).
  - Enforces entry count and expansion limits (prevents zip bomb attacks).
  - Verifies unique paths and safe archive permissions.
- **Integrity & Authenticity**:
  - Real-time SHA-256 calculation and file size verification.
  - Optional Minisign Ed25519 signature verification (`--key` and `--signature`).
  - Expected checksum and size matching (`--expected-sha256`, `--expected-size`).
- **Clear Error vs. Warning Distinction**:
  - Errors mark packages as invalid (syntax errors, security violations, missing manifests, path traversal).
  - Warnings highlight non-fatal quality issues (missing description/authors, unpinned native hook API level, experimental capabilities).
- **Dual Reporting**:
  - Formatted human-readable terminal output.
  - Machine-readable JSON output conforming to formal JSON Schema.

---

## 2. Install

```sh
git clone https://github.com/CGRLabs/horizon-inspector.git
cd horizon-inspector
cargo build --release
```

Binary: `horizon-inspect` (at `target/release/horizon-inspect`)

## 3. CLI Usage

```bash
# Basic inspection of any supported package
horizon-inspect <package-file>

# Machine-readable JSON report
horizon-inspect <package-file> --json

# Verify with expected SHA-256 checksum
horizon-inspect <package-file> --expected-sha256 <hex64>

# Verify Minisign signature against a public key
horizon-inspect <package-file> --key <base64-public-key>

# Provide custom signature path
horizon-inspect <package-file> --key <base64-key> --signature <file.minisig>

# Strict validation mode (warnings fail the exit code)
horizon-inspect <package-file> --strict

# Cross-validate native mod against an authoritative target Horizon hooks API level
horizon-inspect <native-mod.hnmod> --target-hooks-api <level>

# Override archive limits
horizon-inspect <package-file> --max-entries <count> --max-uncompressed <bytes>

# Override package kind detection
horizon-inspect <file> --kind content-mod
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Package is valid (0 errors). If `--strict` was specified, 0 warnings. |
| `1` | Package failed validation (one or more errors, or warnings under `--strict`). |
| `2` | CLI argument error or target file could not be read from disk. |

---

## 4. AI Agent Usage

This CLI is designed to be easy for AI agents to call programmatically:

- All commands return clear exit codes (`0` = valid, `1` = validation failure, `2` = tool error)
- Use `--json` for machine-readable output from `inspect`
- Exit codes make it easy to gate CI pipelines or agent workflows

Example AI agent workflow:

```sh
# 1. Inspect a mod package
horizon-inspect some_mod.hmod --json > inspection.json

# 2. Check exit code
if [ $? -eq 0 ]; then
  echo "Mod passed inspection"
else
  echo "Mod failed inspection"
fi
```

---

## 5. Library Usage

Add `horizon-inspector` as a dependency in your Rust backend or CLI project:

```toml
[dependencies]
horizon-inspector = { path = "development/mod-inspector" }
```

### Example: Inspecting in Rust

```rust
use horizon_inspector::{inspect_package, InspectorConfig, PackageKind, Severity};
use std::path::Path;

fn main() {
    let path = Path::new("cozy-1.0.0.hpack");
    let mut config = InspectorConfig::default();
    config.expected_sha256 = Some("241ac840f9c5ea3f6252d849da10c90d36cb1da4d6cd8d1d268c2760a353cd65".into());

    let report = inspect_package(path, &config);

    if report.is_valid {
        println!("Package {} is valid!", report.file.file_name);
        println!("Security tier: {:?}", report.security_tier);
    } else {
        eprintln!("Package failed validation:");
        for diag in report.diagnostics.iter().filter(|d| d.severity == Severity::Error) {
            eprintln!("  [{}] {}", diag.code, diag.message);
        }
    }
}
```

---

## 4. Diagnostics & Error Codes

| Code | Severity | Description |
|------|----------|-------------|
| `SEC_UNSANDBOXED_NATIVE` | Warning | Notice that native mod contains unsandboxed executable code. |
| `SEC_WASM_DISALLOWED` | Error | Legacy WebAssembly `mod.wasm` detected in content mod. |
| `ARCHIVE_ZIP_SLIP` | Error | Path traversal element (`..`) detected in archive entry. |
| `ARCHIVE_INVALID_PATH` | Error | Absolute path, backslash, colon, or illegal character in entry. |
| `ARCHIVE_EXPANSION_LIMIT`| Error | Archive expansion exceeds safe threshold (256 MiB). |
| `ARCHIVE_CORRUPTED` | Error | File is not a valid ZIP/Horizon archive or entry unreadable. |
| `ARCHIVE_DUPLICATE_SCAN_SKIPPED` | Warning | Raw duplicate-entry scan could not parse central directory; detection skipped. |
| `MANIFEST_MISSING` | Error | Required manifest (`horizon-mod.toml`, `horizon-native.json`, etc.) missing. |
| `MANIFEST_INVALID_ID` | Error | Mod ID does not conform to `[a-z0-9_]{1,64}`. |
| `MANIFEST_SYNTAX_ERROR` | Error | TOML or JSON parsing syntax error. |
| `NATIVE_REVISION_INVALID`| Error | Git commit hash for Horizon or Mixins is not 40 lowercase hex characters. |
| `NATIVE_HOOKS_UNPINNED` | Warning | Native mod lacks stable `hooks` API level; pinned to single commit. |
| `CHECKSUM_MISMATCH` | Error | Computed SHA-256 does not match `--expected-sha256`. |
| `SIZE_MISMATCH` | Error | File size does not match `--expected-size`. |
| `SIGNATURE_INVALID` | Error | Minisign signature failed cryptographic verification against public key. |
| `QUALITY_MISSING_DESCRIPTION` | Warning | Optional description is empty or missing. |
| `QUALITY_MISSING_AUTHORS` | Warning | No authors specified in manifest. |

## Notes

- The compressed archive size cap (max_archive_size) is an ingest policy, not an upstream Horizon specification limit; upstream enforces uncompressed totals only. Configurable via InspectorConfig::custom_limits or CLI overrides.
- DEFAULT_TARGET_HOOKS_API = 40 is exposed (upstream NATIVE_HOOKS_API) as a documented default; runtime behavior still requires explicit --target-hooks-api to enforce.

