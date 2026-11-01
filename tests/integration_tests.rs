//! Automated tests for Horizon Mod Inspector.

use horizon_inspector::{
    DiagnosticCode, InspectorConfig, PackageKind, SecurityTier, SignatureInfo,
    inspect_package,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;

/// Helper to create a temp file with an explicit extension.
fn create_test_package_with_ext(ext: &str, entries: &[(&str, &[u8])]) -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("test_package.{}", ext));
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default();

    for (name, content) in entries {
        zip.start_file(*name, options).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap();
    // Persist file by forgetting the tempdir cleanup until test ends or using tempdir path
    let target = std::env::temp_dir().join(format!(
        "horizon_test_{}_{}.{}",
        std::process::id(),
        fastrand_u32(),
        ext
    ));
    std::fs::copy(&path, &target).unwrap();
    target
}

fn fastrand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    nanos
}

// -----------------------------------------------------------------------------
// 1. Existing sample fixtures test
// -----------------------------------------------------------------------------

#[test]
fn test_inspect_official_modpack() {
    let pack = Path::new("../../repositories/horizon/crates/horizon-mods/tests/index/cozy-1.0.0.hpack");
    assert!(pack.exists(), "Official cozy-1.0.0.hpack fixture exists");

    let report = inspect_package(pack, &InspectorConfig::default());
    assert_eq!(report.package_kind, PackageKind::Modpack);
    assert_eq!(report.security_tier, SecurityTier::ConfigurationOnly);
    assert!(report.is_valid);
    assert_eq!(report.identity.id.as_deref(), Some("cozy"));
    assert_eq!(report.identity.name.as_deref(), Some("Cozy"));
    assert_eq!(report.identity.version.as_deref(), Some("1.0.0"));
    assert_eq!(report.compatibility.game.as_deref(), Some("26.3"));
    assert_eq!(report.dependencies.len(), 1);
    assert_eq!(report.dependencies[0].id, "coords_hud");
}

#[test]
fn test_inspect_official_shader() {
    let shader = Path::new("../../repositories/horizon/crates/horizon-mods/tests/index/glow-1.0.0.hshader");
    assert!(shader.exists(), "Official glow-1.0.0.hshader fixture exists");

    let report = inspect_package(shader, &InspectorConfig::default());
    assert_eq!(report.package_kind, PackageKind::Shader);
    assert_eq!(report.security_tier, SecurityTier::VisualShader);
    assert!(report.is_valid);
    assert_eq!(report.identity.id.as_deref(), Some("glow"));
    assert_eq!(report.compatibility.api.as_deref(), Some("0.1"));
}

#[test]
fn test_inspect_official_wasm_hmod_rejected() {
    let hmod = Path::new("../../repositories/horizon/crates/horizon-mods/tests/index/coords_hud-0.1.0.hmod");
    assert!(hmod.exists());

    let report = inspect_package(hmod, &InspectorConfig::default());
    assert_eq!(report.package_kind, PackageKind::ContentMod);
    assert_eq!(report.security_tier, SecurityTier::SandboxedContent);
    assert!(!report.is_valid, "Legacy hmod with WASM must fail inspection");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::SEC_WASM_DISALLOWED),
        "Diagnostic SEC_WASM_DISALLOWED must be present"
    );
}

// -----------------------------------------------------------------------------
// 2. Valid Content Mod (.hmod) test
// -----------------------------------------------------------------------------

#[test]
fn test_inspect_valid_content_mod() {
    let manifest = r#"
id = "ruby_gems"
name = "Ruby Gems"
version = "1.0.0"
description = "Adds rare ruby minerals and gear"
authors = ["CGRLabs"]
api = "0.2"
capabilities = ["registries"]
"#;

    let block_json = r#"{
    "template": "minecraft:amethyst_block",
    "properties": {
        "hardness": 2.0,
        "light": 7
    }
}"#;

    let path = create_test_package_with_ext(
        "hmod",
        &[
            ("horizon-mod.toml", manifest.as_bytes()),
            ("data/ruby_gems/horizon/block/ruby_ore.json", block_json.as_bytes()),
        ],
    );


    let report = inspect_package(&path, &InspectorConfig::default());
    assert_eq!(report.package_kind, PackageKind::ContentMod);
    assert_eq!(report.security_tier, SecurityTier::SandboxedContent);
    assert!(report.is_valid, "Valid content mod must pass inspection");
    assert_eq!(report.identity.id.as_deref(), Some("ruby_gems"));
    assert_eq!(report.identity.version.as_deref(), Some("1.0.0"));
    assert_eq!(report.capabilities, vec!["registries"]);

    std::fs::remove_file(path).ok();
}

// -----------------------------------------------------------------------------
// 3. Valid Native Mod (.hnmod) test
// -----------------------------------------------------------------------------

#[test]
fn test_inspect_valid_native_mod() {
    let native_manifest = r#"{
    "schema": 1,
    "id": "fast_leaf",
    "version": "1.2.0",
    "game": "26.3",
    "horizon": "0123456789abcdef0123456789abcdef01234567",
    "mixins": "abcdef0123456789abcdef0123456789abcdef01",
    "hooks": 5
}"#;

    let mixin_toml = r#"
[mod]
id = "fast_leaf"
version = "1.2.0"

[compatibility]
horizon_revision = "0123456789abcdef0123456789abcdef01234567"
"#;

    let path = create_test_package_with_ext(
        "hnmod",
        &[
            ("horizon-native.json", native_manifest.as_bytes()),
            ("mixins/fast_leaf/horizon-mixin.toml", mixin_toml.as_bytes()),
            ("mixins/fast_leaf/src/lib.rs", b"// Native mixin implementation"),
        ],
    );


    let report = inspect_package(&path, &InspectorConfig::default());
    assert_eq!(report.package_kind, PackageKind::NativeMod);
    assert_eq!(report.security_tier, SecurityTier::UnsandboxedNative);
    assert!(report.is_valid, "Valid native mod must be syntactically valid");

    // Must emit the unsandboxed native security notice
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::SEC_UNSANDBOXED_NATIVE),
        "Native mod must emit SEC_UNSANDBOXED_NATIVE notice"
    );

    assert_eq!(report.compatibility.hooks_api, Some(5));
    assert_eq!(report.compatibility.game.as_deref(), Some("26.3"));

    std::fs::remove_file(path).ok();
}

// -----------------------------------------------------------------------------
// 4. Resource Pack (.zip) test
// -----------------------------------------------------------------------------

#[test]
fn test_inspect_resource_pack() {
    let pack_mcmeta = r#"{
    "pack": {
        "pack_format": 46,
        "description": "High definition skybox textures"
    }
}"#;

    let path = create_test_package_with_ext(
        "zip",
        &[
            ("pack.mcmeta", pack_mcmeta.as_bytes()),
            ("assets/minecraft/textures/environment/sun.png", b"PNG-DATA"),
        ],
    );


    let report = inspect_package(&path, &InspectorConfig::default());
    assert_eq!(report.package_kind, PackageKind::ResourcePack);
    assert_eq!(report.security_tier, SecurityTier::AssetOnly);
    assert!(report.is_valid);
    assert_eq!(report.compatibility.api.as_deref(), Some("46"));
    assert_eq!(
        report.identity.description.as_deref(),
        Some("High definition skybox textures")
    );

    std::fs::remove_file(path).ok();
}

// -----------------------------------------------------------------------------
// 5. Security & Malformed Archive Tests
// -----------------------------------------------------------------------------

#[test]
fn test_detects_zip_slip_path_traversal() {
    let path = create_test_package_with_ext(
        "hmod",
        &[
            ("horizon-mod.toml", b"id = \"test\"\nname = \"T\"\nversion = \"1.0.0\"\napi = \"0.2\"\ncapabilities = [\"registries\"]\n"),
            ("assets/../../../etc/passwd", b"malicious"),
        ],
    );


    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_ZIP_SLIP),
        "Zip-slip path traversal must be detected and flagged with ARCHIVE_ZIP_SLIP"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_detects_colon_paths() {
    let path = create_test_package_with_ext(
        "hmod",
        &[
            ("horizon-mod.toml", b"id = \"test\"\nname = \"T\"\nversion = \"1.0.0\"\napi = \"0.2\"\ncapabilities = [\"registries\"]\n"),
            ("C:/evil.txt", b"drive letter injection"),
        ],
    );


    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_INVALID_PATH),
        "Path with colon must be flagged as invalid"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_detects_missing_manifest() {
    let path = create_test_package_with_ext(
        "hmod",
        &[
            ("data/something.json", b"{}"),
        ],
    );


    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::MANIFEST_MISSING),
        "Missing manifest must produce MANIFEST_MISSING diagnostic"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_detects_invalid_mod_id() {
    let manifest = r#"
id = "Invalid-ID!"
name = "Bad ID Mod"
version = "1.0.0"
api = "0.2"
capabilities = ["registries"]
"#;

    let path = create_test_package_with_ext(
        "hmod",
        &[
            ("horizon-mod.toml", manifest.as_bytes()),
        ],
    );


    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::MANIFEST_INVALID_ID),
        "Uppercase/dash in ID must produce MANIFEST_INVALID_ID"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_detects_checksum_and_size_mismatch() {
    let pack = Path::new("../../repositories/horizon/crates/horizon-mods/tests/index/cozy-1.0.0.hpack");
    let mut config = InspectorConfig::default();
    config.expected_sha256 = Some("0000000000000000000000000000000000000000000000000000000000000000".to_string());
    config.expected_size = Some(999999);

    let report = inspect_package(pack, &config);
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::CHECKSUM_MISMATCH),
        "Checksum mismatch must be reported"
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::SIZE_MISMATCH),
        "Size mismatch must be reported"
    );
}

#[test]
fn test_signature_verification_success() {
    let hmod = Path::new("../../repositories/horizon/crates/horizon-mods/tests/index/coords_hud-0.1.0.hmod");
    let mut config = InspectorConfig::default();
    config.public_key = Some("RWTVtuGb/GRXcBf3Re5hzM07EzoStr2sLTJjghJia0xX15ULoZRFFZDb".to_string());

    let report = inspect_package(hmod, &config);
    match report.signature {
        SignatureInfo::Verified { ref public_key } => {
            assert_eq!(public_key, "RWTVtuGb/GRXcBf3Re5hzM07EzoStr2sLTJjghJia0xX15ULoZRFFZDb");
        }
        other => panic!("Expected verified signature, got {:?}", other),
    }
}

// -----------------------------------------------------------------------------
// 6. Additional Strict Mode & Diagnostic Tests
// -----------------------------------------------------------------------------

#[test]
fn test_unpinned_native_hooks_emits_warning() {
    let native_manifest = r#"{
    "schema": 1,
    "id": "tree_axe",
    "version": "1.0.0",
    "game": "26.3",
    "horizon": "0123456789abcdef0123456789abcdef01234567",
    "mixins": "abcdef0123456789abcdef0123456789abcdef01"
}"#;

    let mixin_toml = r#"
[mod]
id = "tree_axe"
version = "1.0.0"

[compatibility]
horizon_revision = "0123456789abcdef0123456789abcdef01234567"
"#;

    let path = create_test_package_with_ext(
        "hnmod",
        &[
            ("horizon-native.json", native_manifest.as_bytes()),
            ("mixins/tree_axe/horizon-mixin.toml", mixin_toml.as_bytes()),
            ("mixins/tree_axe/src/lib.rs", b"// source"),
        ],
    );


    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(report.is_valid, "Native mod without hooks is still valid (not error)");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::NATIVE_HOOKS_UNPINNED),
        "Native mod without hooks must emit NATIVE_HOOKS_UNPINNED warning"
    );
    assert_eq!(report.stats.warning_count, 2); // SEC_UNSANDBOXED_NATIVE + NATIVE_HOOKS_UNPINNED

    std::fs::remove_file(path).ok();
}

#[test]
fn test_report_json_serialization_roundtrip() {
    let pack = Path::new("../../repositories/horizon/crates/horizon-mods/tests/index/cozy-1.0.0.hpack");
    let report = inspect_package(pack, &InspectorConfig::default());

    let json = report.to_json().expect("Report serializes to JSON");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON is valid");

    assert_eq!(parsed["schema_version"], "1.0.0");
    assert_eq!(parsed["package_kind"], "modpack");
    assert_eq!(parsed["is_valid"], true);
    assert_eq!(parsed["file"]["file_name"], "cozy-1.0.0.hpack");
}

// -----------------------------------------------------------------------------
// 7. Audit Remediation Regression Tests
// -----------------------------------------------------------------------------

#[test]
fn test_detects_duplicate_archive_entries_without_overwriting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("duplicate.hmod");
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default();

    let manifest = r#"
id = "dup_test"
name = "Duplicate Test"
version = "1.0.0"
api = "0.2"
capabilities = ["registries"]
"#;

    zip.start_file("horizon-mod.toml", options).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();

    let name1 = "data/dup_test/horizon/block/file_alpha.json";
    let name2 = "data/dup_test/horizon/block/file_bravo.json";

    zip.start_file(name1, options).unwrap();
    zip.write_all(b"{\"template\":\"minecraft:stone\"}").unwrap();

    zip.start_file(name2, options).unwrap();
    zip.write_all(b"{\"template\":\"minecraft:dirt\"}").unwrap();

    zip.finish().unwrap();

    // Now replace name2 with name1 in raw bytes to create a valid zip with duplicate filenames
    let mut bytes = std::fs::read(&path).unwrap();
    let name1_bytes = name1.as_bytes();
    let name2_bytes = name2.as_bytes();
    assert_eq!(name1_bytes.len(), name2_bytes.len());

    let mut count = 0;
    for i in 0..=bytes.len().saturating_sub(name2_bytes.len()) {
        if &bytes[i..i + name2_bytes.len()] == name2_bytes {
            bytes[i..i + name2_bytes.len()].copy_from_slice(name1_bytes);
            count += 1;
        }
    }
    eprintln!("Replaced name2 occurrences: {}", count);
    assert!(count >= 2, "Replaced name2 in both local and central directory");
    std::fs::write(&path, &bytes).unwrap();


    let report = inspect_package(&path, &InspectorConfig::default());
    eprintln!("Report is_valid: {}, diags: {:?}", report.is_valid, report.diagnostics);
    assert!(!report.is_valid, "Archive with duplicate file entries must fail inspection");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_DUPLICATE_FILE),
        "Diagnostic ARCHIVE_DUPLICATE_FILE must be emitted"
    );
}

#[test]
fn test_decompression_bomb_rejected_at_archive_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bomb.hmod");
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(file);

    // Write a valid manifest
    let manifest = r#"
id = "bomb_test"
name = "Bomb Test"
version = "1.0.0"
api = "0.2"
capabilities = ["registries"]
"#;
    zip.start_file("horizon-mod.toml", SimpleFileOptions::default()).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();

    // Write 20 MiB of zeros using Deflate compression (exceeds content mod 16 MiB per-file limit)
    // 20 MiB of zeros will compress to ~20 KiB
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("data/bomb_test/horizon/block/huge.json", options).unwrap();
    let chunk = [b'0'; 64 * 1024];
    for _ in 0..(20 * 1024 * 1024 / chunk.len()) {
        zip.write_all(&chunk).unwrap();
    }
    zip.finish().unwrap();


    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid, "Archive exceeding per-file uncompressed limit must fail");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_FILE_TOO_LARGE
                || d.code == DiagnosticCode::ARCHIVE_EXPANSION_LIMIT),
        "Must emit ARCHIVE_FILE_TOO_LARGE or ARCHIVE_EXPANSION_LIMIT at archive boundary"
    );
}

#[test]
fn test_native_mod_entry_limit_512() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("too_many_entries.hnmod");
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default();

    let native_manifest = r#"{
    "schema": 1,
    "id": "bulk",
    "version": "1.0.0",
    "game": "26.3",
    "horizon": "0123456789abcdef0123456789abcdef01234567",
    "mixins": "abcdef0123456789abcdef0123456789abcdef01",
    "hooks": 1
}"#;
    zip.start_file("horizon-native.json", options).unwrap();
    zip.write_all(native_manifest.as_bytes()).unwrap();

    let mixin_toml = r#"
[mod]
id = "bulk"
version = "1.0.0"

[compatibility]
horizon_revision = "0123456789abcdef0123456789abcdef01234567"
"#;
    zip.start_file("mixins/bulk/horizon-mixin.toml", options).unwrap();
    zip.write_all(mixin_toml.as_bytes()).unwrap();

    // Create 513 total entries (exceeding native mod 512 entry limit from native.rs:77)
    for i in 2..514 {
        zip.start_file(format!("mixins/bulk/src/file_{i}.rs"), options).unwrap();
        zip.write_all(b"// code").unwrap();
    }
    zip.finish().unwrap();


    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_TOO_MANY_ENTRIES),
        "Native mod with >512 entries must be rejected with ARCHIVE_TOO_MANY_ENTRIES"
    );
}

#[test]
fn test_authoritative_target_hooks_api_validation() {
    let native_manifest = r#"{
    "schema": 1,
    "id": "hooks_test",
    "version": "1.0.0",
    "game": "26.3",
    "horizon": "0123456789abcdef0123456789abcdef01234567",
    "mixins": "abcdef0123456789abcdef0123456789abcdef01",
    "hooks": 5
}"#;

    let mixin_toml = r#"
[mod]
id = "hooks_test"
version = "1.0.0"

[compatibility]
horizon_revision = "0123456789abcdef0123456789abcdef01234567"
"#;

    let path = create_test_package_with_ext(
        "hnmod",
        &[
            ("horizon-native.json", native_manifest.as_bytes()),
            ("mixins/hooks_test/horizon-mixin.toml", mixin_toml.as_bytes()),
            ("mixins/hooks_test/src/lib.rs", b"// source"),
        ],
    );

    // 1. Compatible target: target hooks API 5 >= required 5
    let mut config_ok = InspectorConfig::default();
    config_ok.target_hooks_api = Some(5);
    let report_ok = inspect_package(&path, &config_ok);
    assert!(report_ok.is_valid);
    assert!(
        report_ok
            .diagnostics
            .iter()
            .any(|d| d.code == "NATIVE_HOOKS_DECLARED"),
        "Target API 5 satisfies required 5"
    );

    // 2. Incompatible target: target hooks API 4 < required 5
    let mut config_fail = InspectorConfig::default();
    config_fail.target_hooks_api = Some(4);
    let report_fail = inspect_package(&path, &config_fail);
    assert!(!report_fail.is_valid);
    assert!(
        report_fail
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::NATIVE_HOOKS_INCOMPATIBLE),
        "Target API 4 must reject required API 5 with NATIVE_HOOKS_INCOMPATIBLE"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_signature_tampered_rejected() {
    let hmod = Path::new("../../repositories/horizon/crates/horizon-mods/tests/index/coords_hud-0.1.0.hmod");
    let mut config = InspectorConfig::default();
    config.public_key = Some("RWTVtuGb/GRXcBf3Re5hzM07EzoStr2sLTJjghJia0xX15ULoZRFFZDb".to_string());

    // Create a tampered signature file
    let dir = tempfile::tempdir().unwrap();
    let tampered_sig_path = dir.path().join("tampered.minisig");
    std::fs::write(&tampered_sig_path, "untrusted comment: minisign signature\nRUQ=\ntrusted comment: timestamp:0\nAAAA\n").unwrap();

    config.signature_path = Some(tampered_sig_path);

    let report = inspect_package(hmod, &config);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::SIGNATURE_INVALID),
        "Tampered signature must produce SIGNATURE_INVALID"
    );
    assert!(matches!(report.signature, SignatureInfo::Invalid { .. }));
}

#[test]
fn test_signature_missing_when_key_supplied() {
    let pack = Path::new("../../repositories/horizon/crates/horizon-mods/tests/index/cozy-1.0.0.hpack");
    let mut config = InspectorConfig::default();
    // Provide a public key for cozy, which has no .minisig file
    config.public_key = Some("RWTVtuGb/GRXcBf3Re5hzM07EzoStr2sLTJjghJia0xX15ULoZRFFZDb".to_string());

    let report = inspect_package(pack, &config);
    assert!(matches!(report.signature, SignatureInfo::SignatureMissing { .. }));
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::SIGNATURE_FILE_MISSING)
    );
}

#[test]
fn test_empty_archive_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.hmod");
    let file = std::fs::File::create(&path).unwrap();
    let zip = zip::ZipWriter::new(file);
    zip.finish().unwrap();


    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_EMPTY),
        "Empty archive must produce ARCHIVE_EMPTY"
    );
}

#[test]
fn test_resource_pack_missing_pack_object() {
    let pack_mcmeta = r#"{
    "description": "missing pack object"
}"#;

    let path = create_test_package_with_ext(
        "zip",
        &[
            ("pack.mcmeta", pack_mcmeta.as_bytes()),
        ],
    );


    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::RESOURCE_PACK_META_INVALID)
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_invalid_public_key_format() {
    let hmod = Path::new("../../repositories/horizon/crates/horizon-mods/tests/index/coords_hud-0.1.0.hmod");
    let mut config = InspectorConfig::default();
    config.public_key = Some("!!!not-valid-base64!!!".to_string());

    let report = inspect_package(hmod, &config);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::SIGNATURE_KEY_MISSING),
        "Invalid public key base64 format must produce SIGNATURE_KEY_MISSING"
    );
    assert!(matches!(report.signature, SignatureInfo::Invalid { .. }));
}

#[test]
fn test_content_mod_missing_registries_capability_specific_code() {
    let manifest = r#"
id = "missing_cap"
name = "Missing Cap"
version = "1.0.0"
api = "0.2"
capabilities = []
"#;

    let path = create_test_package_with_ext(
        "hmod",
        &[
            ("horizon-mod.toml", manifest.as_bytes()),
            ("data/missing_cap/horizon/block/ore.json", b"{\"template\":\"minecraft:stone\"}"),
        ],
    );

    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::MANIFEST_CAPABILITY_MISMATCH),
        "Content mod missing registries capability must produce MANIFEST_CAPABILITY_MISMATCH"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_content_mod_allows_over_4096_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("many_content_entries.hmod");
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default();

    let manifest = r#"
id = "bulk_content"
name = "Bulk Content"
version = "1.0.0"
api = "0.2"
capabilities = ["registries"]
"#;
    zip.start_file("horizon-mod.toml", options).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();

    // Write 4100 entries (exceeds old generic 4096 cap, but within 65,536 content mod limit)
    for i in 0..4100 {
        zip.start_file(format!("assets/bulk_content/textures/item/icon_{i}.png"), options).unwrap();
        zip.write_all(b"PNG").unwrap();
    }
    zip.finish().unwrap();

    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_TOO_MANY_ENTRIES),
        "Content mod with 4100 entries must NOT be rejected by archive entry limit"
    );
    assert!(report.is_valid);
}
#[test]
fn test_signature_key_missing_when_signature_present() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unsigned.hmod");
    std::fs::write(&path, b"dummy").unwrap();

    // Create a signature file at the default location (<file>.minisig)
    let sig_path = path.with_extension(format!(
        "{}.minisig",
        path.extension().and_then(|s| s.to_str()).unwrap_or("")
    ));
    std::fs::write(&sig_path, "untrusted comment: ...\n").unwrap();

    let mut config = InspectorConfig::default();
    // No public key supplied
    config.signature_path = Some(sig_path.clone());

    let report = inspect_package(&path, &config);
    assert!(matches!(report.signature, SignatureInfo::KeyMissing { .. }));
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::SIGNATURE_KEY_MISSING),
        "SIGNATURE_KEY_MISSING must be emitted when signature present but no key"
    );

    std::fs::remove_file(path).ok();
    std::fs::remove_file(sig_path).ok();
}
#[test]
fn test_high_ratio_entry_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("highratio.hmod");
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(file);

    let manifest = r#"
id = "hr_test"
name = "High Ratio Test"
version = "1.0.0"
api = "0.2"
capabilities = ["registries"]
"#;
    zip.start_file("horizon-mod.toml", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();

    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("data/hr_test/horizon/block/huge.json", options).unwrap();
    let chunk = [0u8; 64 * 1024];
    for _ in 0..(12 * 1024 * 1024 / chunk.len()) {
        zip.write_all(&chunk).unwrap();
    }
    zip.finish().unwrap();

    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_EXPANSION_LIMIT),
        "High-ratio entry must be rejected with ARCHIVE_EXPANSION_LIMIT"
    );

    std::fs::remove_file(path).ok();
}
#[test]
fn test_malformed_eocd_emits_scan_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("truncated.hmod");
    // Build a valid zip then truncate last bytes to corrupt EOCD
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("horizon-mod.toml", options).unwrap();
    zip.write_all(b"id=\"x\"\n").unwrap();
    zip.finish().unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    // Truncate trailing bytes to break EOCD
    bytes.truncate(bytes.len().saturating_sub(10));
    std::fs::write(&path, &bytes).unwrap();

    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_DUPLICATE_SCAN_SKIPPED),
        "Malformed EOCD must emit ARCHIVE_DUPLICATE_SCAN_SKIPPED warning"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_content_mod_reserved_namespace_specific_code() {
    let manifest = r#"
id = "mymod"
name = "My Mod"
version = "1.0.0"
api = "0.2"
capabilities = ["registries"]
"#;

    let path = create_test_package_with_ext(
        "hmod",
        &[
            ("horizon-mod.toml", manifest.as_bytes()),
            ("data/minecraft/horizon/block/stone.json", b"{\"template\":\"minecraft:stone\"}"),
        ],
    );

    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::CONTENT_RESERVED_NAMESPACE),
        "Reserved/foreign namespace must produce CONTENT_RESERVED_NAMESPACE"
    );

    std::fs::remove_file(path).ok();
}
#[test]
fn test_shader_wgsl_over_limit_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bigshader.hshader");
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();

    // 300 KiB of zeros as a .wgsl file (exceeds 256 KiB WGSL cap)
    zip.start_file("shaders/big.wgsl", options).unwrap();
    let chunk = [0u8; 1024];
    for _ in 0..300 {
        zip.write_all(&chunk).unwrap();
    }
    zip.finish().unwrap();

    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_FILE_TOO_LARGE),
        "Oversized WGSL must be rejected at archive boundary"
    );

    std::fs::remove_file(path).ok();
}
#[test]
fn test_genuine_duplicate_central_entries_detected() {
    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFFFFFF;
        for &b in data {
            let mut c = crc ^ (b as u32);
            for _ in 0..8 {
                if c & 1 == 1 {
                    c = (c >> 1) ^ 0xEDB88320;
                } else {
                    c >>= 1;
                }
            }
            crc = c;
        }
        crc ^ 0xFFFFFFFF
    }

    let name = b"dup.txt";
    let data1 = b"first";
    let data2 = b"second";

    let mut buf: Vec<u8> = Vec::new();

    // Local header + data for entry 1
    let off1 = buf.len() as u32;
    buf.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    buf.extend_from_slice(&20u16.to_le_bytes()); // version
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u16.to_le_bytes()); // method stored
    buf.extend_from_slice(&0u16.to_le_bytes()); // time
    buf.extend_from_slice(&0u16.to_le_bytes()); // date
    buf.extend_from_slice(&crc32(data1).to_le_bytes());
    buf.extend_from_slice(&(data1.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(data1.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
    buf.extend_from_slice(name);
    buf.extend_from_slice(data1);

    // Local header + data for entry 2
    let off2 = buf.len() as u32;
    buf.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&crc32(data2).to_le_bytes());
    buf.extend_from_slice(&(data2.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(data2.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(name);
    buf.extend_from_slice(data2);

    // Central directory
    let cd_start = buf.len() as u32;
    // entry 1
    buf.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    buf.extend_from_slice(&20u16.to_le_bytes()); // version made by
    buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u16.to_le_bytes()); // method
    buf.extend_from_slice(&0u16.to_le_bytes()); // time
    buf.extend_from_slice(&0u16.to_le_bytes()); // date
    buf.extend_from_slice(&crc32(data1).to_le_bytes());
    buf.extend_from_slice(&(data1.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(data1.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk
    buf.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    buf.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    buf.extend_from_slice(&off1.to_le_bytes());
    buf.extend_from_slice(name);

    // entry 2 (same name)
    buf.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&crc32(data2).to_le_bytes());
    buf.extend_from_slice(&(data2.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(data2.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&off2.to_le_bytes());
    buf.extend_from_slice(name);

    let cd_size = (buf.len() as u32) - cd_start;
    let total_entries: u16 = 2;

    // EOCD
    buf.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk
    buf.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    buf.extend_from_slice(&total_entries.to_le_bytes());
    buf.extend_from_slice(&total_entries.to_le_bytes());
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_start.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment len

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dup.hmod");
    std::fs::write(&path, &buf).unwrap();

    let report = inspect_package(&path, &InspectorConfig::default());
    assert!(!report.is_valid, "duplicate central entries must fail");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::ARCHIVE_DUPLICATE_FILE),
        "ARCHIVE_DUPLICATE_FILE must be emitted for genuine duplicate central entries"
    );

    std::fs::remove_file(path).ok();
}
