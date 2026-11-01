//! Tests for the inspector export formats (HTML, JSON, text) and the `--export` CLI flag.

use horizon_inspector::{
    InspectorConfig, PackageKind, SecurityTier, inspect_package,
};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// Build a valid content-mod `.hmod` archive and persist it in the system temp dir.
fn make_valid_hmod() -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export_test.hmod");
    let file = fs::File::create(&path).unwrap();
    let mut zip = zip::write::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    let manifest = r#"
id = "export_mod"
name = "Export Mod"
version = "2.0.0"
description = "A mod used for export tests"
authors = ["CGRLabs"]
api = "0.2"
capabilities = ["registries"]
"#;
    zip.start_file("horizon-mod.toml", options).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();
    zip.start_file("data/export_mod/horizon/block/ore.json", options).unwrap();
    zip.write_all(r#"{"template":"minecraft:stone"}"#.as_bytes()).unwrap();
    zip.finish().unwrap();

    // Persist beyond the tempdir lifetime (mirrors create_test_package_with_ext).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let target = std::env::temp_dir().join(format!("horizon_export_test_{}_{}.hmod", std::process::id(), nanos));
    fs::copy(&path, &target).unwrap();
    target
}

#[test]
fn test_to_html_contains_key_fields() {
    let path = make_valid_hmod();
    let file_name = path.file_name().unwrap().to_str().unwrap();
    let report = inspect_package(&path, &InspectorConfig::default());
    assert_eq!(report.package_kind, PackageKind::ContentMod);
    assert_eq!(report.security_tier, SecurityTier::SandboxedContent);
    assert!(report.is_valid);

    let html = report.to_html();

    // Document shell
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("<title>Horizon Mod Inspector Report</title>"));
    assert!(html.contains("<style>")); // inline CSS
    // Status badge
    assert!(html.contains("Horizon Mod Inspector Report"));
    assert!(html.contains("badge-valid"));
    assert!(html.contains("PASSED (VALID)"));
    // File info
    assert!(html.contains(file_name));
    assert!(html.contains("Content Mod (.hmod)"));
    assert!(html.contains("SANDBOXED"));
    assert!(html.contains("SHA-256"));
    // Identity
    assert!(html.contains("export_mod"));
    assert!(html.contains("2.0.0"));
    assert!(html.contains("CGRLabs"));
    // Diagnostics table scaffold
    assert!(html.contains("Diagnostics"));
    assert!(html.contains("Severity"));
    assert!(html.contains("Code"));
    assert!(html.contains("Message"));
    // Print-to-PDF hint
    assert!(html.contains("Print to PDF"));
}

#[test]
fn test_to_html_escapes_dangerous_content() {
    use horizon_inspector::model::{FileInfo, InspectionReport};
    let mut report = InspectionReport::new(
        PackageKind::ContentMod,
        SecurityTier::SandboxedContent,
        FileInfo {
            file_path: "C:/evil/<script>.hmod".to_string(),
            file_name: "<script>alert('xss')</script>.hmod".to_string(),
            size_bytes: 1,
            sha256: "deadbeef".to_string(),
        },
    );
    report.add_info("ESCAPE_TEST", "harmless info".to_string(), None, None);

    let html = report.to_html();
    // Dangerous markup must be HTML-escaped, never emitted raw.
    assert!(!html.contains("<script>"));
    assert!(!html.contains("alert('xss')"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(html.contains("&lt;"));
}

#[test]
fn test_to_json_pretty_roundtrip() {
    let path = make_valid_hmod();
    let report = inspect_package(&path, &InspectorConfig::default());
    let json = report.to_json_pretty().expect("report serializes to JSON");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON is valid");
    assert_eq!(parsed["schema_version"], "1.0.0");
    assert_eq!(parsed["package_kind"], "content-mod");
    assert_eq!(parsed["is_valid"], true);
    assert_eq!(parsed["file"]["file_name"], path.file_name().unwrap().to_str().unwrap());
}

#[test]
fn test_to_text_contains_key_fields() {
    let path = make_valid_hmod();
    let file_name = path.file_name().unwrap().to_str().unwrap();
    let report = inspect_package(&path, &InspectorConfig::default());
    let text = report.to_text();
    assert!(text.contains("HORIZON MOD INSPECTOR REPORT"));
    assert!(text.contains(file_name));
    assert!(text.contains("PASSED (VALID)"));
    assert!(text.contains("SHA-256"));
}

#[test]
fn test_cli_export_writes_html_json_txt() {
    let hmod = make_valid_hmod();
    let bin = env!("CARGO_BIN_EXE_horizon-inspect");
    let dir = tempfile::tempdir().unwrap();

    let html_out = dir.path().join("report.html");
    let json_out = dir.path().join("report.json");
    let txt_out = dir.path().join("report.txt");
    let noext_out = dir.path().join("report"); // no extension -> default JSON

    for (out, expected_marker, ext_label) in [
        (&html_out, "<!DOCTYPE html>", "html"),
        (&json_out, "\"package_kind\"", "json"),
        (&txt_out, "HORIZON MOD INSPECTOR REPORT", "txt"),
        (&noext_out, "\"package_kind\"", "no-extension (defaults to json)"),
    ] {
        let status = Command::new(bin)
            .args(["--export", out.to_str().unwrap(), hmod.to_str().unwrap()])
            .status()
            .unwrap_or_else(|e| panic!("failed to run {bin}: {e}"));
        assert!(status.success(), "export to {ext_label} should succeed");
        assert!(out.exists(), "export file {ext_label} should be created");
        let content = fs::read_to_string(out).unwrap_or_default();
        assert!(
            content.contains(expected_marker),
            "export {ext_label} should contain {expected_marker:?}, got: {content:?}"
        );
    }
}
