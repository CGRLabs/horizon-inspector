//! Inspector for `.hmod` packages (content, WebAssembly code and native source mods).

use crate::archive::SafeArchive;
use crate::error::DiagnosticCode;
use crate::model::{InspectionReport, SecurityTier};
use horizon_mods::index::valid_id;
use horizon_mods::manifest::{Capability, MANIFEST, Side};
use std::path::Path;

fn str_field(value: &toml::Value, key: &str) -> Option<String> {
    value.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

fn string_array(value: &toml::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Identity/compatibility fields shared by wasm and native code mods.
///
/// The old `horizon_mods::Manifest` parser this crate depends on predates the
/// `[wasm]` and `[native]` tables, so code mods are read directly from the
/// TOML value instead of being rejected as unknown schema fields.
fn inspect_code_manifest(
    value: &toml::Value,
    archive: &SafeArchive,
    report: &mut InspectionReport,
    is_wasm: bool,
) {
    let id = str_field(value, "id").unwrap_or_default();
    let name = str_field(value, "name").unwrap_or_default();
    let version = str_field(value, "version").unwrap_or_default();
    let description = str_field(value, "description").filter(|s| !s.is_empty());
    let authors = string_array(value, "authors");
    let api = str_field(value, "api");
    let side = str_field(value, "side").unwrap_or_else(|| "both".to_string());

    report.identity.id = (!id.is_empty()).then_some(id.clone());
    report.identity.name = (!name.is_empty()).then_some(name);
    report.identity.version = (!version.is_empty()).then_some(version);
    report.identity.description = description.clone();
    report.identity.authors = authors.clone();
    report.compatibility.api = api;
    report.compatibility.side = Some(side);
    report.capabilities = string_array(value, "capabilities");

    if !valid_id(&id) {
        report.add_error(
            DiagnosticCode::MANIFEST_INVALID_ID,
            format!("Mod ID '{id}' is invalid: must match [a-z0-9_]{{1,64}}"),
            Some(MANIFEST.to_string()),
            Some("Use only lowercase alphanumeric characters and underscores (1-64 characters)".to_string()),
        );
    }

    if is_wasm {
        if !archive.entries.contains_key("mod.wasm") {
            report.add_error(
                DiagnosticCode::MANIFEST_INVALID_SCHEMA,
                "Manifest declares [wasm] but the package has no mod.wasm",
                Some("mod.wasm".to_string()),
                Some("Run cargo horizon-mod build --wasm before packaging".to_string()),
            );
        }
    } else {
        let native = value.get("native");
        report.compatibility.game = native.and_then(|v| str_field(v, "game"));
        report.compatibility.horizon_revision = native.and_then(|v| str_field(v, "horizon"));
        report.compatibility.mixins_revision = native.and_then(|v| str_field(v, "mixins"));

        let has_source = archive
            .entries
            .keys()
            .any(|k| k.starts_with("src/") && k.ends_with(".rs"));
        if !has_source {
            report.add_warning(
                DiagnosticCode::NATIVE_UNEXPECTED_SOURCE,
                "Native manifest has no Rust source under src/",
                Some("src/".to_string()),
                Some("Include the source this native mod was built from".to_string()),
            );
        }
    }

    if description.is_none() {
        report.add_warning(
            DiagnosticCode::QUALITY_MISSING_DESCRIPTION,
            "Manifest is missing a description",
            Some(MANIFEST.to_string()),
            Some("Add a 'description' field to horizon-mod.toml to improve discovery".to_string()),
        );
    }
    if authors.is_empty() {
        report.add_warning(
            DiagnosticCode::QUALITY_MISSING_AUTHORS,
            "Manifest has no authors listed",
            Some(MANIFEST.to_string()),
            Some("Add an 'authors' list to horizon-mod.toml".to_string()),
        );
    }
}

pub fn inspect_content_mod(
    path: &Path,
    archive: &SafeArchive,
    report: &mut InspectionReport,
) {
    // 1. Locate and parse horizon-mod.toml
    let manifest_bytes = match archive.get_file(MANIFEST) {
        Some(b) => b,
        None => {
            report.add_error(
                DiagnosticCode::MANIFEST_MISSING,
                format!("Required manifest '{MANIFEST}' is missing from the package root"),
                Some(MANIFEST.to_string()),
                Some("Add a valid horizon-mod.toml manifest to the root of the .hmod".to_string()),
            );
            return;
        }
    };

    let manifest_text = match std::str::from_utf8(manifest_bytes) {
        Ok(s) => s,
        Err(_) => {
            report.add_error(
                DiagnosticCode::MANIFEST_NOT_UTF8,
                format!("Manifest '{MANIFEST}' is not valid UTF-8"),
                Some(MANIFEST.to_string()),
                Some("Save horizon-mod.toml using standard UTF-8 encoding without BOM".to_string()),
            );
            return;
        }
    };

    let manifest_value = match toml::from_str::<toml::Value>(manifest_text) {
        Ok(v) => v,
        Err(e) => {
            report.add_error(
                DiagnosticCode::MANIFEST_SYNTAX_ERROR,
                format!("Failed to parse {MANIFEST}: {e}"),
                Some(MANIFEST.to_string()),
                Some("Fix manifest TOML syntax and schema attributes".to_string()),
            );
            return;
        }
    };

    let has_wasm_table = manifest_value.get("wasm").is_some();
    let has_native_table = manifest_value.get("native").is_some();
    let has_wasm_binary = archive.entries.contains_key("mod.wasm");

    // A wasm binary without a [wasm] table is the discontinued legacy format.
    if has_wasm_binary && !has_wasm_table {
        report.add_error(
            DiagnosticCode::SEC_WASM_DISALLOWED,
            "Package contains a legacy 'mod.wasm' without a [wasm] manifest table. Current WebAssembly mods must declare [wasm].",
            Some("mod.wasm".to_string()),
            Some("Rebuild with cargo horizon-mod build --wasm on the current SDK".to_string()),
        );
        return;
    }

    if has_wasm_table && has_native_table {
        report.add_error(
            DiagnosticCode::MANIFEST_INVALID_SCHEMA,
            "Manifest declares both [wasm] and [native]; a package may carry only one code kind",
            Some(MANIFEST.to_string()),
            Some("Remove one of the two tables".to_string()),
        );
        return;
    }

    if has_wasm_table || has_native_table {
        if has_wasm_table {
            report.security_tier = SecurityTier::SandboxedWasm;
            report.add_info(
                DiagnosticCode::MOD_WASM_CODE,
                "WebAssembly code mod: executable wasm runs inside Horizon's sandbox",
                Some("mod.wasm".to_string()),
                None,
            );
        } else {
            report.security_tier = SecurityTier::UnsandboxedNative;
            report.add_warning(
                DiagnosticCode::MOD_NATIVE_CODE,
                "Native source mod: unsandboxed code built into the game on each player's machine",
                Some(MANIFEST.to_string()),
                Some("Install only from authors you trust".to_string()),
            );
        }
        inspect_code_manifest(&manifest_value, archive, report, has_wasm_table);
        return;
    }

    // Pure content mod path: use the engine's own strict manifest/content validation.
    let manifest = match horizon_mods::Manifest::parse(manifest_text) {
        Ok(m) => m,
        Err(e) => {
            let code = if e.contains("is not [a-z0-9_]{1,64}") {
                DiagnosticCode::MANIFEST_INVALID_ID
            } else if e.contains("built for API") {
                DiagnosticCode::MANIFEST_UNSUPPORTED_API
            } else {
                DiagnosticCode::MANIFEST_SYNTAX_ERROR
            };
            report.add_error(
                code,
                format!("Failed to parse {MANIFEST}: {e}"),
                Some(MANIFEST.to_string()),
                Some("Fix manifest TOML syntax and schema attributes".to_string()),
            );
            return;
        }
    };

    // Extract Identity
    report.identity.id = Some(manifest.id.clone());
    report.identity.name = Some(manifest.name.clone());
    report.identity.version = Some(manifest.version.clone());
    report.identity.description = if manifest.description.is_empty() {
        None
    } else {
        Some(manifest.description.clone())
    };
    report.identity.authors = manifest.authors.clone();

    // Extract Compatibility
    report.compatibility.api = Some(manifest.api.clone());
    report.compatibility.side = Some(match manifest.side {
        Side::Client => "client".to_string(),
        Side::Server => "server".to_string(),
        Side::Both => "both".to_string(),
    });

    // Extract Capabilities
    report.capabilities = manifest.capabilities.iter().map(ToString::to_string).collect();

    // Validation checks
    if !valid_id(&manifest.id) {
        report.add_error(
            DiagnosticCode::MANIFEST_INVALID_ID,
            format!("Mod ID '{}' is invalid: must match [a-z0-9_]{{1,64}}", manifest.id),
            Some(MANIFEST.to_string()),
            Some("Use only lowercase alphanumeric characters and underscores (1-64 characters)".to_string()),
        );
    }

    // Server mod consistency
    let is_server = manifest.side == Side::Server;
    if is_server && manifest.api != "0.3" {
        report.add_error(
            DiagnosticCode::MANIFEST_SERVER_MISCONFIG,
            format!("Server mod specifies api '{}' but server mods require api = '0.3'", manifest.api),
            Some(MANIFEST.to_string()),
            Some("Set api = \"0.3\" in horizon-mod.toml for server mods".to_string()),
        );
    }

    // Content capability
    if !manifest.capabilities.contains(&Capability::Registries) {
        report.add_warning(
            DiagnosticCode::MANIFEST_CAPABILITY_MISMATCH,
            "Content mod does not declare capability 'registries'. New blocks/items/recipes require capability registries.",
            Some(MANIFEST.to_string()),
            Some("Add capabilities = [\"registries\"] if this mod introduces content".to_string()),
        );
    }

    // Experimental capability checks
    for cap in &manifest.experimental {
        report.add_warning(
            DiagnosticCode::QUALITY_EXPERIMENTAL_CAP,
            format!("Mod uses experimental capability '{}', which may change across Horizon releases", cap),
            Some(MANIFEST.to_string()),
            Some("Note that experimental capabilities are not covered by API stability guarantees".to_string()),
        );
    }

    // Content deep validation using horizon_mods::Content
    match horizon_mods::Content::read(path, &manifest) {
        Ok(content) => {
            report.add_info(
                "CONTENT_VALIDATED",
                format!("Successfully validated {} content file(s) across assets/ and data/", content.files.len()),
                None,
                None,
            );
        }
        Err(e) => {
            let (code, rec) = if e.contains("not a plain assets/ or data/ path") || e.contains("plain path") {
                (
                    DiagnosticCode::ARCHIVE_INVALID_PATH,
                    "Ensure all content files are placed under assets/<namespace>/ or data/<namespace>/ using valid characters",
                )
            } else if e.contains("capability registries") || e.contains("not capability registries") {
                (
                    DiagnosticCode::MANIFEST_CAPABILITY_MISMATCH,
                    "Add capabilities = [\"registries\"] in horizon-mod.toml to introduce blocks/items/recipes",
                )
            } else if e.contains("own namespaces") || e.contains("namespace") {
                (
                    DiagnosticCode::CONTENT_RESERVED_NAMESPACE,
                    "Use your mod's own namespace and avoid claiming reserved vanilla/horizon namespaces",
                )
            } else if e.contains("JSON") || e.contains("syntax") || e.contains("template") {
                (
                    DiagnosticCode::CONTENT_MALFORMED_JSON,
                    "Verify that all JSON files under data/ and assets/ conform to Horizon schemas",
                )
            } else {
                (
                    DiagnosticCode::CONTENT_VALIDATION_ERROR,
                    "Review content assets and data declarations against Horizon content mod specifications",
                )
            };
            report.add_error(
                code,
                format!("Content validation failed: {e}"),
                None,
                Some(rec.to_string()),
            );
        }
    }

    // Quality warnings
    if manifest.description.trim().is_empty() {
        report.add_warning(
            DiagnosticCode::QUALITY_MISSING_DESCRIPTION,
            "Manifest is missing a description",
            Some(MANIFEST.to_string()),
            Some("Add a 'description' field to horizon-mod.toml to improve discovery".to_string()),
        );
    }
    if manifest.authors.is_empty() {
        report.add_warning(
            DiagnosticCode::QUALITY_MISSING_AUTHORS,
            "Manifest has no authors listed",
            Some(MANIFEST.to_string()),
            Some("Add an 'authors' list to horizon-mod.toml".to_string()),
        );
    }
}
