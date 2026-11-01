//! Inspector for unpacked mod directories (workspaces).
//!
//! Mirrors the per-format inspectors but reads from disk instead of a ZIP archive,
//! so developers can validate a mod before packaging it.

use crate::error::DiagnosticCode;
use crate::model::InspectionReport;

use horizon_mods::index::native::Manifest as NativeManifest;
use horizon_mods::index::valid_id;
use horizon_mods::manifest::{Capability, MANIFEST as CONTENT_MANIFEST, Side};
use horizon_mods::modpack::{FORMAT as MODPACK_FORMAT, MANIFEST as MODPACK_MANIFEST, Manifest as ModpackManifest};
use horizon_shader_api::{API as SHADER_API, MANIFEST as SHADER_MANIFEST, Manifest as ShaderManifest};
use serde_json::Value;
use std::path::Path;

/// Inspect an unpacked directory.
pub fn inspect_directory(path: &Path, report: &mut InspectionReport) {
    // Content mod
    if path.join(CONTENT_MANIFEST).exists() {
        inspect_content_dir(path, report);
        return;
    }
    // Native mod
    if path.join("horizon-native.json").exists() {
        inspect_native_dir(path, report);
        return;
    }
    // Modpack
    if path.join(MODPACK_MANIFEST).exists() {
        inspect_modpack_dir(path, report);
        return;
    }
    // Shader pack
    if path.join(SHADER_MANIFEST).exists() {
        inspect_shader_dir(path, report);
        return;
    }
    // Resource pack
    if path.join("pack.mcmeta").exists() {
        inspect_resource_pack_dir(path, report);
        return;
    }
    report.add_error(
        "PACKAGE_KIND_UNKNOWN",
        "Directory does not contain a recognized Horizon manifest (horizon-mod.toml, horizon-native.json, horizon-modpack.toml, horizon-shaders.toml, or pack.mcmeta)".to_string(),
        None,
        Some("Add a manifest to the directory root or package it as a supported archive".to_string()),
    );
}

fn inspect_content_dir(path: &Path, report: &mut InspectionReport) {
    let manifest_path = path.join(CONTENT_MANIFEST);
    let manifest_text = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_NOT_UTF8, format!("Failed to read manifest: {e}"), Some(CONTENT_MANIFEST.to_string()), None);
            return;
        }
    };
    let manifest = match horizon_mods::Manifest::parse(&manifest_text) {
        Ok(m) => m,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_SYNTAX_ERROR, format!("Failed to parse {CONTENT_MANIFEST}: {e}"), Some(CONTENT_MANIFEST.to_string()), None);
            return;
        }
    };
    report.identity.id = Some(manifest.id.clone());
    report.identity.name = Some(manifest.name.clone());
    report.identity.version = Some(manifest.version.clone());
    report.identity.description = if manifest.description.is_empty() { None } else { Some(manifest.description.clone()) };
    report.identity.authors = manifest.authors.clone();
    report.compatibility.api = Some(manifest.api.clone());
    report.compatibility.side = Some(match manifest.side {
        Side::Client => "client".to_string(),
        Side::Server => "server".to_string(),
        Side::Both => "both".to_string(),
    });
    report.capabilities = manifest.capabilities.iter().map(ToString::to_string).collect();

    if !valid_id(&manifest.id) {
        report.add_error(DiagnosticCode::MANIFEST_INVALID_ID, format!("Mod ID '{}' is invalid", manifest.id), Some(CONTENT_MANIFEST.to_string()), None);
    }
    let is_server = manifest.side == Side::Server;
    if is_server && manifest.api != "0.3" {
        report.add_error(DiagnosticCode::MANIFEST_SERVER_MISCONFIG, "Server mod requires api = \"0.3\"".to_string(), Some(CONTENT_MANIFEST.to_string()), None);
    }
    if !manifest.capabilities.contains(&Capability::Registries) {
        report.add_warning(DiagnosticCode::MANIFEST_CAPABILITY_MISMATCH, "Content mod does not declare capability 'registries'".to_string(), Some(CONTENT_MANIFEST.to_string()), None);
    }
    for cap in &manifest.experimental {
        report.add_warning(DiagnosticCode::QUALITY_EXPERIMENTAL_CAP, format!("Experimental capability '{}'", cap), Some(CONTENT_MANIFEST.to_string()), None);
    }
    // Validate content from directory (upstream supports dirs)
    match horizon_mods::Content::read(path, &manifest) {
        Ok(content) => {
            report.add_info("CONTENT_VALIDATED", format!("Validated {} content file(s)", content.files.len()), None, None);
        }
        Err(e) => {
            report.add_error(DiagnosticCode::CONTENT_VALIDATION_ERROR, format!("Content validation failed: {e}"), None, None);
        }
    }
    if manifest.description.trim().is_empty() {
        report.add_warning(DiagnosticCode::QUALITY_MISSING_DESCRIPTION, "Missing description".to_string(), Some(CONTENT_MANIFEST.to_string()), None);
    }
    if manifest.authors.is_empty() {
        report.add_warning(DiagnosticCode::QUALITY_MISSING_AUTHORS, "No authors listed".to_string(), Some(CONTENT_MANIFEST.to_string()), None);
    }
}

fn inspect_native_dir(path: &Path, report: &mut InspectionReport) {
    report.add_warning(DiagnosticCode::SEC_UNSANDBOXED_NATIVE, "SECURITY NOTICE: Native mod contains unsandboxed code.".to_string(), None, Some("Audit source before running".to_string()));
    let manifest_path = path.join("horizon-native.json");
    let bytes = match std::fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_MISSING, format!("Failed to read horizon-native.json: {e}"), Some("horizon-native.json".to_string()), None);
            return;
        }
    };
    let manifest: NativeManifest = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_SYNTAX_ERROR, format!("Failed to parse horizon-native.json: {e}"), Some("horizon-native.json".to_string()), None);
            return;
        }
    };
    report.identity.id = Some(manifest.id.clone());
    report.identity.version = Some(manifest.version.clone());
    report.identity.name = Some(manifest.id.replace('_', " "));
    report.compatibility.game = Some(manifest.game.clone());
    report.compatibility.api = Some(manifest.api());
    report.compatibility.horizon_revision = Some(manifest.horizon.clone());
    report.compatibility.mixins_revision = Some(manifest.mixins.clone());
    report.compatibility.hooks_api = manifest.hooks;

    if !valid_id(&manifest.id) {
        report.add_error(DiagnosticCode::MANIFEST_INVALID_ID, format!("Invalid native mod ID '{}'", manifest.id), Some("horizon-native.json".to_string()), None);
    }
    if manifest.schema != 1 {
        report.add_error(DiagnosticCode::MANIFEST_INVALID_SCHEMA, format!("Schema {} (requires 1)", manifest.schema), Some("horizon-native.json".to_string()), None);
    }
    if !horizon_mods::index::native::revision(&manifest.horizon) {
        report.add_error(DiagnosticCode::NATIVE_REVISION_INVALID, "Invalid Horizon revision".to_string(), Some("horizon-native.json".to_string()), None);
    }
    if !horizon_mods::index::native::revision(&manifest.mixins) {
        report.add_error(DiagnosticCode::NATIVE_REVISION_INVALID, "Invalid Mixins revision".to_string(), Some("horizon-native.json".to_string()), None);
    }
    match manifest.hooks {
        Some(0) => report.add_error(DiagnosticCode::NATIVE_HOOKS_UNPINNED, "hooks = 0 is invalid".to_string(), Some("horizon-native.json".to_string()), None),
        Some(level) => report.add_info("NATIVE_HOOKS_DECLARED", format!("hooks API level {}", level), Some("horizon-native.json".to_string()), None),
        None => report.add_warning(DiagnosticCode::NATIVE_HOOKS_UNPINNED, "No stable hooks API declared".to_string(), Some("horizon-native.json".to_string()), None),
    }
    report.add_info("NATIVE_DIR_INSPECTED", "Native mod directory inspected (bundle validation requires packaging)".to_string(), None, None);
}

fn inspect_modpack_dir(path: &Path, report: &mut InspectionReport) {
    let manifest_path = path.join(MODPACK_MANIFEST);
    let text = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_NOT_UTF8, format!("Failed to read manifest: {e}"), Some(MODPACK_MANIFEST.to_string()), None);
            return;
        }
    };
    let manifest = match ModpackManifest::parse(&text) {
        Ok(m) => m,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_SYNTAX_ERROR, format!("Failed to parse {MODPACK_MANIFEST}: {e}"), Some(MODPACK_MANIFEST.to_string()), None);
            return;
        }
    };
    report.identity.id = Some(manifest.id.clone());
    report.identity.name = Some(manifest.name.clone());
    report.identity.version = Some(manifest.version.clone());
    report.identity.description = if manifest.description.is_empty() { None } else { Some(manifest.description.clone()) };
    report.identity.authors = manifest.authors.clone();
    report.compatibility.game = Some(manifest.game.clone());
    report.compatibility.api = Some(manifest.format.to_string());
    if manifest.format != MODPACK_FORMAT {
        report.add_error(DiagnosticCode::MANIFEST_INVALID_SCHEMA, format!("Unsupported format {}", manifest.format), Some(MODPACK_MANIFEST.to_string()), None);
    }
    for m in &manifest.mods {
        report.dependencies.push(crate::model::DependencyRequirement {
            id: m.id.clone(),
            version: m.version.clone(),
            sha256: m.sha256.clone(),
            enabled: m.on,
        });
    }
    if manifest.mods.is_empty() {
        report.add_warning("MODPACK_EMPTY", "Modpack contains no mods".to_string(), Some(MODPACK_MANIFEST.to_string()), None);
    }
    report.add_info("MODPACK_DIR_INSPECTED", format!("{} mod dependency specification(s)", manifest.mods.len()), None, None);
}

fn inspect_shader_dir(path: &Path, report: &mut InspectionReport) {
    let manifest_path = path.join(SHADER_MANIFEST);
    let text = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_NOT_UTF8, format!("Failed to read manifest: {e}"), Some(SHADER_MANIFEST.to_string()), None);
            return;
        }
    };
    let manifest = match ShaderManifest::parse(&text) {
        Ok(m) => m,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_SYNTAX_ERROR, format!("Failed to parse {SHADER_MANIFEST}: {e}"), Some(SHADER_MANIFEST.to_string()), None);
            return;
        }
    };
    report.identity.id = Some(manifest.id.clone());
    report.identity.name = Some(manifest.name.clone());
    report.identity.version = Some(manifest.version.clone());
    report.identity.description = if manifest.description.is_empty() { None } else { Some(manifest.description.clone()) };
    report.identity.authors = manifest.authors.clone();
    report.identity.license = manifest.license.clone();
    report.compatibility.api = Some(manifest.api.clone());
    if manifest.api != SHADER_API {
        report.add_warning(DiagnosticCode::MANIFEST_UNSUPPORTED_API, format!("Shader API mismatch: {}", manifest.api), Some(SHADER_MANIFEST.to_string()), None);
    }
    report.add_info("SHADER_DIR_INSPECTED", "Shader pack directory inspected (WGSL validation requires packaging)".to_string(), None, None);
}

fn inspect_resource_pack_dir(path: &Path, report: &mut InspectionReport) {
    let meta_path = path.join("pack.mcmeta");
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(s) => s,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_NOT_UTF8, format!("Failed to read pack.mcmeta: {e}"), Some("pack.mcmeta".to_string()), None);
            return;
        }
    };
    let json: Value = match serde_json::from_str(&meta_text) {
        Ok(j) => j,
        Err(e) => {
            report.add_error(DiagnosticCode::MANIFEST_SYNTAX_ERROR, format!("Failed to parse pack.mcmeta: {e}"), Some("pack.mcmeta".to_string()), None);
            return;
        }
    };
    let pack = match json.get("pack") {
        Some(p) if p.is_object() => p,
        _ => {
            report.add_error(DiagnosticCode::RESOURCE_PACK_META_INVALID, "Missing top-level 'pack' object".to_string(), Some("pack.mcmeta".to_string()), None);
            return;
        }
    };
    let format = [&pack["pack_format"], &pack["min_format"]]
        .into_iter()
        .find(|f| !f.is_null())
        .map(|f| match f {
            Value::Array(parts) => parts.iter().map(ToString::to_string).collect::<Vec<_>>().join("."),
            Value::Number(n) => n.to_string(),
            other => other.to_string(),
        })
        .unwrap_or_default();
    if format.is_empty() {
        report.add_warning(DiagnosticCode::RESOURCE_PACK_META_INVALID, "No pack_format specified".to_string(), Some("pack.mcmeta".to_string()), None);
    } else {
        report.compatibility.api = Some(format.clone());
    }
    if let Some(desc) = pack.get("description") {
        if let Some(s) = desc.as_str() {
            report.identity.description = Some(s.to_string());
        } else {
            report.identity.description = Some(desc.to_string());
        }
    }
    report.identity.name = Some("Resource Pack".to_string());
    report.add_info("RESOURCE_PACK_DIR_INSPECTED", format!("Resource pack validated (format: {})", format), None, None);
}

