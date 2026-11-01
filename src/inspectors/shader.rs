//! Inspector for Horizon Shader Packs (.hshader).

use crate::archive::SafeArchive;
use crate::error::DiagnosticCode;
use crate::model::InspectionReport;
use horizon_shader_api::{API, MANIFEST, Pack, check};
use std::path::Path;

pub fn inspect_shader_pack(
    path: &Path,
    _archive: &SafeArchive,
    report: &mut InspectionReport,
) {
    let pack = match Pack::read(path) {
        Ok(p) => p,
        Err(e) => {
            report.add_error(
                DiagnosticCode::MANIFEST_SYNTAX_ERROR,
                format!("Failed to read shader pack: {e}"),
                Some(MANIFEST.to_string()),
                Some("Verify horizon-shaders.toml and WGSL shader files".to_string()),
            );
            return;
        }
    };

    let manifest = &pack.manifest;

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
    report.identity.license = manifest.license.clone();

    // Extract Compatibility
    report.compatibility.api = Some(manifest.api.clone());

    if manifest.api != API {
        report.add_warning(
            DiagnosticCode::MANIFEST_UNSUPPORTED_API,
            format!("Shader pack targets shader API '{}' (current Horizon is {API})", manifest.api),
            Some(MANIFEST.to_string()),
            None,
        );
    }

    // Run WGSL graphics pipeline checks
    match check(&pack) {
        Ok(pass) => {
            report.add_info(
                "SHADER_STAGES_VALIDATED",
                format!(
                    "Validated shader pack: {} option(s), post passes: {}",
                    manifest.options.len(),
                    manifest.post.len()
                ),
                None,
                None,
            );
            let _ = pass;
        }
        Err(problems) => {
            for p in problems {
                report.add_error(
                    DiagnosticCode::SHADER_PIPELINE_ERROR,
                    format!("WGSL Shader stage validation error: {p}"),
                    None,
                    Some("Fix WGSL syntax, entry points, or resource bindings".to_string()),
                );
            }
        }
    }
}
