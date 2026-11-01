//! Inspector for Horizon Modpacks (.hpack).

use crate::archive::SafeArchive;
use crate::error::DiagnosticCode;
use crate::model::{DependencyRequirement, InspectionReport};
use horizon_mods::modpack::{FORMAT, MANIFEST, Modpack};
use std::path::Path;

pub fn inspect_modpack(
    path: &Path,
    _archive: &SafeArchive,
    report: &mut InspectionReport,
) {
    let modpack = match Modpack::read(path) {
        Ok(mp) => mp,
        Err(e) => {
            report.add_error(
                DiagnosticCode::MANIFEST_SYNTAX_ERROR,
                format!("Failed to validate modpack package: {e}"),
                Some(MANIFEST.to_string()),
                Some("Verify horizon-modpack.toml format and overrides/ constraints".to_string()),
            );
            return;
        }
    };

    let manifest = &modpack.manifest;

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
    report.compatibility.game = Some(manifest.game.clone());
    report.compatibility.api = Some(manifest.format.to_string());

    // Check schema / format
    if manifest.format != FORMAT {
        report.add_error(
            DiagnosticCode::MANIFEST_INVALID_SCHEMA,
            format!("Modpack format {} is unsupported (current version is {FORMAT})", manifest.format),
            Some(MANIFEST.to_string()),
            Some("Update format to 1 in horizon-modpack.toml".to_string()),
        );
    }

    // Extract Dependencies
    for m in &manifest.mods {
        report.dependencies.push(DependencyRequirement {
            id: m.id.clone(),
            version: m.version.clone(),
            sha256: m.sha256.clone(),
            enabled: m.on,
        });
    }

    if manifest.mods.is_empty() {
        report.add_warning(
            "MODPACK_EMPTY",
            "Modpack manifest contains no mods in its profile",
            Some(MANIFEST.to_string()),
            Some("Add [[mods]] entries to horizon-modpack.toml".to_string()),
        );
    }

    // Quality warnings
    if manifest.description.trim().is_empty() {
        report.add_warning(
            DiagnosticCode::QUALITY_MISSING_DESCRIPTION,
            "Modpack has no description in its manifest",
            Some(MANIFEST.to_string()),
            None,
        );
    }

    report.add_info(
        "MODPACK_VALIDATED",
        format!(
            "Modpack contains {} mod dependency specification(s) for Minecraft {}",
            manifest.mods.len(),
            manifest.game
        ),
        None,
        None,
    );
}
