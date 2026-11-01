//! Inspector for Native Mods (.hnmod).

use crate::archive::SafeArchive;
use crate::error::DiagnosticCode;
use crate::model::InspectionReport;
use horizon_mods::index::native::{Bundle, MANIFEST, revision};
use horizon_mods::index::valid_id;
use std::path::Path;

/// Upstream Horizon `NATIVE_HOOKS_API` level (native_hooks.rs:194). Exposed as a
/// documented default for callers; the inspector does not hardcode it as a runtime
/// default and still requires explicit `--target-hooks-api` to enforce.
pub const DEFAULT_TARGET_HOOKS_API: u32 = 40;

pub fn inspect_native_mod(
    path: &Path,
    _archive: &SafeArchive,
    target_hooks_api: Option<u32>,
    report: &mut InspectionReport,
) {
    // 1. Mandatory security notice for native mods
    report.add_warning(
        DiagnosticCode::SEC_UNSANDBOXED_NATIVE,
        "SECURITY NOTICE: Native mod (.hnmod) contains native source code executed with full OS account privileges. Static inspection verifies package format and pinned commits, but does NOT audit runtime safety.",
        None,
        Some("Treat native mods as untrusted executable code; audit source code before running".to_string()),
    );

    // 2. Validate using Horizon's native Bundle reader
    let bundle = match Bundle::read(path) {
        Ok(b) => b,
        Err(e) => {
            report.add_error(
                DiagnosticCode::ARCHIVE_CORRUPTED,
                format!("Failed validating native bundle structure: {e}"),
                None,
                Some("Ensure archive conforms to native mod specifications (see docs/native-mods.md)".to_string()),
            );
            return;
        }
    };

    let manifest = &bundle.manifest;

    // Extract Identity
    report.identity.id = Some(manifest.id.clone());
    report.identity.version = Some(manifest.version.clone());
    report.identity.name = Some(manifest.id.replace('_', " "));

    // Extract Compatibility
    report.compatibility.game = Some(manifest.game.clone());
    report.compatibility.api = Some(manifest.api());
    report.compatibility.horizon_revision = Some(manifest.horizon.clone());
    report.compatibility.mixins_revision = Some(manifest.mixins.clone());
    report.compatibility.hooks_api = manifest.hooks;

    // Check ID
    if !valid_id(&manifest.id) {
        report.add_error(
            DiagnosticCode::MANIFEST_INVALID_ID,
            format!("Native mod ID '{}' is invalid: must match [a-z0-9_]{{1,64}}", manifest.id),
            Some(MANIFEST.to_string()),
            Some("Use only lowercase alphanumeric characters and underscores (1-64 characters)".to_string()),
        );
    }

    // Check schema
    if manifest.schema != 1 {
        report.add_error(
            DiagnosticCode::MANIFEST_INVALID_SCHEMA,
            format!("Manifest schema is {} but current Horizon requires schema 1", manifest.schema),
            Some(MANIFEST.to_string()),
            Some("Update schema to 1 in horizon-native.json".to_string()),
        );
    }

    // Check git revisions
    if !revision(&manifest.horizon) {
        report.add_error(
            DiagnosticCode::NATIVE_REVISION_INVALID,
            format!("Invalid Horizon git revision '{}': must be a 40-character lowercase hex commit hash", manifest.horizon),
            Some(MANIFEST.to_string()),
            Some("Pin an exact 40-hex SHA commit hash of Horizon".to_string()),
        );
    }

    if !revision(&manifest.mixins) {
        report.add_error(
            DiagnosticCode::NATIVE_REVISION_INVALID,
            format!("Invalid Mixins git revision '{}': must be a 40-character lowercase hex commit hash", manifest.mixins),
            Some(MANIFEST.to_string()),
            Some("Pin an exact 40-hex SHA commit hash of the mixin framework".to_string()),
        );
    }

    // Hook API stability and authoritative target compatibility validation (H3)
    match manifest.hooks {
        Some(0) => {
            report.add_error(
                DiagnosticCode::NATIVE_HOOKS_UNPINNED,
                "Native manifest sets hooks = 0, which is invalid",
                Some(MANIFEST.to_string()),
                Some("Set hooks to a valid NATIVE_HOOKS_API level (>= 1) or omit if unhooked".to_string()),
            );
        }
        Some(level) => {
            if let Some(target) = target_hooks_api {
                if level > target {
                    report.add_error(
                        DiagnosticCode::NATIVE_HOOKS_INCOMPATIBLE,
                        format!(
                            "Native mod requires hooks API level {level}, which exceeds the authoritative target Horizon hooks API level {target}"
                        ),
                        Some(MANIFEST.to_string()),
                        Some(format!("Compile or test against a Horizon build supporting hooks API level {level}")),
                    );
                } else {
                    report.add_info(
                        "NATIVE_HOOKS_DECLARED",
                        format!("Native mod uses stable hook points (API level {level}), compatible with target hooks API {target}"),
                        Some(MANIFEST.to_string()),
                        None,
                    );
                }
            } else {
                report.add_info(
                    "NATIVE_HOOKS_DECLARED",
                    format!("Native mod uses stable hook points (API level {level}) [target hooks API not specified]"),
                    Some(MANIFEST.to_string()),
                    Some("Supply --target-hooks-api to cross-check compatibility against a specific Horizon release".to_string()),
                );
            }
        }
        None => {
            report.add_warning(
                DiagnosticCode::NATIVE_HOOKS_UNPINNED,
                "Mod does not declare a stable 'hooks' API version. It will ONLY compile against the exact pinned Horizon revision and will fail on newer versions.",
                Some(MANIFEST.to_string()),
                Some("If using native hook points, declare 'hooks' = <version> to allow running across Horizon updates".to_string()),
            );
        }
    }

    report.add_info(
        "NATIVE_BUNDLE_VERIFIED",
        format!(
            "Native bundle verified: {} file(s) across mixins/{}/",
            bundle.files.len(),
            manifest.id
        ),
        None,
        None,
    );
}
