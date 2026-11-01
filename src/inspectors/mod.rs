//! Inspection dispatch and coordinator.

pub mod content_mod;
pub mod directory;
pub mod native_mod;
pub mod modpack;
pub mod resource_pack;
pub mod shader;

use crate::archive::{ArchiveLimits, SafeArchive, compute_file_stats};
use crate::error::DiagnosticCode;
use crate::model::{FileInfo, InspectionReport, PackageKind, SecurityTier};
use crate::signature::verify_file_signature;
use std::path::{Path, PathBuf};

/// Configuration options for the inspector.
#[derive(Clone, Debug, Default)]
pub struct InspectorConfig {
    /// Explicit package kind override if file extension is non-standard.
    pub forced_kind: Option<PackageKind>,
    /// Expected SHA-256 hash (lowercase hex) to verify against.
    pub expected_sha256: Option<String>,
    /// Expected file size in bytes to verify against.
    pub expected_size: Option<u64>,
    /// Minisign Ed25519 public key (base64 string).
    pub public_key: Option<String>,
    /// Path to a .minisig signature file.
    pub signature_path: Option<PathBuf>,
    /// Authoritative target Horizon native hooks API version to validate native mods against.
    pub target_hooks_api: Option<u32>,
    /// Custom archive limits override.
    pub custom_limits: Option<ArchiveLimits>,
    /// Optional path to a revoked.toml list for offline revocation checks.
    pub revocation_list: Option<PathBuf>,
    /// Maximum allowed package archive size in bytes override.
    pub max_file_size: Option<u64>,
    /// Maximum entries allowed in the archive override.
    pub max_entries: Option<usize>,
    /// Maximum total uncompressed bytes override.
    pub max_uncompressed: Option<u64>,
}

/// Primary inspection entry point.
pub fn inspect_package(path: &Path, config: &InspectorConfig) -> InspectionReport {
    // Directory (unpacked workspace) inspection
    if path.is_dir() {
        return inspect_directory_path(path, config);
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_string();

    // Determine package kind
    let package_kind = config.forced_kind.unwrap_or_else(|| {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        PackageKind::from_extension(ext)
    });

    let security_tier = match package_kind {
        PackageKind::ContentMod => SecurityTier::SandboxedContent,
        PackageKind::NativeMod => SecurityTier::UnsandboxedNative,
        PackageKind::Modpack => SecurityTier::ConfigurationOnly,
        PackageKind::Shader => SecurityTier::VisualShader,
        PackageKind::ResourcePack => SecurityTier::AssetOnly,
        PackageKind::Unknown => SecurityTier::Unclassified,
    };

    // Determine authoritative package limits (H1, M1)
    let mut limits = config
        .custom_limits
        .unwrap_or_else(|| ArchiveLimits::for_kind(package_kind));

    if let Some(max_sz) = config.max_file_size {
        limits.max_archive_size = max_sz;
    }
    if let Some(max_ent) = config.max_entries {
        limits.max_entries = max_ent;
    }
    if let Some(max_unc) = config.max_uncompressed {
        limits.max_total_uncompressed = max_unc;
    }

    // Fast-path: Check file metadata before computing hashes (L3)
    let file_metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            let mut report = InspectionReport::new(
                package_kind,
                security_tier,
                FileInfo {
                    file_path: path.display().to_string(),
                    file_name,
                    size_bytes: 0,
                    sha256: String::new(),
                },
            );
            report.add_error(
                DiagnosticCode::ARCHIVE_NOT_FOUND,
                format!("Failed to read file: {e}"),
                Some(path.display().to_string()),
                Some("Verify that the target path points to an accessible file".to_string()),
            );
            return report;
        }
    };

    let size_bytes = file_metadata.len();

    // Early size check against max_archive_size before hashing (L3)
    if size_bytes > limits.max_archive_size {
        let file_info = FileInfo {
            file_path: path.display().to_string(),
            file_name: file_name.clone(),
            size_bytes,
            sha256: String::new(),
        };
        let mut report = InspectionReport::new(package_kind, security_tier, file_info);
        report.add_error(
            DiagnosticCode::ARCHIVE_EXPANSION_LIMIT,
            format!(
                "Package size {} bytes exceeds maximum allowed limit for {} ({} MiB)",
                size_bytes,
                package_kind.display_name(),
                limits.max_archive_size >> 20
            ),
            None,
            Some("Reduce asset or model sizes to remain under the package format limit".to_string()),
        );
        return report;
    }

    // Compute cryptographic SHA-256
    let (computed_size, sha256) = match compute_file_stats(path) {
        Ok(stats) => stats,
        Err(e) => {
            let mut report = InspectionReport::new(
                package_kind,
                security_tier,
                FileInfo {
                    file_path: path.display().to_string(),
                    file_name,
                    size_bytes,
                    sha256: String::new(),
                },
            );
            report.add_error(
                DiagnosticCode::ARCHIVE_NOT_FOUND,
                format!("Failed reading package contents: {e}"),
                Some(path.display().to_string()),
                None,
            );
            return report;
        }
    };

    let file_info = FileInfo {
        file_path: path.display().to_string(),
        file_name,
        size_bytes: computed_size,
        sha256: sha256.clone(),
    };

    let mut report = InspectionReport::new(package_kind, security_tier, file_info);

    // Verify expected size
    if let Some(expected_size) = config.expected_size {
        if size_bytes != expected_size {
            report.add_error(
                DiagnosticCode::SIZE_MISMATCH,
                format!(
                    "File size {size_bytes} bytes does not match expected size of {expected_size} bytes"
                ),
                None,
                Some("Verify the package was downloaded or transferred completely".to_string()),
            );
        }
    }

    // Verify expected SHA-256
    if let Some(ref expected_hash) = config.expected_sha256 {
        let clean_expected = expected_hash.trim().to_ascii_lowercase();
        if sha256 != clean_expected {
            report.add_error(
                DiagnosticCode::CHECKSUM_MISMATCH,
                format!(
                    "SHA-256 mismatch: calculated {sha256}, but expected {clean_expected}"
                ),
                None,
                Some("Ensure the package matches the expected registry or distribution digest".to_string()),
            );
        }
    }

    // Verify signature
    verify_file_signature(
        path,
        config.public_key.as_deref(),
        config.signature_path.as_deref(),
        &mut report,
    );

    // Safe archive extraction and scanning with package-specific limits (H1, H2, H4, H5)
    let archive = match SafeArchive::open_and_scan(path, &limits, &mut report) {
        Ok(a) => a,
        Err(_) => {
            // Error was recorded in report
            return report;
        }
    };

    // Offline revocation check (if a revoked.toml is supplied)
    if let Some(ref rl) = config.revocation_list {
        if let Ok(entries) = crate::revocation::load(rl) {
            if let Some(entry) = crate::revocation::find_revoked(&entries, report.identity.id.as_deref(), &report.file.sha256) {
                let reason = entry.reason.clone().unwrap_or_else(|| "revoked".to_string());
                report.add_error("REVOKED", format!("Package is revoked: {}", reason), None, Some("Do not use this package".to_string()));
            }
        } else {
            report.add_warning("REVOCATION_LIST_UNREADABLE", "Could not read revocation list".to_string(), None, None);
        }
    }

    // Dispatch to specific format inspector
    match package_kind {
        PackageKind::ContentMod => {
            content_mod::inspect_content_mod(path, &archive, &mut report);
        }
        PackageKind::NativeMod => {
            native_mod::inspect_native_mod(path, &archive, config.target_hooks_api, &mut report);
        }
        PackageKind::Modpack => {
            modpack::inspect_modpack(path, &archive, &mut report);
        }
        PackageKind::Shader => {
            shader::inspect_shader_pack(path, &archive, &mut report);
        }
        PackageKind::ResourcePack => {
            resource_pack::inspect_resource_pack(&archive, &mut report);
        }
        PackageKind::Unknown => {
            report.add_error(
                "PACKAGE_KIND_UNKNOWN",
                format!(
                    "Unrecognized package extension '{}'. Supported extensions: .hmod, .hnmod, .hpack, .hshader, .zip",
                    path.extension().and_then(|s| s.to_str()).unwrap_or("<none>")
                ),
                None,
                Some("Use a supported Horizon package format or pass --kind <kind>".to_string()),
            );
        }
    }

    report
}

/// Inspect an unpacked directory (workspace) instead of a packaged archive.
fn inspect_directory_path(path: &Path, config: &InspectorConfig) -> InspectionReport {
    // Determine package kind by manifest presence
    let package_kind = config.forced_kind.unwrap_or_else(|| {
        if path.join("horizon-mod.toml").exists() {
            PackageKind::ContentMod
        } else if path.join("horizon-native.json").exists() {
            PackageKind::NativeMod
        } else if path.join("horizon-modpack.toml").exists() {
            PackageKind::Modpack
        } else if path.join("horizon-shaders.toml").exists() {
            PackageKind::Shader
        } else if path.join("pack.mcmeta").exists() {
            PackageKind::ResourcePack
        } else {
            PackageKind::Unknown
        }
    });

    let security_tier = match package_kind {
        PackageKind::ContentMod => SecurityTier::SandboxedContent,
        PackageKind::NativeMod => SecurityTier::UnsandboxedNative,
        PackageKind::Modpack => SecurityTier::ConfigurationOnly,
        PackageKind::Shader => SecurityTier::VisualShader,
        PackageKind::ResourcePack => SecurityTier::AssetOnly,
        PackageKind::Unknown => SecurityTier::Unclassified,
    };

    // Compute total size of all files in the directory
    let mut total_size: u64 = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    total_size += meta.len();
                } else if meta.is_dir() {
                    // shallow sum; good enough for info
                }
            }
        }
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<directory>")
        .to_string();

    let file_info = FileInfo {
        file_path: path.display().to_string(),
        file_name,
        size_bytes: total_size,
        sha256: String::new(),
    };

    let mut report = InspectionReport::new(package_kind, security_tier, file_info);

    // Signature verification if .minisig present
    verify_file_signature(path, config.public_key.as_deref(), config.signature_path.as_deref(), &mut report);

    // Delegate to directory inspector
    match package_kind {
        PackageKind::Unknown => {
            report.add_error(
                "PACKAGE_KIND_UNKNOWN",
                "Directory does not contain a recognized Horizon manifest".to_string(),
                None,
                Some("Add horizon-mod.toml, horizon-native.json, horizon-modpack.toml, horizon-shaders.toml, or pack.mcmeta".to_string()),
            );
        }
        _ => {
            directory::inspect_directory(path, &mut report);
        }
    }

    // Offline revocation check
    if let Some(ref rl) = config.revocation_list {
        if let Ok(entries) = crate::revocation::load(rl) {
            if let Some(entry) = crate::revocation::find_revoked(&entries, report.identity.id.as_deref(), &report.file.sha256) {
                let reason = entry.reason.clone().unwrap_or_else(|| "revoked".to_string());
                report.add_error("REVOKED", format!("Package is revoked: {}", reason), None, Some("Do not use this package".to_string()));
            }
        }
    }

    report
}
