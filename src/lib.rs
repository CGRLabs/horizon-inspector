//! Horizon Mod Inspector Library
//!
//! A comprehensive inspection, validation, and security analysis engine for Horizon mod packages:
//! - Content mods (`.hmod`)
//! - Native mods (`.hnmod`)
//! - Modpacks (`.hpack`)
//! - Horizon shaders (`.hshader`)
//! - Resource packs (`.zip`)
//!
//! Never executes mod code. Classifies security risk tiers and strictly separates fatal errors
//! from quality warnings.

pub mod archive;
pub mod error;
pub mod inspectors;
pub mod model;
pub mod revocation;
pub mod signature;

pub use archive::ArchiveLimits;
pub use error::{DiagnosticCode, InspectorError};
pub use inspectors::{InspectorConfig, inspect_package};
pub use revocation::{RevokedEntry, load as load_revocation_list, find_revoked};
pub use inspectors::native_mod::DEFAULT_TARGET_HOOKS_API;
pub use model::{
    CompatibilityInfo, DependencyRequirement, Diagnostic, FileInfo, InspectionReport,
    PackageIdentity, PackageKind, PackageStats, SecurityTier, Severity, SignatureInfo,
};

use std::path::Path;

/// Convenient function to inspect a package using default configuration.
pub fn inspect(path: impl AsRef<Path>) -> InspectionReport {
    inspect_package(path.as_ref(), &InspectorConfig::default())
}

/// Convenient function to inspect a package with custom configuration.
pub fn inspect_with_config(path: impl AsRef<Path>, config: &InspectorConfig) -> InspectionReport {
    inspect_package(path.as_ref(), config)
}
