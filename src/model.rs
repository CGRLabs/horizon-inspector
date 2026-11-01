//! Data models and schemas for the Horizon Mod Inspector.

use serde::{Deserialize, Serialize};

/// Recognized package kinds in the Horizon ecosystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageKind {
    /// Content Mod (.hmod): Blocks, items, loot tables, recipes, textures. Sandboxed, no code.
    ContentMod,
    /// Native Mod (.hnmod): Source mixin bundle compiled into isolated game builds. Unsandboxed code.
    NativeMod,
    /// Modpack (.hpack): Collection of pinned registry mods with configuration overrides.
    Modpack,
    /// Horizon Shader (.hshader): WGSL shaders run against the native renderer pipeline.
    Shader,
    /// Resource Pack (.zip): Vanilla-compatible resource pack with pack.mcmeta.
    ResourcePack,
    /// Unknown or unsupported package extension.
    Unknown,
}

impl PackageKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PackageKind::ContentMod => "content-mod",
            PackageKind::NativeMod => "native-mod",
            PackageKind::Modpack => "modpack",
            PackageKind::Shader => "shader",
            PackageKind::ResourcePack => "resource-pack",
            PackageKind::Unknown => "unknown",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            PackageKind::ContentMod => "Content Mod (.hmod)",
            PackageKind::NativeMod => "Native Mod (.hnmod)",
            PackageKind::Modpack => "Modpack (.hpack)",
            PackageKind::Shader => "Horizon Shader (.hshader)",
            PackageKind::ResourcePack => "Resource Pack (.zip)",
            PackageKind::Unknown => "Unknown Package",
        }
    }

    pub fn from_extension(ext: &str) -> Self {
        match ext.to_ascii_lowercase().as_str() {
            "hmod" => PackageKind::ContentMod,
            "hnmod" => PackageKind::NativeMod,
            "hpack" => PackageKind::Modpack,
            "hshader" => PackageKind::Shader,
            "zip" => PackageKind::ResourcePack,
            _ => PackageKind::Unknown,
        }
    }
}

/// Security risk classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityTier {
    /// Content mod: purely assets and data, zero executable code. Sandboxed.
    SandboxedContent,
    /// Native mod: C/Rust mixin code running with full user OS privileges. Unsandboxed.
    UnsandboxedNative,
    /// Modpack: metadata collection pinning signed/hashed mod entries and text overrides.
    ConfigurationOnly,
    /// Shader: WGSL graphics code compiled and bound to the GPU pipeline.
    VisualShader,
    /// Resource pack: Client visual assets.
    AssetOnly,
    /// Unclassified or unknown package format.
    Unclassified,
}

impl SecurityTier {
    pub fn description(&self) -> &'static str {
        match self {
            SecurityTier::SandboxedContent => "SANDBOXED: Data and assets only, no executable code.",
            SecurityTier::UnsandboxedNative => "HIGH RISK: Unsandboxed native code executing with full user privileges.",
            SecurityTier::ConfigurationOnly => "LOW RISK: Declarative modpack specification and configuration files.",
            SecurityTier::VisualShader => "CONTROLLED: WGSL shader pack verified against graphics pipeline stages.",
            SecurityTier::AssetOnly => "LOW RISK: Textures and assets loaded by client renderer.",
            SecurityTier::Unclassified => "UNKNOWN: Unrecognized format cannot be security evaluated.",
        }
    }
}

/// Severity level of an inspection diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn badge(&self) -> &'static str {
        match self {
            Severity::Info => "[INFO]",
            Severity::Warning => "[WARN]",
            Severity::Error => "[ERROR]",
        }
    }
}

/// A structured diagnostic entry detailing a finding during package inspection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Machine-readable code, e.g. "SEC_UNSANDBOXED_NATIVE", "ARCHIVE_ZIP_SLIP", "WASM_DISALLOWED".
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// The target file or path within the package, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Actionable advice or resolution steps for the package author.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

/// File metadata and cryptographic checksums.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    pub file_path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

/// Mod identity extracted from package manifests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,
    pub license: Option<String>,
    pub source: Option<String>,
}

/// Compatibility and environment requirements.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityInfo {
    /// Targeted game version, e.g. "26.3".
    pub game: Option<String>,
    /// Manifest API format line (e.g. "0.1", "0.2", "0.3", "native-1/...").
    pub api: Option<String>,
    /// API level requirement if specified.
    pub api_level: Option<u32>,
    /// Target execution side ("client", "server", "both").
    pub side: Option<String>,
    /// Native mod exact Horizon git commit hash (40 hex chars).
    pub horizon_revision: Option<String>,
    /// Native mod exact Mixins git commit hash (40 hex chars).
    pub mixins_revision: Option<String>,
    /// Minimum native hook API level if using stable hook points.
    pub hooks_api: Option<u32>,
}

/// A required dependency inside a modpack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyRequirement {
    pub id: String,
    pub version: String,
    pub sha256: String,
    pub enabled: bool,
}

/// Minisign Ed25519 signature status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum SignatureInfo {
    /// Signature was verified against the provided public key.
    Verified { public_key: String },
    /// No signature or public key provided; file is unauthenticated.
    Unsigned,
    /// Public key provided but no signature found.
    SignatureMissing { public_key: String },
    /// Signature provided but no public key specified to verify it.
    KeyMissing { signature_path: String },
    /// Verification attempted but failed cryptographic check.
    Invalid { reason: String },
}

/// Statistical summary of package contents.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageStats {
    pub file_count: usize,
    pub total_uncompressed_bytes: u64,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
}

/// Comprehensive inspection report for a Horizon package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InspectionReport {
    /// Inspector schema version (e.g. "1.0").
    pub schema_version: String,
    /// Package kind detected.
    pub package_kind: PackageKind,
    /// Security classification.
    pub security_tier: SecurityTier,
    /// Overall validity (true if error_count == 0).
    pub is_valid: bool,
    /// Inspected file information.
    pub file: FileInfo,
    /// Extracted package identity metadata.
    pub identity: PackageIdentity,
    /// Compatibility requirements.
    pub compatibility: CompatibilityInfo,
    /// Declared capabilities (e.g. "registries", "hud", "ui", "render").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Modpack dependencies if this is a .hpack.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<DependencyRequirement>,
    /// Signature status.
    pub signature: SignatureInfo,
    /// Detailed diagnostics (errors, warnings, informational findings).
    pub diagnostics: Vec<Diagnostic>,
    /// Metrics and summary.
    pub stats: PackageStats,
}

impl InspectionReport {
    pub fn new(package_kind: PackageKind, security_tier: SecurityTier, file: FileInfo) -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            package_kind,
            security_tier,
            is_valid: true,
            file,
            identity: PackageIdentity::default(),
            compatibility: CompatibilityInfo::default(),
            capabilities: Vec::new(),
            dependencies: Vec::new(),
            signature: SignatureInfo::Unsigned,
            diagnostics: Vec::new(),
            stats: PackageStats::default(),
        }
    }

    pub fn add_diagnostic(
        &mut self,
        severity: Severity,
        code: impl Into<String>,
        message: impl Into<String>,
        target: Option<String>,
        recommendation: Option<String>,
    ) {
        match severity {
            Severity::Error => {
                self.stats.error_count += 1;
                self.is_valid = false;
            }
            Severity::Warning => {
                self.stats.warning_count += 1;
            }
            Severity::Info => {
                self.stats.info_count += 1;
            }
        }
        self.diagnostics.push(Diagnostic {
            severity,
            code: code.into(),
            message: message.into(),
            target,
            recommendation,
        });
    }

    pub fn add_error(
        &mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        target: Option<String>,
        recommendation: Option<String>,
    ) {
        self.add_diagnostic(Severity::Error, code, message, target, recommendation);
    }

    pub fn add_warning(
        &mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        target: Option<String>,
        recommendation: Option<String>,
    ) {
        self.add_diagnostic(Severity::Warning, code, message, target, recommendation);
    }

    pub fn add_info(
        &mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        target: Option<String>,
        recommendation: Option<String>,
    ) {
        self.add_diagnostic(Severity::Info, code, message, target, recommendation);
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Generates human-readable terminal output.
    pub fn to_terminal_text(&self) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        let status_str = if self.is_valid {
            if self.stats.warning_count > 0 {
                "PASSED WITH WARNINGS"
            } else {
                "PASSED (VALID)"
            }
        } else {
            "FAILED (INVALID)"
        };
        out.push_str(&format!(
            "HORIZON MOD INSPECTOR REPORT: {}\n",
            status_str
        ));
        out.push_str("================================================================================\n");
        out.push_str(&format!("Package File   : {}\n", self.file.file_name));
        out.push_str(&format!("Package Type   : {}\n", self.package_kind.display_name()));
        out.push_str(&format!("Security Tier  : {}\n", self.security_tier.description()));
        out.push_str(&format!("File Size      : {} bytes ({:.2} KiB)\n", self.file.size_bytes, self.file.size_bytes as f64 / 1024.0));
        out.push_str(&format!("SHA-256        : {}\n", self.file.sha256));

        // Identity
        out.push_str("\n--- Identity ---\n");
        out.push_str(&format!("ID             : {}\n", self.identity.id.as_deref().unwrap_or("<none>")));
        out.push_str(&format!("Name           : {}\n", self.identity.name.as_deref().unwrap_or("<none>")));
        out.push_str(&format!("Version        : {}\n", self.identity.version.as_deref().unwrap_or("<none>")));
        if let Some(desc) = &self.identity.description {
            if !desc.is_empty() {
                out.push_str(&format!("Description    : {}\n", desc));
            }
        }
        if !self.identity.authors.is_empty() {
            out.push_str(&format!("Authors        : {}\n", self.identity.authors.join(", ")));
        }
        if let Some(lic) = &self.identity.license {
            out.push_str(&format!("License        : {}\n", lic));
        }

        // Compatibility
        out.push_str("\n--- Compatibility ---\n");
        if let Some(game) = &self.compatibility.game {
            out.push_str(&format!("Target Game    : Minecraft Java {}\n", game));
        }
        if let Some(api) = &self.compatibility.api {
            out.push_str(&format!("API Line       : {}\n", api));
        }
        if let Some(level) = self.compatibility.api_level {
            out.push_str(&format!("API Level      : {}\n", level));
        }
        if let Some(side) = &self.compatibility.side {
            out.push_str(&format!("Side           : {}\n", side));
        }
        if let Some(rev) = &self.compatibility.horizon_revision {
            out.push_str(&format!("Horizon Commit : {}\n", rev));
        }
        if let Some(rev) = &self.compatibility.mixins_revision {
            out.push_str(&format!("Mixins Commit  : {}\n", rev));
        }
        if let Some(hooks) = self.compatibility.hooks_api {
            out.push_str(&format!("Hooks API Level: {}\n", hooks));
        }

        // Capabilities
        if !self.capabilities.is_empty() {
            out.push_str("\n--- Declared Capabilities ---\n");
            for cap in &self.capabilities {
                out.push_str(&format!("  • {}\n", cap));
            }
        }

        // Dependencies
        if !self.dependencies.is_empty() {
            out.push_str("\n--- Package Dependencies ---\n");
            for dep in &self.dependencies {
                out.push_str(&format!(
                    "  • {} v{} (hash: {}...) [enabled: {}]\n",
                    dep.id,
                    dep.version,
                    &dep.sha256[..12.min(dep.sha256.len())],
                    dep.enabled
                ));
            }
        }

        // Signature
        out.push_str("\n--- Signature ---\n");
        match &self.signature {
            SignatureInfo::Verified { public_key } => {
                out.push_str(&format!("Status         : Verified with key {}\n", public_key));
            }
            SignatureInfo::Unsigned => {
                out.push_str("Status         : Unsigned\n");
            }
            SignatureInfo::SignatureMissing { .. } => {
                out.push_str("Status         : Key provided but package has no signature\n");
            }
            SignatureInfo::KeyMissing { signature_path } => {
                out.push_str(&format!("Status         : Signature present ({}) but no public key provided\n", signature_path));
            }
            SignatureInfo::Invalid { reason } => {
                out.push_str(&format!("Status         : INVALID SIGNATURE: {}\n", reason));
            }
        }

        // Diagnostics
        out.push_str("\n--- Diagnostics ---\n");
        out.push_str(&format!(
            "Total: {} error(s), {} warning(s), {} info item(s)\n",
            self.stats.error_count, self.stats.warning_count, self.stats.info_count
        ));
        for diag in &self.diagnostics {
            out.push_str(&format!("  {} [{}] {}\n", diag.severity.badge(), diag.code, diag.message));
            if let Some(target) = &diag.target {
                out.push_str(&format!("      Target: {}\n", target));
            }
            if let Some(rec) = &diag.recommendation {
                out.push_str(&format!("      Fix   : {}\n", rec));
            }
        }

        out.push_str("================================================================================\n");
        out
    }
}
