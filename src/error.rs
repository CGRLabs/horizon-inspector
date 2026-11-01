//! Error types and diagnostic standard error codes.

use std::fmt;

/// Standard diagnostic codes emitted during inspection.
pub struct DiagnosticCode;

impl DiagnosticCode {
    // Archive errors
    pub const ARCHIVE_NOT_FOUND: &'static str = "ARCHIVE_NOT_FOUND";
    pub const ARCHIVE_EMPTY: &'static str = "ARCHIVE_EMPTY";
    pub const ARCHIVE_UNREADABLE: &'static str = "ARCHIVE_UNREADABLE";
    pub const ARCHIVE_ZIP_SLIP: &'static str = "ARCHIVE_ZIP_SLIP";
    pub const ARCHIVE_INVALID_PATH: &'static str = "ARCHIVE_INVALID_PATH";
    pub const ARCHIVE_TOO_MANY_ENTRIES: &'static str = "ARCHIVE_TOO_MANY_ENTRIES";
    pub const ARCHIVE_FILE_TOO_LARGE: &'static str = "ARCHIVE_FILE_TOO_LARGE";
    pub const ARCHIVE_EXPANSION_LIMIT: &'static str = "ARCHIVE_EXPANSION_LIMIT";
    pub const ARCHIVE_DUPLICATE_FILE: &'static str = "ARCHIVE_DUPLICATE_FILE";
    pub const ARCHIVE_DUPLICATE_SCAN_SKIPPED: &'static str = "ARCHIVE_DUPLICATE_SCAN_SKIPPED";
    pub const ARCHIVE_CORRUPTED: &'static str = "ARCHIVE_CORRUPTED";

    // Manifest errors & warnings
    pub const MANIFEST_MISSING: &'static str = "MANIFEST_MISSING";
    pub const MANIFEST_NOT_UTF8: &'static str = "MANIFEST_NOT_UTF8";
    pub const MANIFEST_SYNTAX_ERROR: &'static str = "MANIFEST_SYNTAX_ERROR";
    pub const MANIFEST_INVALID_ID: &'static str = "MANIFEST_INVALID_ID";
    pub const MANIFEST_INVALID_SCHEMA: &'static str = "MANIFEST_INVALID_SCHEMA";
    pub const MANIFEST_UNSUPPORTED_API: &'static str = "MANIFEST_UNSUPPORTED_API";
    pub const MANIFEST_SERVER_MISCONFIG: &'static str = "MANIFEST_SERVER_MISCONFIG";
    pub const MANIFEST_CAPABILITY_MISMATCH: &'static str = "MANIFEST_CAPABILITY_MISMATCH";

    // Security & Code execution
    pub const SEC_UNSANDBOXED_NATIVE: &'static str = "SEC_UNSANDBOXED_NATIVE";
    pub const SEC_WASM_DISALLOWED: &'static str = "SEC_WASM_DISALLOWED";
    pub const SEC_UNEXPECTED_EXECUTABLE: &'static str = "SEC_UNEXPECTED_EXECUTABLE";

    // Native mod specific
    pub const NATIVE_REVISION_INVALID: &'static str = "NATIVE_REVISION_INVALID";
    pub const NATIVE_MIXIN_DIFFERS: &'static str = "NATIVE_MIXIN_DIFFERS";
    pub const NATIVE_HOOKS_UNPINNED: &'static str = "NATIVE_HOOKS_UNPINNED";
    pub const NATIVE_HOOKS_INCOMPATIBLE: &'static str = "NATIVE_HOOKS_INCOMPATIBLE";
    pub const NATIVE_UNEXPECTED_SOURCE: &'static str = "NATIVE_UNEXPECTED_SOURCE";

    // Integrity & Signature
    pub const CHECKSUM_MISMATCH: &'static str = "CHECKSUM_MISMATCH";
    pub const SIZE_MISMATCH: &'static str = "SIZE_MISMATCH";
    pub const SIGNATURE_INVALID: &'static str = "SIGNATURE_INVALID";
    pub const SIGNATURE_KEY_MISSING: &'static str = "SIGNATURE_KEY_MISSING";
    pub const SIGNATURE_FILE_MISSING: &'static str = "SIGNATURE_FILE_MISSING";

    // Shader & Content
    pub const SHADER_PIPELINE_ERROR: &'static str = "SHADER_PIPELINE_ERROR";
    pub const CONTENT_MALFORMED_JSON: &'static str = "CONTENT_MALFORMED_JSON";
    pub const CONTENT_RESERVED_NAMESPACE: &'static str = "CONTENT_RESERVED_NAMESPACE";
    pub const CONTENT_VALIDATION_ERROR: &'static str = "CONTENT_VALIDATION_ERROR";
    pub const RESOURCE_PACK_META_MISSING: &'static str = "RESOURCE_PACK_META_MISSING";
    pub const RESOURCE_PACK_META_INVALID: &'static str = "RESOURCE_PACK_META_INVALID";

    // Quality & Warnings
    pub const QUALITY_MISSING_DESCRIPTION: &'static str = "QUALITY_MISSING_DESCRIPTION";
    pub const QUALITY_MISSING_AUTHORS: &'static str = "QUALITY_MISSING_AUTHORS";
    pub const QUALITY_MISSING_LICENSE: &'static str = "QUALITY_MISSING_LICENSE";
    pub const QUALITY_EXPERIMENTAL_CAP: &'static str = "QUALITY_EXPERIMENTAL_CAP";
}

/// Core inspector error.
#[derive(Debug)]
pub enum InspectorError {
    Io(std::io::Error),
    Zip(zip::result::ZipError),
    Format(String),
}

impl fmt::Display for InspectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InspectorError::Io(e) => write!(f, "I/O error: {}", e),
            InspectorError::Zip(e) => write!(f, "Zip archive error: {}", e),
            InspectorError::Format(msg) => write!(f, "Format error: {}", msg),
        }
    }
}

impl std::error::Error for InspectorError {}

impl From<std::io::Error> for InspectorError {
    fn from(e: std::io::Error) -> Self {
        InspectorError::Io(e)
    }
}

impl From<zip::result::ZipError> for InspectorError {
    fn from(e: zip::result::ZipError) -> Self {
        InspectorError::Zip(e)
    }
}
