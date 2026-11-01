//! Inspector for Resource Packs (.zip).

use crate::archive::SafeArchive;
use crate::error::DiagnosticCode;
use crate::model::InspectionReport;
use serde_json::Value;

pub const PACK_MCMETA: &str = "pack.mcmeta";

pub fn inspect_resource_pack(
    archive: &SafeArchive,
    report: &mut InspectionReport,
) {
    let meta_bytes = match archive.get_file(PACK_MCMETA) {
        Some(b) => b,
        None => {
            report.add_error(
                DiagnosticCode::RESOURCE_PACK_META_MISSING,
                format!("Resource pack is missing required '{PACK_MCMETA}' manifest at root"),
                Some(PACK_MCMETA.to_string()),
                Some("Add pack.mcmeta with a 'pack' object specifying 'pack_format' and 'description'".to_string()),
            );
            return;
        }
    };

    let meta_text = match std::str::from_utf8(meta_bytes) {
        Ok(t) => t,
        Err(_) => {
            report.add_error(
                DiagnosticCode::MANIFEST_NOT_UTF8,
                format!("'{PACK_MCMETA}' is not valid UTF-8"),
                Some(PACK_MCMETA.to_string()),
                None,
            );
            return;
        }
    };

    let json: Value = match serde_json::from_str(meta_text) {
        Ok(j) => j,
        Err(e) => {
            report.add_error(
                DiagnosticCode::MANIFEST_SYNTAX_ERROR,
                format!("Failed to parse '{PACK_MCMETA}' as JSON: {e}"),
                Some(PACK_MCMETA.to_string()),
                Some("Fix JSON syntax errors in pack.mcmeta".to_string()),
            );
            return;
        }
    };

    let pack = match json.get("pack") {
        Some(p) if p.is_object() => p,
        _ => {
            report.add_error(
                DiagnosticCode::RESOURCE_PACK_META_INVALID,
                format!("'{PACK_MCMETA}' is missing the required top-level 'pack' object"),
                Some(PACK_MCMETA.to_string()),
                Some("Ensure pack.mcmeta has a {\"pack\": { ... }} structure".to_string()),
            );
            return;
        }
    };

    // Extract pack format
    let format = [&pack["pack_format"], &pack["min_format"]]
        .into_iter()
        .find(|f| !f.is_null())
        .map(|f| match f {
            Value::Array(parts) => parts
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("."),
            Value::Number(n) => n.to_string(),
            other => other.to_string(),
        })
        .unwrap_or_default();

    if format.is_empty() {
        report.add_warning(
            DiagnosticCode::RESOURCE_PACK_META_INVALID,
            "Resource pack pack.mcmeta does not specify 'pack_format'",
            Some(PACK_MCMETA.to_string()),
            Some("Add \"pack_format\": <version> to the pack object in pack.mcmeta".to_string()),
        );
    } else {
        report.compatibility.api = Some(format.clone());
    }

    // Extract description
    if let Some(desc) = pack.get("description") {
        if let Some(s) = desc.as_str() {
            report.identity.description = Some(s.to_string());
        } else {
            report.identity.description = Some(desc.to_string());
        }
    }

    report.identity.name = Some("Resource Pack".to_string());

    report.add_info(
        "RESOURCE_PACK_VALIDATED",
        format!("Resource pack structure validated (pack format: {format})"),
        None,
        None,
    );
}
