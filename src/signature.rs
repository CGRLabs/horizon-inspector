//! Cryptographic signature verification using Minisign (Ed25519).

use crate::error::DiagnosticCode;
use crate::model::{InspectionReport, SignatureInfo};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Verifies a minisign signature against a file on disk.
pub fn verify_file_signature(
    target_path: &Path,
    public_key_str: Option<&str>,
    signature_path: Option<&Path>,
    report: &mut InspectionReport,
) {
    let default_sig_path = target_path.with_extension(format!(
        "{}.minisig",
        target_path.extension().and_then(|s| s.to_str()).unwrap_or("")
    ));

    let active_sig_path = signature_path.unwrap_or(&default_sig_path);
    let sig_exists = active_sig_path.exists();

    match (public_key_str, sig_exists) {
        (Some(key_str), true) => {
            let sig_text = match std::fs::read_to_string(active_sig_path) {
                Ok(s) => s,
                Err(e) => {
                    report.add_error(
                        DiagnosticCode::SIGNATURE_INVALID,
                        format!("Failed to read signature file '{}': {e}", active_sig_path.display()),
                        Some(active_sig_path.display().to_string()),
                        Some("Check signature file path and permissions".to_string()),
                    );
                    report.signature = SignatureInfo::Invalid {
                        reason: format!("Signature file unreadable: {e}"),
                    };
                    return;
                }
            };

            let public_key = match minisign_verify::PublicKey::from_base64(key_str.trim()) {
                Ok(k) => k,
                Err(e) => {
                    report.add_error(
                        DiagnosticCode::SIGNATURE_KEY_MISSING,
                        format!("Invalid Minisign public key format: {e}"),
                        None,
                        Some("Ensure the public key is a valid base64-encoded Minisign public key".to_string()),
                    );
                    report.signature = SignatureInfo::Invalid {
                        reason: format!("Invalid public key: {e}"),
                    };
                    return;
                }
            };

            let signature = match minisign_verify::Signature::decode(&sig_text) {
                Ok(s) => s,
                Err(e) => {
                    report.add_error(
                        DiagnosticCode::SIGNATURE_INVALID,
                        format!("Malformed Minisign signature: {e}"),
                        Some(active_sig_path.display().to_string()),
                        Some("Regenerate the signature with minisign".to_string()),
                    );
                    report.signature = SignatureInfo::Invalid {
                        reason: format!("Malformed signature: {e}"),
                    };
                    return;
                }
            };

            let file = match File::open(target_path) {
                Ok(f) => f,
                Err(e) => {
                    report.add_error(
                        DiagnosticCode::ARCHIVE_NOT_FOUND,
                        format!("Target file could not be opened for signature verification: {e}"),
                        Some(target_path.display().to_string()),
                        None,
                    );
                    return;
                }
            };

            let mut verifier = match public_key.verify_stream(&signature) {
                Ok(v) => v,
                Err(e) => {
                    report.add_error(
                        DiagnosticCode::SIGNATURE_INVALID,
                        format!("Signature initialization error: {e}"),
                        None,
                        None,
                    );
                    report.signature = SignatureInfo::Invalid {
                        reason: format!("Verification init failed: {e}"),
                    };
                    return;
                }
            };

            let mut reader = std::io::BufReader::new(file);
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        report.add_error(
                            DiagnosticCode::ARCHIVE_CORRUPTED,
                            format!("Failed reading file during signature stream: {e}"),
                            None,
                            None,
                        );
                        return;
                    }
                };
                if n == 0 {
                    break;
                }
                verifier.update(&buf[..n]);
            }

            match verifier.finalize() {
                Ok(()) => {
                    report.signature = SignatureInfo::Verified {
                        public_key: key_str.trim().to_string(),
                    };
                    report.add_info(
                        "SIGNATURE_VERIFIED",
                        "Minisign Ed25519 signature successfully verified",
                        Some(active_sig_path.display().to_string()),
                        None,
                    );
                }
                Err(_) => {
                    report.add_error(
                        DiagnosticCode::SIGNATURE_INVALID,
                        "Signature verification failed: signature does not match public key or package has been altered",
                        Some(active_sig_path.display().to_string()),
                        Some("Ensure the package matches the signature and public key".to_string()),
                    );
                    report.signature = SignatureInfo::Invalid {
                        reason: "Signature does not match public key".to_string(),
                    };
                }
            }
        }
        (Some(key_str), false) => {
            report.signature = SignatureInfo::SignatureMissing {
                public_key: key_str.to_string(),
            };
            report.add_warning(
                DiagnosticCode::SIGNATURE_FILE_MISSING,
                format!("Public key was provided but signature file '{}' was not found", active_sig_path.display()),
                Some(active_sig_path.display().to_string()),
                Some("Provide the .minisig file or omit the public key parameter".to_string()),
            );
        }
        (None, true) => {
            report.signature = SignatureInfo::KeyMissing {
                signature_path: active_sig_path.display().to_string(),
            };
            report.add_warning(
                DiagnosticCode::SIGNATURE_KEY_MISSING,
                format!("Signature file '{}' exists but no public key was supplied to verify it", active_sig_path.display()),
                Some(active_sig_path.display().to_string()),
                Some("Supply --key <public-key> to verify the signature".to_string()),
            );
        }
        (None, false) => {
            report.signature = SignatureInfo::Unsigned;
            report.add_info(
                "PACKAGE_UNSIGNED",
                "Package is unsigned (no minisign signature verified)",
                None,
                Some("For registry release, sign your package using minisign".to_string()),
            );
        }
    }
}
