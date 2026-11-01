//! Secure archive inspection and validation primitives.

use crate::error::{DiagnosticCode, InspectorError};
use crate::model::{InspectionReport, PackageKind};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Per-package-kind resource limits matching upstream Horizon specifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// Maximum allowed compressed archive size on disk.
    pub max_archive_size: u64,
    /// Maximum number of file entries permitted inside the archive.
    pub max_entries: usize,
    /// Maximum uncompressed size allowed for any single entry.
    pub max_file_uncompressed: u64,
    /// Maximum total uncompressed size across all entries combined.
    pub max_total_uncompressed: u64,
    /// Optional per-entry uncompressed cap for WGSL shader files (shader packs only).
    pub max_wgsl_uncompressed: Option<u64>,
}

impl ArchiveLimits {
    /// Authoritative limits derived directly from upstream Horizon specs:
    /// - Content mod (.hmod): 16 MiB/file, 512 MiB total, 65,536 files (`horizon-mods/src/content.rs:20-22`).
    /// - Native mod (.hnmod): 64 MiB total, 512 entries (`horizon-mods/src/index/native.rs:77-108`).
    /// - Modpack (.hpack): 64 MiB/override, 256 MiB total overrides (`horizon-mods/src/modpack.rs:19-20`).
    /// - Shader pack (.hshader): 1 MiB/file (256 KiB WGSL), 8 MiB total, 512 entries (`horizon-shader-api/src/package.rs:14-18`).
    /// - Resource pack (.zip): 16 MiB/file, 512 MiB total, 65,536 files (aligned with content asset limits).
    pub fn for_kind(kind: PackageKind) -> Self {
        match kind {
            PackageKind::ContentMod => Self {
                max_archive_size: 512 << 20,         // 512 MiB ingest cap (aligned with uncompressed total)
                max_entries: 65_536,                 // horizon-mods/src/content.rs:20 MAX_FILES
                max_file_uncompressed: 16 << 20,     // horizon-mods/src/content.rs:21 MAX_FILE (16 MiB)
                max_total_uncompressed: 512 << 20,   // horizon-mods/src/content.rs:22 MAX_TOTAL (512 MiB)
                max_wgsl_uncompressed: None,
            },
            PackageKind::NativeMod => Self {
                max_archive_size: 64 << 20,          // 64 MiB
                max_entries: 512,                    // horizon-mods/src/index/native.rs:77 (max 512 entries)
                max_file_uncompressed: 64 << 20,     // 64 MiB
                max_total_uncompressed: 64 << 20,    // horizon-mods/src/index/native.rs:107 (64 MiB)
                max_wgsl_uncompressed: None,
            },
            PackageKind::Modpack => Self {
                max_archive_size: 256 << 20,         // 256 MiB ingest cap (aligned with overrides total)
                max_entries: 4_096,                  // standard profile override limit
                max_file_uncompressed: 64 << 20,     // horizon-mods/src/modpack.rs:19 MAX_OVERRIDE (64 MiB)
                max_total_uncompressed: 256 << 20,   // horizon-mods/src/modpack.rs:20 MAX_OVERRIDES (256 MiB)
                max_wgsl_uncompressed: None,
            },
            PackageKind::Shader => Self {
                max_archive_size: 8 << 20,           // horizon-shader-api/src/package.rs:16 MAX_TOTAL (8 MiB)
                max_entries: 512,                    // horizon-shader-api/src/package.rs:18 MAX_ENTRIES
                max_file_uncompressed: 1 << 20,      // horizon-shader-api/src/package.rs:15 MAX_OTHER (1 MiB)
                max_total_uncompressed: 8 << 20,     // horizon-shader-api/src/package.rs:16 MAX_TOTAL (8 MiB)
                max_wgsl_uncompressed: Some(256 << 10), // horizon-shader-api/src/package.rs:14 MAX_WGSL (256 KiB)
            },
            PackageKind::ResourcePack => Self {
                max_archive_size: 512 << 20,         // 512 MiB ingest cap (aligned with content total)
                max_entries: 65_536,                 // Standard asset count limit
                max_file_uncompressed: 16 << 20,     // 16 MiB
                max_total_uncompressed: 512 << 20,   // 512 MiB
                max_wgsl_uncompressed: None,
            },
            PackageKind::Unknown => Self {
                max_archive_size: 64 << 20,
                max_entries: 4_096,
                max_file_uncompressed: 16 << 20,
                max_total_uncompressed: 64 << 20,
                max_wgsl_uncompressed: None,
            },
        }
    }
}

/// In-memory representation of a safely inspected zip archive.
pub struct SafeArchive {
    pub entries: BTreeMap<String, Vec<u8>>,
    pub total_uncompressed_bytes: u64,
}

impl SafeArchive {
    /// Inspects and reads an archive from disk, validating entry paths, per-entry sizes,
    /// duplicate filenames, symlinks, and decompression bomb limits against `limits`.
    /// Emits structured diagnostics into `report` and returns early on security violations.
    pub fn open_and_scan(
        path: &Path,
        limits: &ArchiveLimits,
        report: &mut InspectionReport,
    ) -> Result<Self, InspectorError> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                report.add_error(
                    DiagnosticCode::ARCHIVE_NOT_FOUND,
                    format!("Failed to open package: {e}"),
                    Some(path.display().to_string()),
                    Some("Ensure the file exists and is accessible".to_string()),
                );
                return Err(InspectorError::Io(e));
            }
        };

        // Check raw Central Directory for duplicate entries before zip crate extraction (H4)
        if let Err(scan_err) = scan_raw_zip_for_duplicates(path) {
            if let Some(reason) = scan_err.strip_prefix("SCAN_SKIPPED: ") {
                report.add_warning(
                    DiagnosticCode::ARCHIVE_DUPLICATE_SCAN_SKIPPED,
                    format!("Raw duplicate-entry scan skipped: {reason}"),
                    Some(path.display().to_string()),
                    Some("Duplicate detection relies on standard central directory parsing; extraction continues".to_string()),
                );
            } else {
                let dup_name = scan_err;
                report.add_error(
                    DiagnosticCode::ARCHIVE_DUPLICATE_FILE,
                    format!("Archive contains duplicate file path: '{dup_name}'"),
                    Some(dup_name.clone()),
                    Some("Ensure all file entries in the archive have unique names".to_string()),
                );
                return Err(InspectorError::Format(format!("Duplicate archive entry: {dup_name}")));
            }
        }

        let mut zip = match zip::ZipArchive::new(file) {
            Ok(z) => z,
            Err(e) => {
                report.add_error(
                    DiagnosticCode::ARCHIVE_CORRUPTED,
                    format!("Not a valid ZIP/Horizon archive: {e}"),
                    Some(path.display().to_string()),
                    Some("Repack the package as a valid ZIP archive".to_string()),
                );
                return Err(InspectorError::Zip(e));
            }
        };

        if zip.is_empty() {
            report.add_error(
                DiagnosticCode::ARCHIVE_EMPTY,
                "Archive is empty (contains 0 entries)",
                Some(path.display().to_string()),
                Some("Include required package manifests and content files".to_string()),
            );
            return Err(InspectorError::Format("Archive is empty".to_string()));
        }

        if zip.len() > limits.max_entries {
            report.add_error(
                DiagnosticCode::ARCHIVE_TOO_MANY_ENTRIES,
                format!(
                    "Archive contains {} entries, exceeding the maximum allowed for this format ({})",
                    zip.len(),
                    limits.max_entries
                ),
                None,
                Some("Remove unnecessary files or assets from the package".to_string()),
            );
            return Err(InspectorError::Format("Too many archive entries".to_string()));
        }

        let mut entries = BTreeMap::new();
        let mut total_uncompressed: u64 = 0;
        let mut total_compressed: u64 = 0;

        for i in 0..zip.len() {
            let mut entry = match zip.by_index(i) {
                Ok(e) => e,
                Err(e) => {
                    report.add_error(
                        DiagnosticCode::ARCHIVE_CORRUPTED,
                        format!("Corrupted archive entry at index {i}: {e}"),
                        None,
                        None,
                    );
                    report.stats.file_count = entries.len();
                    report.stats.total_uncompressed_bytes = total_uncompressed;
                    return Err(InspectorError::Zip(e));
                }
            };

            let name = entry.name().to_string();

            // Directory entries: skip reading contents
            if entry.is_dir() {
                continue;
            }

            // Path security checks (zip-slip defense)
            if name.starts_with('/') || name.contains('\\') || name.contains(':') {
                report.add_error(
                    DiagnosticCode::ARCHIVE_INVALID_PATH,
                    format!("Archive contains illegal path characters: '{name}'"),
                    Some(name.clone()),
                    Some("Use plain, forward-slash-separated relative paths without colons or backslashes".to_string()),
                );
                report.stats.file_count = entries.len();
                report.stats.total_uncompressed_bytes = total_uncompressed;
                return Err(InspectorError::Format(format!("Illegal path in entry: {name}")));
            }

            if name.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
                report.add_error(
                    DiagnosticCode::ARCHIVE_ZIP_SLIP,
                    format!("Potential Zip-Slip path traversal detected in entry: '{name}'"),
                    Some(name.clone()),
                    Some("Remove '.' or '..' traversal elements from archive paths".to_string()),
                );
                report.stats.file_count = entries.len();
                report.stats.total_uncompressed_bytes = total_uncompressed;
                return Err(InspectorError::Format(format!("Zip-slip detected in entry: {name}")));
            }

            // Cross-platform symlink and non-regular file detection:
            // 1. Standard ZipFile::is_symlink()
            // 2. Unix mode inspection when available (mode & 0o170000 == 0o120000 for symlinks)
            let is_symlink = entry.is_symlink();
            let is_non_regular_unix = entry.unix_mode().is_some_and(|m| {
                let file_type = m & 0o170000;
                file_type != 0 && file_type != 0o100000
            });

            if is_symlink || is_non_regular_unix {
                report.add_error(
                    DiagnosticCode::ARCHIVE_INVALID_PATH,
                    format!("Entry '{name}' is a symbolic link or non-regular file, which is disallowed"),
                    Some(name.clone()),
                    Some("Include only regular files in Horizon packages".to_string()),
                );
                report.stats.file_count = entries.len();
                report.stats.total_uncompressed_bytes = total_uncompressed;
                return Err(InspectorError::Format(format!("Symlink or non-regular entry: {name}")));
            }

            // Duplicate filename check: fail fast without overwriting existing content (H4)
            if entries.contains_key(&name) {
                report.add_error(
                    DiagnosticCode::ARCHIVE_DUPLICATE_FILE,
                    format!("Archive contains duplicate file path: '{name}'"),
                    Some(name.clone()),
                    Some("Ensure all file entries in the archive have unique names".to_string()),
                );
                report.stats.file_count = entries.len();
                report.stats.total_uncompressed_bytes = total_uncompressed;
                return Err(InspectorError::Format(format!("Duplicate archive path: {name}")));
            }

            let declared_entry_size = entry.size();

            // Shader WGSL per-file distinction: .wgsl entries are capped separately (M1)
            if name.ends_with(".wgsl") {
                if let Some(wgsl_limit) = limits.max_wgsl_uncompressed {
                    if declared_entry_size > wgsl_limit {
                        report.add_error(
                            DiagnosticCode::ARCHIVE_FILE_TOO_LARGE,
                            format!(
                                "Entry '{name}' uncompressed size ({} bytes) exceeds WGSL limit of {} KiB",
                                declared_entry_size,
                                wgsl_limit >> 10
                            ),
                            Some(name.clone()),
                            Some("Reduce WGSL shader size to remain under the 256 KiB limit".to_string()),
                        );
                        report.stats.file_count = entries.len();
                        report.stats.total_uncompressed_bytes = total_uncompressed;
                        return Err(InspectorError::Format("Archive entry exceeds maximum WGSL file size".to_string()));
                    }
                }
            }

            // Pre-check entry uncompressed size from header before allocating
            if declared_entry_size > limits.max_file_uncompressed {
                report.add_error(
                    DiagnosticCode::ARCHIVE_FILE_TOO_LARGE,
                    format!(
                        "Entry '{name}' uncompressed size ({} bytes) exceeds limit of {} MiB",
                        declared_entry_size,
                        limits.max_file_uncompressed >> 20
                    ),
                    Some(name.clone()),
                    Some("Reduce file size or split assets into smaller files".to_string()),
                );
                report.stats.file_count = entries.len();
                report.stats.total_uncompressed_bytes = total_uncompressed;
                return Err(InspectorError::Format("Archive entry exceeds maximum file size".to_string()));
            }

            // Pre-check cumulative size to prevent zip-bomb allocation (H2)
            if total_uncompressed.saturating_add(declared_entry_size) > limits.max_total_uncompressed {
                report.add_error(
                    DiagnosticCode::ARCHIVE_EXPANSION_LIMIT,
                    format!(
                        "Archive uncompressed size exceeds limit ({} MiB)",
                        limits.max_total_uncompressed >> 20
                    ),
                    Some(name.clone()),
                    Some("Compress or reduce the size of assets in the package".to_string()),
                );
                report.stats.file_count = entries.len();
                report.stats.total_uncompressed_bytes = total_uncompressed;
                return Err(InspectorError::Format("Archive expansion limit exceeded".to_string()));
            }

            // High-compression ratio bomb defense: detect extreme compression anomalies
            let compressed_size = entry.compressed_size();
            if compressed_size > 0 && declared_entry_size > 1 * 1024 * 1024 {
                let ratio = declared_entry_size / compressed_size;
                if ratio > 100 {
                    report.add_error(
                        DiagnosticCode::ARCHIVE_EXPANSION_LIMIT,
                        format!(
                            "Entry '{name}' exhibits suspicious compression ratio ({}:1), potential zip bomb",
                            ratio
                        ),
                        Some(name.clone()),
                        Some("Ensure archive contains standard compressed mod assets".to_string()),
                    );
                    report.stats.file_count = entries.len();
                    report.stats.total_uncompressed_bytes = total_uncompressed;
                    return Err(InspectorError::Format("Suspicious compression ratio".to_string()));
                }
            }

            // Safely read entry bytes with a bounded reader to guard against spoofed zip headers
            let mut content = Vec::new();
            let bytes_read = (&mut entry)
                .take(limits.max_file_uncompressed + 1)
                .read_to_end(&mut content)
                .map_err(|e| {
                    report.add_error(
                        DiagnosticCode::ARCHIVE_CORRUPTED,
                        format!("Failed reading archive entry '{name}': {e}"),
                        Some(name.clone()),
                        None,
                    );
                    InspectorError::Io(e)
                })? as u64;

            if bytes_read > limits.max_file_uncompressed {
                report.add_error(
                    DiagnosticCode::ARCHIVE_FILE_TOO_LARGE,
                    format!(
                        "Entry '{name}' decompressed beyond maximum permitted file size of {} MiB",
                        limits.max_file_uncompressed >> 20
                    ),
                    Some(name.clone()),
                    None,
                );
                report.stats.file_count = entries.len();
                report.stats.total_uncompressed_bytes = total_uncompressed;
                return Err(InspectorError::Format("Decompressed entry exceeds limit".to_string()));
            }

            total_uncompressed += bytes_read;
            total_compressed += compressed_size;
            if total_uncompressed > limits.max_total_uncompressed {
                report.add_error(
                    DiagnosticCode::ARCHIVE_EXPANSION_LIMIT,
                    format!(
                        "Archive total uncompressed bytes exceeded limit ({} MiB)",
                        limits.max_total_uncompressed >> 20
                    ),
                    Some(name.clone()),
                    None,
                );
                report.stats.file_count = entries.len();
                report.stats.total_uncompressed_bytes = total_uncompressed;
                return Err(InspectorError::Format("Cumulative expansion limit exceeded".to_string()));
            }

            // Cumulative compression-ratio sanity (H2)
            if total_compressed > 0 && total_uncompressed > 8 * 1024 * 1024 {
                let cumulative_ratio = total_uncompressed / total_compressed;
                if cumulative_ratio > 200 {
                    report.add_error(
                        DiagnosticCode::ARCHIVE_EXPANSION_LIMIT,
                        format!(
                            "Archive exhibits suspicious cumulative compression ratio ({}:1), potential zip bomb",
                            cumulative_ratio
                        ),
                        Some(name.clone()),
                        Some("Ensure archive contains standard compressed mod assets".to_string()),
                    );
                    report.stats.file_count = entries.len();
                    report.stats.total_uncompressed_bytes = total_uncompressed;
                    return Err(InspectorError::Format("Suspicious cumulative compression ratio".to_string()));
                }
            }

            entries.insert(name, content);

            // Incremental stats (L1)
            report.stats.file_count = entries.len();
            report.stats.total_uncompressed_bytes = total_uncompressed;
        }

        report.stats.file_count = entries.len();
        report.stats.total_uncompressed_bytes = total_uncompressed;

        Ok(Self {
            entries,
            total_uncompressed_bytes: total_uncompressed,
        })
    }

    /// Retrieves an entry's bytes by relative path.
    pub fn get_file(&self, name: &str) -> Option<&[u8]> {
        self.entries.get(name).map(Vec::as_slice)
    }

    /// Retrieves an entry as a UTF-8 string.
    pub fn get_str(&self, name: &str) -> Option<Result<&str, std::str::Utf8Error>> {
        self.entries.get(name).map(|b| std::str::from_utf8(b))
    }
}

/// Inspects the raw ZIP Central Directory directly from disk to detect duplicate filenames
/// that higher-level ZIP parser implementations might silently deduplicate or mask (H4).
pub fn scan_raw_zip_for_duplicates(path: &Path) -> Result<(), String> {
    use std::io::Seek;
    let mut file = File::open(path).map_err(|e| format!("SCAN_SKIPPED: {e}"))?;
    let file_len = file.metadata().map_err(|e| format!("SCAN_SKIPPED: {e}"))?.len();
    if file_len < 22 {
        return Err("SCAN_SKIPPED: file too small for EOCD".to_string());
    }

    // Search the trailing buffer (up to 65 KiB max comment + 22 byte EOCD)
    let search_len = file_len.min(65536 + 22) as usize;
    file.seek(std::io::SeekFrom::End(-(search_len as i64)))
        .map_err(|e| format!("SCAN_SKIPPED: {e}"))?;
    let mut buf = vec![0u8; search_len];
    file.read_exact(&mut buf).map_err(|e| format!("SCAN_SKIPPED: {e}"))?;

    let eocd_pos = buf.windows(4).rposition(|w| w == [0x50, 0x4b, 0x05, 0x06]);
    let eocd_pos = match eocd_pos {
        Some(p) => p,
        None => return Err("SCAN_SKIPPED: EOCD not found".to_string()),
    };

    if eocd_pos + 22 > buf.len() {
        return Err("SCAN_SKIPPED: truncated EOCD".to_string());
    }

    let eocd = &buf[eocd_pos..];
    let mut total_entries = u16::from_le_bytes([eocd[10], eocd[11]]) as usize;
    let mut cd_size = u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]) as u64;
    let mut cd_offset = u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]) as u64;

    // Zip64 EOCD support (H4): if sentinel values present, parse Zip64 EOCD via locator.
    let needs_zip64 = total_entries == 0xFFFF || cd_offset == 0xFFFFFFFF || cd_size == 0xFFFFFFFF;
    if needs_zip64 {
        // Find Zip64 EOCD locator (signature 0x07064b50) preceding the standard EOCD.
        let locator_sig = [0x50u8, 0x4b, 0x06, 0x07];
        let search_end = eocd_pos;
        let locator_pos = buf[..search_end].windows(4).rposition(|w| w == locator_sig);
        let locator_pos = match locator_pos {
            Some(p) => p,
            None => return Err("SCAN_SKIPPED: Zip64 locator not found".to_string()),
        };
        if locator_pos + 20 > buf.len() {
            return Err("SCAN_SKIPPED: truncated Zip64 locator".to_string());
        }
        let zip64_eocd_offset = u64::from_le_bytes([
            buf[locator_pos + 8],
            buf[locator_pos + 9],
            buf[locator_pos + 10],
            buf[locator_pos + 11],
            buf[locator_pos + 12],
            buf[locator_pos + 13],
            buf[locator_pos + 14],
            buf[locator_pos + 15],
        ]);
        // Seek and read Zip64 EOCD record (signature 0x06064b50)
        file.seek(std::io::SeekFrom::Start(zip64_eocd_offset))
            .map_err(|e| format!("SCAN_SKIPPED: {e}"))?;
        let mut z64 = [0u8; 56];
        file.read_exact(&mut z64).map_err(|e| format!("SCAN_SKIPPED: {e}"))?;
        if z64[0..4] != [0x50, 0x4b, 0x06, 0x06] {
            return Err("SCAN_SKIPPED: bad Zip64 EOCD signature".to_string());
        }
        total_entries = u64::from_le_bytes([
            z64[24], z64[25], z64[26], z64[27], z64[28], z64[29], z64[30], z64[31],
        ]) as usize;
        cd_size = u64::from_le_bytes([
            z64[40], z64[41], z64[42], z64[43], z64[44], z64[45], z64[46], z64[47],
        ]);
        cd_offset = u64::from_le_bytes([
            z64[48], z64[49], z64[50], z64[51], z64[52], z64[53], z64[54], z64[55],
        ]);
    }

    if cd_offset + cd_size > file_len {
        return Err("SCAN_SKIPPED: invalid central directory bounds".to_string());
    }

    file.seek(std::io::SeekFrom::Start(cd_offset))
        .map_err(|e| format!("SCAN_SKIPPED: {e}"))?;
    let mut cd_data = vec![0u8; cd_size as usize];
    file.read_exact(&mut cd_data).map_err(|e| format!("SCAN_SKIPPED: {e}"))?;

    let mut cursor = 0;
    let mut seen = std::collections::BTreeSet::new();
    let mut count = 0;
    let mut parse_error = false;

    while cursor + 46 <= cd_data.len() && count < total_entries {
        if &cd_data[cursor..cursor + 4] != [0x50, 0x4b, 0x01, 0x02] {
            parse_error = true;
            break;
        }
        let fn_len = u16::from_le_bytes([cd_data[cursor + 28], cd_data[cursor + 29]]) as usize;
        let extra_len = u16::from_le_bytes([cd_data[cursor + 30], cd_data[cursor + 31]]) as usize;
        let comment_len = u16::from_le_bytes([cd_data[cursor + 32], cd_data[cursor + 33]]) as usize;

        cursor += 46;
        if cursor + fn_len > cd_data.len() {
            parse_error = true;
            break;
        }

        let name = String::from_utf8_lossy(&cd_data[cursor..cursor + fn_len]).to_string();
        cursor += fn_len + extra_len + comment_len;
        count += 1;

        if !seen.insert(name.clone()) {
            return Err(name);
        }
    }

    if parse_error {
        return Err("SCAN_SKIPPED: central directory parse failure".to_string());
    }

    Ok(())
}

/// Computes file size and lowercase SHA-256 hash.
pub fn compute_file_stats(path: &Path) -> Result<(u64, String), std::io::Error> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let hash = format!("{:x}", hasher.finalize());
    Ok((size, hash))
}
