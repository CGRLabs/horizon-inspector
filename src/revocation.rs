//! Offline revocation list support (revoked.toml).

use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct RevokedEntry {
    pub id: Option<String>,
    pub sha256: Option<String>,
    pub reason: Option<String>,
}

pub fn load(path: &Path) -> Result<Vec<RevokedEntry>, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut entries = Vec::new();
    let mut current: Option<RevokedEntry> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("[[") && line.ends_with("]]") {
            if let Some(e) = current.take() {
                entries.push(e);
            }
            current = Some(RevokedEntry { id: None, sha256: None, reason: None });
            continue;
        }
        if let Some(ref mut e) = current {
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'');
                match key {
                    "id" => e.id = Some(val.to_string()),
                    "sha256" => e.sha256 = Some(val.to_lowercase()),
                    "reason" => e.reason = Some(val.to_string()),
                    _ => {}
                }
            }
        }
    }
    if let Some(e) = current {
        entries.push(e);
    }
    Ok(entries)
}

pub fn find_revoked<'a>(
    entries: &'a [RevokedEntry],
    id: Option<&str>,
    sha256: &str,
) -> Option<&'a RevokedEntry> {
    for e in entries {
        let id_ok = e.id.as_deref().map(|i| Some(i) == id).unwrap_or(true);
        let hash_ok = e.sha256.as_deref().map(|h| h == sha256).unwrap_or(true);
        if id_ok && hash_ok {
            return Some(e);
        }
    }
    None
}