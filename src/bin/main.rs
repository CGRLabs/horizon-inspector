//! CLI frontend for the Horizon Mod Inspector (`horizon-inspect`).

use horizon_inspector::{
    InspectionReport, InspectorConfig, PackageKind, inspect_package,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!(
        r#"horizon-inspect v{VERSION} — Horizon Mod Package Inspector
Inspect, validate, and analyze Horizon mod packages (.hmod, .hnmod, .hpack, .hshader, .zip)

USAGE:
    horizon-inspect <FILE> [OPTIONS]

ARGUMENTS:
    <FILE>                          Package file to inspect

OPTIONS:
    --json                          Output report in machine-readable JSON format
    --format <text|json>            Choose output format (default: text)
    --kind <KIND>                   Override format (mod|native-mod|modpack|shader|resourcepack)
    --expected-sha256 <HEX>         Verify calculated SHA-256 against expected hash
    --expected-size <BYTES>         Verify file size against expected byte count
    --key <PUBLIC_KEY>              Minisign Ed25519 public key to verify signature
    --signature <PATH>              Path to .minisig signature file
    --target-hooks-api <LEVEL>      Authoritative target Horizon native hooks API level
    --max-entries <N>               Override maximum archive entries limit
    --max-uncompressed <BYTES>      Override maximum uncompressed bytes limit
    --max-file-size <BYTES>         Override maximum compressed file size limit
    --strict                        Treat warnings as validation errors (non-zero exit)
    --revocation-list <PATH>        Check against a local revoked.toml
    -q, --quiet                     Suppress diagnostic output if package is valid
    --export <PATH>                 Write the report to a file. Format is derived from the
                                    extension: .html, .json, .txt (default: .json).
    -h, --help                      Print this help guide
    -v, --version                   Print version information

EXIT CODES:
    0                               Package is valid (0 errors)
    1                               Package has validation errors (or warnings with --strict)
    2                               CLI usage error or unreadable target path
"#
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return if args.is_empty() {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }

    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("horizon-inspect {VERSION}");
        return ExitCode::SUCCESS;
    }

    let mut target_file: Option<String> = None;
    let mut json_output = false;
    let mut strict_mode = false;
    let mut quiet_mode = false;
    let mut export_path: Option<String> = None;
    let mut config = InspectorConfig::default();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--json" => {
                json_output = true;
            }
            "--format" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --format requires an argument (text or json)");
                    return ExitCode::from(2);
                }
                match args[i].to_ascii_lowercase().as_str() {
                    "json" => json_output = true,
                    "text" => json_output = false,
                    other => {
                        eprintln!("error: invalid format '{other}', expected 'text' or 'json'");
                        return ExitCode::from(2);
                    }
                }
            }
            "--kind" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --kind requires an argument");
                    return ExitCode::from(2);
                }
                let kind = match args[i].to_ascii_lowercase().as_str() {
                    "mod" | "content-mod" | "hmod" => PackageKind::ContentMod,
                    "native-mod" | "native" | "hnmod" => PackageKind::NativeMod,
                    "modpack" | "pack" | "hpack" => PackageKind::Modpack,
                    "shader" | "hshader" => PackageKind::Shader,
                    "resourcepack" | "resource-pack" | "zip" => PackageKind::ResourcePack,
                    other => {
                        eprintln!("error: unknown package kind '{other}'");
                        return ExitCode::from(2);
                    }
                };
                config.forced_kind = Some(kind);
            }
            "--expected-sha256" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --expected-sha256 requires a hex hash argument");
                    return ExitCode::from(2);
                }
                config.expected_sha256 = Some(args[i].clone());
            }
            "--expected-size" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --expected-size requires a byte count argument");
                    return ExitCode::from(2);
                }
                match args[i].parse::<u64>() {
                    Ok(size) => config.expected_size = Some(size),
                    Err(e) => {
                        eprintln!("error: invalid byte count for --expected-size: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--key" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --key requires a Minisign public key");
                    return ExitCode::from(2);
                }
                config.public_key = Some(args[i].clone());
            }
            "--signature" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --signature requires a file path");
                    return ExitCode::from(2);
                }
                config.signature_path = Some(PathBuf::from(&args[i]));
            }
            "--target-hooks-api" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --target-hooks-api requires an integer level");
                    return ExitCode::from(2);
                }
                match args[i].parse::<u32>() {
                    Ok(level) => config.target_hooks_api = Some(level),
                    Err(e) => {
                        eprintln!("error: invalid level for --target-hooks-api: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--max-entries" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --max-entries requires an integer count");
                    return ExitCode::from(2);
                }
                match args[i].parse::<usize>() {
                    Ok(entries) => config.max_entries = Some(entries),
                    Err(e) => {
                        eprintln!("error: invalid count for --max-entries: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--max-uncompressed" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --max-uncompressed requires a byte count");
                    return ExitCode::from(2);
                }
                match args[i].parse::<u64>() {
                    Ok(bytes) => config.max_uncompressed = Some(bytes),
                    Err(e) => {
                        eprintln!("error: invalid byte count for --max-uncompressed: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--max-file-size" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --max-file-size requires a byte count");
                    return ExitCode::from(2);
                }
                match args[i].parse::<u64>() {
                    Ok(bytes) => config.max_file_size = Some(bytes),
                    Err(e) => {
                        eprintln!("error: invalid byte count for --max-file-size: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--strict" => {
                strict_mode = true;
            }
            "--revocation-list" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --revocation-list requires a file path");
                    return ExitCode::from(2);
                }
                config.revocation_list = Some(PathBuf::from(&args[i]));
            }
            "--quiet" | "-q" => {
                quiet_mode = true;
            }
            "--export" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --export requires a file path");
                    return ExitCode::from(2);
                }
                export_path = Some(args[i].clone());
            }
            other if !other.starts_with('-') => {
                if target_file.is_some() {
                    eprintln!("error: multiple target files specified ('{}' and '{other}')", target_file.unwrap());
                    return ExitCode::from(2);
                }
                target_file = Some(other.to_string());
            }
            other => {
                eprintln!("error: unrecognized option '{other}'. Use --help for usage.");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let target = match target_file {
        Some(t) => t,
        None => {
            eprintln!("error: no package file specified");
            print_usage();
            return ExitCode::from(2);
        }
    };

    let target_path = Path::new(&target);
    // Default to the current upstream NATIVE_HOOKS_API level when not specified,
    // so native mods are cross-checked out of the box.
    if config.target_hooks_api.is_none() {
        config.target_hooks_api = Some(horizon_inspector::DEFAULT_TARGET_HOOKS_API);
    }

    let report = inspect_package(target_path, &config);

    if json_output {
        match report.to_json() {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("error: failed to serialize report to JSON: {e}");
                return ExitCode::from(2);
            }
        }
    } else if !quiet_mode || !report.is_valid || (strict_mode && report.stats.warning_count > 0) {
        print!("{}", report.to_terminal_text());
    }

    // Optional file export. Format is derived from the extension; defaults to JSON.
    if let Some(ref path) = export_path {
        if let Err(e) = write_export(path, &report) {
            eprintln!("error: failed to write export to '{path}': {e}");
            return ExitCode::from(2);
        }
    }

    if !report.is_valid {
        ExitCode::from(1)
    } else if strict_mode && report.stats.warning_count > 0 {
        eprintln!("error: package inspection passed with warnings and --strict was specified");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Serialize `report` to `path`, choosing the format from the file extension.
/// `.html` produces an HTML report, `.txt` produces the terminal rendering,
/// and anything else (including no extension) defaults to pretty JSON.
fn write_export(path: &str, report: &InspectionReport) -> Result<(), std::io::Error> {
    let path_buf = Path::new(path);
    let ext = path_buf.extension().and_then(|s| s.to_str()).unwrap_or("");

    let content = match ext.to_ascii_lowercase().as_str() {
        "html" => report.to_html(),
        "txt" => report.to_text(),
        _ => match report.to_json_pretty() {
            Ok(json) => json,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        },
    };

    // Create parent directories if needed so the export is drag-and-drop friendly.
    if let Some(parent) = path_buf.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| e)?;
        }
    }
    std::fs::write(path, content).map_err(|e| e)?;
    Ok(())
}
