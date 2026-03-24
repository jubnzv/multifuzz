//! Corpus sync directories (all under {output}/{target}/):
//!
//! AFL:
//!   afl/master/queue/  — AFL main queue. Source for syncing to other engines.
//!                               Inbound sync from hongg/libfuzzer is handled by AFL's -F flag.
//! Honggfuzz:
//!   honggfuzz/corpus/         — hongg output corpus. Source for syncing FROM hongg.
//!   honggfuzz/dynamic_input/  — hongg --dynamic_input dir. Polled by hongg, files DELETED after ingestion:
//!                               https://github.com/google/honggfuzz/blob/f0314885bab1a4d9aa64eda51ba100b98aa360b0/input.c#L712-L713
//!                               This is the sync TARGET for feeding new inputs to hongg.
//! Libfuzzer:
//!   libfuzzer/corpus/         — libfuzzer corpus dir. Both source AND target.
//!                               libfuzzer re-scans it periodically (-reload=1).
//! External:
//!   User-supplied --external-corpus dirs. Source only.

use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::{fs, io::Write};
use twox_hash::XxHash64;

/// Sync new files from `source_dirs` into `dest_dir`.
///
/// - Time-filters: only files with mtime > `since`
/// - Size-filters: skip files > `max_len` or empty
/// - Hash-deduplicates via `seen_hashes` (shared across all sync targets)
/// - Atomic write: tmp file + rename
///
/// On first call (`seen_hashes` is empty), seeds it by scanning `source_dirs`.
/// Returns the newest file mtime seen (pass as `since` on next cycle).
pub fn sync_files(
    source_dirs: &[PathBuf],
    dest_dir: &Path,
    since: Option<SystemTime>,
    max_len: u64,
    seen_hashes: &mut HashSet<u64>,
) -> Result<Option<SystemTime>> {
    if !dest_dir.exists() {
        fs::create_dir_all(dest_dir)?;
    }

    // Seed hashes from source dirs on first call.
    if seen_hashes.is_empty() {
        for dir in source_dirs {
            seed_hashes_from_dir(dir, seen_hashes);
        }
    }

    let mut newest = since;

    for dir in source_dirs {
        if !dir.exists() {
            continue;
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // Time filter.
            if let Some(cutoff) = since {
                let mtime = path
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                if mtime <= cutoff {
                    continue;
                }
            }

            // Size filter.
            let file_len = path.metadata().map(|m| m.len()).unwrap_or(0);
            if file_len == 0 || file_len > max_len {
                continue;
            }

            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let hash = XxHash64::oneshot(0, &bytes);

            if !seen_hashes.insert(hash) {
                continue; // already seen
            }

            // Track newest mtime.
            if let Ok(mtime) = path.metadata().and_then(|m| m.modified()) {
                if newest.is_none_or(|t| mtime > t) {
                    newest = Some(mtime);
                }
            }

            // Atomic write: tmp + rename.
            let dest_path = dest_dir.join(format!("sync_{hash:x}"));
            if dest_path.exists() {
                continue;
            }
            let tmp_path = dest_dir.join(format!(".sync_tmp_{hash:x}"));
            if let Ok(mut f) = fs::File::create(&tmp_path) {
                if f.write_all(&bytes).is_ok() {
                    let _ = fs::rename(&tmp_path, &dest_path);
                } else {
                    let _ = fs::remove_file(&tmp_path);
                }
            }
        }
    }

    Ok(newest)
}

/// Collect files from external corpus directories, optionally recursive.
/// Only files modified after `since` are returned.
pub fn collect_external_files(
    dirs: &[PathBuf],
    recursive: bool,
    since: Option<SystemTime>,
) -> Vec<PathBuf> {
    let mut scan_dirs: Vec<PathBuf> = dirs.to_vec();

    if recursive {
        let mut all_dirs = HashSet::new();
        for dir in dirs {
            all_dirs.insert(dir.clone());
            collect_dirs_recursively(dir, &mut all_dirs);
        }
        for dir in all_dirs {
            if !scan_dirs.contains(&dir) {
                scan_dirs.push(dir);
            }
        }
    }

    scan_dirs
        .iter()
        .flat_map(|path| {
            if path.is_dir() {
                fs::read_dir(path)
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.is_file())
                    .collect::<Vec<_>>()
            } else {
                vec![path.clone()]
            }
        })
        .filter(|p| {
            since.is_none_or(|t| {
                p.metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|mt| mt > t)
            })
        })
        .collect()
}

/// Recursively collect all directories under `dir`.
fn collect_dirs_recursively(dir: &Path, dir_list: &mut HashSet<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && dir_list.insert(path.clone()) {
                collect_dirs_recursively(&path, dir_list);
            }
        }
    }
}

fn seed_hashes_from_dir(dir: &Path, hashes: &mut HashSet<u64>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(bytes) = fs::read(&path) {
                    hashes.insert(XxHash64::oneshot(0, &bytes));
                }
            }
        }
    }
}
