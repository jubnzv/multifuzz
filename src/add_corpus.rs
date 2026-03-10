use crate::AddCorpus;
use anyhow::Result;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use twox_hash::XxHash64;

impl AddCorpus {
    fn output_target(&self) -> String {
        format!("{}/{}", self.output.display(), self.target)
    }

    pub fn add_corpus(&self) -> Result<()> {
        let files = self.collect_input_files();
        if files.is_empty() {
            eprintln!("No input files found.");
            return Ok(());
        }

        let max_len = self.max_input_size as u64;
        let mut added = 0u64;
        let mut dupes = 0u64;
        let mut too_large = 0u64;

        let corpus_dir = format!("{}/corpus", self.output_target());
        fs::create_dir_all(&corpus_dir)?;

        // Determine which engine dirs to write to.
        let hfuzz_queue = if !self.no_honggfuzz {
            let d = format!("{}/queue", self.output_target());
            fs::create_dir_all(&d)?;
            Some(d)
        } else {
            None
        };

        let lf_corpus = if !self.no_libfuzzer {
            let d = format!("{}/libfuzzer/corpus", self.output_target());
            fs::create_dir_all(&d)?;
            Some(d)
        } else {
            None
        };

        // When only AFL++ is enabled (no honggfuzz/libfuzzer whose dirs AFL
        // syncs via -F), write directly into AFL's queue.
        let afl_queue = if !self.no_afl && self.no_honggfuzz && self.no_libfuzzer {
            let d = format!("{}/afl/mainaflfuzzer/queue", self.output_target());
            fs::create_dir_all(&d)?;
            Some(d)
        } else {
            None
        };

        for file in &files {
            let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
            if file_len > max_len {
                too_large += 1;
                continue;
            }

            let bytes = fs::read(file).unwrap_or_default();
            let hash = XxHash64::oneshot(0, &bytes);
            let hash_name = format!("{hash:x}");

            // Shared corpus (dedup check)
            let corpus_path = format!("{corpus_dir}/{hash_name}");
            if Path::new(&corpus_path).exists() {
                dupes += 1;
                continue;
            }
            fs::copy(file, &corpus_path)?;

            if let Some(ref dir) = hfuzz_queue {
                let _ = fs::copy(file, format!("{dir}/{hash_name}"));
            }
            if let Some(ref dir) = lf_corpus {
                let _ = fs::copy(file, format!("{dir}/{hash_name}"));
            }
            if let Some(ref dir) = afl_queue {
                let _ = fs::copy(file, format!("{dir}/id:external_{hash_name}"));
            }

            added += 1;
        }

        eprintln!("Added {added} new file(s) ({dupes} duplicates, {too_large} too large).");
        Ok(())
    }

    fn collect_input_files(&self) -> Vec<PathBuf> {
        let mut dirs = self.inputs.clone();

        if self.recursive {
            let mut all_dirs = HashSet::new();
            for input in &self.inputs {
                all_dirs.insert(input.clone());
                collect_dirs_recursively(input, &mut all_dirs);
            }
            for dir in all_dirs {
                if !dirs.contains(&dir) {
                    dirs.push(dir);
                }
            }
        }

        dirs.iter()
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
            .collect()
    }
}

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
