use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub build: Option<BuildConfig>,
    pub fuzz: Option<FuzzConfig>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    pub always_build: Option<bool>,
    pub afl: Option<String>,
    pub afl_cmplog: Option<String>,
    pub honggfuzz: Option<String>,
    pub libfuzzer: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FuzzConfig {
    pub target: Option<String>,
    pub corpus: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub timeout: Option<u32>,
    pub max_input_size: Option<u32>,
    pub sync_interval: Option<u64>,
    pub dictionaries: Option<Vec<PathBuf>>,
    pub external_corpus: Option<Vec<PathBuf>>,
    pub external_corpus_recursive: Option<bool>,
    pub no_colors: Option<bool>,
    /// Honggfuzz config: [fuzz.honggfuzz.worker]. Present = enabled.
    pub honggfuzz: Option<SatelliteEngineConfig>,
    /// Libfuzzer config: [fuzz.libfuzzer.worker]. Present = enabled.
    pub libfuzzer: Option<SatelliteEngineConfig>,
    /// Per-worker AFL++ configuration. Keys: "all" or "workerN".
    /// e.g. [fuzz.afl.all.env], [fuzz.afl.worker2.env]
    pub afl: Option<HashMap<String, WorkerConfig>>,
}

#[derive(Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SatelliteEngineConfig {
    pub worker: Option<WorkerConfig>,
}

/// Worker config shared by ALL engines (AFL, honggfuzz, libfuzzer).
#[derive(Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    /// Full command override. When set, replaces all auto-generated args.
    /// Executed via `sh -c`.
    pub command: Option<String>,
    /// Extra CLI args appended to the auto-generated command.
    pub args: Option<String>,
    /// Env vars for this worker (or all workers if key is "all").
    pub env: Option<HashMap<String, String>>,
}

/// Parsed AFL worker configs: the "all" config + per-worker configs.
pub type AflWorkerConfigs = HashMap<u32, WorkerConfig>;

/// Parse the `[fuzz.afl.*]` map into (all_config, per_worker_configs).
///
/// Accepts "all" and "workerN" keys. Rejects "even"/"odd".
pub fn parse_afl_worker_configs(
    afl: &HashMap<String, WorkerConfig>,
) -> Result<(Option<WorkerConfig>, AflWorkerConfigs)> {
    let mut all_config = None;
    let mut workers = HashMap::new();
    for (key, config) in afl {
        match key.as_str() {
            "all" => {
                all_config = Some(config.clone());
            }
            "even" | "odd" => {
                return Err(anyhow!(
                    "AFL config key '{key}' is no longer supported. \
                     Use 'all' or per-worker keys: [fuzz.afl.worker0], [fuzz.afl.worker1], etc."
                ));
            }
            _ => {
                let n = key
                    .strip_prefix("worker")
                    .ok_or_else(|| {
                        anyhow!("unknown AFL config key: '{key}' (expected 'all' or 'workerN')")
                    })?
                    .parse::<u32>()
                    .with_context(|| format!("invalid worker number in key: '{key}'"))?;
                workers.insert(n, config.clone());
            }
        }
    }
    Ok((all_config, workers))
}

/// Merge `all.env` + `workerN.env` into a sorted map. Worker-specific values win on conflict.
pub fn resolve_afl_env(
    all: &Option<WorkerConfig>,
    worker: Option<&WorkerConfig>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    if let Some(all_cfg) = all {
        if let Some(all_env) = &all_cfg.env {
            env.extend(all_env.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
    }
    if let Some(w_cfg) = worker {
        if let Some(w_env) = &w_cfg.env {
            env.extend(w_env.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
    }
    env
}

/// Rebase a relative path so it is relative to `base` instead of CWD.
fn rebase(base: &Path, p: PathBuf) -> PathBuf {
    if p.is_absolute() {
        p
    } else {
        base.join(p)
    }
}

/// Load config from explicit path, `./multifuzz.toml`, or return default.
///
/// Relative paths inside the config are resolved relative to the config
/// file's parent directory, NOT the current working directory.
pub fn load_config(explicit_path: Option<&Path>) -> Result<ConfigFile> {
    let path = match explicit_path {
        Some(p) => {
            if !p.exists() {
                return Err(anyhow!("Config file not found: {}", p.display()));
            }
            p.to_path_buf()
        }
        None => {
            let default = PathBuf::from("multifuzz.toml");
            if !default.exists() {
                return Ok(ConfigFile::default());
            }
            default
        }
    };

    // Canonicalize so that the base dir is absolute even when the config
    // path itself was given as a relative path.
    let path = path
        .canonicalize()
        .with_context(|| format!("canonicalizing config path {}", path.display()))?;
    let base = path
        .parent()
        .ok_or_else(|| anyhow!("config path has no parent dir: {}", path.display()))?;

    let contents =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut cfg: ConfigFile =
        toml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))?;

    // Rebase all relative paths in [fuzz] so they resolve from the config
    // file's directory rather than from the process CWD.
    if let Some(fuzz) = &mut cfg.fuzz {
        if let Some(p) = fuzz.corpus.take() {
            fuzz.corpus = Some(rebase(base, p));
        }
        if let Some(p) = fuzz.output.take() {
            fuzz.output = Some(rebase(base, p));
        }
        if let Some(dicts) = fuzz.dictionaries.take() {
            fuzz.dictionaries = Some(dicts.into_iter().map(|p| rebase(base, p)).collect());
        }
        if let Some(dirs) = fuzz.external_corpus.take() {
            fuzz.external_corpus = Some(dirs.into_iter().map(|p| rebase(base, p)).collect());
        }
    }

    Ok(cfg)
}
