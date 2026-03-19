use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[derive(Deserialize, Default)]
pub struct ConfigFile {
    pub fuzz: Option<FuzzConfig>,
}

#[derive(Deserialize, Default)]
pub struct FuzzConfig {
    pub target: Option<String>,
    pub jobs: Option<u32>,
    pub corpus: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub timeout: Option<u32>,
    pub max_input_size: Option<u32>,
    pub sync_interval: Option<u64>,
    pub dictionaries: Option<Vec<PathBuf>>,
    pub external_corpus: Option<Vec<PathBuf>>,
    pub external_corpus_recursive: Option<bool>,
    pub engines: Option<EnginesConfig>,
    pub web: Option<WebConfig>,
    /// Per-worker AFL++ configuration. Keys: "all" or "workerN".
    /// e.g. [fuzz.afl.all.env], [fuzz.afl.worker2.env]
    pub afl: Option<HashMap<String, AflWorkerConfig>>,
}

#[derive(Deserialize, Default)]
pub struct EnginesConfig {
    pub no_afl: Option<bool>,
    pub no_honggfuzz: Option<bool>,
    pub no_libfuzzer: Option<bool>,
}

#[derive(Deserialize, Default)]
pub struct WebConfig {
    pub enabled: Option<bool>,
    pub port: Option<u16>,
}

#[derive(Clone, Deserialize, Default)]
pub struct AflWorkerConfig {
    /// Full command override. When set, replaces all auto-generated args.
    /// Executed via `sh -c`.
    pub command: Option<String>,
    /// Env vars for this worker (or all workers if key is "all").
    pub env: Option<HashMap<String, String>>,
}

/// Parsed AFL worker configs: the "all" config + per-worker configs.
pub type AflWorkerConfigs = HashMap<u32, AflWorkerConfig>;

/// Parse the `[fuzz.afl.*]` map into (all_config, per_worker_configs).
///
/// Accepts "all" and "workerN" keys. Rejects "even"/"odd".
pub fn parse_afl_worker_configs(
    afl: &HashMap<String, AflWorkerConfig>,
) -> Result<(Option<AflWorkerConfig>, AflWorkerConfigs)> {
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
                        anyhow!(
                            "unknown AFL config key: '{key}' (expected 'all' or 'workerN')"
                        )
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
    all: &Option<AflWorkerConfig>,
    worker: Option<&AflWorkerConfig>,
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

/// Load config from explicit path, `./multifuzz.toml`, or return default.
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
            eprintln!("    Loading config from ./multifuzz.toml");
            default
        }
    };

    let contents =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let cfg: ConfigFile =
        toml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))?;
    Ok(cfg)
}
