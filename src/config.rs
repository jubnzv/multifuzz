use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process;

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
    pub strategy: Option<String>,
    pub duration: Option<u64>,
    pub sync_interval: Option<u64>,
    pub dictionaries: Option<Vec<PathBuf>>,
    pub external_corpus: Option<Vec<PathBuf>>,
    pub external_corpus_recursive: Option<bool>,
    pub engines: Option<EnginesConfig>,
    pub web: Option<WebConfig>,
    /// Per-worker AFL++ env overrides. Keys: "all", "even", "odd", "workerN".
    /// e.g. [fuzz.afl.worker2.env]
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

#[derive(Clone, Deserialize)]
pub struct AflWorkerConfig {
    pub env: Option<HashMap<String, String>>,
}

// ── Selector ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum WorkerSelector {
    All,
    Even,
    Odd,
    Single(u32),
}

impl WorkerSelector {
    /// Parse a TOML key like "all", "even", "odd", "worker2".
    fn from_key(key: &str) -> Result<Self> {
        match key {
            "all" => Ok(Self::All),
            "even" => Ok(Self::Even),
            "odd" => Ok(Self::Odd),
            _ => {
                let n = key
                    .strip_prefix("worker")
                    .ok_or_else(|| {
                        anyhow!(
                            "unknown AFL worker key: '{key}' \
                             (expected 'all', 'even', 'odd', or 'workerN')"
                        )
                    })?
                    .parse::<u32>()
                    .with_context(|| format!("invalid worker number in key: '{key}'"))?;
                Ok(Self::Single(n))
            }
        }
    }

    pub fn matches(&self, job_num: u32) -> bool {
        match self {
            Self::All => true,
            Self::Even => job_num.is_multiple_of(2),
            Self::Odd => job_num % 2 == 1,
            Self::Single(n) => job_num == *n,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AflEnvRule {
    pub key: String,
    pub value: String,
    pub selector: WorkerSelector,
}

/// Parse the `[fuzz.afl.*]` map into a flat vec of env rules.
pub fn parse_afl_env_rules(afl: &HashMap<String, AflWorkerConfig>) -> Result<Vec<AflEnvRule>> {
    let mut rules = Vec::new();
    for (worker_key, config) in afl {
        let selector = WorkerSelector::from_key(worker_key)?;
        if let Some(env) = &config.env {
            for (k, v) in env {
                rules.push(AflEnvRule {
                    key: k.clone(),
                    value: v.clone(),
                    selector: selector.clone(),
                });
            }
        }
    }
    Ok(rules)
}

/// Apply matching AFL env rules to a [`process::Command`].
pub fn apply_afl_env_rules(cmd: &mut process::Command, job_num: u32, rules: &[AflEnvRule]) {
    for rule in rules {
        if rule.selector.matches(job_num) {
            cmd.env(&rule.key, &rule.value);
            if rule.key == "AFL_TMPDIR" {
                let _ = std::fs::create_dir_all(&rule.value);
            }
        }
    }
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
