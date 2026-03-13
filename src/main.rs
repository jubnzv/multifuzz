mod build;
mod config;
mod fuzz;
mod run;
mod ui;
mod web;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Default, PartialEq, clap::ValueEnum)]
pub enum Strategy {
    #[default]
    Parallel,
    Sequential,
    #[clap(name = "afl-only")]
    AflOnly,
    #[clap(name = "hongg-only")]
    HonggOnly,
    #[clap(name = "libfuzzer-only")]
    LibfuzzerOnly,
}

pub const DEFAULT_OUTPUT_DIR: &str = "./output";
pub const DEFAULT_MAX_INPUT_SIZE: u32 = 8192;

#[derive(Parser)]
#[clap(
    name = "multifuzz",
    version,
    about = "Multi-engine fuzzer orchestrator"
)]
pub struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Build the fuzzer and runner binaries
    Build(Build),
    /// Fuzz a target using AFL++ and honggfuzz in parallel
    Fuzz(Box<Fuzz>),
    /// Run specific inputs through the runner binary
    Run(Run),
}

#[derive(clap::Args)]
pub struct Build {
    /// Disable AFL++
    #[clap(long = "no-afl", action)]
    no_afl: bool,
    /// Disable honggfuzz
    #[clap(long = "no-honggfuzz", action)]
    no_honggfuzz: bool,
    /// Disable libfuzzer
    #[clap(long = "no-libfuzzer", action)]
    no_libfuzzer: bool,
}

#[derive(clap::Args)]
pub struct Fuzz {
    /// Target binary name to fuzz
    #[clap(value_name = "TARGET")]
    target: Option<String>,
    /// Path to TOML config file (default: ./multifuzz.toml if present)
    #[clap(short = 'c', long = "config", value_name = "FILE")]
    config: Option<PathBuf>,
    /// Number of concurrent fuzzing jobs
    #[clap(short, long, value_name = "NUM")]
    jobs: Option<u32>,
    /// Shared corpus directory
    #[clap(short = 'i', long = "corpus", value_name = "DIR")]
    corpus: Option<PathBuf>,
    /// Fuzzers output directory
    #[clap(short = 'o', long = "output", value_name = "DIR")]
    output: Option<PathBuf>,
    /// Dictionary file(s); may be repeated (e.g. -x a.dict -x b.dict)
    #[clap(short = 'x', long = "dict", value_name = "FILE", action = clap::ArgAction::Append)]
    dictionaries: Vec<PathBuf>,
    #[clap(skip)]
    merged_dict: Option<PathBuf>,
    /// Monotonically increasing AFL job counter (avoids output dir collisions on scale).
    #[clap(skip)]
    next_afl_job_num: u32,
    /// Timeout for a single run in seconds
    #[clap(short, long, value_name = "SECS")]
    timeout: Option<u32>,
    /// Disable AFL++
    #[clap(long = "no-afl", action)]
    no_afl: bool,
    /// Disable honggfuzz
    #[clap(long = "no-honggfuzz", action)]
    no_honggfuzz: bool,
    /// Disable libfuzzer
    #[clap(long = "no-libfuzzer", action)]
    no_libfuzzer: bool,
    /// Maximum input size in bytes
    #[clap(long = "max-input-size", value_name = "BYTES")]
    max_input_size: Option<u32>,
    /// Corpus sync interval in minutes
    #[clap(long = "sync-interval", value_name = "MINS")]
    sync_interval: Option<u64>,
    /// External corpus directories to import during each sync cycle.
    /// Files are hash-deduplicated, size-filtered (--max-input-size), and
    /// only files modified since the last sync are considered — so adding
    /// new files to the directory between syncs is cheap.
    #[clap(short = 'e', long = "external-corpus", value_name = "DIR", action = clap::ArgAction::Append)]
    external_corpus: Vec<PathBuf>,
    /// Recursively traverse external corpus directories
    #[clap(long = "external-corpus-recursive")]
    external_corpus_recursive: bool,
    /// Execution strategy: parallel (default) runs all engines at once;
    /// sequential runs each engine one at a time with all jobs
    #[clap(long, value_enum)]
    strategy: Option<Strategy>,
    /// Total session duration in minutes (required with --strategy sequential)
    #[clap(long = "duration", value_name = "MINS")]
    duration: Option<u64>,
    /// Enable web dashboard (auto-refreshing HTML page)
    #[clap(long = "web", action)]
    web: bool,
    /// Port for the web dashboard
    #[clap(long = "web-port", value_name = "PORT")]
    web_port: Option<u16>,
    /// Parsed AFL env rules from TOML config (not a CLI flag).
    #[clap(skip)]
    afl_env_rules: Vec<config::AflEnvRule>,
}

impl Fuzz {
    /// Merge TOML config into self, with CLI args taking priority.
    pub fn resolve_config(&mut self) -> Result<()> {
        let cfg = config::load_config(self.config.as_deref())?;
        let toml = cfg.fuzz.unwrap_or_default();

        // target: CLI positional wins, else TOML
        if self.target.is_none() {
            self.target = toml.target;
        }

        // Option fields: CLI if Some, else TOML
        if self.corpus.is_none() {
            self.corpus = toml.corpus;
        }
        if self.output.is_none() {
            self.output = toml.output;
        }
        if self.timeout.is_none() {
            self.timeout = toml.timeout;
        }
        if self.duration.is_none() {
            self.duration = toml.duration;
        }

        // Fields with defaults: CLI if Some, else TOML, else hardcoded default
        self.jobs = Some(self.jobs.or(toml.jobs).unwrap_or(1));
        self.max_input_size = Some(
            self.max_input_size
                .or(toml.max_input_size)
                .unwrap_or(DEFAULT_MAX_INPUT_SIZE),
        );
        self.sync_interval = Some(self.sync_interval.or(toml.sync_interval).unwrap_or(60));
        self.web_port = Some(
            self.web_port
                .or(toml.web.as_ref().and_then(|w| w.port))
                .unwrap_or(8080),
        );

        // Strategy
        if self.strategy.is_none() {
            self.strategy = toml.strategy.as_deref().and_then(|s| match s {
                "parallel" => Some(Strategy::Parallel),
                "sequential" => Some(Strategy::Sequential),
                "afl-only" => Some(Strategy::AflOnly),
                "hongg-only" => Some(Strategy::HonggOnly),
                "libfuzzer-only" => Some(Strategy::LibfuzzerOnly),
                _ => None,
            });
        }
        self.strategy = Some(self.strategy.unwrap_or(Strategy::Parallel));

        // Output defaults
        if self.output.is_none() {
            self.output = Some(PathBuf::from(DEFAULT_OUTPUT_DIR));
        }

        // Bool flags: CLI true wins, else TOML
        if !self.no_afl {
            self.no_afl = toml
                .engines
                .as_ref()
                .and_then(|e| e.no_afl)
                .unwrap_or(false);
        }
        if !self.no_honggfuzz {
            self.no_honggfuzz = toml
                .engines
                .as_ref()
                .and_then(|e| e.no_honggfuzz)
                .unwrap_or(false);
        }
        if !self.no_libfuzzer {
            self.no_libfuzzer = toml
                .engines
                .as_ref()
                .and_then(|e| e.no_libfuzzer)
                .unwrap_or(false);
        }

        // Vec fields: CLI non-empty wins, else TOML
        if self.dictionaries.is_empty() {
            self.dictionaries = toml.dictionaries.unwrap_or_default();
        }
        if self.external_corpus.is_empty() {
            self.external_corpus = toml.external_corpus.unwrap_or_default();
        }
        if !self.external_corpus_recursive {
            self.external_corpus_recursive = toml.external_corpus_recursive.unwrap_or(false);
        }

        // Web
        if !self.web {
            self.web = toml.web.as_ref().and_then(|w| w.enabled).unwrap_or(false);
        }

        // AFL env rules (TOML only)
        self.afl_env_rules = toml
            .afl
            .as_ref()
            .map(config::parse_afl_env_rules)
            .transpose()?
            .unwrap_or_default();

        Ok(())
    }

    // Accessors for resolved Option<T> fields (guaranteed Some after resolve_config).
    pub fn jobs(&self) -> u32 {
        self.jobs.unwrap()
    }
    pub fn max_input_size(&self) -> u32 {
        self.max_input_size.unwrap()
    }
    pub fn sync_interval(&self) -> u64 {
        self.sync_interval.unwrap()
    }
    pub fn web_port(&self) -> u16 {
        self.web_port.unwrap()
    }
    pub fn strategy(&self) -> Strategy {
        self.strategy.unwrap()
    }
    pub fn output(&self) -> &Path {
        self.output.as_deref().unwrap()
    }
    pub fn target(&self) -> &str {
        self.target.as_deref().unwrap()
    }
}

#[derive(clap::Args)]
pub struct Run {
    /// Target binary name
    #[clap(value_name = "TARGET")]
    target: String,
    /// Input files or directories to replay
    #[clap(short = 'i', long = "inputs", value_name = "PATH", num_args = 1..)]
    inputs: Vec<PathBuf>,
    /// Recursively traverse input directories
    #[clap(short, long)]
    recursive: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Build(args) => args.build().context("Failed to build the fuzzers"),
        Command::Fuzz(mut args) => args.fuzz().context("Failure running fuzzers"),
        Command::Run(args) => args.run().context("Failure running inputs"),
    }
}
