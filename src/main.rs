mod build;
mod fuzz;
mod run;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub const DEFAULT_OUTPUT_DIR: &str = "./output";

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
    Fuzz(Fuzz),
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
    target: String,
    /// Number of concurrent fuzzing jobs
    #[clap(short, long, value_name = "NUM", default_value_t = 1)]
    jobs: u32,
    /// Shared corpus directory
    #[clap(short = 'i', long = "corpus", value_name = "DIR")]
    corpus: Option<PathBuf>,
    /// Fuzzers output directory
    #[clap(short = 'o', long = "output", value_name = "DIR", default_value = DEFAULT_OUTPUT_DIR)]
    output: PathBuf,
    /// Dictionary file(s); may be repeated (e.g. -x a.dict -x b.dict)
    #[clap(short = 'x', long = "dict", value_name = "FILE", action = clap::ArgAction::Append)]
    dictionaries: Vec<PathBuf>,
    #[clap(skip)]
    merged_dict: Option<PathBuf>,
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
