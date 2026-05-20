//! `zac` — ZAC command-line tool.
//!
//! Thin wrapper over the `zac` library crate. Every subcommand drives one
//! library API (`zac::ZacFile::parse`, `zac::verify`, `zac::prove`, …) and
//! prints a hex-dump-friendly summary so a human reading the terminal can
//! verify the result by eye. Exit codes are disciplined:
//!
//! ```text
//! 0  success / proof accepted
//! 1  generic error (parse failure, I/O, programmer error)
//! 2  proof verification rejection — a normal pipeline outcome
//! 3  argument / I/O error before any crypto work runs
//! ```

// The CLI is otherwise unsafe-free; the one localised `unsafe` block lives
// in `reset_sigpipe` (see its safety note), so we `deny(unsafe_code)`
// rather than `forbid` and explicitly opt that single function in.
#![deny(unsafe_code)]

mod commands;

use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

/// Exit code: generic failure.
const EXIT_ERR: u8 = 1;
/// Exit code: proof verification rejection (E### code).
const EXIT_REJECT: u8 = 2;
/// Exit code: I/O or argument problem before crypto runs.
const EXIT_IO: u8 = 3;

/// Top-level CLI parser.
#[derive(Parser, Debug)]
#[command(
    name = "zac",
    version,
    about = "ZAC — Groth16 BN254 artifact container tool",
    long_about = None,
    propagate_version = true,
)]
struct Cli {
    /// Set tracing filter (e.g. `zac=debug`, `info,zac=trace`). When unset,
    /// the `RUST_LOG` env var is honoured; otherwise tracing is silent.
    #[arg(long, value_name = "FILTER", global = true)]
    trace: Option<String>,

    /// Shorthand for `--trace zac=debug`. Stacks with `-vv` → `zac=trace`.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    cmd: Cmd,
}

/// CLI subcommands.
#[derive(Subcommand, Debug)]
enum Cmd {
    /// Verify a `.zacp` proof against a `.zac` circuit container.
    Verify {
        /// Path to the `.zac` circuit container.
        zac: std::path::PathBuf,
        /// Path to the `.zacp` proof.
        zacp: std::path::PathBuf,
    },

    /// Produce a `.zacp` proof natively in Rust from a `.zac` + `.zkey` + `.wtns`.
    Prove {
        /// Path to the `.zac` circuit container.
        zac: std::path::PathBuf,
        /// Path to the snarkjs `.zkey` proving key.
        zkey: std::path::PathBuf,
        /// Path to the snarkjs `.wtns` witness.
        wtns: std::path::PathBuf,
        /// Output `.zacp` proof file.
        #[arg(short, long, value_name = "PATH")]
        out: std::path::PathBuf,
        /// Overwrite the output if it exists (default: refuse).
        #[arg(long)]
        force: bool,
        /// Use `OsRng` instead of the deterministic seed=0 ChaCha20 RNG.
        ///
        /// Default proofs are deterministic for regression-test ease; pass
        /// `--randomize` in production to sample fresh blinding scalars per
        /// proof.
        #[arg(long)]
        randomize: bool,
    },

    /// Dump the parsed structure of a `.zac` or `.zacp` file.
    Inspect {
        /// Path to the file to inspect (type auto-detected by magic bytes).
        file: std::path::PathBuf,
    },

    /// Build a `.zac` container from a `.zkey` + `.r1cs` pair.
    Pack {
        /// Path to the snarkjs `.zkey` proving key.
        zkey: std::path::PathBuf,
        /// Path to the snarkjs `.r1cs` constraint system.
        r1cs: std::path::PathBuf,
        /// Output `.zac` container.
        #[arg(short, long, value_name = "PATH")]
        out: std::path::PathBuf,
        /// Overwrite the output if it exists (default: refuse).
        #[arg(long)]
        force: bool,
        /// Comma-separated public-input names (overrides default `pub_N`).
        #[arg(long, value_name = "n1,n2,...")]
        names: Option<String>,
    },

    /// Print BLAKE3 hashes for a `.zac`, `.zacp`, or raw `--raw <kind>` blob.
    Hash {
        /// Path to the file to hash.
        file: std::path::PathBuf,
        /// Treat input as a raw `vkey` or `r1cs` blob and apply the
        /// corresponding domain-tagged BLAKE3.
        #[arg(long, value_enum, value_name = "KIND")]
        raw: Option<RawKind>,
    },
}

/// `--raw` argument: which domain tag to apply.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum RawKind {
    /// Treat as VKEY bytes (BLAKE3 with `zac1.vkey.v1\0`).
    Vkey,
    /// Treat as raw `.r1cs` bytes (BLAKE3 with `zac1.r1cs.v1\0`).
    R1cs,
}

fn main() -> ExitCode {
    // Restore the default SIGPIPE behaviour on Unix so that piping our
    // stdout into `head`, `less`, etc. exits cleanly instead of panicking
    // with "Broken pipe" in the middle of a `println!`.
    #[cfg(unix)]
    reset_sigpipe();

    let cli = Cli::parse();
    init_tracing(cli.trace.as_deref(), cli.verbose);
    match dispatch(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => match e.downcast_ref::<commands::CliError>() {
            Some(commands::CliError::Reject(msg)) => {
                eprintln!("{msg}");
                ExitCode::from(EXIT_REJECT)
            }
            Some(commands::CliError::Io(msg)) => {
                eprintln!("zac: {msg}");
                ExitCode::from(EXIT_IO)
            }
            _ => {
                eprintln!("zac: {e:#}");
                ExitCode::from(EXIT_ERR)
            }
        },
    }
}

fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.cmd {
        Cmd::Verify { zac, zacp } => commands::verify::run(zac, zacp),
        Cmd::Prove {
            zac,
            zkey,
            wtns,
            out,
            force,
            randomize,
        } => commands::prove::run(zac, zkey, wtns, out, *force, *randomize),
        Cmd::Inspect { file } => commands::inspect::run(file),
        Cmd::Pack {
            zkey,
            r1cs,
            out,
            force,
            names,
        } => commands::pack::run(zkey, r1cs, out, *force, names.as_deref()),
        Cmd::Hash { file, raw } => commands::hash::run(file, *raw),
    }
}

/// Initialise `tracing_subscriber` from `--trace` / `-v` / `RUST_LOG`.
///
/// Priority (highest first):
///   1. `--trace FILTER`
///   2. `-v` (`zac=debug`), `-vv` (`zac=trace`)
///   3. `RUST_LOG` env var
///   4. default: silent (no filter, no output)
fn init_tracing(trace_flag: Option<&str>, verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let filter = if let Some(f) = trace_flag {
        EnvFilter::new(f)
    } else {
        match verbose {
            0 => match EnvFilter::try_from_default_env() {
                Ok(f) => f,
                // No RUST_LOG, no -v → keep quiet (errors still go to stderr
                // via println/eprintln, not tracing).
                Err(_) => EnvFilter::new("zac=warn"),
            },
            1 => EnvFilter::new("zac=debug"),
            _ => EnvFilter::new("zac=trace"),
        }
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Map a `RawKind` to the matching hash function. Re-exported for
/// `commands::hash`.
pub(crate) fn raw_hash(kind: RawKind, bytes: &[u8]) -> [u8; 32] {
    match kind {
        RawKind::Vkey => zac::vk_fingerprint(bytes),
        RawKind::R1cs => zac::r1cs_hash(bytes),
    }
}

/// Restore SIGPIPE to its default handler.
///
/// Rust's std installs `SIG_IGN` for SIGPIPE at startup, which means a
/// broken-pipe write turns into a `println!` panic ("failed printing to
/// stdout: Broken pipe"). For a Unix CLI tool that's wrong: we want
/// `zac inspect foo.zac | head` to terminate the writer normally. We use
/// raw `libc::signal` via the `unsafe` stdlib FFI wrapper — but that's
/// already gated behind `#[cfg(unix)]` and requires `libc`, so instead we
/// invoke the same trick via the safe `nix`-style `sigaction` shim:
/// reset by writing the raw signal number through a minimal extern decl.
#[cfg(unix)]
#[allow(unsafe_code)]
fn reset_sigpipe() {
    // Safety: SIGPIPE = 13, SIG_DFL = 0 on every supported Unix; no
    // memory or threading invariants are touched by `signal(2)`.
    unsafe {
        extern "C" {
            fn signal(signum: i32, handler: usize) -> usize;
        }
        const SIGPIPE: i32 = 13;
        const SIG_DFL: usize = 0;
        let _ = signal(SIGPIPE, SIG_DFL);
    }
}
