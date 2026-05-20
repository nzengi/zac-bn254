//! `zac` subcommand implementations.
//!
//! Each module owns one verb. They all share two conventions:
//!
//! * Output goes to **stdout** in plain ASCII (no ANSI colour, no emoji);
//!   a checkmark is rendered as the ASCII string `OK` so the output is
//!   safe to pipe through `less`, `tee`, or `grep`.
//! * Errors that represent a normal proof rejection bubble up as
//!   [`CliError::Reject`] so the binary can exit with code 2 (versus
//!   1 for a programmer-facing crash).

pub mod hash;
pub mod inspect;
pub mod pack;
pub mod prove;
pub mod verify;

/// CLI-level error envelope. The discriminant tells `main` which exit code to
/// emit; the inner message is what shows up on stderr.
#[derive(Debug)]
pub enum CliError {
    /// Proof verification was structurally fine but the pairing rejected.
    /// Exit code 2.
    Reject(String),
    /// I/O or argument problem before any crypto runs. Exit code 3.
    Io(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Reject(s) => f.write_str(s),
            CliError::Io(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for CliError {}
