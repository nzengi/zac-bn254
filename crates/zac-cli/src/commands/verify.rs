//! `zac verify <zac> <zacp>` — bind a proof to a circuit + run pairing.
//!
//! Exit behaviour:
//!
//! * Pairing OK → stdout: `verify: OK` + one-line summary, exit 0.
//! * Any `zac::ZacError` from parsing or pairing → stderr:
//!   `verify: REJECTED (Exxx)` plus the full `Display`-formatted error,
//!   exit 2.
//! * I/O failure → exit 3 (handled by the `CliError::Io` arm in `main`).

use std::path::Path;

use anyhow::Result;

use crate::commands::CliError;

/// Run the `verify` subcommand. See module docs.
pub fn run(zac_path: &Path, zacp_path: &Path) -> Result<()> {
    let zac_bytes = read_file(zac_path)?;
    let zacp_bytes = read_file(zacp_path)?;

    let zf = match zac::ZacFile::parse(&zac_bytes) {
        Ok(zf) => zf,
        Err(e) => {
            return Err(CliError::Reject(format!(
                "verify: REJECTED ({})\n  parse .zac: {e}",
                e.code()
            ))
            .into());
        }
    };
    let zpf = match zac::ZacProofFile::parse(&zacp_bytes) {
        Ok(zpf) => zpf,
        Err(e) => {
            return Err(CliError::Reject(format!(
                "verify: REJECTED ({})\n  parse .zacp: {e}",
                e.code()
            ))
            .into());
        }
    };

    match zac::verify(&zf, &zpf) {
        Ok(()) => {
            println!("verify: OK");
            println!(
                "  zac_file_hash={}  vk_fingerprint={}  public_inputs={}",
                hex::encode(zf.trailer.file_hash),
                hex::encode(zpf.header.vk_fingerprint),
                zpf.header.public_input_count
            );
            Ok(())
        }
        Err(e) => Err(CliError::Reject(format!("verify: REJECTED ({})\n  {e}", e.code())).into()),
    }
}

fn read_file(p: &Path) -> Result<Vec<u8>> {
    std::fs::read(p).map_err(|e| CliError::Io(format!("read {}: {e}", p.display())).into())
}
