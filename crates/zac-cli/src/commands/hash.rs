//! `zac hash <file>` — print the BLAKE3 hashes a verifier would compute.
//!
//! Auto-detects the file kind:
//!
//! * `.zac` (magic `ZAC1`) → trailer `file_hash` + recomputed `file_hash`
//!   + per-VKEY `vk_fingerprint` + per-R1CS-section `r1cs_hash`.
//! * `.zacp` (magic `ZAP1`) → `zac_file_hash` + `vk_fingerprint` from the
//!   header.
//! * Anything else with `--raw <kind>` → domain-tagged hash over the raw
//!   bytes (`vkey` or `r1cs`). Without `--raw`, an unknown magic produces
//!   an E001-equivalent error and exit 2.

use std::path::Path;

use anyhow::Result;

use crate::commands::CliError;
use crate::RawKind;

/// Run the `hash` subcommand. See module docs.
pub fn run(file: &Path, raw: Option<RawKind>) -> Result<()> {
    let bytes =
        std::fs::read(file).map_err(|e| CliError::Io(format!("read {}: {e}", file.display())))?;

    // `--raw` short-circuits magic detection so the user can hash an
    // exported .vkey blob or raw r1cs body without wrapping it in ZAC.
    if let Some(kind) = raw {
        let h = crate::raw_hash(kind, &bytes);
        let label = match kind {
            RawKind::Vkey => "vk_fingerprint (zac1.vkey.v1)",
            RawKind::R1cs => "r1cs_hash      (zac1.r1cs.v1)",
        };
        println!("file: {}", file.display());
        println!("size: {} B", bytes.len());
        println!("{label} = {}", hex::encode(h));
        return Ok(());
    }

    if bytes.len() < 4 {
        return Err(CliError::Reject(format!(
            "hash: REJECTED (E001)\n  file too short ({} B) to detect magic; consider --raw",
            bytes.len()
        ))
        .into());
    }

    match &bytes[0..4] {
        b"ZAC1" => hash_zac(&bytes, file),
        b"ZAP1" => hash_zacp(&bytes, file),
        other => Err(CliError::Reject(format!(
            "hash: REJECTED (E001)\n  unknown magic at offset 0: {other:02x?}; pass --raw vkey|r1cs"
        ))
        .into()),
    }
}

fn hash_zac(bytes: &[u8], path: &Path) -> Result<()> {
    let zf = zac::ZacFile::parse(bytes)
        .map_err(|e| CliError::Reject(format!("hash: REJECTED ({})\n  {e}", e.code())))?;

    // Recompute file_hash independently of the trailer so the user can
    // spot trailer corruption that slipped past parse (it can't, but the
    // belt-and-braces print makes the binding auditable).
    let version_bytes = &bytes[4..8];
    let body_bytes = &bytes[0x20..bytes.len() - zac::TRAILER_SIZE];
    let computed = zac::file_hash(version_bytes, body_bytes);

    println!("file: {}", path.display());
    println!("kind: ZAC1 (.zac container)");
    println!("size: {} B", bytes.len());
    println!();
    println!(
        "file_hash (trailer)   = {}",
        hex::encode(zf.trailer.file_hash)
    );
    println!("file_hash (computed)  = {}", hex::encode(computed));
    if zf.trailer.file_hash != computed {
        return Err(CliError::Reject(
            "hash: REJECTED (E009)\n  trailer file_hash != computed".into(),
        )
        .into());
    }
    for s in &zf.sections {
        match s {
            zac::Section::Vkey(b) => {
                println!(
                    "vk_fingerprint        = {}",
                    hex::encode(zac::vk_fingerprint(b))
                );
            }
            zac::Section::R1csHash(h) => {
                println!("r1cs_hash (recorded)  = {}", hex::encode(h));
            }
            _ => {}
        }
    }
    Ok(())
}

fn hash_zacp(bytes: &[u8], path: &Path) -> Result<()> {
    let zpf = zac::ZacProofFile::parse(bytes)
        .map_err(|e| CliError::Reject(format!("hash: REJECTED ({})\n  {e}", e.code())))?;
    println!("file: {}", path.display());
    println!("kind: ZAP1 (.zacp proof)");
    println!("size: {} B", bytes.len());
    println!();
    println!(
        "zac_file_hash         = {}",
        hex::encode(zpf.header.zac_file_hash)
    );
    println!(
        "vk_fingerprint        = {}",
        hex::encode(zpf.header.vk_fingerprint)
    );
    Ok(())
}
