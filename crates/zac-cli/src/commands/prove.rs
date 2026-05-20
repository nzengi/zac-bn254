//! `zac prove <zac> <zkey> <wtns> -o <out.zacp>` — native Rust Groth16 prover.
//!
//! Produces a 240 B `.zacp` byte-compatible with snarkjs's
//! `groth16.verify`. The output path defaults to `create_new` (refuses to
//! overwrite); pass `--force` to overwrite. `--randomize` swaps the
//! deterministic seed=0 ChaCha20 RNG for `OsRng`.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::commands::CliError;

/// Run the `prove` subcommand. See module docs.
pub fn run(
    zac_path: &Path,
    zkey_path: &Path,
    wtns_path: &Path,
    out_path: &Path,
    force: bool,
    randomize: bool,
) -> Result<()> {
    let zac_bytes = read_file(zac_path)?;
    let zkey_bytes = read_file(zkey_path)?;
    let wtns_bytes = read_file(wtns_path)?;

    let zf =
        zac::ZacFile::parse(&zac_bytes).map_err(|e| CliError::Io(format!("parse .zac: {e}")))?;
    let zkey =
        zac::parse_zkey(&zkey_bytes).map_err(|e| CliError::Io(format!("parse .zkey: {e}")))?;
    let wtns =
        zac::parse_wtns(&wtns_bytes).map_err(|e| CliError::Io(format!("parse .wtns: {e}")))?;

    let t0 = Instant::now();
    let zpf = if randomize {
        zac::prove_with_rng(&zf, &zkey, &wtns, &mut OsRng)
    } else {
        zac::prove_with_rng(&zf, &zkey, &wtns, &mut ChaCha20Rng::seed_from_u64(0))
    }
    .map_err(|e| CliError::Reject(format!("prove: REJECTED ({})\n  {e}", e.code())))?;
    let elapsed_ms = t0.elapsed().as_millis();

    let bytes = zpf.encode();
    write_output(out_path, &bytes, force)?;

    println!("prove: OK ({elapsed_ms} ms)");
    println!(
        "  -> wrote {} ({} B)  vk_fingerprint={}  zac_file_hash={}",
        out_path.display(),
        bytes.len(),
        hex::encode(zpf.header.vk_fingerprint),
        hex::encode(zpf.header.zac_file_hash),
    );
    if randomize {
        println!("  randomness: OsRng (production)");
    } else {
        println!("  randomness: ChaCha20Rng::seed_from_u64(0) (deterministic)");
    }
    Ok(())
}

fn read_file(p: &Path) -> Result<Vec<u8>> {
    std::fs::read(p).map_err(|e| CliError::Io(format!("read {}: {e}", p.display())).into())
}

/// Write `bytes` to `path`. Refuses to overwrite unless `force` is set —
/// this is a small but real safety property (it's the kind of thing the
/// Phase 5 audit will flag if we don't surface it here first).
fn write_output(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::Io(format!(
                "{} already exists (pass --force to overwrite)",
                path.display()
            ))
        } else {
            CliError::Io(format!("open {}: {e}", path.display()))
        }
    })?;
    f.write_all(bytes)
        .map_err(|e| CliError::Io(format!("write {}: {e}", path.display())))?;
    Ok(())
}
