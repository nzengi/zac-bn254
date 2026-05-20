//! Phase 3 (final) — end-to-end **native Rust** prove → verify round trip.
//!
//! Reads `fixtures/multiplier.{zac,zkey,wtns}`, invokes `zac::prover::prove`
//! to produce a `.zacp`, then calls `zac::verify` on the result. The whole
//! pipeline runs in-process with **zero subprocess spawn**; the Node /
//! snarkjs helper is only used by the cross-verify script.
//!
//! Run:
//! ```sh
//! cargo run --example prove_from_wtns
//! ```

use std::path::PathBuf;

use tracing::info;

use zac::iden3::wtns::parse_wtns;
use zac::iden3::zkey::parse_zkey;
use zac::prover::prove;
use zac::{verify, ZacFile};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zac=info,prove_from_wtns=info".into()),
        )
        .with_target(true)
        .init();

    let fixtures = workspace_root().join("fixtures");
    let zac_path = fixtures.join("multiplier.zac");
    let zkey_path = fixtures.join("multiplier.zkey");
    let wtns_path = fixtures.join("multiplier.wtns");
    let zacp_path = fixtures.join("multiplier.zacp");

    info!("Phase 3 (final): parse .zac + .zkey + .wtns");
    let zac_bytes = std::fs::read(&zac_path)?;
    let zac = ZacFile::parse(&zac_bytes)?;
    let zkey_bytes = std::fs::read(&zkey_path)?;
    let zkey = parse_zkey(&zkey_bytes)?;
    let wtns_bytes = std::fs::read(&wtns_path)?;
    let wtns = parse_wtns(&wtns_bytes)?;
    println!("  parsed .zac        ({} B)", zac_bytes.len());
    println!(
        "  parsed .zkey       n_vars={}, n_public={}, domain_size={}, coefs={}",
        zkey.n_vars,
        zkey.n_public,
        zkey.domain_size,
        zkey.coefs.len()
    );
    println!("  parsed .wtns       {} witnesses", wtns.values.len());

    info!("Phase 3 (final): native Rust groth16 prove (no subprocess)");
    let started = std::time::Instant::now();
    let zacp = prove(&zac, &zkey, &wtns)?;
    let elapsed = started.elapsed();
    let zacp_bytes = zacp.encode();
    std::fs::write(&zacp_path, &zacp_bytes)?;
    println!();
    println!(
        "wrote {} ({} B) — native prove took {:?}",
        zacp_path.display(),
        zacp_bytes.len(),
        elapsed,
    );
    println!(
        "  vk_fingerprint = {}",
        hex::encode(zacp.header.vk_fingerprint)
    );
    println!(
        "  zac_file_hash  = {}",
        hex::encode(zacp.header.zac_file_hash)
    );
    println!("  proof block    = {}", hex::encode(zacp.proof));
    println!(
        "  public_inputs  = [{}]",
        zacp.public_inputs
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join(", ")
    );

    info!("Phase 3 (final): verify");
    verify(&zac, &zacp)?;
    println!();
    println!("[OK] native prove + verify round-trip OK");
    Ok(())
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}
