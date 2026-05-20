//! Phase 3 — emit `fixtures/multiplier.{r1cs,wtns}` to disk.
//!
//! No `circom` is installed; we hand-roll the canonical iden3 R1CS bytes for
//! the multiplier circuit `x * y = z` (BN254). The WTNS file pins the
//! concrete assignment `[1, z=33, x=3, y=11]` so snarkjs can prove against
//! it.
//!
//! Run:
//! ```sh
//! cargo run --example build_fixtures
//! ```

use std::path::PathBuf;

use tracing::info;

use zac::iden3::r1cs::{encode_r1cs, multiplier_circuit};
use zac::iden3::wtns::{encode_wtns, fr_u64_le};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zac=info,build_fixtures=info".into()),
        )
        .with_target(true)
        .init();

    let fixtures_dir = workspace_root().join("fixtures");
    std::fs::create_dir_all(&fixtures_dir)?;

    info!("Phase 3 step 1: emit iden3 .r1cs (multiplier circuit)");
    let r1cs_bytes = encode_r1cs(&multiplier_circuit());
    let r1cs_path = fixtures_dir.join("multiplier.r1cs");
    std::fs::write(&r1cs_path, &r1cs_bytes)?;
    let preview_n = r1cs_bytes.len().min(64);
    println!("wrote {} ({} B)", r1cs_path.display(), r1cs_bytes.len());
    println!(
        "  first {preview_n} B: {}",
        hex::encode(&r1cs_bytes[..preview_n])
    );

    info!("Phase 3 step 1: emit iden3 .wtns (x=3, y=11, z=33)");
    let values = vec![
        fr_u64_le(1),  // wire 0 = 1
        fr_u64_le(33), // wire 1 = z (public)
        fr_u64_le(3),  // wire 2 = x
        fr_u64_le(11), // wire 3 = y
    ];
    let wtns_bytes = encode_wtns(&values);
    let wtns_path = fixtures_dir.join("multiplier.wtns");
    std::fs::write(&wtns_path, &wtns_bytes)?;
    let preview_n = wtns_bytes.len().min(64);
    println!("wrote {} ({} B)", wtns_path.display(), wtns_bytes.len());
    println!(
        "  first {preview_n} B: {}",
        hex::encode(&wtns_bytes[..preview_n])
    );

    println!();
    println!("next: cd node-tools && npm run setup");
    Ok(())
}

/// Walk up from CARGO_MANIFEST_DIR until we find the workspace root
/// (containing `fixtures/`). The workspace layout pins this at two
/// directories up from `crates/zac`.
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // workspace root
    p
}
