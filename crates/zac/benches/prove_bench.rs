//! Phase 3 (final) prover benches — **native Rust only**.
//!
//! `prove_native_rust` benchmarks the full ZAC prove path through
//! [`zac::prover::prove`], which calls the native Groth16 prover in
//! [`zac::groth16_prover`]. There is no subprocess and no snarkjs in
//! this path; the bench is reproducible without Node installed.
//!
//! For comparison against the pre-Phase-3-final subprocess baseline,
//! historical numbers (median ≈ 313 ms on a 4-constraint multiplier
//! circuit, dominated by Node + snarkjs process startup) are recorded
//! in the Phase 3 report. The native path should clock in ≪ 10 ms on
//! the same fixture.
//!
//! Run:
//! ```sh
//! cargo bench -p zac --bench prove_bench -- --warm-up-time 1 --measurement-time 2 --sample-size 10
//! ```

use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Criterion};

use zac::iden3::wtns::parse_wtns;
use zac::iden3::zkey::parse_zkey;
use zac::prover::prove;
use zac::ZacFile;

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fixtures_paths() -> (PathBuf, PathBuf, PathBuf) {
    let root = workspace_root();
    let fix = root.join("fixtures");
    (
        fix.join("multiplier.zac"),
        fix.join("multiplier.zkey"),
        fix.join("multiplier.wtns"),
    )
}

fn bench_prove_native_rust(c: &mut Criterion) {
    let (zac_path, zkey_path, wtns_path) = fixtures_paths();
    if !zac_path.exists() {
        eprintln!(
            "skipping prove_native_rust: {} missing — run phase 3 setup first",
            zac_path.display()
        );
        return;
    }
    let zac = ZacFile::parse(&std::fs::read(&zac_path).unwrap()).unwrap();
    let zkey = parse_zkey(&std::fs::read(&zkey_path).unwrap()).unwrap();
    let wtns = parse_wtns(&std::fs::read(&wtns_path).unwrap()).unwrap();

    c.bench_function("prove_native_rust", |b| {
        b.iter(|| {
            let _ = prove(&zac, &zkey, &wtns).unwrap();
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_prove_native_rust
}
criterion_main!(benches);
