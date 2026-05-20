# ZAC v1.0 — Phase 5 bench baseline

Captured 2026-05-20, host: Linux 6.17 x86_64, rustc 1.95.0, release+thin-LTO.
Fixture: `fixtures/multiplier.{zac,zacp,zkey,wtns}` (4-constraint multiplier
circuit, 1 public input).

Criterion parameters: `--warm-up-time 2 --measurement-time 5 --sample-size 30`.
Times are the criterion median (middle column).

| bench                | median       | 95% interval               |
|----------------------|--------------|----------------------------|
| `parse_header_only`  |    10.109 ns | [ 9.9577 ns ,  10.283 ns]  |
| `parse_full_zac_256` |   494.04 ns  | [489.38 ns , 498.78 ns]    |
| `encode_full_zac_256`|   446.88 ns  | [444.75 ns , 449.05 ns]    |
| `verify_cold`        |     3.0492 ms| [3.0106 ms , 3.0885 ms]    |
| `vkey_decode`        |   820.71 us  | [811.96 us , 830.90 us]    |
| `proof_decode`       |   301.04 us  | [298.67 us , 303.98 us]    |
| `prove_native_rust`  |     1.1632 ms| [1.1514 ms , 1.1757 ms]    |

## Notes

* `verify_cold` is the full `zac::verify(&zac, &proof)` cost with no PVK
  caching. The pairing equation dominates (~2 ms of the ~3 ms total).
* `prove_native_rust` is the native Rust Groth16 prover end-to-end on the
  multiplier circuit — replaces the snarkjs subprocess baseline (~313 ms
  median, dominated by Node + snarkjs startup) recorded in Phase 3.
* `vkey_decode` includes explicit subgroup checks on `alpha_g1`, three G2
  points, and the `gamma_abc_g1` slice; the bulk of the cost is the G2
  subgroup multiplication.
* `proof_decode` decodes the fixed 128-byte canonical compressed proof
  (32 + 64 + 32) with subgroup checks.

## Regression policy

This file is the **reference baseline**. CI does not currently fail on
regression — alerts are out-of-band. To re-baseline:

```sh
cargo bench -p zac --bench parse_bench --bench verify_bench --bench prove_bench \
    -- --warm-up-time 2 --measurement-time 5 --sample-size 30
```

Then update the table above with the new medians.
