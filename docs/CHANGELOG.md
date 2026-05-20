# Changelog

## v1.0.0 — 2026-05-20

First public release of ZAC.

ZAC is a binary container for Groth16 BN254 zk-SNARK artifacts, plus a
Rust library and CLI that work with them. The motivation was simple:
snarkjs ships a fine prover and verifier, but it lives in Node.js, and
that is awkward to embed in a Rust service, ship to a mobile target,
or hand to a hardware verifier. So I wrote a format, parsers, a native
prover that does not shell out, and a CLI.

### What v1.0 actually does

The wire format covers two files. A `.zac` carries the verifying key,
the circuit's public-input interface (count and names), an R1CS
digest, and optionally some free-form CBOR metadata. A `.zacp` carries
the proof itself plus the binding fields needed to tie it back to a
specific `.zac`. Both formats are byte-typed; the verifier never has
to parse JSON to verify a proof. Hashes use domain-separated BLAKE3
with explicit version tags, so two ZAC versions cannot collide on the
wire by accident. The full spec is in `docs/SPEC.md` and is normative.
It was written so someone could re-implement the verifier in Go or
TypeScript from the document alone.

The Rust side is one library crate (`zac`, in `crates/zac/`) and one
binary (`zac-cli`, exposing the `zac` command). The library has no
unsafe code at all. The CLI has exactly one `unsafe` block — a SIGPIPE
reset that calls `libc::signal` so `zac inspect | head` does not panic
on a broken pipe. cargo-geiger confirms both numbers.

The bigger piece of work was the native prover. snarkjs's Groth16
prove path uses an odd-coset FFT with `Fr.shift = nqr²` and an
`h_query` array of length `domainSize`. arkworks 0.4 uses a different
coset shift and an `h_query` of length `domainSize - 1`. A naive port
that maps snarkjs `.zkey` points into an `ark_groth16::ProvingKey` and
calls `Groth16::prove` produces bytes that are structurally valid and
mathematically wrong — they fail the pairing equation under any
verifier. Getting them to match required two things: porting
`buildABC1` and `joinABC` byte-for-byte against the ffjavascript
reference, and applying an `R⁻²` correction because snarkjs operates
in Montgomery domain throughout the FFT pipeline while arkworks does
not. I found the `R⁻²` factor by dumping intermediate
`(A_T, B_T, C_T, P_odd_T)` values from both implementations and
solving `mine · X = snarkjs` for `X`. The result lives in
`crates/zac/src/groth16_prover.rs`, runs in 1.16 ms on the multiplier
fixture, and produces proofs that snarkjs verifies every run.

A second silent bug fell out during cross-verify debugging:
arkworks 0.4's `QuadExtField::cmp` orders `Fq2` elements as
`(c1, c0)` lex, but the JS code in `cross_verify.mjs` was ordering
them as `(c0, c1)`. The two agreed on every input I tried first, then
disagreed on a specific `pi_b`. The `fq2LexGreater` helper in the
Node script is fixed.

### Forgery vectors

`crates/zac/examples/forgery_vectors.rs` contains eight attack
constructions. The verifier rejects each with the right error code:

| attack                                                     | code |
|------------------------------------------------------------|------|
| non-canonical G1 `pi_a` (forbidden flag combination)       | E010 |
| on-curve / off-subgroup G2 `pi_b`                          | E011 |
| public input set to the Fr modulus (= `r`)                 | E012 |
| bit-flipped `pi_c`                                         | E010 |
| bit-flipped `vk_fingerprint` in the `.zacp` header         | E014 |
| bit-flipped `zac_file_hash` in the `.zacp` header          | E009 |
| `public_input_count` mismatch between `.zacp` and INTERFACE| E013 |
| proof swapped in from a different witness                  | E017 |

BN254 G2 has a non-trivial cofactor (≈ 2²⁵⁴), which is why
constructing an on-curve, off-subgroup point is feasible — a small
search over `x ∈ Fq2` finds one in a few attempts. BN254 G1 has
cofactor 1, so G1 off-subgroup is mathematically impossible; the G1
negative cases go through the SW flag byte instead (setting both
`infinity` and `y_is_negative` is a forbidden combination).

### CLI

Five subcommands: `verify`, `prove`, `inspect`, `pack`, `hash`. The
exit-code contract is the thing most worth knowing. `0` for success,
`2` when a proof is structurally valid but the pairing equation does
not hold (a normal outcome a shell pipeline might want to grep for),
`3` for I/O or argument problems, `1` for anything else. `prove` and
`pack` refuse to overwrite an existing output file unless you pass
`--force`. That is there because losing a snapshot fixture to a typo
is too easy. `prove` defaults to a deterministic `ChaCha20Rng` seed
of 0 so you can diff proofs across runs; `--randomize` switches to
`OsRng`.

### Cross-verify with snarkjs

Both directions work and are gated in CI. A snarkjs-produced
`proof.json` reads into ZAC, gets re-encoded as a 240-byte `.zacp`,
and verifies under `zac::verify`. A ZAC-produced `.zacp` decompresses
into snarkjs's expected `proof.json` shape and verifies under
`snarkjs.groth16.verify`. The script is
`node-tools/scripts/cross_verify.mjs`. Node 24+ is required.

### Hardening

- 60,000 proptest cases across six parsers (`.zac`, `.zacp`, `.zkey`,
  `.wtns`, `decode_vk`, `decode_proof`). 0 panics.
- `cargo audit` is clean apart from three transitive advisories on
  arkworks 0.4 dependencies, all explicitly ignored in `deny.toml`
  with rationale. None of them reach attacker-controlled input.
- `cargo deny check` is clean across advisories, bans, licenses,
  sources.
- `cargo machete` is clean, no unused dependencies.
- `cargo geiger` reports zero unsafe in the library crate, one block
  in the CLI as expected.
- CycloneDX SBOMs published in `sbom/`.
- A CI workflow at `.github/workflows/ci.yml` runs lint, test, MSRV
  check, audit, deny, and the end-to-end cross-verify on every push.

### Benchmarks

Captured with `cargo bench --warm-up-time 2 --measurement-time 5
--sample-size 30`, host Linux 6.17 x86_64, rustc 1.95.0, thin LTO.
All times are the criterion median.

| operation                            | time    |
|--------------------------------------|---------|
| parse header (32 B)                  | 10 ns   |
| parse a 456-B `.zac`                 | 494 ns  |
| encode a 456-B `.zac`                | 447 ns  |
| `verify_cold` (no PVK cache)         | 3.05 ms |
| `vkey_decode` (incl. subgroup check) | 821 µs  |
| `proof_decode` (incl. subgroup)      | 301 µs  |
| native Rust Groth16 prove            | 1.16 ms |

The multiplier circuit is small (4 constraints), so the prove number
is not representative of SHA-256 or Poseidon. Read it as a floor, not
a ceiling. What it does say is that the format and binding code are
not the bottleneck — pairing dominates verify, MSM dominates prove.

### Known limits

- BN254 only. No BLS12-381, Halo2, PLONK, or FFLonk. Adding any of
  them is a major version bump because the format binds proofs to
  verifying keys with a curve-specific fingerprint.
- MSRV is 1.89. The transitive `clap_lex 1.1.0` pulls in
  `edition2024`, which requires Rust 1.85 or newer. I would rather
  state the verified floor than ship a `rust-version = 1.74` claim
  that does not hold.
- The native prover is single-threaded. arkworks's
  `VariableBaseMSM` already uses Pippenger inside, but rayon
  parallelism in the FFT step is not wired up. Worth doing for
  larger circuits.
- No registry / CDN spec yet. The `vk_fingerprint` enables
  content-addressing but the URI scheme, manifest format, and HTTP
  semantics have not been written. Likely v1.1 or v2.
- No WASM verifier in this release. The two known blockers are
  `getrandom`'s `js` feature flagging and `zstd`'s C bindings.
- The three ignored RUSTSEC advisories (RUSTSEC-2025-0055,
  RUSTSEC-2024-0388, RUSTSEC-2024-0436) resolve naturally when
  arkworks ships 0.5+.

### Build status at release

```
cargo test -p zac                           # 28 passing
cargo bench                                 # parse / verify / prove green
cargo audit                                 # 3 transitive, all ignored with rationale
cargo deny --all-features check             # clean
cargo machete                               # no unused deps
bash scripts/e2e_demo.sh                    # ALL OK incl. negative + no-overwrite cases
cd node-tools && npm run cross-verify       # both directions verified
```

The wire spec is in `docs/SPEC.md` and is the source of truth. The
implementation is one realization of it.
