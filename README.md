# zac-bn254

A binary container format and Rust toolchain for Groth16 BN254
zk-SNARK proofs. Built so that a verifier does not have to ship
snarkjs and a Node runtime alongside it.

> **Proprietary software — prior written permission required for any
> use, copy, fork, derivative work, or AI/ML ingestion. See
> [`LICENSE`](./LICENSE).** Visibility of this repository on GitHub
> is not a grant of any rights. Reach out at
> `zenginureddin1@gmail.com` if you have a use case in mind.

## Why

snarkjs is fine when you already live in Node. When you do not — a
Rust service, an iOS build, an embedded verifier, a CI runner that
cannot afford a 200 MB Node install — the alternatives are all
awkward. Spawn a Node subprocess for every verify. Package a Docker
layer. Or write a custom arkworks integration and find out that
snarkjs's QAP reduction does not match arkworks's. ZAC is the third
option taken seriously. The container format pins a verifying key, a
public-input interface, and an R1CS digest into one file with a
BLAKE3 binding. A second file carries the proof itself, bound to its
container by hash. The library parses both, verifies in roughly 3 ms
on a multiplier circuit, and proves natively in 1.16 ms without
shelling out. snarkjs cross-verifies the result.

## Quick start

```
cargo build --release --bin zac
./target/release/zac verify fixtures/multiplier.zac fixtures/multiplier.zacp
```

That should print `verify: OK` and exit 0. To see what is in the
container:

```
./target/release/zac inspect fixtures/multiplier.zac
```

You will get a typed dump of the header, section index, every body,
and the trailer hash. To prove from a snarkjs `.zkey` plus a
`.wtns` and immediately verify the result:

```
./target/release/zac prove fixtures/multiplier.zac \
                          fixtures/multiplier.zkey \
                          fixtures/multiplier.wtns \
                          -o /tmp/out.zacp
./target/release/zac verify fixtures/multiplier.zac /tmp/out.zacp
```

The full pipeline lives in `scripts/e2e_demo.sh`, including the
failure cases: a tampered proof (verify exits 2) and the
overwrite-refusal guard (`prove` exits 3 when the output file
already exists and `--force` was not passed).

## What it looks like on the wire

The format is documented in `docs/SPEC.md`. Two file types.

A `.zac` is a 32-byte header, a section index, the section bodies
(8-byte aligned, zero-padded), and a 40-byte trailer. Sections are
VKEY (an arkworks canonical-compressed Groth16 verifying key),
INTERFACE (a typed binary record with the public-input count and
names), R1CS_HASH (a 32-byte digest of the canonical iden3 R1CS
binary), and optionally META_CBOR (a deterministic CBOR blob that
the verifier ignores). The magic bytes are `ZAC1`.

A `.zacp` is an 80-byte header containing the bound `.zac`'s file
hash and the verifying key fingerprint, followed by a tight
128-byte proof block (`pi_a || pi_b || pi_c` in arkworks canonical
compressed form: 32 + 64 + 32 bytes), followed by the public inputs
as 32-byte little-endian field elements. The magic bytes are `ZAP1`.

All binding hashes are 32-byte BLAKE3 with explicit domain separation
tags: `zac1.file.v1\0`, `zac1.vkey.v1\0`, `zac1.r1cs.v1\0`. So two
ZAC versions cannot produce a hash collision by accident, and the
v1 verifier cannot be tricked into accepting a v2 binding.

## CLI

```
zac verify  <zac> <zacp>
zac prove   <zac> <zkey> <wtns> -o <zacp> [--force] [--randomize]
zac inspect <file>
zac pack    <zkey> <r1cs> -o <zac> [--force]
zac hash    <file> [--raw vkey|r1cs]
```

Exit codes: `0` for success, `1` for tool errors, `2` when the
verifier rejects a structurally valid proof because the pairing
equation does not hold, and `3` for I/O or argument problems. The
`2` versus `1` split exists so a shell pipeline can grep for proof
rejection without false positives from tool crashes.

`prove` is deterministic by default. The `ChaCha20Rng` seed is hard
coded to 0 so re-running on the same inputs gives bit-identical
output, which makes diffs across versions meaningful. Pass
`--randomize` to switch to `OsRng` for production work where you
want fresh blinding scalars every run.

## Cross-verify with snarkjs

The thing that matters most for interop claims is that a snarkjs
proof verifies under ZAC and a ZAC proof verifies under snarkjs.
Both directions are checked in CI by
`node-tools/scripts/cross_verify.mjs`:

```
cd node-tools && npm install
npm run cross-verify
```

You need Node 24 or newer. The script reads
`fixtures/snarkjs_proof.json` (produced by snarkjs at setup time),
re-encodes it as a `.zacp`, and runs it through `zac::verify`. Then
it reads `fixtures/multiplier.zacp` (produced by ZAC's native Rust
prover), converts the proof bytes back into snarkjs's JSON shape,
and runs it through `snarkjs.groth16.verify`. Both come back `true`.

The native Rust prover is in `crates/zac/src/groth16_prover.rs`. It
ports the snarkjs Groth16 prove pipeline — `buildABC1`, `joinABC`,
and the odd-coset FFT with `Fr.shift = nqr²` — into arkworks
primitives. The CHANGELOG has more detail on the `R⁻²` Montgomery
correction that took the longest to track down.

## What v1.0 does not do

BN254 only. There is no support for BLS12-381, Halo2, PLONK, or
FFLonk in this release. Each of those would be a major version bump,
because the format binds proofs to verifying keys with a
curve-specific fingerprint.

There is no WASM verifier yet. The `zstd` crate's C bindings and the
`getrandom/js` feature flag are the two blockers; both are
solvable, neither is solved here.

There is no registry or CDN spec. The `vk_fingerprint` field
enables content-addressing in principle, but a URI scheme, a
manifest format, and HTTP cache semantics have not been written.

The native prover is single-threaded. arkworks's
`VariableBaseMSM` uses Pippenger internally, but rayon parallelism
in the FFT step is not wired up. The multiplier fixture is too small
to need it; a SHA-256 circuit would benefit.

## Building from source

```
cargo build --release            # produces target/release/zac
cargo test -p zac                # 28 tests including the 60k-case proptest
cargo bench                      # parse / verify / prove benches
```

MSRV is 1.89. The transitive `clap_lex 1.1.0` requires `edition2024`
which lands in Rust 1.85. I would rather state the verified floor
than ship a 1.74 claim that does not hold.

The CI workflow at `.github/workflows/ci.yml` runs six lanes on
every push and pull request: lint, test, MSRV check, `cargo audit`,
`cargo deny check`, and the end-to-end cross-verify. The audit lane
ignores three transitive RUSTSEC advisories from arkworks 0.4
dependencies, all with written rationale in `deny.toml`; they
resolve when arkworks ships 0.5+.

## Status

v1.0.0, released 2026-05-20. The CHANGELOG in `docs/CHANGELOG.md`
has the full release notes plus the list of things that are not in
v1.0. The wire spec is in `docs/SPEC.md` and is normative. The
implementation in `crates/zac/` is one realization of it; if you
want to write a Go or TypeScript verifier, the spec is what you
read, not the Rust source.

## License

Proprietary. All rights reserved. The repository being visible on
GitHub does not grant any license to use, copy, fork, mirror,
distribute, modify, or otherwise deal with the software, and it does
not permit ingestion of this code or its documentation by any AI or
ML system, whether for training, fine-tuning, evaluation, retrieval,
or inference. Use of any kind — commercial, academic, personal, or
exploratory — requires prior written permission. The full terms are
in [`LICENSE`](./LICENSE). For permission requests, write to
`zenginureddin1@gmail.com`.
