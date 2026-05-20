#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Canonical wire format for `snarkjs`-compatible Groth16 BN254 proofs,
//! without the JavaScript runtime.
//!
//! `zac-bn254` is the binding-checked, byte-typed container that lets a
//! Rust service, an iOS or Android build, an embedded verifier, or a CI
//! runner consume a Groth16 BN254 proof without shelling out to
//! `snarkjs` or carrying a 200 MB Node install. The wire format is
//! defined in `docs/SPEC.md` (normative) and is reproduced bit-for-bit
//! by the reference implementation here; round-trip cross-verification
//! with `snarkjs` is gated on every push by
//! `node-tools/scripts/cross_verify.mjs`.
//!
//! # Quick start
//!
//! Verifying a proof is a single call once you have the two byte
//! slices. This example is a runnable doctest: the multiplier fixture
//! is embedded in the crate so `cargo test --doc -p zac-bn254` actually
//! exercises the verifier.
//!
//! ```
//! use zac::{verify, ZacFile, ZacProofFile};
//!
//! let zac_bytes  = include_bytes!("../tests/fixtures/multiplier.zac");
//! let zacp_bytes = include_bytes!("../tests/fixtures/multiplier.zacp");
//!
//! let zac  = ZacFile::parse(zac_bytes)?;
//! let zacp = ZacProofFile::parse(zacp_bytes)?;
//! verify(&zac, &zacp)?;
//! # Ok::<(), zac::ZacError>(())
//! ```
//!
//! `verify` returns `Ok(())` for a valid proof, [`ZacError::ProofRejected`]
//! (E017) when the Groth16 pairing equation does not hold, and the precise
//! `E001..E018` code from `docs/SPEC.md` §10 for any structural failure
//! (truncated, non-canonical, off-curve / off-subgroup, identity at a
//! forbidden position, …). See [`error::ZacError`] for the full taxonomy
//! and `docs/ERROR-CODES.md` for the long-form registry.
//!
//! # Scope
//!
//! v0.1 implements **only** Groth16 over BN254. Additional proof systems
//! and curves (BLS12-381, Halo2, PLONK, FFLonk) are out of scope and will
//! be considered in future major versions, not bolted onto v0.1.
//!
//! # Crate layout
//!
//! - [`ZacFile`] / [`ZacProofFile`] — parse + encode the two file types.
//! - [`verify`] — the single end-to-end entry point. Runs every check in
//!   SPEC order.
//! - [`prove`] / [`prove_with_rng`] — the native Rust Groth16 prover,
//!   matching `snarkjs`'s output byte-for-byte (1.16 ms on the multiplier
//!   fixture).
//! - [`groth16`] — the crypto boundary: canonical-compressed `ark-bn254`
//!   decode, identity rejection, subgroup membership, Fr canonical check.
//! - [`error::ZacError`] — every spec-level error code with full
//!   structured context (offsets, section types, byte indices).
//!
//! # Tracing
//!
//! Every parser and the verifier emit `trace`-level spans with byte
//! offsets. Set `RUST_LOG=zac=trace` for a byte-by-byte narrative of any
//! failure path.

pub mod crc;
pub mod error;
pub mod groth16;
pub mod groth16_prover;
pub mod hash;
pub mod header;
pub mod iden3;
pub mod index;
pub mod prover;
pub mod section;
pub mod trailer;
pub mod verifier;
pub mod zac_file;
pub mod zac_proof;

pub use error::{ZacError, ZacResult};
pub use hash::{file_hash, r1cs_hash, vk_fingerprint};
pub use header::{Header, HEADER_SIZE, MAGIC_ZAC};
pub use iden3::wtns::{parse_wtns, Wtns};
pub use iden3::zkey::{parse_zkey, vkey_bytes_compressed, Zkey};
pub use index::IndexEntry;
pub use prover::{prove, prove_with_rng};
pub use section::{InterfaceSection, Section};
pub use trailer::{Trailer, TRAILER_SIZE};
pub use verifier::verify;
pub use zac_file::ZacFile;
pub use zac_proof::{ProofHeader, ZacProofFile, MAGIC_ZACP, PROOF_PREFIX_SIZE, PROOF_SIZE};
