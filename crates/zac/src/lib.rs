#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! ZAC — Groth16 BN254 artifact container (v1.0).
//!
//! v1.0 implements **only** Groth16 over BN254. Additional proof systems
//! and curves (BLS12-381, Halo2, PLONK, FFLonk) are out of scope and will
//! be considered in future major versions, not bolted onto v1.
//!
//! The wire format is defined in `docs/SPEC.md`. Every byte of every section
//! is parseable from the spec alone; there is no hidden invariant. Tracing
//! logs at the `trace` level provide a byte-by-byte narrative for debugging.
//!
//! ## Phase 1 scope
//!
//! Phase 1 implemented pure **parse + encode** round-tripping with every
//! SPEC-level structural invariant enforced. The VKEY body and the `.zacp`
//! proof block were kept as opaque byte slices.
//!
//! ## Phase 2 scope
//!
//! Phase 2 wraps those opaque byte slices with `ark-bn254 0.4` canonical
//! parsing, runs the SPEC §6 binding checks (E009 / E013 / E014), the
//! SPEC §7 subgroup checks (E010 / E011), the SPEC §8 Fr canonical check
//! (E012), and finally runs the Groth16 pairing equation (E017 on
//! rejection). The single entry point is [`verify`].

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
