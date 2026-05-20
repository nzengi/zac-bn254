//! Groth16 prover — Phase 3 final, **fully native Rust**.
//!
//! ## Phase 3 (final) implementation note
//!
//! Earlier Phase 3 prototypes shelled out to Node + snarkjs as a
//! subprocess and treated snarkjs as a black box. That path produced a
//! real Groth16 proof, but the prover toolchain dependency made
//! `cargo run` / `cargo bench` flakey, doubled the wall-clock cost
//! (~300 ms vs ~3 ms per proof on the multiplier fixture), and prevented
//! downstream crates from embedding ZAC without bundling Node + snarkjs.
//!
//! Phase 3 (final) replaces that shim with [`crate::groth16_prover`], a
//! native Rust port of `snarkjs/src/groth16_prove.js`. The crate now has
//! **zero runtime dependency on Node**. A reference oracle for the
//! cross-verify direction A (snarkjs proof → ZAC verify) still lives in
//! the `node-tools` workspace, but is invoked only by the JS cross-verify
//! script, not from Rust.
//!
//! See the [`crate::groth16_prover`] module for the step-by-step math.

use ark_bn254::Fr;
use ark_ff::{One, PrimeField};
use ark_serialize::CanonicalSerialize;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing::{instrument, trace};

use crate::error::{ZacError, ZacResult};
use crate::groth16_prover::{groth16_native_prove_with_rng, RNG_SEED};
use crate::hash::vk_fingerprint;
use crate::iden3::wtns::Wtns;
use crate::iden3::zkey::{vkey_bytes_compressed, Zkey};
use crate::zac_file::ZacFile;
use crate::zac_proof::{ProofHeader, ZacProofFile, PROOF_SIZE};

/// Top-level entry point: bind a `.zac` + parsed `.zkey` + parsed `.wtns`
/// into a `.zacp`.
///
/// Pure-Rust prover — no subprocess, no temp files, no filesystem I/O.
/// Caller pre-parses `.zkey` via [`crate::iden3::zkey::parse_zkey`] and
/// `.wtns` via [`crate::iden3::wtns::parse_wtns`].
///
/// The proof produced here is byte-compatible with snarkjs's
/// `groth16.verify` and structurally identical to what `snarkjs groth16
/// prove` would emit; both directions of the cross-verify suite confirm
/// this in CI.
#[instrument(level = "trace", skip(zac, zkey, wtns))]
pub fn prove(zac: &ZacFile, zkey: &Zkey, wtns: &Wtns) -> ZacResult<ZacProofFile> {
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED);
    prove_with_rng(zac, zkey, wtns, &mut rng)
}

/// Like [`prove`], but with caller-provided randomness for the Groth16
/// blinding scalars `r, s`. Use `&mut OsRng` for production builds; the
/// default [`prove`] entry point keeps the deterministic seed=0 RNG so
/// regression tests and benchmarks see a stable proof byte-for-byte.
#[instrument(level = "trace", skip(zac, zkey, wtns, rng))]
pub fn prove_with_rng<R: RngCore>(
    zac: &ZacFile,
    zkey: &Zkey,
    wtns: &Wtns,
    rng: &mut R,
) -> ZacResult<ZacProofFile> {
    // 1. Witness sanity (mirrors snarkjs/groth16_prove.js).
    if wtns.values.len() != zkey.n_vars as usize {
        return Err(ZacError::PublicInputCountMismatch {
            offset: 0,
            declared: wtns.values.len() as u64,
            expected: zkey.n_vars as u64,
        });
    }
    if wtns.values[0] != Fr::one() {
        return Err(ZacError::NonCanonicalFr {
            offset: 0,
            input_index: 0,
        });
    }
    trace!(
        n_vars = zkey.n_vars,
        n_public = zkey.n_public,
        domain_size = zkey.domain_size,
        "prove: witness shape OK"
    );

    // 2. Native Groth16 prove.
    let (pi_a, pi_b, pi_c) = groth16_native_prove_with_rng(zkey, wtns, rng)?;
    trace!("prove: native prove returned (A, B, C)");

    // 3. Serialize (A, B, C) as arkworks canonical compressed (32 + 64 + 32 = 128 B).
    let mut proof_bytes = [0u8; PROOF_SIZE];
    {
        let (a_buf, rest) = proof_bytes.split_at_mut(32);
        let (b_buf, c_buf) = rest.split_at_mut(64);
        pi_a.serialize_compressed(&mut a_buf[..])
            .map_err(|_| ZacError::NonCanonicalPoint {
                offset: 0x50,
                reason: "ark-bn254 G1 compress (pi_a)",
            })?;
        pi_b.serialize_compressed(&mut b_buf[..])
            .map_err(|_| ZacError::NonCanonicalPoint {
                offset: 0x70,
                reason: "ark-bn254 G2 compress (pi_b)",
            })?;
        pi_c.serialize_compressed(&mut c_buf[..])
            .map_err(|_| ZacError::NonCanonicalPoint {
                offset: 0xB0,
                reason: "ark-bn254 G1 compress (pi_c)",
            })?;
    }
    trace!("prove: compressed proof block built");

    // 4. Public inputs — w[1..=n_public] in 32-byte LE form.
    let mut public_inputs: Vec<[u8; 32]> = Vec::with_capacity(zkey.n_public as usize);
    for i in 1..=(zkey.n_public as usize) {
        let fr = wtns.values[i];
        public_inputs.push(fr_to_le_32(&fr));
    }

    // 5. vk_fingerprint from the bound .zac's VKEY section.
    let vkey_body = zac
        .sections
        .iter()
        .find_map(|s| match s {
            crate::section::Section::Vkey(b) => Some(b.clone()),
            _ => None,
        })
        .ok_or(ZacError::MissingMandatorySection {
            missing_type: 0x01,
            name: "VKEY",
        })?;
    let fp = vk_fingerprint(&vkey_body);

    // 6. Sanity-bind: the zkey's parsed vk must re-serialize to exactly
    //    the bytes in the .zac's VKEY section. Otherwise .zac and .zkey
    //    are from different setups.
    let zkey_vk = vkey_bytes_compressed(zkey);
    if zkey_vk != vkey_body {
        return Err(ZacError::VkFingerprintMismatch);
    }
    trace!(vk_fingerprint = %hex::encode(fp), "prove: vk_fingerprint OK");

    Ok(ZacProofFile {
        header: ProofHeader {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            public_input_count: public_inputs.len() as u32,
            zac_file_hash: zac.trailer.file_hash,
            vk_fingerprint: fp,
        },
        proof: proof_bytes,
        public_inputs,
    })
}

fn fr_to_le_32(fr: &Fr) -> [u8; 32] {
    use ark_ff::BigInteger;
    let bytes = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_to_le_32_zero() {
        let z = Fr::from(0u64);
        assert_eq!(fr_to_le_32(&z), [0u8; 32]);
    }

    #[test]
    fn fr_to_le_32_one() {
        let one = Fr::one();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(fr_to_le_32(&one), expected);
    }
}
