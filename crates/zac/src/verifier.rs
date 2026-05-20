//! Top-level Groth16 verifier orchestration (SPEC §6, §7, §8).
//!
//! This module wires together the structural `.zac` / `.zacp` parsers from
//! Phase 1 with the arkworks crypto primitives in [`crate::groth16`]. The
//! public surface is a single function — [`verify`] — that takes already-
//! parsed `ZacFile` + `ZacProofFile` values and returns `Ok(())` on success
//! or a precise `E###` on the first failed check.
//!
//! ## Order of operations (fail-fast)
//!
//! Phase 1 already validated every byte of the container; this module focuses
//! on cryptographic binding + pairing. Every step is traced; bail on the
//! first failure so a hex-dump + the error message is enough to diagnose.
//!
//! 1. Locate VKEY and INTERFACE sections.
//! 2. (E014) `proof.vk_fingerprint == BLAKE3("zac1.vkey.v1\0" || VKEY)`.
//! 3. (E009) `proof.zac_file_hash == zac.trailer.file_hash`.
//! 4. (E013) `proof.public_input_count == interface.public_input_count`.
//! 5. Decode VKEY (E010 / E011 from `groth16::decode_vk`).
//! 6. (E013) `vk.gamma_abc_g1.len() == interface.public_input_count + 1`.
//! 7. Decode the 128-byte proof block (E010 / E011 from `groth16::decode_proof`).
//! 8. Decode each public input (E012 from `groth16::decode_fr_canonical`).
//! 9. `prepare_verifying_key` (uncached in Phase 2 — bench measures cost).
//! 10. `Groth16::verify_proof` — on `Ok(true)` return `Ok(())`; otherwise E017.

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use tracing::{instrument, trace};

use crate::error::{ZacError, ZacResult};
use crate::groth16::{
    decode_fr_canonical, decode_proof, decode_vk, prepare_vk, OFFSET_PUBLIC_INPUTS,
};
use crate::hash::vk_fingerprint;
use crate::section::{InterfaceSection, Section};
use crate::zac_file::ZacFile;
use crate::zac_proof::ZacProofFile;

/// Verify a parsed `.zacp` against a parsed `.zac`.
///
/// Returns `Ok(())` iff every binding + structural check passes AND the
/// Groth16 pairing equation holds. Otherwise the first failure surfaces as
/// the most specific `E###` (see module docs for the order).
///
/// # Example
///
/// ```
/// use zac::{verify, ZacFile, ZacProofFile};
///
/// let zac  = ZacFile::parse(include_bytes!("../tests/fixtures/multiplier.zac"))?;
/// let zacp = ZacProofFile::parse(include_bytes!("../tests/fixtures/multiplier.zacp"))?;
/// verify(&zac, &zacp)?;
/// # Ok::<(), zac::ZacError>(())
/// ```
///
/// On rejection the returned error carries the offset and field name. A
/// typical incident-response loop logs `err.code()` (`"E017"`, `"E010"`,
/// …) alongside the structured `Debug` output and grep-checks the spec.
#[instrument(level = "trace", skip(zac, proof))]
pub fn verify(zac: &ZacFile, proof: &ZacProofFile) -> ZacResult<()> {
    trace!("verify: step 1 — locate VKEY + INTERFACE sections");
    let (vkey_bytes, iface) = find_vkey_and_interface(zac)?;

    // 2. vk_fingerprint binding (E014).
    trace!(step = 2, field = "vk_fingerprint", "checking");
    let recomputed_fp = vk_fingerprint(vkey_bytes);
    if recomputed_fp != proof.header.vk_fingerprint {
        trace!(
            expected = %hex::encode(proof.header.vk_fingerprint),
            computed = %hex::encode(recomputed_fp),
            "rejecting: vk_fingerprint mismatch"
        );
        return Err(ZacError::VkFingerprintMismatch);
    }

    // 3. zac_file_hash binding (E009 — same code as the trailer self-hash
    //    mismatch because the underlying semantic match is identical:
    //    "this proof claims to bind to file X but X's BLAKE3 differs").
    trace!(step = 3, field = "zac_file_hash", "checking");
    if proof.header.zac_file_hash != zac.trailer.file_hash {
        trace!(
            expected = %hex::encode(proof.header.zac_file_hash),
            computed = %hex::encode(zac.trailer.file_hash),
            "rejecting: zac_file_hash mismatch"
        );
        return Err(ZacError::BadFileHash {
            trailer: zac.trailer.file_hash,
            computed: proof.header.zac_file_hash,
        });
    }

    // 4. public_input_count binding against INTERFACE (E013).
    trace!(
        step = 4,
        declared = proof.header.public_input_count,
        expected = iface.public_input_count,
        "checking public_input_count"
    );
    if proof.header.public_input_count != iface.public_input_count {
        return Err(ZacError::PublicInputCountMismatch {
            offset: 8, // .zacp public_input_count field offset
            declared: proof.header.public_input_count as u64,
            expected: iface.public_input_count as u64,
        });
    }
    // Belt-and-braces: the parser already enforces <= 4096, but we re-check
    // because INTERFACE could in principle declare a larger count (Phase 1
    // would have accepted that since the cap is .zacp-side).
    if (iface.public_input_count as usize) > crate::zac_proof::MAX_PUBLIC_INPUTS {
        return Err(ZacError::PublicInputCountMismatch {
            offset: 0,
            declared: iface.public_input_count as u64,
            expected: crate::zac_proof::MAX_PUBLIC_INPUTS as u64,
        });
    }

    // 5. Decode VKEY (E010 / E011).
    trace!(step = 5, bytes = vkey_bytes.len(), "decoding VKEY");
    let decoded_vk = decode_vk(vkey_bytes)?;

    // 6. Cross-check `vk.gamma_abc_g1.len() == public_input_count + 1`.
    let ic_len = decoded_vk.0.gamma_abc_g1.len();
    let expected_ic_len = iface.public_input_count as usize + 1;
    if ic_len != expected_ic_len {
        trace!(
            ic_len,
            expected_ic_len,
            "rejecting: vk.gamma_abc_g1.len mismatch"
        );
        return Err(ZacError::PublicInputCountMismatch {
            offset: 0,
            declared: ic_len as u64,
            expected: expected_ic_len as u64,
        });
    }
    trace!(step = 6, ic_len, "vk IC length OK");

    // 7. Decode 128-byte proof block (E010 / E011).
    trace!(step = 7, "decoding proof block");
    let decoded_proof = decode_proof(&proof.proof)?;

    // 8. Decode public inputs (E012).
    trace!(
        step = 8,
        count = proof.header.public_input_count,
        "decoding Fr public inputs"
    );
    let mut inputs = Vec::with_capacity(proof.public_inputs.len());
    for (i, chunk) in proof.public_inputs.iter().enumerate() {
        let off = OFFSET_PUBLIC_INPUTS + i * 32;
        let fr = decode_fr_canonical(chunk, off, i)?;
        inputs.push(fr);
    }

    // 9. Prepare VK (uncached — Phase 3 will add a cache; the bench shows
    //    how much pairing prep costs).
    trace!(step = 9, "preparing VK (pairing precompute)");
    let pvk = prepare_vk(&decoded_vk);

    // 10. Run the pairing equation.
    trace!(step = 10, "Groth16::verify_proof");
    let ark_proof = decoded_proof.into_arkworks();
    match Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &inputs) {
        Ok(true) => {
            trace!("verify: pairing equation holds — OK");
            Ok(())
        }
        Ok(false) => {
            trace!("rejecting: pairing equation does not hold");
            Err(ZacError::ProofRejected {
                reason: "Groth16 pairing equation does not hold",
            })
        }
        Err(e) => {
            // The most common cause here is `MalformedVerifyingKey` when the
            // IC length disagrees with `inputs.len() + 1`. We re-check above
            // explicitly (step 6), so an error reaching this branch is
            // genuinely upstream — surface as E017.
            trace!(error = ?e, "Groth16 verifier returned Err");
            Err(ZacError::ProofRejected {
                reason: "arkworks verifier returned error (see trace)",
            })
        }
    }
}

/// Locate the mandatory VKEY (returns its byte slice) and INTERFACE sections.
///
/// `ZacFile::parse` already enforces mandatory-section presence (E016), so
/// the unwraps below would only fire on a hand-constructed `ZacFile`. We
/// still surface E016 if a caller constructs `ZacFile` programmatically and
/// skips it.
fn find_vkey_and_interface(zac: &ZacFile) -> ZacResult<(&[u8], &InterfaceSection)> {
    let mut vkey: Option<&[u8]> = None;
    let mut iface: Option<&InterfaceSection> = None;
    for s in &zac.sections {
        match s {
            Section::Vkey(b) => vkey = Some(b.as_slice()),
            Section::Interface(i) => iface = Some(i),
            _ => {}
        }
    }
    let vkey = vkey.ok_or(ZacError::MissingMandatorySection {
        missing_type: crate::index::SECTION_VKEY,
        name: "VKEY",
    })?;
    let iface = iface.ok_or(ZacError::MissingMandatorySection {
        missing_type: crate::index::SECTION_INTERFACE,
        name: "INTERFACE",
    })?;
    Ok((vkey, iface))
}
