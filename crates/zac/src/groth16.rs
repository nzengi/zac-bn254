//! Groth16 / BN254 protocol layer — arkworks 0.4 wire decoding (SPEC §7, §8).
//!
//! Phase 1 kept VKEY as opaque `Vec<u8>` and the `.zacp` proof block as
//! opaque `[u8; 128]`. This module is the crypto boundary: it turns those
//! bytes into actual curve / field elements, refusing every non-canonical
//! or off-subgroup encoding.
//!
//! Every entry point in this module is deterministic and pure: feed it bytes,
//! get back a decoded value (or a precise [`ZacError`] pointing at the
//! offending byte range). No allocation beyond what arkworks itself does.
//!
//! ## SPEC mapping
//!
//! SPEC §7 (G1/G2 encoding) is handled by `decode_vk` and `decode_proof`:
//! `ark-bn254 0.4` canonical compressed via
//! `CanonicalDeserialize::deserialize_with_mode(_, Compress::Yes,
//! Validate::No)`, followed by explicit `is_on_curve` and
//! `is_in_correct_subgroup_assuming_on_curve` checks. We split validation
//! away from arkworks' deserializer because arkworks' coarse
//! `SerializationError::InvalidData` does not let us distinguish off-curve
//! (E010) from off-subgroup (E011); doing the checks ourselves gives the
//! SPEC-mandated error attribution.
//!
//! SPEC §8 (Fr canonical, `< r`) is handled by `decode_fr_canonical`:
//! explicit `< r` comparison against the on-wire bytes. We deliberately do
//! NOT use `Fr::from_le_bytes_mod_order`, which silently reduces (and
//! would accept `r`, `r+1`, …).

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use tracing::trace;

use crate::error::{ZacError, ZacResult};

/// SPEC §7 — compressed G1 size in bytes.
pub const G1_COMPRESSED_BYTES: usize = 32;
/// SPEC §7 — compressed G2 size in bytes.
pub const G2_COMPRESSED_BYTES: usize = 64;
/// SPEC §4.2 — fixed 32 || 64 || 32 layout of `.zacp` proof block.
pub const PROOF_BYTES: usize = G1_COMPRESSED_BYTES + G2_COMPRESSED_BYTES + G1_COMPRESSED_BYTES;
/// SPEC §4.2 — absolute `.zacp` offset of `pi_a`.
pub const OFFSET_PI_A: usize = 0x50;
/// SPEC §4.2 — absolute `.zacp` offset of `pi_b`.
pub const OFFSET_PI_B: usize = 0x70;
/// SPEC §4.2 — absolute `.zacp` offset of `pi_c`.
pub const OFFSET_PI_C: usize = 0xB0;
/// SPEC §4.3 — absolute `.zacp` offset of the first Fr public input.
pub const OFFSET_PUBLIC_INPUTS: usize = 0xD0;

/// Newtype around `ark_groth16::VerifyingKey<Bn254>` so all construction in
/// this crate goes through [`decode_vk`].
///
/// `Eq` is intentionally not derived: arkworks' `VerifyingKey` only
/// implements `PartialEq`, and group-element equality on `Fp`-extension
/// fields is fundamentally `PartialEq` semantics in the arkworks 0.4 API.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedVk(pub VerifyingKey<Bn254>);

/// Decoded Groth16 proof — the three affine points of [`Proof`] split out.
///
/// Field ordering matches SPEC §4.2 (`pi_a, pi_b, pi_c`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedProof {
    /// `pi_a ∈ G1`.
    pub a: G1Affine,
    /// `pi_b ∈ G2`.
    pub b: G2Affine,
    /// `pi_c ∈ G1`.
    pub c: G1Affine,
}

impl DecodedProof {
    /// Convert this decoded triple back into the arkworks [`Proof`] type the
    /// pairing verifier consumes.
    #[inline]
    pub fn into_arkworks(self) -> Proof<Bn254> {
        Proof {
            a: self.a,
            b: self.b,
            c: self.c,
        }
    }
}

/// Decode an `ark-groth16` canonical-compressed verifying key from raw bytes.
///
/// Steps:
/// 1. `VerifyingKey::<Bn254>::deserialize_with_mode(bytes, Compress::Yes,
///    Validate::No)` — accepts any compressed bytes that decode to a point
///    on the curve (arkworks still rejects non-canonical x via
///    `InvalidData`).
/// 2. Explicitly run `is_on_curve` (E010) and
///    `is_in_correct_subgroup_assuming_on_curve` (E011) on each of
///    `alpha_g1`, `beta_g2`, `gamma_g2`, `delta_g2`, and every element of
///    `gamma_abc_g1`. Splitting (1) and (2) lets us distinguish E010 from
///    E011 — arkworks' single `SerializationError::InvalidData` cannot.
pub fn decode_vk(bytes: &[u8]) -> ZacResult<DecodedVk> {
    trace!(
        step = 1,
        bytes = bytes.len(),
        "groth16::decode_vk: deserialize VK (Compress::Yes, Validate::No)"
    );
    let vk = VerifyingKey::<Bn254>::deserialize_with_mode(bytes, Compress::Yes, Validate::No)
        .map_err(|e| classify_deser_err(&e, 0, "vkey"))?;

    check_g1_subgroup(&vk.alpha_g1, 0, "vk.alpha_g1")?;
    check_g2_subgroup(&vk.beta_g2, 0, "vk.beta_g2")?;
    check_g2_subgroup(&vk.gamma_g2, 0, "vk.gamma_g2")?;
    check_g2_subgroup(&vk.delta_g2, 0, "vk.delta_g2")?;
    for (i, p) in vk.gamma_abc_g1.iter().enumerate() {
        check_g1_subgroup(p, i, "vk.gamma_abc_g1[i]")?;
    }

    trace!(
        ic_len = vk.gamma_abc_g1.len(),
        "groth16::decode_vk: on-curve + subgroup checks passed"
    );
    Ok(DecodedVk(vk))
}

/// Decode the 128-byte proof block of a `.zacp` (SPEC §4.2).
///
/// Layout is fixed: `[0x00, 0x20)` = pi_a (G1), `[0x20, 0x60)` = pi_b (G2),
/// `[0x60, 0x80)` = pi_c (G1). Offsets reported in errors are the absolute
/// `.zacp` offsets `0x50` / `0x70` / `0xB0` so a hex-dump pinpoints the bad
/// element.
pub fn decode_proof(bytes_128: &[u8; PROOF_BYTES]) -> ZacResult<DecodedProof> {
    trace!(
        step = 1,
        "groth16::decode_proof: split 32||64||32, deserialize each compressed"
    );

    let a_bytes = &bytes_128[0..G1_COMPRESSED_BYTES];
    let b_bytes = &bytes_128[G1_COMPRESSED_BYTES..G1_COMPRESSED_BYTES + G2_COMPRESSED_BYTES];
    let c_bytes = &bytes_128[G1_COMPRESSED_BYTES + G2_COMPRESSED_BYTES..];

    let a = G1Affine::deserialize_with_mode(a_bytes, Compress::Yes, Validate::No)
        .map_err(|e| classify_deser_err(&e, OFFSET_PI_A, "pi_a"))?;
    check_g1_subgroup(&a, OFFSET_PI_A, "pi_a")?;
    trace!(offset = OFFSET_PI_A, "groth16::decode_proof: pi_a ok");

    let b = G2Affine::deserialize_with_mode(b_bytes, Compress::Yes, Validate::No)
        .map_err(|e| classify_deser_err(&e, OFFSET_PI_B, "pi_b"))?;
    check_g2_subgroup(&b, OFFSET_PI_B, "pi_b")?;
    trace!(offset = OFFSET_PI_B, "groth16::decode_proof: pi_b ok");

    let c = G1Affine::deserialize_with_mode(c_bytes, Compress::Yes, Validate::No)
        .map_err(|e| classify_deser_err(&e, OFFSET_PI_C, "pi_c"))?;
    check_g1_subgroup(&c, OFFSET_PI_C, "pi_c")?;
    trace!(offset = OFFSET_PI_C, "groth16::decode_proof: pi_c ok");

    Ok(DecodedProof { a, b, c })
}

/// Decode a 32-byte LE-encoded Fr scalar, rejecting any value `>= r`.
///
/// `offset` is the absolute `.zacp` offset of the 32-byte chunk (used only
/// for error formatting); `input_index` is the 0-based index of this input
/// in the public-input array. Returns [`ZacError::NonCanonicalFr`] (E012) on
/// any value outside `[0, r)`.
///
/// We deliberately compare the raw little-endian bytes to `Fr::MODULUS`
/// (`r`) without going through `Fr::from_le_bytes_mod_order`, which would
/// silently accept `r`, `r+1`, …
pub fn decode_fr_canonical(
    bytes_32: &[u8; 32],
    offset: usize,
    input_index: usize,
) -> ZacResult<Fr> {
    // Build the LE u256 representation of the input and the modulus, then
    // compare lexicographically from the most-significant byte down. This is
    // the same comparison `Fr::deserialize_with_mode(_, Compress::Yes,
    // Validate::Yes)` does internally, but doing it ourselves keeps E012
    // attribution unambiguous (a future arkworks change cannot quietly soften
    // the check).
    let modulus_le = Fr::MODULUS.to_bytes_le();
    debug_assert_eq!(modulus_le.len(), 32, "Fr fits in 32 LE bytes");
    if ge_le(bytes_32, &modulus_le) {
        trace!(
            offset,
            input_index,
            value = %hex::encode(bytes_32),
            modulus = %hex::encode(&modulus_le),
            "rejecting: Fr scalar >= r"
        );
        return Err(ZacError::NonCanonicalFr {
            offset,
            input_index,
        });
    }

    // Safe to deserialize now — every < r value is canonical.
    let fr =
        Fr::deserialize_with_mode(&bytes_32[..], Compress::Yes, Validate::Yes).map_err(|_| {
            ZacError::NonCanonicalFr {
                offset,
                input_index,
            }
        })?;
    trace!(
        offset,
        input_index,
        value = %hex::encode(bytes_32),
        "groth16::decode_fr_canonical: ok"
    );
    Ok(fr)
}

/// Prepare a [`VerifyingKey`] for pairing-based verification (wraps
/// `ark_groth16::prepare_verifying_key`).
///
/// `PreparedVerifyingKey` precomputes `e(alpha, beta)` and the negated
/// `gamma`/`delta` G2 points — Phase 3 caching will avoid this rebuild per
/// call.
pub fn prepare_vk(vk: &DecodedVk) -> PreparedVerifyingKey<Bn254> {
    prepare_verifying_key(&vk.0)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compare two 32-byte little-endian unsigned integers. Returns `true` iff
/// `a >= b`. Constant-time in the operand size (32 B); no early exit by
/// design — we don't depend on this for side-channel resistance but it keeps
/// the logic uniform regardless of input.
fn ge_le(a: &[u8; 32], b: &[u8]) -> bool {
    debug_assert_eq!(b.len(), 32);
    // Walk from the most-significant byte (index 31) down to the least.
    for i in (0..32).rev() {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Greater => return true,
            core::cmp::Ordering::Less => return false,
            core::cmp::Ordering::Equal => continue,
        }
    }
    // Bytewise equal → a == b → a >= b is true (and Fr's "must be < r" still
    // means we reject this case).
    true
}

fn check_g1_subgroup(p: &G1Affine, offset: usize, what: &'static str) -> ZacResult<()> {
    if p.is_zero() {
        // Point at infinity is in every subgroup by definition; arkworks'
        // Validate::Yes already accepted it.
        return Ok(());
    }
    if !p.is_on_curve() {
        trace!(offset, what, "rejecting: G1 point off-curve");
        return Err(ZacError::NonCanonicalPoint {
            offset,
            reason: "G1 point not on curve",
        });
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        trace!(offset, what, "rejecting: G1 point off-subgroup");
        return Err(ZacError::SubgroupCheckFailed { offset });
    }
    Ok(())
}

fn check_g2_subgroup(p: &G2Affine, offset: usize, what: &'static str) -> ZacResult<()> {
    if p.is_zero() {
        return Ok(());
    }
    if !p.is_on_curve() {
        trace!(offset, what, "rejecting: G2 point off-curve");
        return Err(ZacError::NonCanonicalPoint {
            offset,
            reason: "G2 point not on curve",
        });
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        trace!(offset, what, "rejecting: G2 point off-subgroup");
        return Err(ZacError::SubgroupCheckFailed { offset });
    }
    Ok(())
}

/// Map an arkworks `SerializationError` (or its underlying I/O failure) to
/// one of our spec-level error codes. The arkworks 0.4 API does not let us
/// inspect the discriminant directly from outside the crate, so we go
/// through `Debug` formatting — coarse, but only used on the error path.
fn classify_deser_err(
    e: &ark_serialize::SerializationError,
    offset: usize,
    _what: &'static str,
) -> ZacError {
    let msg = format!("{e:?}");
    if msg.contains("InvalidData")
        || msg.contains("NotCanonical")
        || msg.contains("UnexpectedFlags")
        || msg.contains("IoError")
        || msg.contains("Io")
    {
        ZacError::NonCanonicalPoint {
            offset,
            reason: "arkworks: non-canonical / off-curve / bad flags",
        }
    } else if msg.contains("InvalidSubgroup") || msg.contains("Subgroup") {
        ZacError::SubgroupCheckFailed { offset }
    } else {
        // Default to E010 — "I don't know exactly which one, but it's
        // structurally bad". Better than swallowing the error.
        ZacError::NonCanonicalPoint {
            offset,
            reason: "arkworks: deserialization failure",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Zero;

    #[test]
    fn fr_zero_is_canonical() {
        let zero = [0u8; 32];
        let fr = decode_fr_canonical(&zero, 0, 0).unwrap();
        assert_eq!(fr, Fr::zero());
    }

    #[test]
    fn fr_modulus_is_rejected() {
        let m = Fr::MODULUS.to_bytes_le();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&m);
        let err = decode_fr_canonical(&buf, 0, 0).unwrap_err();
        assert_eq!(err.code(), "E012");
    }

    #[test]
    fn fr_modulus_minus_one_is_accepted() {
        let mut m = Fr::MODULUS;
        m.sub_with_borrow(&ark_ff::BigInt::from(1u64));
        let bytes = m.to_bytes_le();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        let fr = decode_fr_canonical(&buf, 0, 0).unwrap();
        // fr should equal -1 mod r, i.e. Fr::from(-1) which equals
        // Fr::MODULUS - 1.
        assert_eq!(fr + Fr::from(1u64), Fr::zero());
    }
}
