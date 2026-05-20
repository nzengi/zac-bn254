//! snarkjs Groth16 `.zkey` parser (iden3 ZKEY format, type 1 = groth16).
//!
//! ## Sections (per snarkjs/src/zkey_utils.js)
//!
//! ```text
//! 0x01  Header              — 4-byte protocol id (1 = groth16)
//! 0x02  HeaderGroth         — n8q, q, n8r, r, nVars, nPublic, domainSize,
//!                              alpha1, beta1, beta2, gamma2, delta1, delta2
//! 0x03  IC                  — (nPublic + 1) × G1
//! 0x04  Coefs               — nCoefs (u32) | per coef (m u32, c u32, s u32, v Fr Mont LE)
//! 0x05  PointsA             — nVars × G1
//! 0x06  PointsB1            — nVars × G1
//! 0x07  PointsB2            — nVars × G2
//! 0x08  PointsC             — (nVars - nPublic - 1) × G1
//! 0x09  PointsH             — domainSize × G1
//! 0x0a  Contributions       — opaque (skipped)
//! ```
//!
//! ## Montgomery convention
//!
//! Both Fr values in section 4 AND Fq coordinates inside G1/G2 points are
//! encoded **little-endian Montgomery**: the on-wire integer `n` satisfies
//! `n ≡ x · R (mod q)` where `R = 2^256`. Conversion to standard form is
//! `x ≡ n · R^(-1) (mod q)`.
//!
//! The conversion is done by `from_mont_le_fq` (Fq) and `from_mont_le_fr`
//! (Fr). G1 reads `[x_mont, y_mont]` (64 bytes), G2 reads
//! `[c0_x, c1_x, c0_y, c1_y]` (128 bytes).

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalDeserialize;
use byteorder::{ByteOrder, LittleEndian};

use crate::error::{ZacError, ZacResult};
use crate::iden3::{find_section, read_binfile_header, BN254_Q_LE, BN254_R_LE};

/// Size on-wire of one G1 point in snarkjs format (LE Montgomery, uncompressed).
pub const SNARKJS_G1_BYTES: usize = 64;
/// Size on-wire of one G2 point in snarkjs format.
pub const SNARKJS_G2_BYTES: usize = 128;

/// Parsed snarkjs Groth16 verifying key + proving key triple.
///
/// Phase 3 (native prover) populates **all** proving-key segments:
/// `coefs`, `a_query`, `b_g1_query`, `b_g2_query`, `c_query`, `h_query`.
#[derive(Debug, Clone)]
pub struct Zkey {
    /// Number of total wires (including the constant `1` wire).
    pub n_vars: u32,
    /// Number of public inputs/outputs (not counting the constant `1`).
    pub n_public: u32,
    /// FFT domain size (power of two).
    pub domain_size: u32,

    /// `α · G ∈ G1`.
    pub alpha_g1: G1Affine,
    /// `β · G ∈ G1`.
    pub beta_g1: G1Affine,
    /// `β · H ∈ G2`.
    pub beta_g2: G2Affine,
    /// `γ · H ∈ G2`.
    pub gamma_g2: G2Affine,
    /// `δ · G ∈ G1`.
    pub delta_g1: G1Affine,
    /// `δ · H ∈ G2`.
    pub delta_g2: G2Affine,

    /// `IC[i] = (β·u_i + α·v_i + w_i)/γ · G` for `i ∈ [0, nPublic]`.
    pub ic: Vec<G1Affine>,

    /// Raw bytes of section 0x02 (the snarkjs Groth-header). Useful for
    /// downstream cross-verify scripts that want to re-export the vk.
    pub raw_header_groth: Vec<u8>,

    /// Section 0x04 — sparse R1CS coefficient table.
    ///
    /// Each entry is the snarkjs quadruple `(m, c, s, v)` where:
    ///   * `m ∈ {0, 1}` selects the R1CS matrix (0 = A, 1 = B; the C matrix
    ///     is reconstructed implicitly via `C·w = A·w * B·w` on the
    ///     evaluation domain — see snarkjs `groth16_prove.js::buildABC1`);
    ///   * `c` is the constraint index in `[0, n_constraints)` plus a fake
    ///     "public-input identity" tail in `[n_constraints, domain_size)`;
    ///   * `s` is the witness signal index in `[0, n_vars)`;
    ///   * `v` is the coefficient already converted from Montgomery LE to
    ///     standard `Fr` form.
    pub coefs: Vec<ZkeyCoef>,
    /// Section 0x05 — `A` MSM bases (G1, length = `n_vars`).
    pub a_query: Vec<G1Affine>,
    /// Section 0x06 — `B1` MSM bases (G1, length = `n_vars`).
    pub b_g1_query: Vec<G1Affine>,
    /// Section 0x07 — `B2` MSM bases (G2, length = `n_vars`).
    pub b_g2_query: Vec<G2Affine>,
    /// Section 0x08 — `C` MSM bases (G1, length = `n_vars − n_public − 1`).
    ///
    /// These bases multiply the *non-public* part of the witness, so the
    /// MSM consumes `w[n_public + 1 ..]` (see snarkjs `groth16_prove.js`).
    pub c_query: Vec<G1Affine>,
    /// Section 0x09 — `H` MSM bases (G1, length = `domain_size`).
    ///
    /// The `i`-th element is the snarkjs-encoded "odd-coset" Lagrange basis
    /// `δ^(−1) · τ^(2i+1) · G`, scaled by `1/(α^n − 1)` (with
    /// `α = nqr²`); the prover MSMs them against
    /// `P_odd[i] = (A_odd · B_odd − C_odd)(α · ω^i)` to obtain
    /// `H(τ) · δ^(−1) · G1`.
    pub h_query: Vec<G1Affine>,
}

/// One row of the snarkjs `.zkey` section 0x04 sparse coefficient table.
#[derive(Debug, Clone, Copy)]
pub struct ZkeyCoef {
    /// Matrix selector: 0 = A, 1 = B.
    pub matrix: u8,
    /// Constraint index (row in the QAP evaluation domain).
    pub constraint: u32,
    /// Witness signal index (column in the R1CS).
    pub signal: u32,
    /// Coefficient value in standard `Fr` form (Montgomery scaling already
    /// removed by [`fr_from_mont_le`]).
    pub value: Fr,
}

/// Parse a snarkjs `.zkey` file. Phase 3 fully decodes both the verifying
/// key portion (sections 1–3) **and** every proving-key segment (sections
/// 4–9) so the native Rust Groth16 prover in [`crate::groth16_prover`] can
/// run without invoking snarkjs.
///
/// All G1/G2 points are validated on-curve + in-subgroup; all Fr/Fq values
/// undergo SPEC §8 canonical checks (E012) before exiting the parser.
pub fn parse_zkey(bytes: &[u8]) -> ZacResult<Zkey> {
    let (_hdr, sects) = read_binfile_header(bytes, b"zkey")?;

    // Section 1: protocol id
    let s1 = find_section(&sects, 1).ok_or(ZacError::MissingMandatorySection {
        missing_type: 0x01,
        name: "zkey.header",
    })?;
    if s1.size < 4 {
        return Err(ZacError::Truncated {
            offset: s1.offset,
            need: 4,
            have: s1.size as usize,
        });
    }
    let proto = LittleEndian::read_u32(&bytes[s1.offset..s1.offset + 4]);
    if proto != 1 {
        return Err(ZacError::BadFlags {
            offset: s1.offset,
            field: "zkey.protocol",
            value: proto as u64,
        });
    }

    // Section 2: Groth16 header (curve + counts + vk elements)
    let s2 = find_section(&sects, 2).ok_or(ZacError::MissingMandatorySection {
        missing_type: 0x02,
        name: "zkey.header_groth",
    })?;
    let mut off = s2.offset;

    let n8q = LittleEndian::read_u32(&bytes[off..off + 4]);
    off += 4;
    if n8q != 32 {
        return Err(ZacError::BadFlags {
            offset: off - 4,
            field: "zkey.n8q",
            value: n8q as u64,
        });
    }
    let mut prime_q = [0u8; 32];
    prime_q.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    if prime_q != BN254_Q_LE {
        return Err(ZacError::BadFlags {
            offset: off - 32,
            field: "zkey.q",
            value: u64::from_le_bytes(prime_q[0..8].try_into().unwrap()),
        });
    }
    let n8r = LittleEndian::read_u32(&bytes[off..off + 4]);
    off += 4;
    if n8r != 32 {
        return Err(ZacError::BadFlags {
            offset: off - 4,
            field: "zkey.n8r",
            value: n8r as u64,
        });
    }
    let mut prime_r = [0u8; 32];
    prime_r.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    if prime_r != BN254_R_LE {
        return Err(ZacError::BadFlags {
            offset: off - 32,
            field: "zkey.r",
            value: u64::from_le_bytes(prime_r[0..8].try_into().unwrap()),
        });
    }
    let n_vars = LittleEndian::read_u32(&bytes[off..off + 4]);
    off += 4;
    let n_public = LittleEndian::read_u32(&bytes[off..off + 4]);
    off += 4;
    let domain_size = LittleEndian::read_u32(&bytes[off..off + 4]);
    off += 4;

    let alpha_g1 = read_snarkjs_g1(&bytes[off..off + SNARKJS_G1_BYTES], off)?;
    off += SNARKJS_G1_BYTES;
    let beta_g1 = read_snarkjs_g1(&bytes[off..off + SNARKJS_G1_BYTES], off)?;
    off += SNARKJS_G1_BYTES;
    let beta_g2 = read_snarkjs_g2(&bytes[off..off + SNARKJS_G2_BYTES], off)?;
    off += SNARKJS_G2_BYTES;
    let gamma_g2 = read_snarkjs_g2(&bytes[off..off + SNARKJS_G2_BYTES], off)?;
    off += SNARKJS_G2_BYTES;
    let delta_g1 = read_snarkjs_g1(&bytes[off..off + SNARKJS_G1_BYTES], off)?;
    off += SNARKJS_G1_BYTES;
    let delta_g2 = read_snarkjs_g2(&bytes[off..off + SNARKJS_G2_BYTES], off)?;
    off += SNARKJS_G2_BYTES;

    let _ = off; // off is the end of section 2 body
    let raw_header_groth = bytes[s2.offset..s2.offset + s2.size as usize].to_vec();

    // Section 3: IC (nPublic + 1 G1 points)
    let s3 = find_section(&sects, 3).ok_or(ZacError::MissingMandatorySection {
        missing_type: 0x03,
        name: "zkey.IC",
    })?;
    let need = (n_public as usize + 1) * SNARKJS_G1_BYTES;
    if s3.size as usize != need {
        return Err(ZacError::Truncated {
            offset: s3.offset,
            need,
            have: s3.size as usize,
        });
    }
    let mut ic = Vec::with_capacity(n_public as usize + 1);
    for i in 0..=n_public as usize {
        let a = s3.offset + i * SNARKJS_G1_BYTES;
        let p = read_snarkjs_g1(&bytes[a..a + SNARKJS_G1_BYTES], a)?;
        ic.push(p);
    }

    // Section 4: Coefs — sparse coefficient table for matrices A (m=0) and B (m=1).
    let s4 = find_section(&sects, 4).ok_or(ZacError::MissingMandatorySection {
        missing_type: 0x04,
        name: "zkey.coefs",
    })?;
    if s4.size < 4 {
        return Err(ZacError::Truncated {
            offset: s4.offset,
            need: 4,
            have: s4.size as usize,
        });
    }
    let n_coefs = LittleEndian::read_u32(&bytes[s4.offset..s4.offset + 4]) as usize;
    // Each row: 4-byte m | 4-byte c | 4-byte s | 32-byte Fr Mont LE = 44 bytes.
    let coef_stride = 4 + 4 + 4 + 32;
    let coefs_need = 4 + n_coefs * coef_stride;
    if s4.size as usize != coefs_need {
        return Err(ZacError::Truncated {
            offset: s4.offset,
            need: coefs_need,
            have: s4.size as usize,
        });
    }
    let mut coefs = Vec::with_capacity(n_coefs);
    for i in 0..n_coefs {
        let a = s4.offset + 4 + i * coef_stride;
        let m = LittleEndian::read_u32(&bytes[a..a + 4]);
        let c = LittleEndian::read_u32(&bytes[a + 4..a + 8]);
        let s = LittleEndian::read_u32(&bytes[a + 8..a + 12]);
        if m > 1 {
            return Err(ZacError::BadFlags {
                offset: a,
                field: "zkey.coef.matrix",
                value: m as u64,
            });
        }
        if c >= domain_size {
            return Err(ZacError::PublicInputCountMismatch {
                offset: a + 4,
                declared: c as u64,
                expected: domain_size as u64,
            });
        }
        if s >= n_vars {
            return Err(ZacError::PublicInputCountMismatch {
                offset: a + 8,
                declared: s as u64,
                expected: n_vars as u64,
            });
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes[a + 12..a + 12 + 32]);
        let v = from_mont_le_fr_bytes(&buf).map_err(|e| match e {
            ZacError::NonCanonicalFr { input_index, .. } => ZacError::NonCanonicalFr {
                offset: a + 12,
                input_index,
            },
            other => other,
        })?;
        coefs.push(ZkeyCoef {
            matrix: m as u8,
            constraint: c,
            signal: s,
            value: v,
        });
    }
    tracing::trace!(n_coefs, "zkey: parsed section 4 (Coefs)");

    // Section 5: PointsA — nVars G1 bases for the A-MSM.
    let a_query = parse_g1_array(bytes, &sects, 5, n_vars as usize, "zkey.points_a")?;
    // Section 6: PointsB1 — nVars G1 bases for the B1-MSM.
    let b_g1_query = parse_g1_array(bytes, &sects, 6, n_vars as usize, "zkey.points_b1")?;
    // Section 7: PointsB2 — nVars G2 bases for the B2-MSM.
    let b_g2_query = parse_g2_array(bytes, &sects, 7, n_vars as usize, "zkey.points_b2")?;
    // Section 8: PointsC — (nVars − nPublic − 1) G1 bases for the C-MSM.
    let c_len = (n_vars as usize).saturating_sub(n_public as usize + 1);
    let c_query = parse_g1_array(bytes, &sects, 8, c_len, "zkey.points_c")?;
    // Section 9: PointsH — domainSize G1 bases for the H-MSM.
    let h_query = parse_g1_array(bytes, &sects, 9, domain_size as usize, "zkey.points_h")?;

    tracing::trace!(
        n_vars,
        n_public,
        domain_size,
        ic_len = ic.len(),
        n_coefs,
        a_query_len = a_query.len(),
        b1_len = b_g1_query.len(),
        b2_len = b_g2_query.len(),
        c_len = c_query.len(),
        h_len = h_query.len(),
        "zkey: parsed Groth16 pk + vk"
    );

    Ok(Zkey {
        n_vars,
        n_public,
        domain_size,
        alpha_g1,
        beta_g1,
        beta_g2,
        gamma_g2,
        delta_g1,
        delta_g2,
        ic,
        raw_header_groth,
        coefs,
        a_query,
        b_g1_query,
        b_g2_query,
        c_query,
        h_query,
    })
}

fn parse_g1_array(
    bytes: &[u8],
    sects: &[crate::iden3::SectionRef],
    id: u32,
    n: usize,
    name: &'static str,
) -> ZacResult<Vec<G1Affine>> {
    let s = find_section(sects, id).ok_or(ZacError::MissingMandatorySection {
        missing_type: id as u8,
        name,
    })?;
    let need = n * SNARKJS_G1_BYTES;
    if s.size as usize != need {
        return Err(ZacError::Truncated {
            offset: s.offset,
            need,
            have: s.size as usize,
        });
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let a = s.offset + i * SNARKJS_G1_BYTES;
        out.push(read_snarkjs_g1(&bytes[a..a + SNARKJS_G1_BYTES], a)?);
    }
    Ok(out)
}

fn parse_g2_array(
    bytes: &[u8],
    sects: &[crate::iden3::SectionRef],
    id: u32,
    n: usize,
    name: &'static str,
) -> ZacResult<Vec<G2Affine>> {
    let s = find_section(sects, id).ok_or(ZacError::MissingMandatorySection {
        missing_type: id as u8,
        name,
    })?;
    let need = n * SNARKJS_G2_BYTES;
    if s.size as usize != need {
        return Err(ZacError::Truncated {
            offset: s.offset,
            need,
            have: s.size as usize,
        });
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let a = s.offset + i * SNARKJS_G2_BYTES;
        out.push(read_snarkjs_g2(&bytes[a..a + SNARKJS_G2_BYTES], a)?);
    }
    Ok(out)
}

/// Convert a 32-byte LE Montgomery-form Fq integer to a standard-form
/// `Fq`. `mont · R^(-1) mod q` where `R = 2^256`.
///
/// We use the trick `Fq::from_bigint(mont_bigint)` — internally arkworks
/// stores Fq in its own Montgomery form (`R_ark = 2^256 mod q` happens to
/// match the snarkjs convention). However, arkworks's `from_bigint` expects
/// a value `< q` already in *standard* form. So we read the bytes as a
/// standard-form BigInt, then multiply by `R_inv` to undo the Montgomery
/// scaling.
fn from_mont_le_fq(bytes: &[u8]) -> ZacResult<Fq> {
    assert_eq!(bytes.len(), 32);
    // Reject non-canonical (value >= q).
    if !is_lt_modulus(bytes, &BN254_Q_LE) {
        return Err(ZacError::NonCanonicalPoint {
            offset: 0,
            reason: "Fq Montgomery integer >= q",
        });
    }
    let std_bigint = ark_ff::BigInt::<4>::deserialize_uncompressed(&mut std::io::Cursor::new(
        bytes,
    ))
    .map_err(|_| ZacError::NonCanonicalPoint {
        offset: 0,
        reason: "Fq Montgomery integer decode",
    })?;
    // Treat std_bigint as a Montgomery-form integer m and recover x = m * R^-1.
    // x = m / R = m * R^-1
    // We compute x by constructing m * R^-1 via Fq arithmetic:
    //   represent m as Fq::from_bigint(m) (which arkworks stores in its own
    //   Mont form with the same R = 2^256). Then multiply by R^-1 (precomputed).
    let m = Fq::from_bigint(std_bigint).ok_or(ZacError::NonCanonicalPoint {
        offset: 0,
        reason: "Fq Montgomery integer not in field",
    })?;
    Ok(m * r_inv_fq())
}

/// Same conversion for Fr.
fn from_mont_le_fr_bytes(bytes: &[u8]) -> ZacResult<Fr> {
    assert_eq!(bytes.len(), 32);
    if !is_lt_modulus(bytes, &BN254_R_LE) {
        return Err(ZacError::NonCanonicalFr {
            offset: 0,
            input_index: 0,
        });
    }
    let std_bigint = ark_ff::BigInt::<4>::deserialize_uncompressed(&mut std::io::Cursor::new(
        bytes,
    ))
    .map_err(|_| ZacError::NonCanonicalFr {
        offset: 0,
        input_index: 0,
    })?;
    let m = Fr::from_bigint(std_bigint).ok_or(ZacError::NonCanonicalFr {
        offset: 0,
        input_index: 0,
    })?;
    Ok(m * r_inv_fr())
}

/// `R^(-1) mod q` for `R = 2^256`, as an `Fq`. Built by doubling `1` 256
/// times to obtain `R mod q`, then inverting.
fn r_inv_fq() -> Fq {
    let mut r = Fq::from(1u64);
    for _ in 0..256 {
        r = r + r;
    }
    r.inverse().expect("2^256 mod q nonzero")
}

/// `R^(-1) mod r` for `R = 2^256`, as an `Fr`.
fn r_inv_fr() -> Fr {
    let mut r = Fr::from(1u64);
    for _ in 0..256 {
        r = r + r;
    }
    r.inverse().expect("2^256 mod r nonzero")
}

/// True iff `bytes` (LE) is strictly less than `modulus_le`.
fn is_lt_modulus(bytes: &[u8], modulus_le: &[u8; 32]) -> bool {
    debug_assert_eq!(bytes.len(), 32);
    for i in (0..32).rev() {
        match bytes[i].cmp(&modulus_le[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

fn read_snarkjs_g1(bytes: &[u8], abs_off: usize) -> ZacResult<G1Affine> {
    if bytes.len() != SNARKJS_G1_BYTES {
        return Err(ZacError::Truncated {
            offset: abs_off,
            need: SNARKJS_G1_BYTES,
            have: bytes.len(),
        });
    }
    // Detect the snarkjs "point at infinity" encoding: 64 zero bytes
    // (both coordinates Montgomery-zero). Standard Fq(0) Montgomery form
    // is also zero, so this is unambiguous.
    if bytes.iter().all(|b| *b == 0) {
        return Ok(G1Affine::identity());
    }
    let x = from_mont_le_fq(&bytes[0..32]).map_err(|e| reattribute(e, abs_off))?;
    let y = from_mont_le_fq(&bytes[32..64]).map_err(|e| reattribute(e, abs_off + 32))?;
    let p = G1Affine::new_unchecked(x, y);
    // SPEC §7 subgroup checks (E010/E011).
    if !p.is_on_curve() {
        return Err(ZacError::NonCanonicalPoint {
            offset: abs_off,
            reason: "snarkjs G1 point not on curve",
        });
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZacError::SubgroupCheckFailed { offset: abs_off });
    }
    Ok(p)
}

fn read_snarkjs_g2(bytes: &[u8], abs_off: usize) -> ZacResult<G2Affine> {
    if bytes.len() != SNARKJS_G2_BYTES {
        return Err(ZacError::Truncated {
            offset: abs_off,
            need: SNARKJS_G2_BYTES,
            have: bytes.len(),
        });
    }
    if bytes.iter().all(|b| *b == 0) {
        return Ok(G2Affine::identity());
    }
    let x_c0 = from_mont_le_fq(&bytes[0..32]).map_err(|e| reattribute(e, abs_off))?;
    let x_c1 = from_mont_le_fq(&bytes[32..64]).map_err(|e| reattribute(e, abs_off + 32))?;
    let y_c0 = from_mont_le_fq(&bytes[64..96]).map_err(|e| reattribute(e, abs_off + 64))?;
    let y_c1 = from_mont_le_fq(&bytes[96..128]).map_err(|e| reattribute(e, abs_off + 96))?;
    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(ZacError::NonCanonicalPoint {
            offset: abs_off,
            reason: "snarkjs G2 point not on curve",
        });
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZacError::SubgroupCheckFailed { offset: abs_off });
    }
    Ok(p)
}

fn reattribute(e: ZacError, abs_off: usize) -> ZacError {
    match e {
        ZacError::NonCanonicalPoint { reason, .. } => ZacError::NonCanonicalPoint {
            offset: abs_off,
            reason,
        },
        other => other,
    }
}

/// Re-export the convenient Fr Montgomery decoder so the ingest example
/// can read snarkjs ccoefs values when/if Phase 4 needs them.
pub fn fr_from_mont_le(bytes: &[u8; 32]) -> ZacResult<Fr> {
    from_mont_le_fr_bytes(bytes)
}

/// Serialize the parsed zkey's verifying key as an `ark-groth16` canonical
/// compressed VKEY blob, ready to be placed in a ZAC `0x01` (VKEY) section.
///
/// The arkworks [`ark_groth16::VerifyingKey<Bn254>`] struct stores:
/// `alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1`. We populate it
/// straight from the snarkjs vk fields — note `beta_g1`, `delta_g1` are not
/// in arkworks's VK (they live in the proving key).
pub fn vkey_bytes_compressed(zkey: &Zkey) -> Vec<u8> {
    use ark_groth16::VerifyingKey;
    use ark_serialize::CanonicalSerialize;

    let vk: VerifyingKey<ark_bn254::Bn254> = VerifyingKey {
        alpha_g1: zkey.alpha_g1,
        beta_g2: zkey.beta_g2,
        gamma_g2: zkey.gamma_g2,
        delta_g2: zkey.delta_g2,
        gamma_abc_g1: zkey.ic.clone(),
    };
    let mut out = Vec::with_capacity(vk.compressed_size());
    vk.serialize_compressed(&mut out)
        .expect("ark-groth16 VK serialization is infallible for in-range data");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_inv_q_times_2_pow_256_eq_1() {
        let mut r = Fq::from(1u64);
        for _ in 0..256 {
            r = r + r;
        }
        let product = r * r_inv_fq();
        assert_eq!(product, Fq::from(1u64));
    }

    #[test]
    fn r_inv_r_times_2_pow_256_eq_1() {
        let mut r = Fr::from(1u64);
        for _ in 0..256 {
            r = r + r;
        }
        let product = r * r_inv_fr();
        assert_eq!(product, Fr::from(1u64));
    }
}
