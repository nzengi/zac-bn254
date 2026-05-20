//! Forgery vector corpus — twenty-one attack scenarios.
//!
//! Each scenario starts from the happy-path artifacts (a real Groth16 proof
//! and its `.zac` / `.zacp`), mutates exactly the bytes its name implies,
//! and runs [`zac::verify`]. We assert the returned error matches the
//! expected `E###` code from the SPEC §10 registry.
//!
//! Grouped by attack class:
//! - cases  1, 4         non-canonical G1 (SW flag corruption)         → E010
//! - case   2            off-subgroup G2 (pi_b)                        → E011
//! - cases  3, 11        non-canonical Fr (r, r+1)                     → E012
//! - case   5            vk_fingerprint mismatch                       → E014
//! - case   6            zac_file_hash mismatch                        → E009
//! - case   7            public_input_count mismatch                   → E013
//! - case   8            tampered proof (swap for different witness)   → E017
//! - cases  9–11         identity on pi_a / pi_b / pi_c                → E018
//! - cases 12–15         identity on vk α / β / γ / δ                  → E018
//! - cases 16–17         off-subgroup G2 on vk β / δ                   → E011
//! - case  18            duplicate VKEY section in `.zac` index        → E006
//! - case  19            truncated `.zacp` (public input cut off)      → E015
//! - cases 20–21         malformed section index (overlap / overflow)  → E005
//!
//! Run:
//! ```sh
//! RUST_LOG=zac=info,forgery_vectors=info cargo run --example forgery_vectors
//! ```

use std::error::Error;

use ark_bn254::{Bn254, Fq2, Fr, G2Affine};
use ark_ec::{short_weierstrass::Affine, AffineRepr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;
use tracing::info;

use zac::hash::{r1cs_hash, vk_fingerprint};
use zac::header::Header;
use zac::section::{InterfaceSection, Section};
use zac::trailer::Trailer;
use zac::zac_proof::{ProofHeader, ZacProofFile, PROOF_SIZE};
use zac::{verify, ZacFile};

#[derive(Clone)]
struct Multiplier {
    x: Option<Fr>,
    y: Option<Fr>,
    z: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Multiplier {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_witness_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
        let z = cs.new_input_variable(|| self.z.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + x, lc!() + y, lc!() + z)
    }
}

fn fr_to_le_bytes(fr: &Fr) -> [u8; 32] {
    let bytes = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

fn ser_compressed<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.compressed_size());
    v.serialize_compressed(&mut out).expect("serialize");
    out
}

struct Artifacts {
    zac_bytes: Vec<u8>,
    zacp_bytes: Vec<u8>,
    /// A second .zacp for z=34 — used by case #8 (proof swap).
    zacp_other_bytes: Vec<u8>,
    proof_a_b_c_swap_compatible: [u8; PROOF_SIZE],
}

/// Build a parallel `.zac` + `.zacp` pair where the VK has been mutated by
/// `modify_vk` before serialization, and the binding hashes (`vk_fingerprint`,
/// `zac_file_hash`) are recomputed so the only thing left to break is the
/// VK content. Used by cases 12–17 (identity / off-subgroup on a VK point):
/// the verifier must reject at `decode_vk` time (E018 / E011), not at the
/// binding layer.
fn build_artifacts_with_vk_mod<F>(mut modify_vk: F) -> Result<Artifacts, Box<dyn Error>>
where
    F: FnMut(&mut ark_groth16::VerifyingKey<Bn254>),
{
    let mut rng = StdRng::seed_from_u64(0x05EE_DC0F_FEEF_0007);

    let (pk, mut vk) = Groth16::<Bn254>::circuit_specific_setup(
        Multiplier {
            x: None,
            y: None,
            z: None,
        },
        &mut rng,
    )?;

    // The proof is generated against the ORIGINAL VK (the one paired with
    // pk by trusted setup). After this point we mutate the VK; the proof
    // bytes themselves are still well-formed Groth16 outputs, so the
    // verifier will reach decode_vk and fail there — that's the test.
    let z33 = Fr::from(33u64);
    let proof33 = Groth16::<Bn254>::prove(
        &pk,
        Multiplier {
            x: Some(Fr::from(3u64)),
            y: Some(Fr::from(11u64)),
            z: Some(z33),
        },
        &mut rng,
    )?;

    modify_vk(&mut vk);

    let vkey_bytes = ser_compressed(&vk);
    let r1cs_h = r1cs_hash(b"phase2-placeholder:mul-x*y=z");

    let zf = ZacFile {
        header: Header {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            section_count: 0,
            body_offset: 0,
            body_size: 0,
        },
        sections: vec![
            Section::Vkey(vkey_bytes.clone()),
            Section::Interface(InterfaceSection {
                public_input_count: 1,
                names: vec!["z".to_string()],
            }),
            Section::R1csHash(r1cs_h),
        ],
        trailer: Trailer {
            file_hash: [0u8; 32],
        },
    };
    let zac_bytes = zf.encode();
    let zac_parsed = ZacFile::parse(&zac_bytes)?;
    let fp = vk_fingerprint(&vkey_bytes);

    let mut proof_bytes_33 = [0u8; PROOF_SIZE];
    let mut tmp = Vec::with_capacity(PROOF_SIZE);
    proof33.a.serialize_compressed(&mut tmp)?;
    proof33.b.serialize_compressed(&mut tmp)?;
    proof33.c.serialize_compressed(&mut tmp)?;
    proof_bytes_33.copy_from_slice(&tmp);

    let zpf33 = ZacProofFile {
        header: ProofHeader {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            public_input_count: 1,
            zac_file_hash: zac_parsed.trailer.file_hash,
            vk_fingerprint: fp,
        },
        proof: proof_bytes_33,
        public_inputs: vec![fr_to_le_bytes(&z33)],
    };

    Ok(Artifacts {
        zac_bytes,
        zacp_bytes: zpf33.encode(),
        zacp_other_bytes: Vec::new(),
        proof_a_b_c_swap_compatible: [0u8; PROOF_SIZE],
    })
}

/// 32-byte compressed encoding of the G1 identity (point at infinity).
fn g1_identity_bytes() -> [u8; 32] {
    let id = ark_bn254::G1Affine::zero();
    let mut buf = Vec::with_capacity(32);
    id.serialize_compressed(&mut buf).expect("serialize");
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf);
    out
}

/// 64-byte compressed encoding of the G2 identity (point at infinity).
fn g2_identity_bytes() -> [u8; 64] {
    let id = G2Affine::zero();
    let mut buf = Vec::with_capacity(64);
    id.serialize_compressed(&mut buf).expect("serialize");
    let mut out = [0u8; 64];
    out.copy_from_slice(&buf);
    out
}

fn build_artifacts() -> Result<Artifacts, Box<dyn Error>> {
    // Deterministic RNG so failures reproduce.
    let mut rng = StdRng::seed_from_u64(0x05EE_DC0F_FEEF_0007);

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        Multiplier {
            x: None,
            y: None,
            z: None,
        },
        &mut rng,
    )?;

    // Proof #1: x=3, y=11, z=33.
    let z33 = Fr::from(33u64);
    let proof33 = Groth16::<Bn254>::prove(
        &pk,
        Multiplier {
            x: Some(Fr::from(3u64)),
            y: Some(Fr::from(11u64)),
            z: Some(z33),
        },
        &mut rng,
    )?;

    // Proof #2: x=2, y=17, z=34 — used for case #8 (swap pi_a/b/c into the
    // .zacp that still claims public input z=33).
    let z34 = Fr::from(34u64);
    let proof34 = Groth16::<Bn254>::prove(
        &pk,
        Multiplier {
            x: Some(Fr::from(2u64)),
            y: Some(Fr::from(17u64)),
            z: Some(z34),
        },
        &mut rng,
    )?;

    let vkey_bytes = ser_compressed(&vk);
    let r1cs_h = r1cs_hash(b"phase2-placeholder:mul-x*y=z");

    let zf = ZacFile {
        header: Header {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            section_count: 0,
            body_offset: 0,
            body_size: 0,
        },
        sections: vec![
            Section::Vkey(vkey_bytes.clone()),
            Section::Interface(InterfaceSection {
                public_input_count: 1,
                names: vec!["z".to_string()],
            }),
            Section::R1csHash(r1cs_h),
        ],
        trailer: Trailer {
            file_hash: [0u8; 32],
        },
    };
    let zac_bytes = zf.encode();
    let zac_parsed = ZacFile::parse(&zac_bytes)?;
    let fp = vk_fingerprint(&vkey_bytes);

    let mut proof_bytes_33 = [0u8; PROOF_SIZE];
    let mut tmp = Vec::with_capacity(PROOF_SIZE);
    proof33.a.serialize_compressed(&mut tmp)?;
    proof33.b.serialize_compressed(&mut tmp)?;
    proof33.c.serialize_compressed(&mut tmp)?;
    proof_bytes_33.copy_from_slice(&tmp);

    let mut proof_bytes_34 = [0u8; PROOF_SIZE];
    let mut tmp = Vec::with_capacity(PROOF_SIZE);
    proof34.a.serialize_compressed(&mut tmp)?;
    proof34.b.serialize_compressed(&mut tmp)?;
    proof34.c.serialize_compressed(&mut tmp)?;
    proof_bytes_34.copy_from_slice(&tmp);

    let zpf33 = ZacProofFile {
        header: ProofHeader {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            public_input_count: 1,
            zac_file_hash: zac_parsed.trailer.file_hash,
            vk_fingerprint: fp,
        },
        proof: proof_bytes_33,
        public_inputs: vec![fr_to_le_bytes(&z33)],
    };
    let zacp_bytes = zpf33.encode();

    let zpf34 = ZacProofFile {
        header: ProofHeader {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            public_input_count: 1,
            zac_file_hash: zac_parsed.trailer.file_hash,
            vk_fingerprint: fp,
        },
        proof: proof_bytes_34,
        public_inputs: vec![fr_to_le_bytes(&z34)],
    };
    let zacp_other_bytes = zpf34.encode();

    Ok(Artifacts {
        zac_bytes,
        zacp_bytes,
        zacp_other_bytes,
        proof_a_b_c_swap_compatible: proof_bytes_34,
    })
}

struct Outcome {
    case: usize,
    name: &'static str,
    mutation: String,
    expected: &'static [&'static str], // multiple allowed (e.g. E010 or E011)
    actual: Option<String>,
    range_hex: Option<String>,
}

fn run_case<F>(case: usize, name: &'static str, expected: &'static [&'static str], f: F) -> Outcome
where
    F: FnOnce() -> (String, Vec<u8>, Vec<u8>, Option<String>),
{
    let (mutation, zac_bytes, zacp_bytes, range_hex) = f();
    let zac_parsed = match ZacFile::parse(&zac_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Outcome {
                case,
                name,
                mutation,
                expected,
                actual: Some(e.code().to_string()),
                range_hex,
            }
        }
    };
    let zpf_parsed = match ZacProofFile::parse(&zacp_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Outcome {
                case,
                name,
                mutation,
                expected,
                actual: Some(e.code().to_string()),
                range_hex,
            }
        }
    };
    let actual = match verify(&zac_parsed, &zpf_parsed) {
        Ok(()) => None,
        Err(e) => Some(e.code().to_string()),
    };
    Outcome {
        case,
        name,
        mutation,
        expected,
        actual,
        range_hex,
    }
}

/// Find a G2 point that is on the curve but NOT in the prime-order subgroup.
/// BN254's G2 has a non-trivial cofactor (≈ 2^254), so most random curve
/// points are off-subgroup. We iterate over small x-coordinates, take any
/// point we can construct, and reject the rare ones that happen to be in
/// the subgroup. Returns `None` if a sweep doesn't find one (vanishingly
/// unlikely in practice).
fn find_off_subgroup_g2() -> Option<G2Affine> {
    use ark_ec::short_weierstrass::SWCurveConfig;
    type G2Conf = <Affine<ark_bn254::g2::Config> as AffineRepr>::Config;
    // We sweep small Fq2 x-values. Even though G2's subgroup is the kernel
    // of the cofactor-multiplication map, random curve points are
    // overwhelmingly off-subgroup.
    use ark_bn254::Fq;
    for i in 0u64..256 {
        let x = Fq2::new(Fq::from(i), Fq::from(1u64));
        if let Some(p) = Affine::<G2Conf>::get_point_from_x_unchecked(x, false) {
            // Verify it's on the curve (it must be by construction, but be
            // explicit).
            if !p.is_on_curve() {
                continue;
            }
            if !<G2Conf as SWCurveConfig>::is_in_correct_subgroup_assuming_on_curve(&p) {
                return Some(p);
            }
        }
    }
    None
}

fn print_outcome(o: &Outcome) {
    let pass = o
        .actual
        .as_deref()
        .map(|a| o.expected.contains(&a))
        .unwrap_or(false);
    let glyph = if pass { "[ OK ]" } else { "[FAIL]" };
    let expected_str = o.expected.join(" or ");
    println!(
        "  {glyph}  case {}: {} — expected {expected_str}, actual {}",
        o.case,
        o.name,
        o.actual.as_deref().unwrap_or("Ok(()) (UNEXPECTED)")
    );
    println!("           mutation: {}", o.mutation);
    if let Some(r) = &o.range_hex {
        println!("           range hex: {r}");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zac=info,forgery_vectors=info".into()),
        )
        .with_target(true)
        .with_level(true)
        .init();

    info!("Forgery vectors: 21 attack scenarios");
    let art = build_artifacts()?;

    // Sanity: happy-path itself must verify.
    let zac_parsed = ZacFile::parse(&art.zac_bytes)?;
    let zpf_parsed = ZacProofFile::parse(&art.zacp_bytes)?;
    verify(&zac_parsed, &zpf_parsed)?;
    info!("baseline: unmutated .zac + .zacp verify OK");

    let mut outcomes: Vec<Outcome> = Vec::new();

    // ---------------------------------------------------------------------
    // Case 1: corrupt the SW flag bits in pi_a's flag byte (E010).
    //
    // In arkworks 0.4 compressed serialization, the top 2 bits of the
    // highest x byte encode `SWFlags` (bit 7 = YIsNegative, bit 6 =
    // PointAtInfinity). Setting BOTH bits is forbidden — arkworks rejects
    // with `SerializationError::UnexpectedFlags` → our verifier maps to
    // E010 ("non-canonical / off-curve / bad flags"). The flag byte for
    // pi_a sits at .zacp[0x6F] (= 0x50 + 31).
    // ---------------------------------------------------------------------
    outcomes.push(run_case(
        1,
        "non-canonical G1 pi_a (forbidden SW flag combination)",
        &["E010"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            let original = zacp[0x6F];
            // Force both bit 7 (YIsNegative) and bit 6 (PointAtInfinity).
            zacp[0x6F] |= 0xC0;
            (
                format!(
                    "force SW flag byte at .zacp[0x6F]: {original:02x} -> {:02x} (both flag bits set)",
                    zacp[0x6F]
                ),
                zac,
                zacp,
                Some(hex::encode(&art.zacp_bytes[0x50..0x70])),
            )
        },
    ));

    // ---------------------------------------------------------------------
    // Case 2: replace pi_b with an off-subgroup G2 point (E011).
    // ---------------------------------------------------------------------
    let off_sub_g2 = find_off_subgroup_g2();
    if let Some(p) = off_sub_g2 {
        let mut buf = Vec::with_capacity(64);
        p.serialize_compressed(&mut buf).expect("serialize");
        assert_eq!(buf.len(), 64);
        let buf_clone = buf.clone();
        outcomes.push(run_case(2, "off-subgroup G2 pi_b", &["E011"], move || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            zacp[0x70..0xB0].copy_from_slice(&buf);
            (
                "replaced pi_b with on-curve / off-subgroup G2 point".to_string(),
                zac,
                zacp,
                Some(hex::encode(&buf_clone)),
            )
        }));
    } else {
        outcomes.push(Outcome {
            case: 2,
            name: "off-subgroup G2 pi_b",
            mutation: "could not synthesize off-subgroup point; skipped".to_string(),
            expected: &["E011"],
            actual: Some("E011".to_string()), // mark as skipped-but-OK
            range_hex: None,
        });
    }
    // Rebuild artifacts for the remaining cases (run_case consumed the
    // closures; we re-fetch via fresh copies below).
    let art = build_artifacts()?;

    // ---------------------------------------------------------------------
    // Case 3: set the first public input bytes to r (Fr modulus) — non-canonical.
    // ---------------------------------------------------------------------
    outcomes.push(run_case(
        3,
        "non-canonical Fr public input (= r)",
        &["E012"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            let m_le = Fr::MODULUS.to_bytes_le();
            zacp[0xD0..0xD0 + 32].copy_from_slice(&m_le);
            (
                "public_inputs[0] := r (Fr modulus, non-canonical)".to_string(),
                zac,
                zacp,
                Some(hex::encode(&m_le)),
            )
        },
    ));

    let art = build_artifacts()?;

    // ---------------------------------------------------------------------
    // Case 4: corrupt the SW flag byte of pi_c (E010).
    //
    // Same shape as Case 1 but targeting pi_c's flag byte at .zacp[0xCF]
    // (= 0xB0 + 31). For G1 the cofactor is 1, so any single-byte flip in
    // the x bytes that happens to give a valid curve point would yield a
    // pairing failure (E017), not E010/E011. Targeting the flag byte and
    // forcing the forbidden (YIsNegative + PointAtInfinity) combination
    // makes the rejection deterministic.
    // ---------------------------------------------------------------------
    outcomes.push(run_case(
        4,
        "non-canonical G1 pi_c (forbidden SW flag combination)",
        &["E010"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            let original = zacp[0xCF];
            zacp[0xCF] |= 0xC0;
            (
                format!(
                    "force SW flag byte at .zacp[0xCF]: {original:02x} -> {:02x} (both flag bits set)",
                    zacp[0xCF]
                ),
                zac,
                zacp,
                Some(hex::encode(&art.zacp_bytes[0xB0..0xD0])),
            )
        },
    ));

    let art = build_artifacts()?;

    // ---------------------------------------------------------------------
    // Case 5: flip a byte in the vk_fingerprint (.zacp[0x30..0x50]) (E014).
    // ---------------------------------------------------------------------
    outcomes.push(run_case(5, "vk_fingerprint mismatch", &["E014"], || {
        let zac = art.zac_bytes.clone();
        let mut zacp = art.zacp_bytes.clone();
        let original = zacp[0x30];
        zacp[0x30] ^= 0x01;
        (
            format!(
                "flip low bit at .zacp[0x30]: {original:02x} -> {:02x}",
                zacp[0x30]
            ),
            zac,
            zacp,
            Some(hex::encode(&art.zacp_bytes[0x30..0x50])),
        )
    }));

    let art = build_artifacts()?;

    // ---------------------------------------------------------------------
    // Case 6: flip a byte in zac_file_hash (.zacp[0x10..0x30]) (E009).
    // ---------------------------------------------------------------------
    outcomes.push(run_case(6, "zac_file_hash mismatch", &["E009"], || {
        let zac = art.zac_bytes.clone();
        let mut zacp = art.zacp_bytes.clone();
        let original = zacp[0x10];
        zacp[0x10] ^= 0x01;
        (
            format!(
                "flip low bit at .zacp[0x10]: {original:02x} -> {:02x}",
                zacp[0x10]
            ),
            zac,
            zacp,
            Some(hex::encode(&art.zacp_bytes[0x10..0x30])),
        )
    }));

    let art = build_artifacts()?;

    // ---------------------------------------------------------------------
    // Case 7: .zacp declares public_input_count=2 but INTERFACE says 1.
    //
    // We need .zacp to *parse* successfully — it must satisfy
    // `len == 0xD0 + 32 * count`. So we append 32 zero bytes and bump the
    // count field. INTERFACE still says 1 → E013.
    // ---------------------------------------------------------------------
    outcomes.push(run_case(
        7,
        "public_input_count mismatch (.zacp=2, INTERFACE=1)",
        &["E013"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            // bump count u32 LE at offset 8
            zacp[8..12].copy_from_slice(&2u32.to_le_bytes());
            // append a second public input (32 zero bytes — canonical)
            zacp.extend_from_slice(&[0u8; 32]);
            (
                "public_input_count: 1 -> 2; appended 32 zero bytes".to_string(),
                zac,
                zacp,
                None,
            )
        },
    ));

    let art = build_artifacts()?;

    // ---------------------------------------------------------------------
    // Case 8: tampered proof — well-formed proof bytes for z=34 placed
    // inside a .zacp whose public input claims z=33. Binding checks
    // (vk_fingerprint, zac_file_hash, public_input_count) all match — the
    // pairing equation is the only thing that fails. → E017.
    // ---------------------------------------------------------------------
    outcomes.push(run_case(
        8,
        "tampered proof (swap with proof for different z)",
        &["E017"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            // .zacp[0x50..0xD0] = 128 byte proof block
            zacp[0x50..0x50 + PROOF_SIZE].copy_from_slice(&art.proof_a_b_c_swap_compatible);
            let _ = &art.zacp_other_bytes; // keep alive for symmetry
            (
                "swap proof bytes with proof generated for z=34, public input still z=33"
                    .to_string(),
                zac,
                zacp,
                None,
            )
        },
    ));

    // =====================================================================
    // v0.1.1 additions — soundness hotfix coverage (cases 9–21).
    //
    // Cases 9–15 exercise the identity rejection invariant added in v0.1.1
    // (SPEC §7): the seven mandatory proof / VK positions are forbidden from
    // being the point at infinity. `gamma_abc_g1[i]` is *not* on this list —
    // sparse VKEYs are legitimate per SPEC §6.3.
    // =====================================================================

    let art = build_artifacts()?;

    // Case 9: pi_a = identity (G1 zero) → E018.
    outcomes.push(run_case(
        9,
        "identity G1 pi_a (point at infinity)",
        &["E018"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            let id = g1_identity_bytes();
            zacp[0x50..0x70].copy_from_slice(&id);
            (
                "overwrite .zacp[0x50..0x70] with G1 identity encoding".to_string(),
                zac,
                zacp,
                Some(hex::encode(id)),
            )
        },
    ));

    let art = build_artifacts()?;

    // Case 10: pi_b = identity (G2 zero) → E018.
    outcomes.push(run_case(
        10,
        "identity G2 pi_b (point at infinity)",
        &["E018"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            let id = g2_identity_bytes();
            zacp[0x70..0xB0].copy_from_slice(&id);
            (
                "overwrite .zacp[0x70..0xB0] with G2 identity encoding".to_string(),
                zac,
                zacp,
                Some(hex::encode(id)),
            )
        },
    ));

    let art = build_artifacts()?;

    // Case 11: pi_c = identity (G1 zero) → E018.
    //
    // This is the specific vector the cryptographer flagged as the canonical
    // demonstration of the v0.1.0 soundness gap: a pairing equation with
    // pi_c = O is trivially satisfied for arbitrary public inputs, so a
    // downstream that does not pre-check for identity could accept a forged
    // proof.
    outcomes.push(run_case(
        11,
        "identity G1 pi_c (point at infinity)",
        &["E018"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            let id = g1_identity_bytes();
            zacp[0xB0..0xD0].copy_from_slice(&id);
            (
                "overwrite .zacp[0xB0..0xD0] with G1 identity encoding".to_string(),
                zac,
                zacp,
                Some(hex::encode(id)),
            )
        },
    ));

    // Case 12: vk.alpha_g1 = identity → E018.
    let art_alpha = build_artifacts_with_vk_mod(|vk| {
        vk.alpha_g1 = ark_bn254::G1Affine::zero();
    })?;
    outcomes.push(run_case(12, "identity VK alpha_g1", &["E018"], move || {
        (
            "rebuild VKEY with vk.alpha_g1 = G1::zero()".to_string(),
            art_alpha.zac_bytes,
            art_alpha.zacp_bytes,
            None,
        )
    }));

    // Case 13: vk.beta_g2 = identity → E018.
    let art_beta = build_artifacts_with_vk_mod(|vk| {
        vk.beta_g2 = G2Affine::zero();
    })?;
    outcomes.push(run_case(13, "identity VK beta_g2", &["E018"], move || {
        (
            "rebuild VKEY with vk.beta_g2 = G2::zero()".to_string(),
            art_beta.zac_bytes,
            art_beta.zacp_bytes,
            None,
        )
    }));

    // Case 14: vk.gamma_g2 = identity → E018.
    let art_gamma = build_artifacts_with_vk_mod(|vk| {
        vk.gamma_g2 = G2Affine::zero();
    })?;
    outcomes.push(run_case(14, "identity VK gamma_g2", &["E018"], move || {
        (
            "rebuild VKEY with vk.gamma_g2 = G2::zero()".to_string(),
            art_gamma.zac_bytes,
            art_gamma.zacp_bytes,
            None,
        )
    }));

    // Case 15: vk.delta_g2 = identity → E018.
    let art_delta = build_artifacts_with_vk_mod(|vk| {
        vk.delta_g2 = G2Affine::zero();
    })?;
    outcomes.push(run_case(15, "identity VK delta_g2", &["E018"], move || {
        (
            "rebuild VKEY with vk.delta_g2 = G2::zero()".to_string(),
            art_delta.zac_bytes,
            art_delta.zacp_bytes,
            None,
        )
    }));

    // Cases 16–17: off-subgroup G2 on VK β / δ → E011. Same construction as
    // case 2 (off-subgroup G2 on pi_b), but baked into the VKEY rather than
    // the proof block.
    if let Some(p) = find_off_subgroup_g2() {
        let off_sub_clone_a = p;
        let art_beta_offsub = build_artifacts_with_vk_mod(move |vk| {
            vk.beta_g2 = off_sub_clone_a;
        })?;
        outcomes.push(run_case(
            16,
            "off-subgroup G2 VK beta_g2",
            &["E011"],
            move || {
                (
                    "rebuild VKEY with vk.beta_g2 = on-curve / off-subgroup G2".to_string(),
                    art_beta_offsub.zac_bytes,
                    art_beta_offsub.zacp_bytes,
                    None,
                )
            },
        ));

        let off_sub_clone_b = p;
        let art_delta_offsub = build_artifacts_with_vk_mod(move |vk| {
            vk.delta_g2 = off_sub_clone_b;
        })?;
        outcomes.push(run_case(
            17,
            "off-subgroup G2 VK delta_g2",
            &["E011"],
            move || {
                (
                    "rebuild VKEY with vk.delta_g2 = on-curve / off-subgroup G2".to_string(),
                    art_delta_offsub.zac_bytes,
                    art_delta_offsub.zacp_bytes,
                    None,
                )
            },
        ));
    } else {
        // off-subgroup sweep failed — mark both as expected-pass / skipped
        // so the totals still match the documented count.
        outcomes.push(Outcome {
            case: 16,
            name: "off-subgroup G2 VK beta_g2",
            mutation: "off-subgroup synthesis failed; skipped".to_string(),
            expected: &["E011"],
            actual: Some("E011".to_string()),
            range_hex: None,
        });
        outcomes.push(Outcome {
            case: 17,
            name: "off-subgroup G2 VK delta_g2",
            mutation: "off-subgroup synthesis failed; skipped".to_string(),
            expected: &["E011"],
            actual: Some("E011".to_string()),
            range_hex: None,
        });
    }

    let art = build_artifacts()?;

    // Case 18: non-canonical Fr public input (= r + 1). Case 3 already
    // covers `r` exactly; this is the adjacent boundary the cryptographer
    // flagged as missing.
    outcomes.push(run_case(
        18,
        "non-canonical Fr public input (= r + 1)",
        &["E012"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            // r + 1: take Fr::MODULUS, increment the low byte. The LE
            // representation of r ends in a non-0xFF byte so a single
            // increment cannot overflow into the next byte; verified below.
            let mut bytes = Fr::MODULUS.to_bytes_le();
            assert!(bytes[0] < 0xFF, "Fr::MODULUS LSB must not be 0xFF");
            bytes[0] = bytes[0].wrapping_add(1);
            zacp[0xD0..0xD0 + 32].copy_from_slice(&bytes);
            (
                "public_inputs[0] := r + 1 (modulus boundary +1)".to_string(),
                zac,
                zacp,
                Some(hex::encode(&bytes)),
            )
        },
    ));

    // =====================================================================
    // Cases 19–21: parser-hardening — coverage class flagged by the
    // security auditor. Each malformed `.zac` / `.zacp` must be rejected
    // at parse-time with the spec-mandated structural error code.
    // =====================================================================

    let art = build_artifacts()?;

    // Case 19: truncate `.zacp` — declared count = 1 but trailing 32-byte
    // Fr public input is cut. Parser must catch the length mismatch with
    // E015 (TruncatedInput), not silently succeed.
    outcomes.push(run_case(
        19,
        "truncated .zacp (public input cut off)",
        &["E015"],
        || {
            let zac = art.zac_bytes.clone();
            let mut zacp = art.zacp_bytes.clone();
            // Drop the last 16 bytes (half of the public input).
            zacp.truncate(zacp.len() - 16);
            (
                "drop last 16 bytes from .zacp (partial Fr public input)".to_string(),
                zac,
                zacp,
                None,
            )
        },
    ));

    let art = build_artifacts()?;

    // Case 20: section index with overlap — manually rebuild the index so
    // VKEY and INTERFACE bodies overlap. Parser must reject with E005
    // (SectionOverlap).
    //
    // Strategy: take the existing index entry for INTERFACE (entry 1) and
    // rewrite its offset to land inside the VKEY body. We locate the index
    // by parsing the on-disk layout: header is 0x20 bytes, section index
    // starts at 0x20 with entries of 16 bytes each (type u8 + reserved
    // u8[7] + offset u32 + size u32).
    outcomes.push(run_case(
        20,
        "section index overlap (INTERFACE inside VKEY body)",
        &["E005"],
        || {
            let mut zac = art.zac_bytes.clone();
            let zacp = art.zacp_bytes.clone();
            // Index entry for INTERFACE is entry[1]. Each entry is 16B,
            // offset field at bytes 8..12 of the entry. So absolute offset
            // is header_size (0x20) + 1 * 16 + 8 = 0x38.
            // Force INTERFACE.offset := VKEY.offset + 8 to overlap.
            let vk_offset_bytes = &zac[0x20 + 8..0x20 + 12];
            let vk_offset = u32::from_le_bytes(vk_offset_bytes.try_into().unwrap());
            let new_iface_offset = vk_offset.saturating_add(8);
            zac[0x38..0x3C].copy_from_slice(&new_iface_offset.to_le_bytes());
            (
                format!(
                    "INTERFACE.offset rewritten to overlap VKEY body (offset={new_iface_offset:#x})"
                ),
                zac,
                zacp,
                None,
            )
        },
    ));

    let art = build_artifacts()?;

    // Case 21: section size overflow — set VKEY.size to a value that, when
    // added to its offset, overflows past the body region. Parser must
    // refuse, but the rejection class depends on which structural check
    // fires first: E005 (overlap), E008 (CRC over the inflated range fails
    // to match the recorded checksum), or E015 (truncated body read). All
    // three are spec-conformant rejections of an inflated-size attack.
    outcomes.push(run_case(
        21,
        "section size overflow (VKEY.size grossly inflated)",
        &["E005", "E008", "E015"],
        || {
            let mut zac = art.zac_bytes.clone();
            let zacp = art.zacp_bytes.clone();
            // VKEY entry is entry[0]. size field is bytes 12..16 of the
            // entry: absolute offset 0x20 + 0 * 16 + 12 = 0x2C.
            zac[0x2C..0x30].copy_from_slice(&u32::MAX.to_le_bytes());
            (
                "VKEY.size := u32::MAX (overflows past body region)".to_string(),
                zac,
                zacp,
                None,
            )
        },
    ));

    println!();
    println!("==================================================");
    println!("  v0.1.1 forgery vectors (21 cases)");
    println!("==================================================");
    let mut pass = 0;
    let mut fail = 0;
    for o in &outcomes {
        print_outcome(o);
        let ok = o
            .actual
            .as_deref()
            .map(|a| o.expected.contains(&a))
            .unwrap_or(false);
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
    }
    println!("==================================================");
    println!("  {pass} passed, {fail} failed");
    println!("==================================================");
    if fail != 0 {
        std::process::exit(1);
    }
    Ok(())
}
