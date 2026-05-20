//! Phase 3 Step 4 — repackage a snarkjs-produced JSON proof as a `.zacp` and
//! verify it with `zac::verify`.
//!
//! Reads `fixtures/snarkjs_proof.json` + `fixtures/snarkjs_public.json` and
//! the corresponding `.zac`, converts the JSON to arkworks compressed bytes,
//! assembles a `.zacp`, and runs `zac::verify`. This is the **direction A**
//! of the bidirectional cross-verify (snarkjs proof → ZAC verifier);
//! direction B (ZAC proof → snarkjs verifier) lives in
//! `node-tools/scripts/cross_verify.mjs`.
//!
//! The snarkjs-JSON → arkworks-compressed conversion helpers live inline
//! here (not in `zac::prover`) because they are only needed at the
//! cross-verify boundary, not by the prover itself.
//!
//! Run:
//! ```sh
//! cargo run --example verify_snarkjs_proof
//! ```

use std::path::PathBuf;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger as _, PrimeField};
use ark_serialize::CanonicalSerialize;
use tracing::info;

use zac::error::{ZacError, ZacResult};
use zac::hash::vk_fingerprint;
use zac::zac_proof::{ProofHeader, ZacProofFile, PROOF_SIZE};
use zac::{verify, ZacFile};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zac=info,verify_snarkjs_proof=info".into()),
        )
        .with_target(true)
        .init();

    let fixtures = workspace_root().join("fixtures");
    let zac_bytes = std::fs::read(fixtures.join("multiplier.zac"))?;
    let zac = ZacFile::parse(&zac_bytes)?;
    let proof_json = std::fs::read_to_string(fixtures.join("snarkjs_proof.json"))?;
    let public_json = std::fs::read_to_string(fixtures.join("snarkjs_public.json"))?;

    info!("Phase 3 step 4 (ZAC side): converting snarkjs JSON proof → arkworks compressed");
    let proof = parse_snarkjs_proof(&proof_json)
        .ok_or_else(|| anyhow::anyhow!("could not parse snarkjs proof JSON: {}", &proof_json))?;
    let compressed = snarkjs_proof_to_compressed(&proof)?;
    println!("  ark-compressed proof (128 B):");
    println!("    {}", hex::encode(compressed));

    let publics: Vec<String> = parse_string_array(&public_json).unwrap_or_default();
    info!(public_count = publics.len(), "parsed public.json");
    let public_inputs: Vec<[u8; 32]> = publics
        .iter()
        .map(|s| {
            let bi = parse_decimal_to_bigint(s).expect("decimal");
            let fr = Fr::from_bigint(bi).expect("Fr from bigint");
            let mut out = [0u8; 32];
            let bytes = fr.into_bigint().to_bytes_le();
            out[..bytes.len()].copy_from_slice(&bytes);
            out
        })
        .collect();

    // Recompute vk_fingerprint from the .zac's VKEY body.
    let vkey_body = zac
        .sections
        .iter()
        .find_map(|s| match s {
            zac::section::Section::Vkey(b) => Some(b.clone()),
            _ => None,
        })
        .expect("VKEY section");
    let fp = vk_fingerprint(&vkey_body);

    let zacp = ZacProofFile {
        header: ProofHeader {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            public_input_count: public_inputs.len() as u32,
            zac_file_hash: zac.trailer.file_hash,
            vk_fingerprint: fp,
        },
        proof: compressed,
        public_inputs,
    };
    let zacp_bytes = zacp.encode();
    println!();
    println!("re-encoded as .zacp ({} B)", zacp_bytes.len());

    info!("Phase 3 step 4 (ZAC side): running zac::verify on the repackaged proof");
    verify(&zac, &zacp)?;
    println!();
    println!("[OK] snarkjs proof verified by ZAC");
    Ok(())
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

// -----------------------------------------------------------------------------
// snarkjs JSON ↔ arkworks compressed conversion (only used at the
// cross-verify boundary, hence inlined into this example rather than
// living in `zac::prover`).
// -----------------------------------------------------------------------------

#[derive(Debug)]
struct SnarkjsProof {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3],
    pi_c: [String; 3],
}

fn snarkjs_proof_to_compressed(p: &SnarkjsProof) -> ZacResult<[u8; PROOF_SIZE]> {
    let a = g1_from_decimal(&p.pi_a[0], &p.pi_a[1])?;
    let c = g1_from_decimal(&p.pi_c[0], &p.pi_c[1])?;
    let b = g2_from_decimal(&p.pi_b)?;

    let mut buf = Vec::with_capacity(PROOF_SIZE);
    a.serialize_compressed(&mut buf)
        .map_err(|_| ZacError::NonCanonicalPoint {
            offset: 0x50,
            reason: "ark-bn254 G1 compress (pi_a)",
        })?;
    b.serialize_compressed(&mut buf)
        .map_err(|_| ZacError::NonCanonicalPoint {
            offset: 0x70,
            reason: "ark-bn254 G2 compress (pi_b)",
        })?;
    c.serialize_compressed(&mut buf)
        .map_err(|_| ZacError::NonCanonicalPoint {
            offset: 0xB0,
            reason: "ark-bn254 G1 compress (pi_c)",
        })?;
    if buf.len() != PROOF_SIZE {
        return Err(ZacError::NonCanonicalPoint {
            offset: 0x50,
            reason: "compressed proof not 128 bytes",
        });
    }
    let mut out = [0u8; PROOF_SIZE];
    out.copy_from_slice(&buf);
    Ok(out)
}

fn g1_from_decimal(x_s: &str, y_s: &str) -> ZacResult<G1Affine> {
    let x = fq_from_decimal_string(x_s).ok_or(ZacError::NonCanonicalPoint {
        offset: 0,
        reason: "G1 x decimal parse",
    })?;
    let y = fq_from_decimal_string(y_s).ok_or(ZacError::NonCanonicalPoint {
        offset: 0,
        reason: "G1 y decimal parse",
    })?;
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(ZacError::NonCanonicalPoint {
            offset: 0,
            reason: "G1 from JSON not on curve",
        });
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZacError::SubgroupCheckFailed { offset: 0 });
    }
    Ok(p)
}

fn g2_from_decimal(b: &[[String; 2]; 3]) -> ZacResult<G2Affine> {
    let x_c0 = fq_from_decimal_string(&b[0][0]).ok_or(ZacError::NonCanonicalPoint {
        offset: 0,
        reason: "G2 x.c0",
    })?;
    let x_c1 = fq_from_decimal_string(&b[0][1]).ok_or(ZacError::NonCanonicalPoint {
        offset: 0,
        reason: "G2 x.c1",
    })?;
    let y_c0 = fq_from_decimal_string(&b[1][0]).ok_or(ZacError::NonCanonicalPoint {
        offset: 0,
        reason: "G2 y.c0",
    })?;
    let y_c1 = fq_from_decimal_string(&b[1][1]).ok_or(ZacError::NonCanonicalPoint {
        offset: 0,
        reason: "G2 y.c1",
    })?;
    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(ZacError::NonCanonicalPoint {
            offset: 0,
            reason: "G2 from JSON not on curve",
        });
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZacError::SubgroupCheckFailed { offset: 0 });
    }
    Ok(p)
}

fn fq_from_decimal_string(s: &str) -> Option<Fq> {
    let big = parse_decimal_to_bigint(s)?;
    Fq::from_bigint(big)
}

fn parse_string_array(s: &str) -> Option<Vec<String>> {
    let s = s.trim();
    if !s.starts_with('[') || !s.ends_with(']') {
        return None;
    }
    let inner = &s[1..s.len() - 1];
    Some(
        inner
            .split(',')
            .map(|c| c.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

fn parse_snarkjs_proof(s: &str) -> Option<SnarkjsProof> {
    let pi_a = extract_str_array(s, "pi_a")?;
    let pi_c = extract_str_array(s, "pi_c")?;
    let pi_b = extract_nested_str_array(s, "pi_b")?;
    if pi_a.len() < 2 || pi_c.len() < 2 || pi_b.len() < 2 {
        return None;
    }
    let row = |i: usize| -> [String; 2] {
        let r = &pi_b[i];
        if r.len() >= 2 {
            [r[0].clone(), r[1].clone()]
        } else {
            ["1".into(), "0".into()]
        }
    };
    Some(SnarkjsProof {
        pi_a: [
            pi_a[0].clone(),
            pi_a[1].clone(),
            pi_a.get(2).cloned().unwrap_or_else(|| "1".into()),
        ],
        pi_b: [
            row(0),
            row(1),
            if pi_b.len() >= 3 {
                row(2)
            } else {
                ["1".into(), "0".into()]
            },
        ],
        pi_c: [
            pi_c[0].clone(),
            pi_c[1].clone(),
            pi_c.get(2).cloned().unwrap_or_else(|| "1".into()),
        ],
    })
}

fn extract_str_array(s: &str, key: &str) -> Option<Vec<String>> {
    let needle = format!("\"{key}\"");
    let p = s.find(&needle)?;
    let after = &s[p + needle.len()..];
    let arr_start = after.find('[')?;
    let bytes = after.as_bytes();
    let mut depth = 0i32;
    let mut end = 0usize;
    for (i, &c) in bytes.iter().enumerate().skip(arr_start) {
        if c == b'[' {
            depth += 1;
        } else if c == b']' {
            depth -= 1;
            if depth == 0 {
                end = i;
                break;
            }
        }
    }
    if end == 0 {
        return None;
    }
    let inner = &after[arr_start + 1..end];
    Some(
        inner
            .split(',')
            .map(|c| c.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

fn extract_nested_str_array(s: &str, key: &str) -> Option<Vec<Vec<String>>> {
    let needle = format!("\"{key}\"");
    let p = s.find(&needle)?;
    let after = &s[p + needle.len()..];
    let arr_start = after.find('[')?;
    let bytes = after.as_bytes();
    let mut depth = 0i32;
    let mut end = 0usize;
    for (i, &c) in bytes.iter().enumerate().skip(arr_start) {
        if c == b'[' {
            depth += 1;
        } else if c == b']' {
            depth -= 1;
            if depth == 0 {
                end = i;
                break;
            }
        }
    }
    if end == 0 {
        return None;
    }
    let inner = &after[arr_start + 1..end];
    let inner_b = inner.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < inner_b.len() {
        while i < inner_b.len() && (inner_b[i].is_ascii_whitespace() || inner_b[i] == b',') {
            i += 1;
        }
        if i >= inner_b.len() {
            break;
        }
        if inner_b[i] != b'[' {
            break;
        }
        let start = i;
        let mut d = 0i32;
        while i < inner_b.len() {
            if inner_b[i] == b'[' {
                d += 1;
            } else if inner_b[i] == b']' {
                d -= 1;
                if d == 0 {
                    break;
                }
            }
            i += 1;
        }
        if i >= inner_b.len() {
            return None;
        }
        let sub = &inner[start + 1..i];
        i += 1;
        let row: Vec<String> = sub
            .split(',')
            .map(|c| c.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        out.push(row);
    }
    Some(out)
}

fn parse_decimal_to_bigint(s: &str) -> Option<ark_ff::BigInt<4>> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut acc = ark_ff::BigInt::<4>::from(0u64);
    for c in s.bytes() {
        let digit = (c - b'0') as u64;
        acc = mul_bigint_u64(&acc, 10);
        acc = add_bigint_u64(&acc, digit);
    }
    Some(acc)
}

fn mul_bigint_u64(b: &ark_ff::BigInt<4>, m: u64) -> ark_ff::BigInt<4> {
    let mut limbs = [0u64; 4];
    let mut carry: u128 = 0;
    for (i, limb) in limbs.iter_mut().enumerate() {
        let v = (b.0[i] as u128) * (m as u128) + carry;
        *limb = v as u64;
        carry = v >> 64;
    }
    ark_ff::BigInt(limbs)
}

fn add_bigint_u64(b: &ark_ff::BigInt<4>, a: u64) -> ark_ff::BigInt<4> {
    let mut limbs = b.0;
    let (s0, c0) = limbs[0].overflowing_add(a);
    limbs[0] = s0;
    let mut carry = c0 as u64;
    for limb in limbs.iter_mut().skip(1) {
        let (s, c) = limb.overflowing_add(carry);
        *limb = s;
        carry = c as u64;
        if carry == 0 {
            break;
        }
    }
    ark_ff::BigInt(limbs)
}
