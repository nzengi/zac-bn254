//! Generate the gold test vector corpus under `tests/vectors/`.
//!
//! This is a one-shot tool. Run it to (re)materialise the canonical
//! `.zac` / `.zacp` / `vector.json` triples that the
//! `gold_vectors` integration test reads. The bytes it produces ARE the
//! contract: a second clean-room implementation (Go, TypeScript, C++)
//! that consumes the same inputs and outputs different bytes for any
//! vector is non-conformant.
//!
//! Determinism is enforced by:
//! 1. `StdRng::seed_from_u64(seed)` for trusted setup and proof blinding.
//! 2. `r1cs_hash(label_bytes)` from a stable string label per vector.
//! 3. arkworks 0.4 canonical-compressed serialization (locked by Cargo.lock).
//! 4. `serialize_proof_block` writes `pi_a || pi_b || pi_c` in §4.2 order.
//!
//! Run:
//! ```sh
//! cargo run --example generate_gold_vectors -p zac-bn254
//! ```
//!
//! The resulting tree:
//! ```text
//! crates/zac/tests/vectors/
//! ├── mul-default/        x=3, y=11, z=33      — baseline (1 public input)
//! │   ├── mul-default.zac
//! │   ├── mul-default.zacp
//! │   └── vector.json
//! ├── mul-z-zero/         x=0, y=42, z=0       — edge: zero public input
//! ├── mul-z-max/          x=1, y=r-1, z=r-1    — edge: max canonical Fr
//! └── mul-alt-setup/      x=3, y=11, z=33; alt seed — different VKEY shape
//! ```
//!
//! After regeneration, `cargo test --test gold_vectors` MUST pass — if it
//! does not, the implementation has drifted from the wire contract.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fr};
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

use zac::hash::{r1cs_hash, vk_fingerprint};
use zac::header::Header;
use zac::section::{InterfaceSection, Section};
use zac::trailer::Trailer;
use zac::zac_proof::{ProofHeader, ZacProofFile, PROOF_SIZE};
use zac::ZacFile;

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

struct VectorSpec {
    name: &'static str,
    description: &'static str,
    setup_seed: u64,
    x: Fr,
    y: Fr,
    z: Fr,
    r1cs_label: &'static str,
}

fn build_and_write(spec: &VectorSpec, out_root: &Path) -> Result<(), Box<dyn Error>> {
    let dir = out_root.join(spec.name);
    fs::create_dir_all(&dir)?;

    let mut rng = StdRng::seed_from_u64(spec.setup_seed);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        Multiplier {
            x: None,
            y: None,
            z: None,
        },
        &mut rng,
    )?;

    let proof = Groth16::<Bn254>::prove(
        &pk,
        Multiplier {
            x: Some(spec.x),
            y: Some(spec.y),
            z: Some(spec.z),
        },
        &mut rng,
    )?;

    let vkey_bytes = ser_compressed(&vk);
    let r1cs_h = r1cs_hash(spec.r1cs_label.as_bytes());

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

    let mut proof_block = [0u8; PROOF_SIZE];
    let mut tmp = Vec::with_capacity(PROOF_SIZE);
    proof.a.serialize_compressed(&mut tmp)?;
    proof.b.serialize_compressed(&mut tmp)?;
    proof.c.serialize_compressed(&mut tmp)?;
    proof_block.copy_from_slice(&tmp);

    let zpf = ZacProofFile {
        header: ProofHeader {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            public_input_count: 1,
            zac_file_hash: zac_parsed.trailer.file_hash,
            vk_fingerprint: fp,
        },
        proof: proof_block,
        public_inputs: vec![fr_to_le_bytes(&spec.z)],
    };
    let zacp_bytes = zpf.encode();

    fs::write(dir.join(format!("{}.zac", spec.name)), &zac_bytes)?;
    fs::write(dir.join(format!("{}.zacp", spec.name)), &zacp_bytes)?;

    // Hand-rolled JSON to avoid pulling serde_json into the tree just for
    // this corpus. Keys are sorted alphabetically; values are deterministic.
    let manifest = format!(
        r#"{{
  "description": "{}",
  "expected": {{
    "r1cs_hash": "{}",
    "vk_fingerprint": "{}",
    "vkey_size": {},
    "zac_file_hash": "{}",
    "zac_size": {},
    "zacp_size": {}
  }},
  "files": {{
    "zac": "{}.zac",
    "zacp": "{}.zacp"
  }},
  "inputs": {{
    "public_input_count": 1,
    "r1cs_label": "{}",
    "setup_seed": "{:#018x}",
    "witness": {{
      "x_le_hex": "{}",
      "y_le_hex": "{}",
      "z_le_hex": "{}"
    }}
  }},
  "name": "{}"
}}
"#,
        spec.description,
        hex::encode(r1cs_h),
        hex::encode(fp),
        vkey_bytes.len(),
        hex::encode(zac_parsed.trailer.file_hash),
        zac_bytes.len(),
        zacp_bytes.len(),
        spec.name,
        spec.name,
        spec.r1cs_label,
        spec.setup_seed,
        hex::encode(fr_to_le_bytes(&spec.x)),
        hex::encode(fr_to_le_bytes(&spec.y)),
        hex::encode(fr_to_le_bytes(&spec.z)),
        spec.name,
    );
    fs::write(dir.join("vector.json"), manifest)?;

    println!(
        "  [OK] {:<18}  zac={}B  zacp={}B  vk_fingerprint={}",
        spec.name,
        zac_bytes.len(),
        zacp_bytes.len(),
        &hex::encode(fp)[..16]
    );

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let out_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors");
    fs::create_dir_all(&out_root)?;

    println!("Generating gold vectors at {}", out_root.display());

    let fr_minus_one = {
        let mut m = Fr::MODULUS;
        m.sub_with_borrow(&ark_ff::BigInt::from(1u64));
        Fr::from(m)
    };

    let specs = [
        VectorSpec {
            name: "mul-default",
            description: "Baseline multiplier: x=3, y=11, z=33. Matches the canonical multiplier fixture.",
            setup_seed: 0x05EE_DC0F_FEEF_0007,
            x: Fr::from(3u64),
            y: Fr::from(11u64),
            z: Fr::from(33u64),
            r1cs_label: "phase2-placeholder:mul-x*y=z",
        },
        VectorSpec {
            name: "mul-z-zero",
            description: "Edge: zero public input. x=0, y=42, z=0. Exercises Fr::zero() canonical encoding.",
            setup_seed: 0x05EE_DC0F_FEEF_0007,
            x: Fr::from(0u64),
            y: Fr::from(42u64),
            z: Fr::from(0u64),
            r1cs_label: "phase2-placeholder:mul-x*y=z",
        },
        VectorSpec {
            name: "mul-z-max",
            description: "Edge: maximal canonical Fr public input. x=1, y=r-1, z=r-1.",
            setup_seed: 0x05EE_DC0F_FEEF_0007,
            x: Fr::from(1u64),
            y: fr_minus_one,
            z: fr_minus_one,
            r1cs_label: "phase2-placeholder:mul-x*y=z",
        },
        VectorSpec {
            name: "mul-alt-setup",
            description: "Same circuit + witness as mul-default but a different trusted-setup seed; pins that VKEY changes propagate to file_hash and vk_fingerprint.",
            setup_seed: 0xDEAD_BEEF_F00D_BABE,
            x: Fr::from(3u64),
            y: Fr::from(11u64),
            z: Fr::from(33u64),
            r1cs_label: "phase2-placeholder:mul-x*y=z",
        },
    ];

    for spec in specs.iter() {
        build_and_write(spec, &out_root)?;
    }

    // Top-level corpus manifest — points the integration test at all vectors.
    let corpus = specs
        .iter()
        .map(|s| format!("    \"{}\"", s.name))
        .collect::<Vec<_>>()
        .join(",\n");
    let corpus_manifest = format!(
        r#"{{
  "spec_version": "1.0",
  "description": "Gold reproducibility corpus for the zac-bn254 wire format. A conforming second implementation MUST produce byte-identical .zac and .zacp files for the inputs declared in each vector's vector.json.",
  "vectors": [
{}
  ]
}}
"#,
        corpus
    );
    fs::write(out_root.join("corpus.json"), corpus_manifest)?;

    println!("\nWrote {} vectors + corpus.json", specs.len());
    Ok(())
}
