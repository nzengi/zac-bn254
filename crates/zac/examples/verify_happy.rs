//! Phase 2 happy-path: build a real arkworks Groth16 proof, package it into
//! a `.zac` + `.zacp`, parse them, and verify through [`zac::verify`].
//!
//! No mock crypto. The proof comes from `ark_groth16::Groth16::<Bn254>::prove`
//! over a trivial multiplier circuit (`x * y = z`, `z` public). Serialization
//! uses `CanonicalSerialize` compressed — exactly the wire format SPEC §7
//! mandates.
//!
//! Run:
//! ```sh
//! RUST_LOG=zac=info,verify_happy=info cargo run --example verify_happy
//! ```

use std::error::Error;

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
use tracing::info;

use zac::hash::{r1cs_hash, vk_fingerprint};
use zac::header::Header;
use zac::section::{InterfaceSection, Section};
use zac::trailer::Trailer;
use zac::zac_proof::{ProofHeader, ZacProofFile, MAGIC_ZACP, PROOF_SIZE};
use zac::{verify, ZacFile};

/// Trivial multiplier circuit: enforces `x * y == z` with `z` as the single
/// public input. Used purely to produce a valid Groth16 proof for the round
/// trip — Phase 3 will compile real R1CS in `.zac`.
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
        // x * y == z
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

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zac=info,verify_happy=info".into()),
        )
        .with_target(true)
        .with_level(true)
        .init();

    info!("Phase 2 happy-path: real arkworks Groth16 → ZAC round trip");

    // ---------------------------------------------------------------------
    // 1. Generate Groth16 (pk, vk) for the multiplier circuit.
    // ---------------------------------------------------------------------
    info!("step 1/10: Groth16 setup (multiplier circuit, BN254)");
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_C0FF_EE42);
    let setup_circuit = Multiplier {
        x: None,
        y: None,
        z: None,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng)?;
    info!(gamma_abc_len = vk.gamma_abc_g1.len(), "step 1/10: setup OK");

    // ---------------------------------------------------------------------
    // 2. Pick the witness x=3, y=11 (so z=33) and prove.
    // ---------------------------------------------------------------------
    let x = Fr::from(3u64);
    let y = Fr::from(11u64);
    let z = Fr::from(33u64);
    info!("step 2/10: proving (x=3, y=11, z=33)");
    let proof = Groth16::<Bn254>::prove(
        &pk,
        Multiplier {
            x: Some(x),
            y: Some(y),
            z: Some(z),
        },
        &mut rng,
    )?;

    // Native-arkworks sanity (independent of our verifier).
    let ok_native = Groth16::<Bn254>::verify(&vk, &[z], &proof)?;
    info!(native_verify = ok_native, "step 2/10: native verify");
    assert!(ok_native, "native arkworks verify must succeed");

    // ---------------------------------------------------------------------
    // 3. Serialize vk (canonical compressed) — becomes VKEY section body.
    // ---------------------------------------------------------------------
    info!("step 3/10: serializing vk (canonical compressed)");
    let vkey_bytes = ser_compressed(&vk);
    info!(vkey_bytes = vkey_bytes.len(), "step 3/10: vk serialized");

    // ---------------------------------------------------------------------
    // 4. Build R1CS_HASH — Phase 2 uses a placeholder BLAKE3 over a fixed
    //    domain-tagged string. Phase 3 will hash the iden3 R1CS binary.
    // ---------------------------------------------------------------------
    let r1cs_placeholder = b"phase2-placeholder:mul-x*y=z";
    let r1cs_h = r1cs_hash(r1cs_placeholder);
    info!(
        r1cs_hash = %hex::encode(r1cs_h),
        "step 4/10: r1cs_hash (Phase 3 will use real iden3 R1CS bytes)"
    );

    // ---------------------------------------------------------------------
    // 5. Assemble + encode the .zac, then parse it back.
    // ---------------------------------------------------------------------
    info!("step 5/10: assembling .zac");
    let zf_in = ZacFile {
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
    let zac_bytes = zf_in.encode();
    info!(zac_bytes = zac_bytes.len(), "step 5/10: .zac encoded");
    let zac_parsed = ZacFile::parse(&zac_bytes)?;
    info!(
        zac_file_hash = %hex::encode(zac_parsed.trailer.file_hash),
        "step 5/10: .zac re-parsed"
    );

    // ---------------------------------------------------------------------
    // 6. Serialize the proof (compressed) — 128 bytes.
    // ---------------------------------------------------------------------
    info!("step 6/10: serializing proof (a, b, c) canonical compressed");
    let mut proof_bytes = [0u8; PROOF_SIZE];
    let mut tmp = Vec::with_capacity(PROOF_SIZE);
    proof.a.serialize_compressed(&mut tmp)?;
    proof.b.serialize_compressed(&mut tmp)?;
    proof.c.serialize_compressed(&mut tmp)?;
    assert_eq!(tmp.len(), PROOF_SIZE, "proof must serialize to 128 B");
    proof_bytes.copy_from_slice(&tmp);
    info!(
        proof_bytes = %hex::encode(proof_bytes),
        "step 6/10: proof serialized (128 B)"
    );

    // ---------------------------------------------------------------------
    // 7. Compute vk_fingerprint from the VKEY body.
    // ---------------------------------------------------------------------
    let fp = vk_fingerprint(&vkey_bytes);
    info!(
        vk_fingerprint = %hex::encode(fp),
        "step 7/10: vk_fingerprint computed"
    );

    // ---------------------------------------------------------------------
    // 8. Assemble + encode + parse the .zacp.
    // ---------------------------------------------------------------------
    info!("step 8/10: assembling .zacp");
    let z_le = fr_to_le_bytes(&z);
    info!(public_input_z = %hex::encode(z_le), "step 8/10: public input bytes");
    let zpf_in = ZacProofFile {
        header: ProofHeader {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            public_input_count: 1,
            zac_file_hash: zac_parsed.trailer.file_hash,
            vk_fingerprint: fp,
        },
        proof: proof_bytes,
        public_inputs: vec![z_le],
    };
    let zacp_bytes = zpf_in.encode();
    info!(zacp_bytes = zacp_bytes.len(), "step 8/10: .zacp encoded");
    let zpf_parsed = ZacProofFile::parse(&zacp_bytes)?;
    assert_eq!(&zacp_bytes[0..4], MAGIC_ZACP, "magic round-trips");

    // ---------------------------------------------------------------------
    // 9. Run our verifier end-to-end.
    // ---------------------------------------------------------------------
    info!("step 9/10: zac::verify(.zac, .zacp)");
    verify(&zac_parsed, &zpf_parsed)?;
    info!("step 9/10: verifier returned Ok(())");

    // ---------------------------------------------------------------------
    // 10. Report.
    // ---------------------------------------------------------------------
    println!();
    println!("==================================================");
    println!("  verification succeeded");
    println!("==================================================");
    println!("  proof bytes (128):  {}", hex::encode(proof_bytes));
    println!("  public input z:     {}  (LE)", hex::encode(z_le));
    println!("  vk_fingerprint:     {}", hex::encode(fp));
    println!(
        "  zac_file_hash:      {}",
        hex::encode(zac_parsed.trailer.file_hash)
    );
    println!("  vkey body size:     {} B", vkey_bytes.len());
    println!("  .zac total size:    {} B", zac_bytes.len());
    println!("  .zacp total size:   {} B", zacp_bytes.len());
    println!("==================================================");
    Ok(())
}
