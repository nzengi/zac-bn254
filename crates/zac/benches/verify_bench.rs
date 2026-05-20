//! Phase 2 verifier benchmarks.
//!
//! Three benches over the same multiplier-circuit happy-path artifacts:
//!
//! 1. `verify_cold` — full `zac::verify(&zac, &proof)`. Each iteration
//!    re-decodes the VK + proof + public inputs and rebuilds the
//!    `PreparedVerifyingKey` from scratch. This is the cost a caller pays
//!    today (Phase 3 will cache `PVK`).
//! 2. `vkey_decode` — only `groth16::decode_vk`, isolating the SW-affine
//!    deserialization + explicit subgroup checks for `alpha_g1`, three G2
//!    points, and the `gamma_abc_g1` slice.
//! 3. `proof_decode` — only `groth16::decode_proof`, isolating the
//!    fixed 32 || 64 || 32 split + canonical deserialize + subgroup check.

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
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::StdRng;

use zac::groth16::{decode_proof, decode_vk};
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

struct Bench {
    zac: ZacFile,
    zacp: ZacProofFile,
    vkey_bytes: Vec<u8>,
    proof_bytes: [u8; PROOF_SIZE],
}

fn setup() -> Bench {
    let mut rng = StdRng::seed_from_u64(0xBE_EF_C0_FF_EE);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        Multiplier {
            x: None,
            y: None,
            z: None,
        },
        &mut rng,
    )
    .expect("setup");
    let z = Fr::from(33u64);
    let proof = Groth16::<Bn254>::prove(
        &pk,
        Multiplier {
            x: Some(Fr::from(3u64)),
            y: Some(Fr::from(11u64)),
            z: Some(z),
        },
        &mut rng,
    )
    .expect("prove");

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
    let zac = ZacFile::parse(&zac_bytes).expect("parse zac");
    let fp = vk_fingerprint(&vkey_bytes);

    let mut proof_bytes = [0u8; PROOF_SIZE];
    let mut tmp = Vec::with_capacity(PROOF_SIZE);
    proof.a.serialize_compressed(&mut tmp).unwrap();
    proof.b.serialize_compressed(&mut tmp).unwrap();
    proof.c.serialize_compressed(&mut tmp).unwrap();
    proof_bytes.copy_from_slice(&tmp);

    let zpf = ZacProofFile {
        header: ProofHeader {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            public_input_count: 1,
            zac_file_hash: zac.trailer.file_hash,
            vk_fingerprint: fp,
        },
        proof: proof_bytes,
        public_inputs: vec![fr_to_le_bytes(&z)],
    };
    let zacp_bytes = zpf.encode();
    let zacp = ZacProofFile::parse(&zacp_bytes).expect("parse zacp");

    Bench {
        zac,
        zacp,
        vkey_bytes,
        proof_bytes,
    }
}

fn bench_verify_cold(c: &mut Criterion) {
    let b = setup();
    // Pre-flight: confirm the artifacts verify before measuring.
    verify(&b.zac, &b.zacp).expect("baseline verify must succeed");
    c.bench_function("verify_cold", |bencher| {
        bencher.iter(|| {
            let r = verify(black_box(&b.zac), black_box(&b.zacp));
            black_box(r).expect("verify ok")
        })
    });
}

fn bench_vkey_decode(c: &mut Criterion) {
    let b = setup();
    c.bench_function("vkey_decode", |bencher| {
        bencher.iter(|| {
            let v = decode_vk(black_box(&b.vkey_bytes));
            black_box(v).expect("decode_vk ok")
        })
    });
}

fn bench_proof_decode(c: &mut Criterion) {
    let b = setup();
    c.bench_function("proof_decode", |bencher| {
        bencher.iter(|| {
            let p = decode_proof(black_box(&b.proof_bytes));
            black_box(p).expect("decode_proof ok")
        })
    });
}

criterion_group!(
    benches,
    bench_verify_cold,
    bench_vkey_decode,
    bench_proof_decode
);
criterion_main!(benches);
