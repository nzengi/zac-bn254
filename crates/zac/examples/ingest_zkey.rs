//! Phase 3 — parse `fixtures/multiplier.zkey`, dump VKEY fingerprint, and
//! assemble a `fixtures/multiplier.zac` bound to the snarkjs setup.
//!
//! Run:
//! ```sh
//! cargo run --example ingest_zkey
//! ```

use std::path::PathBuf;

use ark_ff::PrimeField;
use tracing::info;

use zac::hash::{r1cs_hash, vk_fingerprint};
use zac::header::Header;
use zac::iden3::zkey::{parse_zkey, vkey_bytes_compressed};
use zac::section::{InterfaceSection, Section};
use zac::trailer::Trailer;
use zac::ZacFile;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zac=info,ingest_zkey=info".into()),
        )
        .with_target(true)
        .init();

    let fixtures_dir = workspace_root().join("fixtures");
    let zkey_path = fixtures_dir.join("multiplier.zkey");
    let r1cs_path = fixtures_dir.join("multiplier.r1cs");
    let out_path = fixtures_dir.join("multiplier.zac");

    info!("Phase 3 step 2: parse snarkjs .zkey");
    let zkey_bytes = std::fs::read(&zkey_path)?;
    let zkey = parse_zkey(&zkey_bytes)?;

    println!("== snarkjs Groth16 vk (parsed from .zkey) ==");
    println!("  nVars       = {}", zkey.n_vars);
    println!("  nPublic     = {}", zkey.n_public);
    println!("  domainSize  = {}", zkey.domain_size);
    println!(
        "  alpha_g1.x  = {}",
        bigint_to_decimal(&fq_to_bytes(&zkey.alpha_g1.x))
    );
    println!(
        "  beta_g2.x.c0= {}",
        bigint_to_decimal(&fq_to_bytes(&zkey.beta_g2.x.c0))
    );
    println!(
        "  delta_g2.x.c0={}",
        bigint_to_decimal(&fq_to_bytes(&zkey.delta_g2.x.c0))
    );
    println!("  ic.len      = {}", zkey.ic.len());

    // Cross-check against snarkjs's exported vkey JSON if available.
    let vkey_json = fixtures_dir.join("multiplier.vkey.json");
    if vkey_json.exists() {
        let txt = std::fs::read_to_string(&vkey_json)?;
        // Print snarkjs's reported vk_alpha_1.x for visual comparison.
        if let Some(s) = extract_first_string_in_array(&txt, "vk_alpha_1") {
            println!("  snarkjs vk_alpha_1.x (decimal):");
            println!("    {s}");
        }
    }

    info!("Phase 3 step 2: re-serialize vk as arkworks canonical compressed");
    let vkey_bytes = vkey_bytes_compressed(&zkey);
    println!("  arkworks vk compressed length = {} B", vkey_bytes.len());
    let fp = vk_fingerprint(&vkey_bytes);
    println!("  vk_fingerprint (BLAKE3) = {}", hex::encode(fp));

    info!("Phase 3 step 2: hash the .r1cs (BLAKE3 with zac1.r1cs.v1\\0 tag)");
    let r1cs_bytes = std::fs::read(&r1cs_path)?;
    let r1cs_h = r1cs_hash(&r1cs_bytes);
    println!("  r1cs_hash = {}", hex::encode(r1cs_h));

    info!("Phase 3 step 2: assemble .zac");
    let zac_in = ZacFile {
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
                public_input_count: zkey.n_public,
                names: vec!["z".to_string()],
            }),
            Section::R1csHash(r1cs_h),
        ],
        trailer: Trailer {
            file_hash: [0u8; 32],
        },
    };
    let zac_bytes = zac_in.encode();
    std::fs::write(&out_path, &zac_bytes)?;
    let parsed = ZacFile::parse(&zac_bytes)?;
    println!();
    println!("wrote {} ({} B)", out_path.display(), zac_bytes.len());
    println!(
        "  trailer.file_hash = {}",
        hex::encode(parsed.trailer.file_hash)
    );
    Ok(())
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fq_to_bytes<F: PrimeField>(f: &F) -> Vec<u8> {
    let mut out = Vec::new();
    f.serialize_uncompressed(&mut out).unwrap();
    out
}

fn bigint_to_decimal(le_bytes: &[u8]) -> String {
    // (re-use the same helper logic as prover.rs — duplicated here to keep
    // the example self-contained without exposing internal API)
    let mut limbs: Vec<u32> = le_bytes
        .chunks(4)
        .map(|c| {
            let mut buf = [0u8; 4];
            buf[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(buf)
        })
        .collect();
    let mut out = String::new();
    loop {
        let mut rem: u64 = 0;
        let mut any_nonzero = false;
        for limb in limbs.iter_mut().rev() {
            let v = (rem << 32) | (*limb as u64);
            *limb = (v / 1_000_000_000) as u32;
            rem = v % 1_000_000_000;
            if *limb != 0 {
                any_nonzero = true;
            }
        }
        if any_nonzero {
            out = format!("{rem:09}{out}");
        } else {
            out = format!("{rem}{out}");
            break;
        }
    }
    let trimmed = out.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

fn extract_first_string_in_array(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let p = s.find(&needle)?;
    let after = &s[p + needle.len()..];
    let lb = after.find('[')?;
    let inner = &after[lb + 1..];
    let q1 = inner.find('"')?;
    let q2 = inner[q1 + 1..].find('"')?;
    Some(inner[q1 + 1..q1 + 1 + q2].to_string())
}
