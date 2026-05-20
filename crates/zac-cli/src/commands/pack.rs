//! `zac pack <zkey> <r1cs> -o <out.zac>` — assemble a `.zac` container from
//! snarkjs artifacts.
//!
//! Mirrors `examples/ingest_zkey.rs` but as a CLI flow. The output path
//! refuses to overwrite unless `--force` is set, matching `prove`.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

use anyhow::Result;

use crate::commands::CliError;

/// Run the `pack` subcommand. See module docs.
pub fn run(
    zkey_path: &Path,
    r1cs_path: &Path,
    out_path: &Path,
    force: bool,
    names_csv: Option<&str>,
) -> Result<()> {
    let zkey_bytes = std::fs::read(zkey_path)
        .map_err(|e| CliError::Io(format!("read {}: {e}", zkey_path.display())))?;
    let r1cs_bytes = std::fs::read(r1cs_path)
        .map_err(|e| CliError::Io(format!("read {}: {e}", r1cs_path.display())))?;

    let zkey =
        zac::parse_zkey(&zkey_bytes).map_err(|e| CliError::Io(format!("parse .zkey: {e}")))?;

    let vkey_bytes = zac::vkey_bytes_compressed(&zkey);
    let vk_fp = zac::vk_fingerprint(&vkey_bytes);
    let r1cs_h = zac::r1cs_hash(&r1cs_bytes);

    let names: Vec<String> = match names_csv {
        Some(csv) => {
            let v: Vec<String> = csv.split(',').map(|s| s.trim().to_string()).collect();
            if v.len() != zkey.n_public as usize {
                return Err(CliError::Io(format!(
                    "--names declared {} entries but zkey.nPublic = {}",
                    v.len(),
                    zkey.n_public
                ))
                .into());
            }
            v
        }
        None => (0..zkey.n_public).map(|i| format!("pub_{i}")).collect(),
    };

    let zf = zac::ZacFile {
        header: zac::Header {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            section_count: 0, // recomputed by encode()
            body_offset: 0,   // recomputed by encode()
            body_size: 0,     // recomputed by encode()
        },
        sections: vec![
            zac::Section::Vkey(vkey_bytes.clone()),
            zac::Section::Interface(zac::InterfaceSection {
                public_input_count: zkey.n_public,
                names,
            }),
            zac::Section::R1csHash(r1cs_h),
        ],
        trailer: zac::Trailer {
            file_hash: [0u8; 32], // recomputed by encode()
        },
    };

    let bytes = zf.encode();
    // Round-trip parse so we surface any structural bug now, not at first
    // verify call.
    let parsed =
        zac::ZacFile::parse(&bytes).map_err(|e| CliError::Io(format!("self-test parse: {e}")))?;

    write_output(out_path, &bytes, force)?;

    println!("pack: OK");
    println!(
        "  -> wrote {} ({} B)  vk_fingerprint={}  r1cs_hash={}",
        out_path.display(),
        bytes.len(),
        hex::encode(vk_fp),
        hex::encode(r1cs_h),
    );
    println!(
        "  file_hash      = {}",
        hex::encode(parsed.trailer.file_hash)
    );
    println!(
        "  public_inputs  = {}  (names: {})",
        zkey.n_public,
        match &parsed.sections[1] {
            zac::Section::Interface(i) => i.names.join(","),
            _ => unreachable!("section 1 is INTERFACE by construction"),
        }
    );
    Ok(())
}

fn write_output(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::Io(format!(
                "{} already exists (pass --force to overwrite)",
                path.display()
            ))
        } else {
            CliError::Io(format!("open {}: {e}", path.display()))
        }
    })?;
    f.write_all(bytes)
        .map_err(|e| CliError::Io(format!("write {}: {e}", path.display())))?;
    Ok(())
}
