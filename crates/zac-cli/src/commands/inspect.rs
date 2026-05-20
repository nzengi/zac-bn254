//! `zac inspect <file>` — readable dump of a `.zac` or `.zacp`.
//!
//! Auto-detects via the first four bytes: `ZAC1` → container, `ZAP1` →
//! proof. Anything else → E001-equivalent error, exit code 2.
//!
//! Output is plain ASCII (safe to pipe to `less`) and every line carries a
//! file offset so the reader can cross-check against `xxd`.

use std::path::Path;

use anyhow::Result;

use crate::commands::CliError;

/// Run the `inspect` subcommand. See module docs.
pub fn run(file: &Path) -> Result<()> {
    let bytes =
        std::fs::read(file).map_err(|e| CliError::Io(format!("read {}: {e}", file.display())))?;
    if bytes.len() < 4 {
        return Err(CliError::Reject(format!(
            "inspect: REJECTED (E001)\n  file too short ({} B) to detect magic",
            bytes.len()
        ))
        .into());
    }
    match &bytes[0..4] {
        b"ZAC1" => inspect_zac(&bytes, file),
        b"ZAP1" => inspect_zacp(&bytes, file),
        other => Err(CliError::Reject(format!(
            "inspect: REJECTED (E001)\n  unknown magic at offset 0: {other:02x?} (expected ZAC1 or ZAP1)"
        ))
        .into()),
    }
}

fn inspect_zac(bytes: &[u8], path: &Path) -> Result<()> {
    let zf = zac::ZacFile::parse(bytes)
        .map_err(|e| CliError::Reject(format!("inspect: REJECTED ({})\n  {e}", e.code())))?;

    println!("file: {}", path.display());
    println!("kind: ZAC1 (.zac container)");
    println!("size: {} B", bytes.len());
    println!();
    println!("== header (offset 0x00, 32 B) ==");
    println!("  0x00  magic            ZAC1");
    println!(
        "  0x04  version          {}.{}.{}",
        zf.header.version_major, zf.header.version_minor, zf.header.version_patch
    );
    println!("  0x07  flags            0x{:02x}", zf.header.flags);
    println!("  0x08  section_count    {}", zf.header.section_count);
    println!("  0x0c  index_offset     0x{:08x}", 0x20u32);
    println!(
        "  0x10  body_offset      0x{:08x}  ({} dec)",
        zf.header.body_offset, zf.header.body_offset
    );
    println!(
        "  0x14  body_size        0x{:08x}  ({} dec)",
        zf.header.body_size, zf.header.body_size
    );

    println!();
    println!(
        "== section index (offset 0x20, {} entries × 16 B) ==",
        zf.header.section_count
    );
    println!("  idx  type  flags  offset      size     crc32       name");
    for (i, section) in zf.sections.iter().enumerate() {
        let (off, size, crc) = compute_index_for(bytes, i);
        let name = section_name(section);
        println!(
            "  [{i:>2}] 0x{:02x}  0x{:02x}   0x{:08x}  {:>6} B 0x{:08x}  {}",
            section.section_type(),
            0,
            off,
            size,
            crc,
            name,
        );
    }

    println!();
    println!("== section bodies ==");
    for (i, section) in zf.sections.iter().enumerate() {
        let (off, size, _crc) = compute_index_for(bytes, i);
        print_section_body(section, off, size);
    }

    println!();
    println!("== trailer (offset 0x{:x}, 40 B) ==", bytes.len() - 40);
    println!("  +0x00 magic            ZACT");
    println!(
        "  +0x08 file_hash        {}",
        hex::encode(zf.trailer.file_hash)
    );
    Ok(())
}

fn print_section_body(section: &zac::Section, offset: u32, size: u32) {
    println!();
    match section {
        zac::Section::Vkey(b) => {
            println!(
                "  [VKEY @ 0x{offset:08x}, {size} B] arkworks canonical-compressed Groth16<BN254>"
            );
            let head: Vec<u8> = b.iter().take(16).copied().collect();
            println!("    first 16 B: {}", hex::encode(&head));
            println!("    full BLAKE3:  {}", hex::encode(zac::vk_fingerprint(b)));
        }
        zac::Section::Interface(i) => {
            println!("  [INTERFACE @ 0x{offset:08x}, {size} B]");
            println!("    public_input_count = {}", i.public_input_count);
            for (k, name) in i.names.iter().enumerate() {
                println!("    [{k}] {name:?}");
            }
        }
        zac::Section::R1csHash(h) => {
            println!("  [R1CS_HASH @ 0x{offset:08x}, 32 B]");
            println!("    hash = {}", hex::encode(h));
        }
        zac::Section::MetaCbor(b) => {
            println!("  [META_CBOR @ 0x{offset:08x}, {size} B] opaque");
            let head: Vec<u8> = b.iter().take(16).copied().collect();
            println!("    first 16 B: {}", hex::encode(&head));
        }
        zac::Section::Vendor { tag, body } => {
            println!("  [VENDOR 0x{tag:02x} @ 0x{offset:08x}, {size} B] opaque",);
            let head: Vec<u8> = body.iter().take(16).copied().collect();
            println!("    first 16 B: {}", hex::encode(&head));
        }
    }
}

fn inspect_zacp(bytes: &[u8], path: &Path) -> Result<()> {
    let zpf = zac::ZacProofFile::parse(bytes)
        .map_err(|e| CliError::Reject(format!("inspect: REJECTED ({})\n  {e}", e.code())))?;

    println!("file: {}", path.display());
    println!("kind: ZAP1 (.zacp proof)");
    println!("size: {} B", bytes.len());
    println!();
    println!("== header (offset 0x00, 0x50 B) ==");
    println!("  0x00  magic            ZAP1");
    println!(
        "  0x04  version          {}.{}.{}",
        zpf.header.version_major, zpf.header.version_minor, zpf.header.version_patch
    );
    println!("  0x07  flags            0x{:02x}", zpf.header.flags);
    println!(
        "  0x08  public_input_count {}",
        zpf.header.public_input_count
    );
    println!(
        "  0x10  zac_file_hash    {}",
        hex::encode(zpf.header.zac_file_hash)
    );
    println!(
        "  0x30  vk_fingerprint   {}",
        hex::encode(zpf.header.vk_fingerprint)
    );

    println!();
    println!("== proof block (offset 0x50, 128 B = 32 + 64 + 32) ==");
    let pi_a = &zpf.proof[0..32];
    let pi_b = &zpf.proof[32..96];
    let pi_c = &zpf.proof[96..128];
    println!("  0x50  pi_a (G1 cmpr 32 B)  {}", hex::encode(pi_a));
    println!("  0x70  pi_b (G2 cmpr 64 B)  {}", hex::encode(&pi_b[..32]));
    println!("                              {}", hex::encode(&pi_b[32..]));
    println!("  0xB0  pi_c (G1 cmpr 32 B)  {}", hex::encode(pi_c));

    println!();
    println!(
        "== public inputs (offset 0xD0, {} × 32 B) ==",
        zpf.public_inputs.len()
    );
    for (i, pi) in zpf.public_inputs.iter().enumerate() {
        let off = 0xD0 + i * 32;
        println!("  0x{off:04x}  [{i}]  hex={}", hex::encode(pi));
        println!("           dec={}", le32_to_decimal(pi));
    }
    Ok(())
}

fn section_name(s: &zac::Section) -> &'static str {
    match s {
        zac::Section::Vkey(_) => "VKEY",
        zac::Section::Interface(_) => "INTERFACE",
        zac::Section::R1csHash(_) => "R1CS_HASH",
        zac::Section::MetaCbor(_) => "META_CBOR",
        zac::Section::Vendor { .. } => "VENDOR",
    }
}

/// Re-read the on-wire index entry for section `i` from `bytes`, so the
/// inspector can show the exact (offset, size, crc32) the parser saw — not
/// just whatever the encoder would emit on a round-trip. This makes the
/// inspect output a faithful witness of what's on disk.
fn compute_index_for(bytes: &[u8], i: usize) -> (u32, u32, u32) {
    let base = 0x20 + i * 16;
    let offset = u32::from_le_bytes(bytes[base + 4..base + 8].try_into().unwrap());
    let size = u32::from_le_bytes(bytes[base + 8..base + 12].try_into().unwrap());
    let crc = u32::from_le_bytes(bytes[base + 12..base + 16].try_into().unwrap());
    (offset, size, crc)
}

/// 32-byte LE → decimal string (Fr values are small enough for human reading).
fn le32_to_decimal(bytes: &[u8; 32]) -> String {
    let mut limbs: Vec<u32> = bytes
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
