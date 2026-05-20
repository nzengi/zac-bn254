//! Phase 1 negative-path evidence.
//!
//! For every SPEC error code that is *parser-reachable* in Phase 1
//! (E010/E011/E012 are Phase 2 crypto; E014 is a cross-file binding check),
//! deliberately construct a malformed byte stream, feed it to the parser,
//! and confirm the expected error code is returned.
//!
//! Run:
//! ```sh
//! RUST_LOG=zac=info cargo run --example negative_cases
//! ```

use byteorder::{ByteOrder, LittleEndian};
use tracing::info;

use zac::header::Header;
use zac::section::{InterfaceSection, Section};
use zac::trailer::Trailer;
use zac::{ZacFile, ZacProofFile};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zac=info,negative_cases=info".into()),
        )
        .with_target(true)
        .init();

    info!("Phase 1 negative cases: 12 deliberately malformed inputs");

    type Builder = Box<dyn Fn() -> Vec<u8>>;
    let cases: Vec<(&str, Builder, &str)> = vec![
        (
            "E001",
            Box::new(|| {
                let mut b = good_zac();
                b[0] = b'X'; // ZAC1 -> XAC1
                b
            }),
            "first 4 bytes != ZAC1",
        ),
        (
            "E002",
            Box::new(|| {
                let mut b = good_zac();
                b[4] = 2; // version_major = 2
                b
            }),
            "version_major != 1",
        ),
        (
            "E003",
            Box::new(|| {
                let mut b = good_zac();
                b[7] = 1; // non-zero flags
                b
            }),
            "non-zero flags",
        ),
        (
            "E004",
            Box::new(|| {
                let mut b = good_zac();
                // body_offset at bytes [16..20]; bump by 1 → not 8-aligned.
                let v = LittleEndian::read_u32(&b[16..20]);
                LittleEndian::write_u32(&mut b[16..20], v + 1);
                b
            }),
            "body_offset not 8-aligned",
        ),
        (
            "E005",
            Box::new(|| {
                // Force overlap: corrupt index entry 1's offset so it lands inside entry 0.
                let mut b = good_zac();
                // first index entry @ 0x20, second @ 0x30 (16 B per entry).
                // Second entry offset field is at 0x30 + 4 = 0x34.
                LittleEndian::write_u32(&mut b[0x34..0x38], 0x50); // == first entry offset (VKEY)
                b
            }),
            "index entries overlap",
        ),
        (
            "E006",
            Box::new(|| {
                // Duplicate section type: change entry[1].type from 0x02 to 0x01.
                let mut b = good_zac();
                b[0x30] = 0x01;
                b
            }),
            "duplicate section type",
        ),
        (
            "E007",
            Box::new(|| {
                // Forbidden type: set entry[2].type to 0xFF.
                let mut b = good_zac();
                b[0x40] = 0xFF;
                b
            }),
            "forbidden type 0xFF",
        ),
        (
            "E008",
            Box::new(|| {
                // Flip a byte inside VKEY body so its CRC no longer matches.
                let mut b = good_zac();
                let v_off = LittleEndian::read_u32(&b[0x24..0x28]) as usize;
                b[v_off] ^= 0x01;
                b
            }),
            "VKEY body byte flipped → CRC mismatch",
        ),
        (
            "E009",
            Box::new(|| {
                // Corrupt one byte of the trailer file_hash.
                let mut b = good_zac();
                let n = b.len();
                b[n - 1] ^= 0x01;
                b
            }),
            "trailer.file_hash corrupted",
        ),
        (
            "E015",
            Box::new(|| {
                // Truncated: only the first 16 bytes.
                good_zac().drain(..).take(16).collect()
            }),
            "truncated to 16 bytes",
        ),
        (
            "E013",
            Box::new(build_zacp_with_too_many_pi),
            ".zacp public_input_count = 4097 (> 4096)",
        ),
        (
            "E016",
            Box::new(build_zac_without_interface),
            "mandatory INTERFACE section missing",
        ),
    ];

    let mut all_ok = true;
    for (i, (expected, builder, descr)) in cases.iter().enumerate() {
        let bytes = builder();
        let head_preview = preview(&bytes);
        let result = if expected == &"E013" {
            ZacProofFile::parse(&bytes).map(|_| ())
        } else {
            ZacFile::parse(&bytes).map(|_| ())
        };
        let actual_code = match &result {
            Ok(_) => "OK".to_string(),
            Err(e) => e.code().to_string(),
        };
        let actual_msg = match &result {
            Ok(_) => "unexpected success".to_string(),
            Err(e) => format!("{e}"),
        };
        let pass = actual_code == *expected;
        if !pass {
            all_ok = false;
        }
        let glyph = if pass { "[OK]" } else { "[FAIL]" };
        println!("\n--- case {} ---", i + 1);
        println!("  description : {descr}");
        println!("  bytes (head): {head_preview}");
        println!("  expected    : {expected}");
        println!("  actual      : {actual_code}");
        println!("  message     : {actual_msg}");
        println!("  result      : {glyph}");
    }

    println!();
    if all_ok {
        info!("all negative cases: PASS");
        Ok(())
    } else {
        anyhow::bail!("at least one negative case did not produce expected error code")
    }
}

/// A valid `.zac` byte stream — every negative case starts from this and
/// mutates exactly the bytes it needs to.
fn good_zac() -> Vec<u8> {
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
            Section::Vkey(vec![0xAAu8; 256]),
            Section::Interface(InterfaceSection {
                public_input_count: 1,
                names: vec!["out".to_string()],
            }),
            Section::R1csHash([0x42u8; 32]),
        ],
        trailer: Trailer {
            file_hash: [0u8; 32],
        },
    };
    zf.encode()
}

/// A `.zac` missing the mandatory INTERFACE section — parser MUST reject
/// with E016. VKEY and R1CS_HASH are present so we don't trip the VKEY
/// check first.
fn build_zac_without_interface() -> Vec<u8> {
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
            Section::Vkey(vec![0xAAu8; 256]),
            Section::R1csHash([0x42u8; 32]),
        ],
        trailer: Trailer {
            file_hash: [0u8; 32],
        },
    };
    zf.encode()
}

/// Build a `.zacp` byte stream with `public_input_count = 4097` and the file
/// size truthfully reporting that many inputs — so the parser must reject
/// on E013 (count > 4096), not on truncation.
fn build_zacp_with_too_many_pi() -> Vec<u8> {
    let mut out = vec![0u8; 0xD0 + 32 * 4097];
    out[0..4].copy_from_slice(b"ZAP1");
    out[4] = 1; // version_major
    out[5] = 0;
    out[6] = 0;
    out[7] = 0;
    LittleEndian::write_u32(&mut out[8..12], 4097);
    // 12..16 reserved zero
    // 16..48 zac_file_hash = zero
    // 48..80 vk_fingerprint = zero
    // 80..0xD0 proof = zero
    // public inputs = all zero
    out
}

fn preview(bytes: &[u8]) -> String {
    let n = bytes.len().min(16);
    let hex: Vec<String> = bytes[..n].iter().map(|b| format!("{b:02x}")).collect();
    format!("{} ({} B total)", hex.join(" "), bytes.len())
}
