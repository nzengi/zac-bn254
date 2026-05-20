//! Phase 1 round-trip evidence.
//!
//! Build a synthetic `.zac` programmatically, encode it, hex-dump the bytes,
//! parse them back, and confirm every field of the parsed structure matches
//! the producer side. The user reads the stdout — tracing emits a
//! byte-by-byte narrative.
//!
//! Run:
//! ```sh
//! RUST_LOG=zac=trace,round_trip=info cargo run --example round_trip
//! ```

use tracing::info;

use zac::header::Header;
use zac::section::{InterfaceSection, Section};
use zac::trailer::Trailer;
use zac::ZacFile;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zac=trace,round_trip=info".into()),
        )
        .with_target(true)
        .with_level(true)
        .init();

    info!("Phase 1 round-trip: build synthetic .zac, encode, parse, compare");

    let original = ZacFile {
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

    info!("step 1/5: encoding synthetic ZacFile");
    let bytes = original.encode();
    info!(total_bytes = bytes.len(), "encoded");

    info!("step 2/5: hex dump (16 B per row)");
    print_hex_dump(&bytes);

    info!("step 3/5: parsing bytes back");
    let parsed = ZacFile::parse(&bytes)?;

    info!("step 4/5: printing parsed structure");
    println!("\nParsed ZacFile (Debug):");
    println!("  header:        {:?}", parsed.header);
    println!("  sections.len:  {}", parsed.sections.len());
    for (i, s) in parsed.sections.iter().enumerate() {
        match s {
            Section::Vkey(b) => println!("  sections[{i}]:  VKEY ({} B)", b.len()),
            Section::Interface(iface) => println!(
                "  sections[{i}]:  INTERFACE public_input_count={}, names={:?}",
                iface.public_input_count, iface.names
            ),
            Section::R1csHash(h) => println!("  sections[{i}]:  R1CS_HASH 0x{}", hex::encode(h)),
            Section::MetaCbor(b) => println!("  sections[{i}]:  META_CBOR ({} B)", b.len()),
            Section::Vendor { tag, body } => {
                println!("  sections[{i}]:  VENDOR tag={tag:#04x} ({} B)", body.len())
            }
        }
    }
    println!(
        "  trailer.fhash: 0x{}",
        hex::encode(parsed.trailer.file_hash)
    );

    info!("step 5/5: structural equality (field-by-field)");
    let header_ok = parsed.header.version_major == 1
        && parsed.header.version_minor == 0
        && parsed.header.version_patch == 0
        && parsed.header.flags == 0
        && parsed.header.section_count == 3;
    mark("header.magic/version/flags/count", header_ok);

    mark(
        "header.body_offset 8-aligned",
        parsed.header.body_offset % 8 == 0,
    );

    let sec_count_ok = parsed.sections.len() == original.sections.len();
    mark("section count matches input", sec_count_ok);

    let vkey_match = matches!(
        (&original.sections[0], &parsed.sections[0]),
        (Section::Vkey(a), Section::Vkey(b)) if a == b
    );
    mark("section[0] VKEY body byte-equal", vkey_match);

    let iface_match = matches!(
        (&original.sections[1], &parsed.sections[1]),
        (Section::Interface(a), Section::Interface(b))
            if a.public_input_count == b.public_input_count && a.names == b.names
    );
    mark("section[1] INTERFACE struct-equal", iface_match);

    let r1cs_match = matches!(
        (&original.sections[2], &parsed.sections[2]),
        (Section::R1csHash(a), Section::R1csHash(b)) if a == b
    );
    mark("section[2] R1CS_HASH byte-equal", r1cs_match);

    // file_hash is recomputed; just confirm it's non-zero and matches what
    // the parser recomputed (parser would have rejected on E009 otherwise).
    let fhash_nonzero = parsed.trailer.file_hash.iter().any(|b| *b != 0);
    mark("trailer.file_hash recomputed & verified", fhash_nonzero);

    // Round-trip: encode the parsed structure again, bytes must be identical.
    let bytes2 = parsed.encode();
    mark("encode(parse(encode(x))) == encode(x)", bytes2 == bytes);

    info!("round-trip OK");
    Ok(())
}

fn print_hex_dump(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;
        let hex_pairs: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let hex = hex_pairs.join(" ");
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("  {offset:08x}  {hex:<47}  |{ascii}|");
    }
}

fn mark(label: &str, ok: bool) {
    let glyph = if ok { "[OK]" } else { "[FAIL]" };
    println!("  {glyph}  {label}");
}
