//! Phase 1 parse + encode benchmarks (SPEC v1.0).
//!
//! Three benches:
//!
//! 1. `parse_header_only` — 32 byte slice → `Header::parse`.
//! 2. `parse_full_zac_256` — synthetic minimal `.zac` with a 256-byte VKEY.
//! 3. `encode_full_zac_256` — encode the same structure to bytes.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use zac::header::Header;
use zac::section::{InterfaceSection, Section};
use zac::trailer::Trailer;
use zac::ZacFile;

fn build_synthetic_zac() -> ZacFile {
    let header = Header {
        version_major: 1,
        version_minor: 0,
        version_patch: 0,
        flags: 0,
        section_count: 0, // filled by encode()
        body_offset: 0,
        body_size: 0,
    };
    let sections = vec![
        Section::Vkey(vec![0xAAu8; 256]),
        Section::Interface(InterfaceSection {
            public_input_count: 1,
            names: vec!["out".to_string()],
        }),
        Section::R1csHash([0x42u8; 32]),
    ];
    ZacFile {
        header,
        sections,
        trailer: Trailer {
            file_hash: [0u8; 32],
        },
    }
}

fn bench_parse_header_only(c: &mut Criterion) {
    let zf = build_synthetic_zac();
    let bytes = zf.encode();
    let head = &bytes[..32];
    c.bench_function("parse_header_only", |b| {
        b.iter(|| {
            let h = Header::parse(black_box(head)).unwrap();
            black_box(h)
        })
    });
}

fn bench_parse_full_zac_256(c: &mut Criterion) {
    let zf = build_synthetic_zac();
    let bytes = zf.encode();
    c.bench_function("parse_full_zac_256", |b| {
        b.iter(|| {
            let zf = ZacFile::parse(black_box(&bytes)).unwrap();
            black_box(zf)
        })
    });
}

fn bench_encode_full_zac_256(c: &mut Criterion) {
    let zf = build_synthetic_zac();
    c.bench_function("encode_full_zac_256", |b| {
        b.iter(|| {
            let out = black_box(&zf).encode();
            black_box(out)
        })
    });
}

criterion_group!(
    benches,
    bench_parse_header_only,
    bench_parse_full_zac_256,
    bench_encode_full_zac_256
);
criterion_main!(benches);
