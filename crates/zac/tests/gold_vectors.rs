//! Gold-vector reproducibility test.
//!
//! For every directory under `tests/vectors/`, this test:
//!   1. Loads the frozen `.zac` and `.zacp` bytes.
//!   2. Parses both via the public API.
//!   3. Runs the full verifier (E001..E018 + pairing).
//!   4. Re-encodes the parsed `ZacFile` / `ZacProofFile` and asserts
//!      byte-for-byte equality with the on-disk bytes. This catches
//!      future implementation changes that break wire compatibility.
//!   5. Recomputes `file_hash` and `vk_fingerprint` from the parsed
//!      artifacts and compares to the values pinned in `vector.json`.
//!
//! A non-Rust second implementation conforms to the wire format iff,
//! for every vector here, it produces the same .zac/.zacp bytes given
//! the inputs in vector.json. The Rust reference catches its own drift;
//! the JSON manifest documents the contract for second implementers.

use std::fs;
use std::path::PathBuf;

use zac::hash::{file_hash, vk_fingerprint};
use zac::section::Section;
use zac::{verify, ZacFile, ZacProofFile};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
}

/// Minimal hand-written extraction of one JSON string field. The vector
/// manifests are emitted by `examples/generate_gold_vectors.rs` in a
/// stable, sorted-key, two-space-indented shape; we deliberately do not
/// pull serde_json into the dev tree just to read a handful of fields.
fn read_json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", key);
    let start = text.find(&needle)? + needle.len();
    let after = &text[start..];
    let quote_open = after.find('"')? + 1;
    let after_quote = &after[quote_open..];
    let quote_close = after_quote.find('"')?;
    Some(after_quote[..quote_close].to_string())
}

fn read_json_number(text: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let start = text.find(&needle)? + needle.len();
    let after = text[start..].trim_start();
    let end = after
        .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
        .unwrap_or(after.len());
    after[..end].parse().ok()
}

fn list_vector_dirs() -> Vec<PathBuf> {
    let root = vectors_dir();
    if !root.exists() {
        return Vec::new();
    }
    let mut out: Vec<_> = fs::read_dir(&root)
        .expect("read tests/vectors")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    out
}

#[test]
fn corpus_is_present_and_nonempty() {
    let dirs = list_vector_dirs();
    assert!(
        !dirs.is_empty(),
        "expected at least one vector directory under tests/vectors/. \
         Run `cargo run --example generate_gold_vectors` to regenerate."
    );
}

#[test]
fn every_vector_parses_verifies_and_round_trips() {
    let dirs = list_vector_dirs();
    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        eprintln!("vector: {name}");

        let zac_bytes = fs::read(dir.join(format!("{name}.zac"))).expect("read .zac");
        let zacp_bytes = fs::read(dir.join(format!("{name}.zacp"))).expect("read .zacp");

        // 1. Parse.
        let zac = ZacFile::parse(&zac_bytes).expect("zac parse");
        let zacp = ZacProofFile::parse(&zacp_bytes).expect("zacp parse");

        // 2. Verify (E017 included — pairing must hold for every gold vector).
        verify(&zac, &zacp).unwrap_or_else(|e| {
            panic!("verify failed for {name}: {e}");
        });

        // 3. Round-trip: re-encode and assert byte-identical to on-disk.
        let zac_reencoded = zac.encode();
        assert_eq!(
            zac_reencoded.len(),
            zac_bytes.len(),
            "{name}: re-encoded .zac length drifted"
        );
        assert_eq!(
            zac_reencoded, zac_bytes,
            "{name}: re-encoded .zac bytes drifted from frozen vector"
        );
        let zacp_reencoded = zacp.encode();
        assert_eq!(
            zacp_reencoded, zacp_bytes,
            "{name}: re-encoded .zacp bytes drifted from frozen vector"
        );

        // 4. Manifest cross-check (hashes + sizes).
        let manifest = fs::read_to_string(dir.join("vector.json")).expect("read vector.json");

        let expected_file_hash =
            read_json_string(&manifest, "zac_file_hash").expect("zac_file_hash in manifest");
        let expected_vk_fp =
            read_json_string(&manifest, "vk_fingerprint").expect("vk_fingerprint in manifest");
        let expected_zac_size =
            read_json_number(&manifest, "zac_size").expect("zac_size in manifest");
        let expected_zacp_size =
            read_json_number(&manifest, "zacp_size").expect("zacp_size in manifest");

        let actual_file_hash = hex::encode(zac.trailer.file_hash);
        assert_eq!(
            actual_file_hash, expected_file_hash,
            "{name}: parsed file_hash mismatches manifest"
        );

        // Recompute against the same byte ranges the encoder fed BLAKE3:
        //   version_bytes = bytes 4..8 (major, minor, patch, flags)
        //   body_bytes    = bytes INDEX_OFFSET..body_end (section index +
        //                   bodies, NOT just the section bodies)
        // See ZacFile::encode in zac_file.rs for the canonical call site.
        const INDEX_OFFSET: usize = 0x20;
        let body_end = zac.header.body_offset as usize + zac.header.body_size as usize;
        let recomputed_file_hash = file_hash(&zac_bytes[4..8], &zac_bytes[INDEX_OFFSET..body_end]);
        assert_eq!(
            hex::encode(recomputed_file_hash),
            expected_file_hash,
            "{name}: recomputed file_hash mismatches manifest"
        );

        // vk_fingerprint comes off the VKEY section body bytes.
        let vkey_bytes = zac
            .sections
            .iter()
            .find_map(|s| match s {
                Section::Vkey(b) => Some(b.clone()),
                _ => None,
            })
            .expect("VKEY section present");
        let actual_vk_fp = hex::encode(vk_fingerprint(&vkey_bytes));
        assert_eq!(
            actual_vk_fp, expected_vk_fp,
            "{name}: recomputed vk_fingerprint mismatches manifest"
        );

        assert_eq!(
            zac_bytes.len() as u64,
            expected_zac_size,
            "{name}: on-disk .zac size mismatches manifest"
        );
        assert_eq!(
            zacp_bytes.len() as u64,
            expected_zacp_size,
            "{name}: on-disk .zacp size mismatches manifest"
        );
    }
}
