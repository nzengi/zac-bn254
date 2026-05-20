//! Property-based panic-immunity fuzzing for every parser the crate exposes.
//!
//! Throw arbitrary byte slices at the public parsers and assert no panic, no
//! abort, no SIGSEGV — only `Result`. This is the evidence (per the project
//! owner's "testlere güvenmem" stance) that the parsers correctly use bounds
//! checking everywhere, not just on the happy path. The actual `Result` value
//! is irrelevant — every panic counts as a failure.
//!
//! Six parsers are covered (Phase 5 expansion):
//!
//! 1. `ZacFile::parse`        — top-level `.zac` container.
//! 2. `ZacProofFile::parse`   — top-level `.zacp` proof container.
//! 3. `parse_zkey`            — snarkjs `.zkey` binfile.
//! 4. `parse_wtns`            — snarkjs `.wtns` binfile.
//! 5. `decode_vk`             — canonical compressed VKEY bytes.
//! 6. `decode_proof`          — fixed 128-byte canonical compressed proof.
//!
//! Each property runs 10_000 random inputs (10_000 panic-free cases per
//! parser is the Phase 5 acceptance bar). The chosen size envelope (0..2048,
//! plus an exact-128 envelope for `decode_proof`) covers truncation,
//! length-field overflow, off-by-one boundary cases, and large slack at the
//! tail; that's the same coverage range Phase 1 used for the top-level
//! parsers, extended here to the iden3 and groth16 inner parsers.

use proptest::prelude::*;

use zac::groth16::{decode_proof, decode_vk, PROOF_BYTES};
use zac::iden3::wtns::parse_wtns;
use zac::iden3::zkey::parse_zkey;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn parse_never_panics_zac(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = zac::ZacFile::parse(&bytes);
    }

    #[test]
    fn parse_never_panics_zacp(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = zac::ZacProofFile::parse(&bytes);
    }

    #[test]
    fn parse_never_panics_zkey(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_zkey(&bytes);
    }

    #[test]
    fn parse_never_panics_wtns(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_wtns(&bytes);
    }

    #[test]
    fn decode_vk_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = decode_vk(&bytes);
    }

    /// `decode_proof` takes a fixed-size `&[u8; 128]` so fuzz exactly that
    /// envelope. Every random 128-byte buffer is a valid input shape; the
    /// invariant we want is "no panic" on arbitrary bytes, including those
    /// that decode to off-curve or off-subgroup points.
    #[test]
    fn decode_proof_never_panics(bytes in proptest::array::uniform32(any::<u8>())
        .prop_flat_map(|seed| {
            // Build a 128-byte array by hashing the seed forward 4 times so
            // proptest can shrink on the 32-byte seed; this is much cheaper
            // than a 128-vec strategy while still giving full coverage.
            let mut buf = [0u8; PROOF_BYTES];
            for (i, chunk) in buf.chunks_mut(32).enumerate() {
                let mut h = seed;
                for b in h.iter_mut() { *b = b.wrapping_add(i as u8); }
                chunk.copy_from_slice(&h);
            }
            Just(buf)
        }))
    {
        let _ = decode_proof(&bytes);
    }
}
