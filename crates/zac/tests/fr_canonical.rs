//! Compile-time confidence test for [`zac::groth16::decode_fr_canonical`].
//!
//! The runtime proof of correctness is `examples/forgery_vectors.rs` (case
//! #3 — Fr scalar `>= r`). This file exists only so a regression that
//! breaks the canonical-check predicate fails `cargo test` at the source
//! level, before any happy-path example has to be re-run.

use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};

use zac::groth16::decode_fr_canonical;

#[test]
fn zero_is_canonical() {
    let buf = [0u8; 32];
    let fr = decode_fr_canonical(&buf, 0, 0).expect("zero must be accepted");
    assert_eq!(fr, Fr::zero());
}

#[test]
fn r_is_rejected_with_e012() {
    let m = Fr::MODULUS.to_bytes_le();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&m);
    let err = decode_fr_canonical(&buf, 0xD0, 0).expect_err("r must be rejected");
    assert_eq!(err.code(), "E012", "{err}");
}

#[test]
fn r_minus_one_is_accepted() {
    let mut m = Fr::MODULUS;
    let borrowed = m.sub_with_borrow(&BigInt::from(1u64));
    assert!(!borrowed, "r >= 1");
    let bytes = m.to_bytes_le();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    let fr = decode_fr_canonical(&buf, 0xD0, 0).expect("r-1 must be accepted");
    // fr should equal -1 mod r.
    assert_eq!(fr + Fr::from(1u64), Fr::zero());
}
