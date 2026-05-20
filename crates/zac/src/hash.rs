//! BLAKE3 helpers with mandatory domain separation (SPEC §6).
//!
//! Every tag is NUL-terminated ASCII; the trailing `\0` is *part of* the
//! hash input — this matches the SPEC exactly and prevents a domain-
//! collision where one input is the prefix of another.

/// Domain tag for the file hash (SPEC §6).
const TAG_FILE: &[u8] = b"zac1.file.v1\0";
/// Domain tag for the VKEY fingerprint (SPEC §6).
const TAG_VKEY: &[u8] = b"zac1.vkey.v1\0";
/// Domain tag for the R1CS hash (SPEC §6).
const TAG_R1CS: &[u8] = b"zac1.r1cs.v1\0";

/// `file_hash = BLAKE3("zac1.file.v1\0" || version_bytes || body_bytes)`.
///
/// `version_bytes` is `[0x04, 0x08)` of the `.zac` (major, minor, patch,
/// flags); `body_bytes` is the file from `0x20` up to (excluding) the
/// trailer.
pub fn file_hash(version_bytes: &[u8], body_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TAG_FILE);
    h.update(version_bytes);
    h.update(body_bytes);
    *h.finalize().as_bytes()
}

/// `vk_fingerprint = BLAKE3("zac1.vkey.v1\0" || vkey_bytes)`.
pub fn vk_fingerprint(vkey_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TAG_VKEY);
    h.update(vkey_bytes);
    *h.finalize().as_bytes()
}

/// `r1cs_hash = BLAKE3("zac1.r1cs.v1\0" || r1cs_bytes)`.
pub fn r1cs_hash(r1cs_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TAG_R1CS);
    h.update(r1cs_bytes);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tags_make_outputs_differ() {
        let same_data = b"\xAA\xAA\xAA";
        assert_ne!(
            file_hash(&[1, 0, 0, 0], same_data),
            vk_fingerprint(same_data)
        );
        assert_ne!(vk_fingerprint(same_data), r1cs_hash(same_data));
    }

    #[test]
    fn known_vk_fingerprint_is_stable_under_repeat() {
        let v = vec![0xAAu8; 256];
        let a = vk_fingerprint(&v);
        let b = vk_fingerprint(&v);
        assert_eq!(a, b);
    }
}
