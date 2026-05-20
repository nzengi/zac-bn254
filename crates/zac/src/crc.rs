//! IEEE CRC-32 wrapper used for per-section integrity (SPEC §3.2).
//!
//! The crate-internal layer is intentionally thin so that swapping the
//! implementation in the future (e.g. for a SIMD-accelerated build) does not
//! ripple through every call site.

/// Compute the IEEE CRC-32 over `bytes`.
#[inline]
pub fn crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_matches_reference() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn known_vector_check_message() {
        // Classic test vector: CRC32("123456789") == 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
