//! `.zac` trailer (SPEC §3.4) — the last 40 bytes of the file.

use tracing::trace;

use crate::error::{ZacError, ZacResult};

/// Trailer size in bytes.
pub const TRAILER_SIZE: usize = 40;
/// Trailer magic bytes.
pub const TRAILER_MAGIC: &[u8; 4] = b"ZACT";

/// Decoded `.zac` trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trailer {
    /// 32-byte BLAKE3 file hash (SPEC §6).
    pub file_hash: [u8; 32],
}

impl Trailer {
    /// Parse the trailer from a 40-byte slice positioned at the trailer's
    /// absolute file offset. `abs_offset` is used purely for error messages.
    pub fn parse(bytes: &[u8], abs_offset: usize) -> ZacResult<Self> {
        if bytes.len() < TRAILER_SIZE {
            trace!(
                offset = abs_offset,
                need = TRAILER_SIZE,
                have = bytes.len(),
                "rejecting: trailer truncated"
            );
            return Err(ZacError::Truncated {
                offset: abs_offset,
                need: TRAILER_SIZE,
                have: bytes.len(),
            });
        }
        let magic: [u8; 4] = bytes[0..4].try_into().expect("len checked");
        if &magic != TRAILER_MAGIC {
            trace!(offset = abs_offset, got = ?magic, "rejecting: bad trailer magic");
            return Err(ZacError::BadMagic {
                offset: abs_offset,
                expected: "ZACT",
                got: magic,
            });
        }
        trace!(offset = abs_offset, field = "trailer_magic", value = ?magic, "parsed");

        let reserved = &bytes[4..8];
        if reserved != [0u8; 4] {
            trace!(
                offset = abs_offset + 4,
                "rejecting: trailer reserved non-zero"
            );
            return Err(ZacError::BadFlags {
                offset: abs_offset + 4,
                field: "trailer._reserved",
                value: u32::from_le_bytes(reserved.try_into().unwrap()) as u64,
            });
        }
        trace!(
            offset = abs_offset + 4,
            field = "trailer._reserved",
            value = 0,
            "parsed"
        );

        let mut file_hash = [0u8; 32];
        file_hash.copy_from_slice(&bytes[8..40]);
        trace!(
            offset = abs_offset + 8,
            field = "file_hash",
            value = %hex::encode(file_hash),
            "parsed"
        );
        Ok(Trailer { file_hash })
    }

    /// Serialise the trailer to 40 raw bytes.
    pub fn encode(&self) -> [u8; TRAILER_SIZE] {
        let mut out = [0u8; TRAILER_SIZE];
        out[0..4].copy_from_slice(TRAILER_MAGIC);
        // 4..8 reserved zero
        out[8..40].copy_from_slice(&self.file_hash);
        out
    }
}
