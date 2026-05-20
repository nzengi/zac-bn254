//! `.zac` header parsing (SPEC §3.1).
//!
//! The header is a fixed-width 32-byte record at offset 0. Every field is
//! validated eagerly so we can refuse pathological inputs *before* spending
//! any cycles on the index or section bodies.

use byteorder::{ByteOrder, LittleEndian};
use tracing::trace;

use crate::error::{ZacError, ZacResult};

/// Magic for `.zac` files.
pub const MAGIC_ZAC: &[u8; 4] = b"ZAC1";
/// Total header size in bytes.
pub const HEADER_SIZE: usize = 32;
/// Mandatory `index_offset` value per SPEC §3.1.
pub const INDEX_OFFSET: u32 = 0x20;
/// Maximum number of sections allowed in v1.0.
pub const MAX_SECTIONS: usize = 16;

/// Parsed representation of the 32-byte `.zac` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Major version byte. Always `1` in v1.0.
    pub version_major: u8,
    /// Minor version byte.
    pub version_minor: u8,
    /// Patch version byte.
    pub version_patch: u8,
    /// Flags byte. MUST be 0 in v1.0.
    pub flags: u8,
    /// Number of section index entries (1..=16).
    pub section_count: u16,
    /// Offset of the first section body.
    pub body_offset: u32,
    /// Total length of all section bodies plus padding.
    pub body_size: u32,
}

impl Header {
    /// Parse the 32-byte header from `bytes`.
    ///
    /// Tracing emits one `trace!` per field read on success and one before
    /// any rejection so a `RUST_LOG=zac=trace` run is a verbatim byte-by-byte
    /// narrative.
    pub fn parse(bytes: &[u8]) -> ZacResult<Self> {
        if bytes.len() < HEADER_SIZE {
            trace!(
                offset = 0,
                need = HEADER_SIZE,
                have = bytes.len(),
                "rejecting: header truncated"
            );
            return Err(ZacError::Truncated {
                offset: 0,
                need: HEADER_SIZE,
                have: bytes.len(),
            });
        }

        // 0x00..0x04 — magic
        let magic: [u8; 4] = bytes[0..4].try_into().expect("len checked");
        if &magic != MAGIC_ZAC {
            trace!(offset = 0, got = ?magic, "rejecting: bad magic");
            return Err(ZacError::BadMagic {
                offset: 0,
                expected: "ZAC1",
                got: magic,
            });
        }
        trace!(offset = 0, field = "magic", value = ?magic, "parsed");

        // 0x04..0x07 — version, 0x07 — flags
        let major = bytes[4];
        let minor = bytes[5];
        let patch = bytes[6];
        let flags = bytes[7];
        if major != 1 {
            trace!(
                offset = 4,
                major,
                minor,
                patch,
                "rejecting: unsupported version"
            );
            return Err(ZacError::UnsupportedVersion {
                offset: 4,
                major,
                minor,
                patch,
            });
        }
        trace!(offset = 4, field = "version_major", value = major, "parsed");
        trace!(offset = 5, field = "version_minor", value = minor, "parsed");
        trace!(offset = 6, field = "version_patch", value = patch, "parsed");

        if flags != 0 {
            trace!(offset = 7, value = flags, "rejecting: non-zero flags");
            return Err(ZacError::BadFlags {
                offset: 7,
                field: "flags",
                value: flags as u64,
            });
        }
        trace!(offset = 7, field = "flags", value = flags, "parsed");

        // 0x08..0x0A — section_count (u16 LE)
        let section_count = LittleEndian::read_u16(&bytes[8..10]);
        if section_count == 0 || section_count as usize > MAX_SECTIONS {
            trace!(
                offset = 8,
                value = section_count,
                "rejecting: section_count out of range 1..=16"
            );
            return Err(ZacError::BadFlags {
                offset: 8,
                field: "section_count",
                value: section_count as u64,
            });
        }
        trace!(
            offset = 8,
            field = "section_count",
            value = section_count,
            "parsed"
        );

        // 0x0A..0x0C — reserved u16
        let reserved_a = LittleEndian::read_u16(&bytes[10..12]);
        if reserved_a != 0 {
            trace!(
                offset = 10,
                value = reserved_a,
                "rejecting: reserved bytes non-zero"
            );
            return Err(ZacError::BadFlags {
                offset: 10,
                field: "_reserved",
                value: reserved_a as u64,
            });
        }
        trace!(offset = 10, field = "_reserved", value = 0, "parsed");

        // 0x0C..0x10 — index_offset (u32 LE)
        let index_offset = LittleEndian::read_u32(&bytes[12..16]);
        if index_offset != INDEX_OFFSET {
            trace!(
                offset = 12,
                value = index_offset,
                expected = INDEX_OFFSET,
                "rejecting: index_offset != 0x20"
            );
            return Err(ZacError::BadAlignment {
                offset: 12,
                reason: "index_offset must be 0x20",
            });
        }
        trace!(
            offset = 12,
            field = "index_offset",
            value = index_offset,
            "parsed"
        );

        // 0x10..0x14 — body_offset
        let body_offset = LittleEndian::read_u32(&bytes[16..20]);
        if body_offset % 8 != 0 {
            trace!(
                offset = 16,
                value = body_offset,
                "rejecting: body_offset not 8-aligned"
            );
            return Err(ZacError::BadAlignment {
                offset: 16,
                reason: "body_offset must be 8-aligned",
            });
        }
        trace!(
            offset = 16,
            field = "body_offset",
            value = body_offset,
            "parsed"
        );

        // 0x14..0x18 — body_size
        let body_size = LittleEndian::read_u32(&bytes[20..24]);
        trace!(
            offset = 20,
            field = "body_size",
            value = body_size,
            "parsed"
        );

        // 0x18..0x20 — reserved 8 B, MUST be zero
        for (i, b) in bytes[24..32].iter().enumerate() {
            if *b != 0 {
                trace!(offset = 24 + i, "rejecting: reserved2 non-zero");
                return Err(ZacError::BadFlags {
                    offset: 24 + i,
                    field: "_reserved2",
                    value: *b as u64,
                });
            }
        }
        trace!(offset = 24, field = "_reserved2", value = "0..0", "parsed");

        Ok(Header {
            version_major: major,
            version_minor: minor,
            version_patch: patch,
            flags,
            section_count,
            body_offset,
            body_size,
        })
    }

    /// Serialise the header to a fixed 32-byte vector. The fields produced
    /// here are guaranteed to round-trip through `Header::parse`.
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..4].copy_from_slice(MAGIC_ZAC);
        out[4] = self.version_major;
        out[5] = self.version_minor;
        out[6] = self.version_patch;
        out[7] = self.flags;
        LittleEndian::write_u16(&mut out[8..10], self.section_count);
        // 10..12 reserved zero
        LittleEndian::write_u32(&mut out[12..16], INDEX_OFFSET);
        LittleEndian::write_u32(&mut out[16..20], self.body_offset);
        LittleEndian::write_u32(&mut out[20..24], self.body_size);
        // 24..32 reserved zero
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_header_bytes() -> Vec<u8> {
        let h = Header {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            flags: 0,
            section_count: 3,
            body_offset: 0x60,
            body_size: 0x40,
        };
        h.encode().to_vec()
    }

    #[test]
    fn round_trip_good_header() {
        let bytes = good_header_bytes();
        let h = Header::parse(&bytes).unwrap();
        assert_eq!(h.section_count, 3);
        assert_eq!(h.body_offset, 0x60);
        assert_eq!(h.encode().to_vec(), bytes);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = good_header_bytes();
        bytes[0] = b'X';
        assert_eq!(Header::parse(&bytes).unwrap_err().code(), "E001");
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = good_header_bytes();
        bytes[4] = 2;
        assert_eq!(Header::parse(&bytes).unwrap_err().code(), "E002");
    }

    #[test]
    fn rejects_non_zero_flags() {
        let mut bytes = good_header_bytes();
        bytes[7] = 1;
        assert_eq!(Header::parse(&bytes).unwrap_err().code(), "E003");
    }

    #[test]
    fn rejects_truncated() {
        let bytes = vec![0u8; 16];
        assert_eq!(Header::parse(&bytes).unwrap_err().code(), "E015");
    }
}
