//! Section index parsing (SPEC §3.2).
//!
//! Every one of the eight invariants in the spec is enforced explicitly so
//! the verifier never advances to body parsing on a malformed index.

use byteorder::{ByteOrder, LittleEndian};
use tracing::trace;

use crate::error::{ZacError, ZacResult};
use crate::header::MAX_SECTIONS;

/// Size of one section index entry in bytes.
pub const INDEX_ENTRY_SIZE: usize = 16;

/// Section type byte: VKEY (SPEC §5).
pub const SECTION_VKEY: u8 = 0x01;
/// Section type byte: INTERFACE (SPEC §5).
pub const SECTION_INTERFACE: u8 = 0x02;
/// Section type byte: R1CS_HASH (SPEC §5).
pub const SECTION_R1CS_HASH: u8 = 0x03;
/// Section type byte: META_CBOR (SPEC §5).
pub const SECTION_META_CBOR: u8 = 0x04;

/// One parsed index entry (matches the on-wire 16-byte layout one-for-one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Section type byte (SPEC §5).
    pub section_type: u8,
    /// Per-entry flags, MUST be 0 in v1.0.
    pub flags: u8,
    /// Absolute file offset where the body begins.
    pub offset: u32,
    /// Length of the body in bytes (no padding).
    pub size: u32,
    /// IEEE CRC-32 of `body[offset..offset + size]`.
    pub crc32: u32,
}

impl IndexEntry {
    /// Parse a single 16-byte index entry from `bytes`.
    fn parse(bytes: &[u8], entry_index: usize, abs_offset: usize) -> ZacResult<Self> {
        if bytes.len() < INDEX_ENTRY_SIZE {
            return Err(ZacError::Truncated {
                offset: abs_offset,
                need: INDEX_ENTRY_SIZE,
                have: bytes.len(),
            });
        }
        let section_type = bytes[0];
        let flags = bytes[1];
        let pad = LittleEndian::read_u16(&bytes[2..4]);
        let offset = LittleEndian::read_u32(&bytes[4..8]);
        let size = LittleEndian::read_u32(&bytes[8..12]);
        let crc32 = LittleEndian::read_u32(&bytes[12..16]);

        trace!(
            offset = abs_offset,
            entry = entry_index,
            section_type,
            flags,
            body_offset = offset,
            body_size = size,
            crc32 = format!("{crc32:#010x}"),
            "parsed index entry"
        );

        if flags != 0 {
            trace!(offset = abs_offset + 1, "rejecting: entry flags non-zero");
            return Err(ZacError::BadFlags {
                offset: abs_offset + 1,
                field: "entry.flags",
                value: flags as u64,
            });
        }
        if pad != 0 {
            trace!(offset = abs_offset + 2, "rejecting: entry pad non-zero");
            return Err(ZacError::BadFlags {
                offset: abs_offset + 2,
                field: "entry._pad",
                value: pad as u64,
            });
        }
        if section_type == 0x00 || section_type == 0xFF {
            trace!(
                offset = abs_offset,
                section_type,
                "rejecting: forbidden section type"
            );
            return Err(ZacError::ForbiddenSectionType {
                entry_index,
                section_type,
            });
        }
        if (0x05..=0x7F).contains(&section_type) {
            trace!(
                offset = abs_offset,
                section_type,
                "rejecting: reserved section type"
            );
            return Err(ZacError::ForbiddenSectionType {
                entry_index,
                section_type,
            });
        }
        if offset % 8 != 0 {
            trace!(
                offset = abs_offset + 4,
                value = offset,
                "rejecting: entry offset not 8-aligned"
            );
            return Err(ZacError::BadAlignment {
                offset: abs_offset + 4,
                reason: "section offset must be 8-aligned",
            });
        }

        Ok(IndexEntry {
            section_type,
            flags,
            offset,
            size,
            crc32,
        })
    }

    /// Encode this entry as 16 raw bytes.
    pub fn encode(&self) -> [u8; INDEX_ENTRY_SIZE] {
        let mut out = [0u8; INDEX_ENTRY_SIZE];
        out[0] = self.section_type;
        out[1] = self.flags;
        // 2..4 _pad = 0
        LittleEndian::write_u32(&mut out[4..8], self.offset);
        LittleEndian::write_u32(&mut out[8..12], self.size);
        LittleEndian::write_u32(&mut out[12..16], self.crc32);
        out
    }
}

/// Parse the full index — `count` entries starting at `bytes_offset` of
/// `bytes` — and enforce every spec-level invariant.
///
/// `body_offset` and `body_size` come from the already-parsed header and are
/// used to verify the geometric invariants (7) and (8).
pub fn parse_index(
    bytes: &[u8],
    bytes_offset: usize,
    count: u16,
    body_offset: u32,
    body_size: u32,
) -> ZacResult<Vec<IndexEntry>> {
    let count_usize = count as usize;
    if count_usize == 0 || count_usize > MAX_SECTIONS {
        return Err(ZacError::BadFlags {
            offset: 8,
            field: "section_count",
            value: count as u64,
        });
    }
    let need = count_usize * INDEX_ENTRY_SIZE;
    let avail = bytes.len().saturating_sub(bytes_offset);
    if avail < need {
        return Err(ZacError::Truncated {
            offset: bytes_offset,
            need,
            have: avail,
        });
    }

    let mut entries = Vec::with_capacity(count_usize);
    let mut seen_types = [false; 256];
    for i in 0..count_usize {
        let abs = bytes_offset + i * INDEX_ENTRY_SIZE;
        let entry = IndexEntry::parse(&bytes[abs..abs + INDEX_ENTRY_SIZE], i, abs)?;
        // (2) uniqueness
        if seen_types[entry.section_type as usize] {
            trace!(
                entry = i,
                section_type = entry.section_type,
                "rejecting: duplicate section type"
            );
            return Err(ZacError::DuplicateSectionType {
                entry_index: i,
                section_type: entry.section_type,
            });
        }
        seen_types[entry.section_type as usize] = true;
        entries.push(entry);
    }

    // (7) first entry's offset must equal body_offset
    if entries[0].offset != body_offset {
        trace!(
            "rejecting: first section offset {:#x} != body_offset {:#x}",
            entries[0].offset,
            body_offset
        );
        return Err(ZacError::BadAlignment {
            offset: bytes_offset + 4,
            reason: "first section offset must equal body_offset",
        });
    }

    // (4)+(5) monotonic, non-overlapping, 8-aligned offsets
    for i in 0..entries.len() - 1 {
        let this_end = entries[i].offset as u64 + entries[i].size as u64;
        let next_off = entries[i + 1].offset as u64;
        if next_off < this_end {
            trace!(
                entry = i,
                this_end,
                next_offset = next_off,
                "rejecting: overlap"
            );
            return Err(ZacError::SectionOverlap {
                entry_index: i,
                this_end,
                next_offset: next_off,
            });
        }
        if next_off <= entries[i].offset as u64 {
            trace!(entry = i, "rejecting: non-monotonic offsets");
            return Err(ZacError::SectionOverlap {
                entry_index: i,
                this_end,
                next_offset: next_off,
            });
        }
    }

    // (8) last entry ends at body_offset + body_size
    let last = entries.last().expect("count >= 1");
    let last_end = last.offset as u64 + last.size as u64;
    let expected_end = body_offset as u64 + body_size as u64;
    if last_end > expected_end {
        trace!(
            last_end,
            expected_end,
            "rejecting: last section past body end"
        );
        return Err(ZacError::SectionOverlap {
            entry_index: entries.len() - 1,
            this_end: last_end,
            next_offset: expected_end,
        });
    }
    // last_end may be < expected_end ONLY due to trailing pad zeros — but the
    // spec says "last section ends at body_offset + body_size" so we round
    // up to the next 8-byte boundary and verify.
    let last_end_padded = (last_end + 7) & !7u64;
    if last_end_padded != expected_end {
        trace!(
            last_end_padded,
            expected_end,
            "rejecting: body_size doesn't match last section + alignment pad"
        );
        return Err(ZacError::BadAlignment {
            offset: 20,
            reason: "body_size must cover last section + 8-byte pad",
        });
    }

    Ok(entries)
}
