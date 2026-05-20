//! Top-level `.zac` file orchestration — header + index + sections + trailer.

use tracing::{instrument, trace};

use crate::crc::crc32;
use crate::error::{ZacError, ZacResult};
use crate::hash::file_hash;
use crate::header::{Header, HEADER_SIZE, INDEX_OFFSET};
use crate::index::{parse_index, IndexEntry, INDEX_ENTRY_SIZE};
use crate::section::Section;
use crate::trailer::{Trailer, TRAILER_SIZE};

/// A fully-parsed `.zac` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZacFile {
    /// 32-byte header (SPEC §3.1).
    pub header: Header,
    /// All parsed sections in on-wire order.
    pub sections: Vec<Section>,
    /// 40-byte trailer (SPEC §3.4).
    pub trailer: Trailer,
}

impl ZacFile {
    /// Parse a complete `.zac` byte stream.
    ///
    /// On success every spec-level invariant has been enforced *except* the
    /// Phase 2 cryptographic checks (subgroup, Fr canonical). The trailer
    /// `file_hash` is recomputed and compared (E009 on mismatch).
    ///
    /// # Example
    ///
    /// ```
    /// use zac::ZacFile;
    ///
    /// let bytes = include_bytes!("../tests/fixtures/multiplier.zac");
    /// let zac = ZacFile::parse(bytes)?;
    /// assert_eq!(zac.header.version_major, 1);
    /// assert_eq!(zac.sections.len(), 3); // VKEY + INTERFACE + R1CS_HASH
    /// # Ok::<(), zac::ZacError>(())
    /// ```
    #[instrument(level = "trace", skip(bytes), fields(len = bytes.len()))]
    pub fn parse(bytes: &[u8]) -> ZacResult<Self> {
        trace!("parse: begin");
        if bytes.len() < HEADER_SIZE + TRAILER_SIZE {
            return Err(ZacError::Truncated {
                offset: 0,
                need: HEADER_SIZE + TRAILER_SIZE,
                have: bytes.len(),
            });
        }
        let header = Header::parse(&bytes[..HEADER_SIZE])?;

        let total_needed =
            INDEX_OFFSET as usize + (header.section_count as usize) * INDEX_ENTRY_SIZE;
        if total_needed > bytes.len() {
            return Err(ZacError::Truncated {
                offset: INDEX_OFFSET as usize,
                need: total_needed - INDEX_OFFSET as usize,
                have: bytes.len().saturating_sub(INDEX_OFFSET as usize),
            });
        }

        // body_offset must come AFTER the index ends.
        let index_end =
            INDEX_OFFSET as u64 + (header.section_count as u64) * INDEX_ENTRY_SIZE as u64;
        if (header.body_offset as u64) < index_end {
            return Err(ZacError::BadAlignment {
                offset: 16,
                reason: "body_offset overlaps the index",
            });
        }

        // File must contain at least body_offset + body_size + trailer.
        let body_end = header.body_offset as u64 + header.body_size as u64;
        let file_len = bytes.len() as u64;
        if body_end + TRAILER_SIZE as u64 > file_len {
            return Err(ZacError::Truncated {
                offset: header.body_offset as usize,
                need: (body_end + TRAILER_SIZE as u64 - file_len) as usize,
                have: 0,
            });
        }
        if body_end + TRAILER_SIZE as u64 != file_len {
            // The trailer MUST be the final 40 B (SPEC §3.4).
            return Err(ZacError::BadAlignment {
                offset: 20,
                reason: "file size doesn't equal body_offset + body_size + 40",
            });
        }

        // Padding between index end and body_offset MUST be zero.
        for (i, b) in bytes[index_end as usize..header.body_offset as usize]
            .iter()
            .enumerate()
        {
            if *b != 0 {
                return Err(ZacError::BadAlignment {
                    offset: index_end as usize + i,
                    reason: "non-zero padding between index and first body",
                });
            }
        }

        let entries = parse_index(
            bytes,
            INDEX_OFFSET as usize,
            header.section_count,
            header.body_offset,
            header.body_size,
        )?;

        // Parse each body and validate CRC.
        let mut sections = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            let abs = entry.offset as usize;
            let end = abs + entry.size as usize;
            if end > bytes.len() - TRAILER_SIZE {
                return Err(ZacError::Truncated {
                    offset: abs,
                    need: entry.size as usize,
                    have: bytes.len().saturating_sub(abs),
                });
            }
            let body = &bytes[abs..end];
            let observed = crc32(body);
            if observed != entry.crc32 {
                trace!(
                    entry = i,
                    expected = format!("{:#010x}", entry.crc32),
                    got = format!("{observed:#010x}"),
                    "rejecting: CRC32 mismatch"
                );
                return Err(ZacError::BadCrc32 {
                    entry_index: i,
                    section_type: entry.section_type,
                    expected: entry.crc32,
                    got: observed,
                });
            }

            // Padding bytes between this body's end and the next entry's
            // offset (or body_end for the last entry) MUST be zero.
            let pad_end = if i + 1 < entries.len() {
                entries[i + 1].offset as usize
            } else {
                (header.body_offset + header.body_size) as usize
            };
            for (j, b) in bytes[end..pad_end].iter().enumerate() {
                if *b != 0 {
                    return Err(ZacError::BadAlignment {
                        offset: end + j,
                        reason: "non-zero alignment padding",
                    });
                }
            }

            let section = Section::parse(entry.section_type, body, abs, i)?;
            sections.push(section);
        }

        // Mandatory section presence check (SPEC §5: VKEY, INTERFACE, R1CS_HASH).
        // First missing section in spec order yields E016.
        let mut has_vkey = false;
        let mut has_iface = false;
        let mut has_r1cs = false;
        for s in &sections {
            match s {
                Section::Vkey(_) => has_vkey = true,
                Section::Interface(_) => has_iface = true,
                Section::R1csHash(_) => has_r1cs = true,
                _ => {}
            }
        }
        if !has_vkey {
            return Err(ZacError::MissingMandatorySection {
                missing_type: crate::index::SECTION_VKEY,
                name: "VKEY",
            });
        }
        if !has_iface {
            return Err(ZacError::MissingMandatorySection {
                missing_type: crate::index::SECTION_INTERFACE,
                name: "INTERFACE",
            });
        }
        if !has_r1cs {
            return Err(ZacError::MissingMandatorySection {
                missing_type: crate::index::SECTION_R1CS_HASH,
                name: "R1CS_HASH",
            });
        }

        // Trailer.
        let trailer_off = bytes.len() - TRAILER_SIZE;
        let trailer = Trailer::parse(&bytes[trailer_off..], trailer_off)?;

        // Recompute file_hash and compare.
        let version_bytes = &bytes[4..8];
        let body_bytes = &bytes[INDEX_OFFSET as usize..trailer_off];
        let computed = file_hash(version_bytes, body_bytes);
        if computed != trailer.file_hash {
            trace!(
                expected = %hex::encode(trailer.file_hash),
                computed = %hex::encode(computed),
                "rejecting: file_hash mismatch"
            );
            return Err(ZacError::BadFileHash {
                trailer: trailer.file_hash,
                computed,
            });
        }
        trace!("parse: success");

        Ok(ZacFile {
            header,
            sections,
            trailer,
        })
    }

    /// Encode an in-memory `ZacFile` to a fresh byte vector. Header geometry
    /// fields (body_offset, body_size, section_count) and the trailer
    /// `file_hash` are recomputed; everything else is taken from `self`.
    ///
    /// Round-trip guarantee: `ZacFile::parse(&zf.encode())` is structurally
    /// equal to `zf` (modulo any fields the encoder re-derives).
    #[instrument(level = "trace", skip(self))]
    pub fn encode(&self) -> Vec<u8> {
        let n = self.sections.len();
        assert!(
            (1..=crate::header::MAX_SECTIONS).contains(&n),
            "section_count must be 1..=16"
        );

        // Encode bodies, computing offsets with 8-byte alignment.
        let index_end = INDEX_OFFSET as usize + n * INDEX_ENTRY_SIZE;
        let body_offset_calc = align_up(index_end, 8);

        let mut bodies: Vec<Vec<u8>> = Vec::with_capacity(n);
        let mut offsets: Vec<u32> = Vec::with_capacity(n);
        let mut sizes: Vec<u32> = Vec::with_capacity(n);
        let mut crcs: Vec<u32> = Vec::with_capacity(n);

        let mut cursor = body_offset_calc;
        for (i, section) in self.sections.iter().enumerate() {
            let body = section.encode_body();
            let size = body.len() as u32;
            let crc = crc32(&body);
            offsets.push(cursor as u32);
            sizes.push(size);
            crcs.push(crc);
            trace!(
                entry = i,
                offset = cursor,
                size,
                crc = format!("{crc:#010x}"),
                "encoded body"
            );
            cursor += body.len();
            // Pad next section to 8 (or pad the last body to 8 for body_size).
            cursor = align_up(cursor, 8);
            bodies.push(body);
        }
        let body_end = cursor;
        let body_size_calc = (body_end - body_offset_calc) as u32;

        // Emit header (with reconstructed geometry).
        let mut header = self.header.clone();
        header.section_count = n as u16;
        header.body_offset = body_offset_calc as u32;
        header.body_size = body_size_calc;
        // version + flags untouched.
        let header_bytes = header.encode();

        // Emit index entries.
        let mut out = Vec::with_capacity(body_end + TRAILER_SIZE);
        out.extend_from_slice(&header_bytes);
        for i in 0..n {
            let entry = IndexEntry {
                section_type: self.sections[i].section_type(),
                flags: 0,
                offset: offsets[i],
                size: sizes[i],
                crc32: crcs[i],
            };
            out.extend_from_slice(&entry.encode());
        }
        // Pad to body_offset.
        while out.len() < body_offset_calc {
            out.push(0);
        }
        // Bodies + padding.
        for (i, body) in bodies.iter().enumerate() {
            out.extend_from_slice(body);
            let next_off = if i + 1 < n {
                offsets[i + 1] as usize
            } else {
                body_end
            };
            while out.len() < next_off {
                out.push(0);
            }
        }
        assert_eq!(out.len(), body_end);

        // Compute file_hash and emit trailer.
        let computed = file_hash(&out[4..8], &out[INDEX_OFFSET as usize..body_end]);
        let trailer = Trailer {
            file_hash: computed,
        };
        out.extend_from_slice(&trailer.encode());
        out
    }
}

#[inline]
fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}
