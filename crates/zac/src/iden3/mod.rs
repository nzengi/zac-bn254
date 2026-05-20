//! iden3 binary formats (R1CS, WTNS, ZKEY) — Phase 3 interop layer.
//!
//! ZAC consumes snarkjs-produced `.zkey` and `.wtns` and emits `.zacp` proofs
//! that snarkjs verifies. This module is the wire-level bridge.
//!
//! ## Wire endian and Montgomery
//!
//! All multi-byte integers are little-endian (matching iden3 conventions).
//! Field elements (Fr and Fq) on the wire come in two flavours:
//!   * **standard LE** — used in R1CS and WTNS files
//!   * **Montgomery LE** (`mont = std · R mod q`, `R = 2^(8·n8)`) — used in
//!     ZKEY for both Fr (the `ccoefs` values) and Fq (the curve point
//!     coordinates).
//!
//! Conversion: `std = mont · R^(-1) mod q`. The helpers in this module
//! perform every conversion explicitly; no Montgomery-form value escapes
//! into arkworks-typed land.

pub mod r1cs;
pub mod wtns;
pub mod zkey;

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{ZacError, ZacResult};

/// iden3 binfile common prefix: 4-byte magic, 4-byte version (LE u32),
/// 4-byte nSections (LE u32). Returned by [`read_binfile_header`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinFileHeader {
    /// 4-byte ASCII magic ("r1cs", "wtns", "zkey").
    pub magic: [u8; 4],
    /// File-format version.
    pub version: u32,
    /// Number of sections that follow.
    pub n_sections: u32,
}

/// Locate the start of section bodies and return them as `(section_id,
/// abs_offset, size)` triples. Each section is laid out as:
///
/// ```text
/// off  sz  field
/// 0    4   section_id  (LE u32)
/// 4    8   size        (LE u64)
/// 12   N   body
/// ```
///
/// Unlike the ZAC container, iden3 binfiles allow duplicate section IDs (the
/// reader picks the first match). For our parsing we record every section in
/// the order it appears.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionRef {
    /// `section_id` from the on-wire 4-byte header.
    pub id: u32,
    /// Absolute file offset of the *body* (i.e. immediately after the 12-byte
    /// section header).
    pub offset: usize,
    /// Size in bytes of the body.
    pub size: u64,
}

/// Parse the 12-byte binfile header and the section table. Returns the
/// header plus a Vec of [`SectionRef`] in file order.
pub fn read_binfile_header(
    bytes: &[u8],
    expected_magic: &[u8; 4],
) -> ZacResult<(BinFileHeader, Vec<SectionRef>)> {
    if bytes.len() < 12 {
        return Err(ZacError::Truncated {
            offset: 0,
            need: 12,
            have: bytes.len(),
        });
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&bytes[0..4]);
    if &magic != expected_magic {
        return Err(ZacError::BadMagic {
            offset: 0,
            expected: match expected_magic {
                b"r1cs" => "r1cs",
                b"wtns" => "wtns",
                b"zkey" => "zkey",
                _ => "iden3-binfile",
            },
            got: magic,
        });
    }
    let version = LittleEndian::read_u32(&bytes[4..8]);
    let n_sections = LittleEndian::read_u32(&bytes[8..12]);

    let mut sections = Vec::with_capacity(n_sections as usize);
    let mut cur = 12usize;
    for i in 0..n_sections {
        if cur + 12 > bytes.len() {
            return Err(ZacError::Truncated {
                offset: cur,
                need: 12,
                have: bytes.len().saturating_sub(cur),
            });
        }
        let id = LittleEndian::read_u32(&bytes[cur..cur + 4]);
        let size = LittleEndian::read_u64(&bytes[cur + 4..cur + 12]);
        let body_off = cur + 12;
        if body_off as u64 + size > bytes.len() as u64 {
            return Err(ZacError::Truncated {
                offset: body_off,
                need: size as usize,
                have: bytes.len().saturating_sub(body_off),
            });
        }
        tracing::trace!(
            section = i,
            id,
            offset = body_off,
            size,
            "iden3: parsed section header"
        );
        sections.push(SectionRef {
            id,
            offset: body_off,
            size,
        });
        cur = body_off + size as usize;
    }

    Ok((
        BinFileHeader {
            magic,
            version,
            n_sections,
        },
        sections,
    ))
}

/// Locate the first occurrence of a section with the given `id`.
/// Returns `None` if not found.
pub fn find_section(sections: &[SectionRef], id: u32) -> Option<&SectionRef> {
    sections.iter().find(|s| s.id == id)
}

/// Write the 12-byte binfile header to `out` and return.
pub(crate) fn write_binfile_header(
    out: &mut Vec<u8>,
    magic: &[u8; 4],
    version: u32,
    n_sections: u32,
) {
    out.extend_from_slice(magic);
    let mut tmp = [0u8; 4];
    LittleEndian::write_u32(&mut tmp, version);
    out.extend_from_slice(&tmp);
    LittleEndian::write_u32(&mut tmp, n_sections);
    out.extend_from_slice(&tmp);
}

/// Begin a section: emit 4-byte id + a placeholder 8-byte size. Returns
/// the byte offset where the size will be back-patched.
pub(crate) fn begin_section(out: &mut Vec<u8>, id: u32) -> usize {
    let mut tmp = [0u8; 4];
    LittleEndian::write_u32(&mut tmp, id);
    out.extend_from_slice(&tmp);
    let size_off = out.len();
    out.extend_from_slice(&[0u8; 8]);
    size_off
}

/// Finish the section started at `size_off` by back-patching the size.
pub(crate) fn end_section(out: &mut [u8], size_off: usize, body_start: usize) {
    let body_len = out.len() - body_start;
    LittleEndian::write_u64(&mut out[size_off..size_off + 8], body_len as u64);
}

/// Standard BN254 base-field modulus q (Fq), little-endian 32 bytes.
/// Identical to `ark_bn254::Fq::MODULUS` but reported here as raw bytes so
/// it can be written to disk verbatim.
pub const BN254_Q_LE: [u8; 32] = [
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c, 0x8d, 0xca, 0x71, 0x68, 0x91, 0x6a, 0x81, 0x97,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

/// Standard BN254 scalar-field modulus r (Fr), little-endian 32 bytes.
pub const BN254_R_LE: [u8; 32] = [
    0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, Fr};
    use ark_ff::{BigInteger, PrimeField};

    #[test]
    fn bn254_q_le_matches_arkworks() {
        let ark = Fq::MODULUS.to_bytes_le();
        assert_eq!(&ark[..], &BN254_Q_LE[..]);
    }

    #[test]
    fn bn254_r_le_matches_arkworks() {
        let ark = Fr::MODULUS.to_bytes_le();
        assert_eq!(&ark[..], &BN254_R_LE[..]);
    }
}
