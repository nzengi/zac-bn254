//! iden3 WTNS binary format — encoder + parser.
//!
//! WTNS v2 layout:
//!
//! ```text
//! magic "wtns" | version 2 | nSections=2
//! section 0x01 header: n8 u32 | prime (n8 LE) | nWitness u32
//! section 0x02 values: nWitness * (n8 LE) field elements (standard form, LE)
//! ```
//!
//! Fr values are encoded in **standard** little-endian (not Montgomery).
//! ZAC accepts only BN254 (`n8 == 32`, `prime == r`).

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{ZacError, ZacResult};
use crate::iden3::{
    begin_section, end_section, find_section, read_binfile_header, write_binfile_header, BN254_R_LE,
};

use ark_bn254::Fr;

/// Parsed `.wtns` file.
#[derive(Debug, Clone)]
pub struct Wtns {
    /// Field-element byte width. MUST be 32 for ZAC.
    pub n8: u32,
    /// Prime modulus. MUST equal BN254 `r` for ZAC.
    pub prime_le: [u8; 32],
    /// Witness values as `Fr` field elements (already canonical-decoded).
    pub values: Vec<Fr>,
    /// Witness values in their original on-wire 32-byte LE form (kept so we
    /// can recompute hashes / cross-check public inputs without re-encoding).
    pub values_le: Vec<[u8; 32]>,
}

/// Encode a synthetic `.wtns` file from Fr values in LE form.
pub fn encode_wtns(values_le: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + values_le.len() * 32);
    write_binfile_header(&mut out, b"wtns", 2, 2);

    // Section 0x01 — header
    let s_off = begin_section(&mut out, 0x01);
    let body_start = out.len();
    let mut tmp4 = [0u8; 4];
    LittleEndian::write_u32(&mut tmp4, 32);
    out.extend_from_slice(&tmp4);
    out.extend_from_slice(&BN254_R_LE);
    LittleEndian::write_u32(&mut tmp4, values_le.len() as u32);
    out.extend_from_slice(&tmp4);
    end_section(&mut out, s_off, body_start);

    // Section 0x02 — values
    let s_off = begin_section(&mut out, 0x02);
    let body_start = out.len();
    for v in values_le {
        out.extend_from_slice(v);
    }
    end_section(&mut out, s_off, body_start);

    out
}

/// Encode an Fr scalar (u64) into a 32-byte LE buffer, zero-padded.
pub fn fr_u64_le(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&v.to_le_bytes());
    out
}

/// Parse a `.wtns` byte stream.
///
/// Validates BN254 modulus and `n8 == 32`; rejects any Fr value ≥ r via the
/// SPEC §8 canonical check (E012).
pub fn parse_wtns(bytes: &[u8]) -> ZacResult<Wtns> {
    let (_hdr, sects) = read_binfile_header(bytes, b"wtns")?;

    let header_sec = find_section(&sects, 0x01).ok_or(ZacError::MissingMandatorySection {
        missing_type: 0x01,
        name: "wtns.header",
    })?;
    let val_sec = find_section(&sects, 0x02).ok_or(ZacError::MissingMandatorySection {
        missing_type: 0x02,
        name: "wtns.values",
    })?;

    if header_sec.size < 4 + 32 + 4 {
        return Err(ZacError::Truncated {
            offset: header_sec.offset,
            need: 40,
            have: header_sec.size as usize,
        });
    }
    let off = header_sec.offset;
    let n8 = LittleEndian::read_u32(&bytes[off..off + 4]);
    if n8 != 32 {
        return Err(ZacError::BadFlags {
            offset: off,
            field: "wtns.n8",
            value: n8 as u64,
        });
    }
    let mut prime_le = [0u8; 32];
    prime_le.copy_from_slice(&bytes[off + 4..off + 36]);
    if prime_le != BN254_R_LE {
        return Err(ZacError::BadFlags {
            offset: off + 4,
            field: "wtns.prime",
            value: u64::from_le_bytes(prime_le[0..8].try_into().unwrap()),
        });
    }
    let n_witness = LittleEndian::read_u32(&bytes[off + 36..off + 40]);
    tracing::trace!(n_witness, "wtns: parsed header");

    let val_off = val_sec.offset;
    if val_sec.size as usize != (n_witness as usize) * 32 {
        return Err(ZacError::Truncated {
            offset: val_off,
            need: (n_witness as usize) * 32,
            have: val_sec.size as usize,
        });
    }

    let mut values = Vec::with_capacity(n_witness as usize);
    let mut values_le = Vec::with_capacity(n_witness as usize);
    for i in 0..n_witness as usize {
        let abs = val_off + i * 32;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes[abs..abs + 32]);
        let fr = crate::groth16::decode_fr_canonical(&buf, abs, i)?;
        values_le.push(buf);
        values.push(fr);
    }

    Ok(Wtns {
        n8,
        prime_le,
        values,
        values_le,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let vals = vec![fr_u64_le(1), fr_u64_le(33), fr_u64_le(3), fr_u64_le(11)];
        let bytes = encode_wtns(&vals);
        let w = parse_wtns(&bytes).unwrap();
        assert_eq!(w.n8, 32);
        assert_eq!(w.prime_le, BN254_R_LE);
        assert_eq!(w.values.len(), 4);
        assert_eq!(w.values_le, vals);
        assert_eq!(w.values[0], Fr::from(1u64));
        assert_eq!(w.values[1], Fr::from(33u64));
        assert_eq!(w.values[2], Fr::from(3u64));
        assert_eq!(w.values[3], Fr::from(11u64));
    }
}
