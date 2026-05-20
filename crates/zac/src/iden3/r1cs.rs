//! iden3 R1CS binary format — encoder for Phase 3 fixtures.
//!
//! Reference: github.com/iden3/r1csfile/doc/r1cs_bin_format.md.
//!
//! ZAC does not run circom; we hand-roll the canonical bytes for the
//! `x * y = z` multiplier circuit so snarkjs has a real `.r1cs` to consume.
//!
//! ## Wire layout
//!
//! ```text
//! magic "r1cs" | version 1 | nSections=3
//! section 0x01 Header
//!   n8 (u32 LE) | prime r (n8 LE) | nWires u32 | nPubOut u32 | nPubIn u32 |
//!   nPrvIn u32 | nLabels u64 | nConstraints u32
//! section 0x02 Constraints
//!   per constraint: nA u32, [(wireId u32, coeff Fr-LE) * nA],
//!                   nB u32, [(wireId u32, coeff Fr-LE) * nB],
//!                   nC u32, [(wireId u32, coeff Fr-LE) * nC]
//! section 0x03 Wire2LabelId
//!   nWires * u64
//! ```

use byteorder::{ByteOrder, LittleEndian};

use crate::iden3::{begin_section, end_section, write_binfile_header, BN254_R_LE};

/// One linear combination entry: `(wireId, coeff_LE)` with coeff as 32-byte LE.
pub type LcEntry = (u32, [u8; 32]);

/// One R1CS constraint: three linear combinations A·B = C.
pub struct Constraint {
    /// Linear combination A — wire-indexed coefficient pairs (sorted ascending
    /// by `wireId`).
    pub a: Vec<LcEntry>,
    /// Linear combination B.
    pub b: Vec<LcEntry>,
    /// Linear combination C.
    pub c: Vec<LcEntry>,
}

/// Description of the multiplier circuit used by Phase 3 fixtures.
///
/// Wire layout: `[wire0=1, wire1=z (public output), wire2=x (private),
/// wire3=y (private)]`. Single constraint: `x · y = z`.
pub fn multiplier_circuit() -> R1csSpec {
    // Coefficient 1 encoded as Fr-LE 32 bytes: 0x01 followed by 31 zeros.
    let mut one_le = [0u8; 32];
    one_le[0] = 1;

    R1csSpec {
        n_wires: 4,
        n_pub_out: 1,
        n_pub_in: 0,
        n_prv_in: 2,
        n_labels: 4,
        constraints: vec![Constraint {
            a: vec![(2, one_le)],
            b: vec![(3, one_le)],
            c: vec![(1, one_le)],
        }],
    }
}

/// Header parameters for the iden3 R1CS encoder.
pub struct R1csSpec {
    /// Total wires (including the `1`-wire at index 0).
    pub n_wires: u32,
    /// Number of public output wires (immediately after wire 0).
    pub n_pub_out: u32,
    /// Number of public input wires.
    pub n_pub_in: u32,
    /// Number of private input wires.
    pub n_prv_in: u32,
    /// Number of labels (used by the wire→label section).
    pub n_labels: u64,
    /// The list of R1CS constraints.
    pub constraints: Vec<Constraint>,
}

/// Encode a complete iden3 R1CS binary file. The wire→label map is emitted
/// as the identity map (`map[i] = i as u64`).
pub fn encode_r1cs(spec: &R1csSpec) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    write_binfile_header(&mut out, b"r1cs", 1, 3);

    // -------- Section 0x01: header --------
    let s_off = begin_section(&mut out, 0x01);
    let body_start = out.len();
    // n8 = 32
    let mut tmp4 = [0u8; 4];
    LittleEndian::write_u32(&mut tmp4, 32);
    out.extend_from_slice(&tmp4);
    // prime r (32 LE bytes)
    out.extend_from_slice(&BN254_R_LE);
    LittleEndian::write_u32(&mut tmp4, spec.n_wires);
    out.extend_from_slice(&tmp4);
    LittleEndian::write_u32(&mut tmp4, spec.n_pub_out);
    out.extend_from_slice(&tmp4);
    LittleEndian::write_u32(&mut tmp4, spec.n_pub_in);
    out.extend_from_slice(&tmp4);
    LittleEndian::write_u32(&mut tmp4, spec.n_prv_in);
    out.extend_from_slice(&tmp4);
    let mut tmp8 = [0u8; 8];
    LittleEndian::write_u64(&mut tmp8, spec.n_labels);
    out.extend_from_slice(&tmp8);
    LittleEndian::write_u32(&mut tmp4, spec.constraints.len() as u32);
    out.extend_from_slice(&tmp4);
    end_section(&mut out, s_off, body_start);

    // -------- Section 0x02: constraints --------
    let s_off = begin_section(&mut out, 0x02);
    let body_start = out.len();
    for c in &spec.constraints {
        write_lc(&mut out, &c.a);
        write_lc(&mut out, &c.b);
        write_lc(&mut out, &c.c);
    }
    end_section(&mut out, s_off, body_start);

    // -------- Section 0x03: wire→label map --------
    let s_off = begin_section(&mut out, 0x03);
    let body_start = out.len();
    for i in 0..spec.n_wires as u64 {
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, i);
        out.extend_from_slice(&buf);
    }
    end_section(&mut out, s_off, body_start);

    out
}

fn write_lc(out: &mut Vec<u8>, lc: &[LcEntry]) {
    let mut tmp4 = [0u8; 4];
    LittleEndian::write_u32(&mut tmp4, lc.len() as u32);
    out.extend_from_slice(&tmp4);
    for (wire, coeff) in lc {
        LittleEndian::write_u32(&mut tmp4, *wire);
        out.extend_from_slice(&tmp4);
        out.extend_from_slice(coeff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iden3::{find_section, read_binfile_header};

    #[test]
    fn multiplier_roundtrips_through_header_parser() {
        let bytes = encode_r1cs(&multiplier_circuit());
        let (hdr, sects) = read_binfile_header(&bytes, b"r1cs").unwrap();
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.n_sections, 3);
        assert!(find_section(&sects, 0x01).is_some());
        assert!(find_section(&sects, 0x02).is_some());
        assert!(find_section(&sects, 0x03).is_some());
    }
}
