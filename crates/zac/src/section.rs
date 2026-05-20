//! Section bodies (SPEC §5).
//!
//! Phase 1 keeps VKEY as an opaque `Vec<u8>` — Phase 2 will wrap it with
//! arkworks `CanonicalDeserialize` and run subgroup checks. INTERFACE,
//! R1CS_HASH, META_CBOR, and Vendor sections are fully parsed here because
//! their structure is self-describing and crypto-independent.

use byteorder::{ByteOrder, LittleEndian};
use tracing::trace;

use crate::error::{ZacError, ZacResult};
use crate::index::{SECTION_INTERFACE, SECTION_META_CBOR, SECTION_R1CS_HASH, SECTION_VKEY};

/// Decoded INTERFACE section (SPEC §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSection {
    /// Number of public inputs declared by the interface.
    pub public_input_count: u32,
    /// One UTF-8 name per public input, in declaration order.
    pub names: Vec<String>,
}

/// All section variants understood in v1.0. Unknown vendor sections are kept
/// verbatim so encode/round-trip stays lossless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    /// VKEY (0x01) — opaque `ark-groth16` canonical compressed bytes.
    Vkey(Vec<u8>),
    /// INTERFACE (0x02) — typed public-input metadata.
    Interface(InterfaceSection),
    /// R1CS_HASH (0x03) — 32 B BLAKE3 over the canonical iden3 R1CS binary.
    R1csHash([u8; 32]),
    /// META_CBOR (0x04) — opaque CBOR; verifier MUST NOT depend on this.
    MetaCbor(Vec<u8>),
    /// Vendor (0x80..=0xFE) — opaque, skipped by verifiers.
    Vendor {
        /// Section type byte.
        tag: u8,
        /// Section body bytes.
        body: Vec<u8>,
    },
}

impl Section {
    /// On-wire section type byte for this variant.
    pub fn section_type(&self) -> u8 {
        match self {
            Section::Vkey(_) => SECTION_VKEY,
            Section::Interface(_) => SECTION_INTERFACE,
            Section::R1csHash(_) => SECTION_R1CS_HASH,
            Section::MetaCbor(_) => SECTION_META_CBOR,
            Section::Vendor { tag, .. } => *tag,
        }
    }

    /// Encode the section body to a fresh `Vec<u8>`. Padding is the caller's
    /// responsibility (it depends on the next section's alignment).
    pub fn encode_body(&self) -> Vec<u8> {
        match self {
            Section::Vkey(b) => b.clone(),
            Section::Interface(i) => {
                let mut out =
                    Vec::with_capacity(4 + i.names.iter().map(|n| 2 + n.len()).sum::<usize>());
                let mut tmp = [0u8; 4];
                LittleEndian::write_u32(&mut tmp, i.public_input_count);
                out.extend_from_slice(&tmp);
                for name in &i.names {
                    let bytes = name.as_bytes();
                    let mut len_buf = [0u8; 2];
                    LittleEndian::write_u16(&mut len_buf, bytes.len() as u16);
                    out.extend_from_slice(&len_buf);
                    out.extend_from_slice(bytes);
                }
                out
            }
            Section::R1csHash(h) => h.to_vec(),
            Section::MetaCbor(b) => b.clone(),
            Section::Vendor { body, .. } => body.clone(),
        }
    }

    /// Parse a section given its type byte and body bytes.
    ///
    /// `abs_offset` is the absolute file offset of the body — propagated into
    /// errors so they can be mapped to a hex-dump.
    pub fn parse(
        section_type: u8,
        body: &[u8],
        abs_offset: usize,
        entry_index: usize,
    ) -> ZacResult<Section> {
        match section_type {
            0x00 | 0xFF => Err(ZacError::ForbiddenSectionType {
                entry_index,
                section_type,
            }),
            v if (0x05..=0x7F).contains(&v) => Err(ZacError::ForbiddenSectionType {
                entry_index,
                section_type,
            }),
            SECTION_VKEY => {
                trace!(
                    offset = abs_offset,
                    bytes = body.len(),
                    "parsed VKEY (opaque, Phase 2 will validate)"
                );
                Ok(Section::Vkey(body.to_vec()))
            }
            SECTION_INTERFACE => {
                let iface = parse_interface(body, abs_offset)?;
                Ok(Section::Interface(iface))
            }
            SECTION_R1CS_HASH => {
                if body.len() != 32 {
                    trace!(
                        offset = abs_offset,
                        got = body.len(),
                        "rejecting: R1CS_HASH must be 32 B"
                    );
                    return Err(ZacError::BadAlignment {
                        offset: abs_offset,
                        reason: "R1CS_HASH body must be exactly 32 bytes",
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(body);
                trace!(offset = abs_offset, hash = %hex::encode(h), "parsed R1CS_HASH");
                Ok(Section::R1csHash(h))
            }
            SECTION_META_CBOR => {
                if body.len() > 64 * 1024 {
                    trace!(
                        offset = abs_offset,
                        size = body.len(),
                        "rejecting: META_CBOR > 64 KiB"
                    );
                    return Err(ZacError::BadAlignment {
                        offset: abs_offset,
                        reason: "META_CBOR body exceeds 64 KiB",
                    });
                }
                trace!(
                    offset = abs_offset,
                    size = body.len(),
                    "parsed META_CBOR (opaque)"
                );
                Ok(Section::MetaCbor(body.to_vec()))
            }
            v if (0x80..=0xFE).contains(&v) => {
                trace!(
                    offset = abs_offset,
                    tag = v,
                    size = body.len(),
                    "parsed vendor section"
                );
                Ok(Section::Vendor {
                    tag: v,
                    body: body.to_vec(),
                })
            }
            _ => Err(ZacError::ForbiddenSectionType {
                entry_index,
                section_type,
            }),
        }
    }
}

fn parse_interface(body: &[u8], abs_offset: usize) -> ZacResult<InterfaceSection> {
    if body.len() < 4 {
        return Err(ZacError::Truncated {
            offset: abs_offset,
            need: 4,
            have: body.len(),
        });
    }
    let public_input_count = LittleEndian::read_u32(&body[0..4]);
    trace!(
        offset = abs_offset,
        field = "public_input_count",
        value = public_input_count,
        "parsed INTERFACE header"
    );

    let mut names = Vec::with_capacity(public_input_count as usize);
    let mut cursor = 4usize;
    for i in 0..public_input_count {
        let abs = abs_offset + cursor;
        if cursor + 2 > body.len() {
            return Err(ZacError::Truncated {
                offset: abs,
                need: 2,
                have: body.len().saturating_sub(cursor),
            });
        }
        let name_len = LittleEndian::read_u16(&body[cursor..cursor + 2]) as usize;
        cursor += 2;
        if cursor + name_len > body.len() {
            return Err(ZacError::Truncated {
                offset: abs_offset + cursor,
                need: name_len,
                have: body.len().saturating_sub(cursor),
            });
        }
        let name_bytes = &body[cursor..cursor + name_len];
        if name_bytes.contains(&0) {
            trace!(
                offset = abs_offset + cursor,
                "rejecting: INTERFACE name contains NUL"
            );
            return Err(ZacError::BadFlags {
                offset: abs_offset + cursor,
                field: "interface.name",
                value: 0,
            });
        }
        let name = std::str::from_utf8(name_bytes).map_err(|_| ZacError::BadFlags {
            offset: abs_offset + cursor,
            field: "interface.name(utf8)",
            value: 0,
        })?;
        trace!(
            offset = abs_offset + cursor,
            entry = i,
            name = name,
            len = name_len,
            "parsed INTERFACE name"
        );
        names.push(name.to_string());
        cursor += name_len;
    }
    if cursor != body.len() {
        // Trailing bytes that aren't padding-of-section are a structural error.
        trace!(
            extra = body.len() - cursor,
            "rejecting: INTERFACE body has trailing bytes"
        );
        return Err(ZacError::BadAlignment {
            offset: abs_offset + cursor,
            reason: "INTERFACE body has trailing bytes after declared names",
        });
    }
    Ok(InterfaceSection {
        public_input_count,
        names,
    })
}
