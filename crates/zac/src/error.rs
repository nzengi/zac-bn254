//! Error taxonomy for `zac` (SPEC §10).
//!
//! Errors are intentionally explicit about *where* they originate (offset,
//! section type, byte index) so a hex-dump + the error message is enough to
//! diagnose any failure without re-running with a debugger.
//!
//! Every variant maps 1:1 to one of the spec-defined codes E001..E017 via
//! [`ZacError::code`]. Variants are constructed by the parser modules and
//! flow back to the caller through [`ZacResult`].

use thiserror::Error;

/// Result alias used throughout `zac`.
pub type ZacResult<T> = Result<T, ZacError>;

/// Top-level error variants for `zac` operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ZacError {
    /// I/O error from the underlying reader/writer.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// E001: Container header magic bytes did not match `ZAC1` / `ZAP1`.
    #[error("E001 BadMagic at offset {offset}: expected {expected:?}, got {got:02x?}")]
    BadMagic {
        /// Offset where the magic was read (always 0 in v1.0).
        offset: usize,
        /// Magic the parser was looking for ("ZAC1" or "ZAP1").
        expected: &'static str,
        /// The four bytes actually found.
        got: [u8; 4],
    },

    /// E002: Container version is outside the supported range for this build.
    #[error("E002 UnsupportedVersion at offset {offset}: {major}.{minor}.{patch}")]
    UnsupportedVersion {
        /// Byte offset of the version_major field.
        offset: usize,
        /// Major version byte.
        major: u8,
        /// Minor version byte.
        minor: u8,
        /// Patch version byte.
        patch: u8,
    },

    /// E003: Non-zero `flags` byte, or non-zero reserved bytes.
    #[error("E003 BadFlags at offset {offset}: field={field}, value={value:#x}")]
    BadFlags {
        /// Byte offset of the offending field.
        offset: usize,
        /// Name of the field that was non-zero.
        field: &'static str,
        /// Observed value (cast to u64 for uniform formatting).
        value: u64,
    },

    /// E004: Section body offset not 8-aligned or non-zero padding observed.
    #[error("E004 BadAlignment at offset {offset}: {reason}")]
    BadAlignment {
        /// Offset of the misaligned field or non-zero padding byte.
        offset: usize,
        /// Human-readable cause.
        reason: &'static str,
    },

    /// E005: Section index overlap or non-monotonic ordering.
    #[error(
        "E005 SectionOverlap at index entry {entry_index}: this_end={this_end:#x}, next_offset={next_offset:#x}"
    )]
    SectionOverlap {
        /// Index entry (0-based) that triggered the violation.
        entry_index: usize,
        /// `offset[i] + size[i]`.
        this_end: u64,
        /// `offset[i+1]` (or `body_offset + body_size` for the last entry).
        next_offset: u64,
    },

    /// E006: Duplicate section type byte.
    #[error("E006 DuplicateSectionType at index entry {entry_index}: type={section_type:#04x}")]
    DuplicateSectionType {
        /// Index entry (0-based) where the duplicate appeared.
        entry_index: usize,
        /// The duplicated section type byte.
        section_type: u8,
    },

    /// E007: Forbidden or reserved section type (0x00, 0xFF, 0x05..=0x7F).
    #[error("E007 ForbiddenSectionType at index entry {entry_index}: type={section_type:#04x}")]
    ForbiddenSectionType {
        /// Index entry (0-based).
        entry_index: usize,
        /// The forbidden type byte.
        section_type: u8,
    },

    /// E008: Section CRC32 mismatch.
    #[error(
        "E008 BadCrc32 at index entry {entry_index} (type={section_type:#04x}): expected={expected:#010x}, got={got:#010x}"
    )]
    BadCrc32 {
        /// Index entry (0-based) whose body failed CRC.
        entry_index: usize,
        /// Section type byte.
        section_type: u8,
        /// CRC32 the index recorded.
        expected: u32,
        /// CRC32 recomputed over the body bytes.
        got: u32,
    },

    /// E009: Trailer `file_hash` did not match the recomputed BLAKE3 hash.
    #[error("E009 BadFileHash: trailer={trailer:02x?}, computed={computed:02x?}")]
    BadFileHash {
        /// `file_hash` field copied verbatim from the trailer.
        trailer: [u8; 32],
        /// Hash recomputed over `version_bytes || body_bytes`.
        computed: [u8; 32],
    },

    /// E010: Group element non-canonical or off-curve. (Phase 2.)
    #[error("E010 NonCanonicalPoint at offset {offset}: {reason}")]
    NonCanonicalPoint {
        /// Offset where the bad point was read.
        offset: usize,
        /// Cause.
        reason: &'static str,
    },

    /// E011: Group element not in the prime-order subgroup. (Phase 2.)
    #[error("E011 SubgroupCheckFailed at offset {offset}")]
    SubgroupCheckFailed {
        /// Offset where the bad point was read.
        offset: usize,
    },

    /// E012: Fr scalar ≥ field modulus. (Phase 2.)
    #[error("E012 NonCanonicalFr at offset {offset} (input index {input_index})")]
    NonCanonicalFr {
        /// Offset where the bad scalar was read.
        offset: usize,
        /// 0-based index into the public-input array.
        input_index: usize,
    },

    /// E013: Public-input count mismatch or > 4096.
    #[error(
        "E013 PublicInputCountMismatch at offset {offset}: declared={declared}, expected={expected}"
    )]
    PublicInputCountMismatch {
        /// Offset where the offending count was read.
        offset: usize,
        /// Count actually declared.
        declared: u64,
        /// Count the parser was expecting (`MAX_PUBLIC_INPUTS` or the INTERFACE
        /// count for `.zacp` binding checks). 0 when only the upper bound was
        /// violated and there is no per-`.zac` expectation yet.
        expected: u64,
    },

    /// E014: `.zacp.vk_fingerprint` did not match BLAKE3(VKEY body).
    #[error("E014 VkFingerprintMismatch")]
    VkFingerprintMismatch,

    /// E015: Read past EOF or declared size exceeds file.
    #[error("E015 TruncatedInput at offset {offset}: need {need} bytes, have {have}")]
    Truncated {
        /// Byte offset where the read attempt began.
        offset: usize,
        /// Bytes the format demands.
        need: usize,
        /// Bytes actually present.
        have: usize,
    },

    /// E016: A SPEC §5 mandatory section (VKEY, INTERFACE, or R1CS_HASH) is
    /// missing from the `.zac` index.
    #[error("E016 MissingMandatorySection: type={missing_type:#04x} ({name})")]
    MissingMandatorySection {
        /// Section type byte that should have been present.
        missing_type: u8,
        /// Human-readable section name (`"VKEY"`, `"INTERFACE"`, `"R1CS_HASH"`).
        name: &'static str,
    },

    /// E017: Proof was structurally valid (all parse + binding checks passed)
    /// but the Groth16 pairing equation does not hold — i.e. the prover did
    /// not actually know a satisfying witness, or the proof was tampered after
    /// fingerprint checks. Surfaced by [`crate::verify`].
    #[error("E017 ProofRejected: {reason}")]
    ProofRejected {
        /// Human-readable cause (pairing returned false, malformed VK length,
        /// or upstream arkworks error).
        reason: &'static str,
    },
}

impl ZacError {
    /// Returns the spec-level error code (`"E001".."E017"`) for this variant.
    ///
    /// Returns `"E000"` for the catch-all `Io` variant which has no spec
    /// counterpart.
    pub fn code(&self) -> &'static str {
        match self {
            ZacError::Io(_) => "E000",
            ZacError::BadMagic { .. } => "E001",
            ZacError::UnsupportedVersion { .. } => "E002",
            ZacError::BadFlags { .. } => "E003",
            ZacError::BadAlignment { .. } => "E004",
            ZacError::SectionOverlap { .. } => "E005",
            ZacError::DuplicateSectionType { .. } => "E006",
            ZacError::ForbiddenSectionType { .. } => "E007",
            ZacError::BadCrc32 { .. } => "E008",
            ZacError::BadFileHash { .. } => "E009",
            ZacError::NonCanonicalPoint { .. } => "E010",
            ZacError::SubgroupCheckFailed { .. } => "E011",
            ZacError::NonCanonicalFr { .. } => "E012",
            ZacError::PublicInputCountMismatch { .. } => "E013",
            ZacError::VkFingerprintMismatch => "E014",
            ZacError::Truncated { .. } => "E015",
            ZacError::MissingMandatorySection { .. } => "E016",
            ZacError::ProofRejected { .. } => "E017",
        }
    }

    /// Maps a spec error code (`"E001".."E016"`) back to a representative
    /// variant. Used only by example/debug code that wants to assert
    /// "the parser returned the right E### for this corrupted input".
    ///
    /// The returned variant has placeholder fields — only the discriminant
    /// (and therefore `code()`) is meaningful.
    pub fn from_e_code(code: &str) -> Option<ZacError> {
        Some(match code {
            "E001" => ZacError::BadMagic {
                offset: 0,
                expected: "ZAC1",
                got: [0; 4],
            },
            "E002" => ZacError::UnsupportedVersion {
                offset: 4,
                major: 0,
                minor: 0,
                patch: 0,
            },
            "E003" => ZacError::BadFlags {
                offset: 7,
                field: "flags",
                value: 0,
            },
            "E004" => ZacError::BadAlignment {
                offset: 0,
                reason: "placeholder",
            },
            "E005" => ZacError::SectionOverlap {
                entry_index: 0,
                this_end: 0,
                next_offset: 0,
            },
            "E006" => ZacError::DuplicateSectionType {
                entry_index: 0,
                section_type: 0,
            },
            "E007" => ZacError::ForbiddenSectionType {
                entry_index: 0,
                section_type: 0,
            },
            "E008" => ZacError::BadCrc32 {
                entry_index: 0,
                section_type: 0,
                expected: 0,
                got: 0,
            },
            "E009" => ZacError::BadFileHash {
                trailer: [0; 32],
                computed: [0; 32],
            },
            "E010" => ZacError::NonCanonicalPoint {
                offset: 0,
                reason: "placeholder",
            },
            "E011" => ZacError::SubgroupCheckFailed { offset: 0 },
            "E012" => ZacError::NonCanonicalFr {
                offset: 0,
                input_index: 0,
            },
            "E013" => ZacError::PublicInputCountMismatch {
                offset: 0,
                declared: 0,
                expected: 0,
            },
            "E014" => ZacError::VkFingerprintMismatch,
            "E015" => ZacError::Truncated {
                offset: 0,
                need: 0,
                have: 0,
            },
            "E016" => ZacError::MissingMandatorySection {
                missing_type: 0,
                name: "placeholder",
            },
            "E017" => ZacError::ProofRejected {
                reason: "placeholder",
            },
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_round_trips() {
        for c in [
            "E001", "E002", "E003", "E004", "E005", "E006", "E007", "E008", "E009", "E010", "E011",
            "E012", "E013", "E014", "E015", "E016", "E017",
        ] {
            let err = ZacError::from_e_code(c).expect("known code");
            assert_eq!(err.code(), c);
        }
        assert!(ZacError::from_e_code("E999").is_none());
    }
}
