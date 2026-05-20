//! `.zacp` parsing and encoding (SPEC §4).
//!
//! Phase 1 keeps the 128-byte proof block as an opaque `[u8; 128]` and each
//! public input as a raw 32-byte chunk. Phase 2 will reject non-canonical
//! Fr scalars (E012) and run subgroup checks on the proof's group elements.

use byteorder::{ByteOrder, LittleEndian};
use tracing::{instrument, trace};

use crate::error::{ZacError, ZacResult};

/// Magic for `.zacp` files.
pub const MAGIC_ZACP: &[u8; 4] = b"ZAP1";
/// Size of the proof block in bytes (32 + 64 + 32).
pub const PROOF_SIZE: usize = 128;
/// Fixed prefix size before public inputs (header + proof).
pub const PROOF_PREFIX_SIZE: usize = 0xD0;
/// Maximum allowed public-input count.
pub const MAX_PUBLIC_INPUTS: usize = 4096;

/// Parsed `.zacp` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofHeader {
    /// Major version.
    pub version_major: u8,
    /// Minor version.
    pub version_minor: u8,
    /// Patch version.
    pub version_patch: u8,
    /// Flags. MUST be 0 in v1.0.
    pub flags: u8,
    /// Number of public inputs (0..=4096).
    pub public_input_count: u32,
    /// BLAKE3 hash of the bound `.zac` (SPEC §6).
    pub zac_file_hash: [u8; 32],
    /// BLAKE3 fingerprint of the VKEY body (SPEC §6).
    pub vk_fingerprint: [u8; 32],
}

/// Fully-parsed `.zacp` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZacProofFile {
    /// Header (SPEC §4.1).
    pub header: ProofHeader,
    /// 128-byte proof block (SPEC §4.2). Crypto-validated in Phase 2.
    pub proof: [u8; PROOF_SIZE],
    /// Public inputs as raw 32-byte LE chunks. Phase 2 enforces Fr canonical.
    pub public_inputs: Vec<[u8; 32]>,
}

impl ZacProofFile {
    /// Parse a `.zacp` byte stream.
    ///
    /// # Example
    ///
    /// ```
    /// use zac::ZacProofFile;
    ///
    /// let bytes = include_bytes!("../tests/fixtures/multiplier.zacp");
    /// let zacp = ZacProofFile::parse(bytes)?;
    /// assert_eq!(zacp.header.public_input_count, 1);
    /// assert_eq!(zacp.public_inputs.len(), 1);
    /// # Ok::<(), zac::ZacError>(())
    /// ```
    #[instrument(level = "trace", skip(bytes), fields(len = bytes.len()))]
    pub fn parse(bytes: &[u8]) -> ZacResult<Self> {
        trace!("parse zacp: begin");
        if bytes.len() < PROOF_PREFIX_SIZE {
            return Err(ZacError::Truncated {
                offset: 0,
                need: PROOF_PREFIX_SIZE,
                have: bytes.len(),
            });
        }
        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if &magic != MAGIC_ZACP {
            trace!(offset = 0, got = ?magic, "rejecting: bad ZAP1 magic");
            return Err(ZacError::BadMagic {
                offset: 0,
                expected: "ZAP1",
                got: magic,
            });
        }
        trace!(offset = 0, field = "magic", value = ?magic, "parsed");

        let major = bytes[4];
        let minor = bytes[5];
        let patch = bytes[6];
        let flags = bytes[7];
        if major != 1 {
            return Err(ZacError::UnsupportedVersion {
                offset: 4,
                major,
                minor,
                patch,
            });
        }
        if flags != 0 {
            return Err(ZacError::BadFlags {
                offset: 7,
                field: "flags",
                value: flags as u64,
            });
        }
        trace!(
            offset = 4,
            version = format!("{major}.{minor}.{patch}"),
            "parsed"
        );

        let public_input_count = LittleEndian::read_u32(&bytes[8..12]);
        if public_input_count as usize > MAX_PUBLIC_INPUTS {
            return Err(ZacError::PublicInputCountMismatch {
                offset: 8,
                declared: public_input_count as u64,
                expected: MAX_PUBLIC_INPUTS as u64,
            });
        }
        trace!(
            offset = 8,
            field = "public_input_count",
            value = public_input_count,
            "parsed"
        );

        let reserved = LittleEndian::read_u32(&bytes[12..16]);
        if reserved != 0 {
            return Err(ZacError::BadFlags {
                offset: 12,
                field: "_reserved",
                value: reserved as u64,
            });
        }
        trace!(offset = 12, field = "_reserved", value = 0, "parsed");

        let mut zac_file_hash = [0u8; 32];
        zac_file_hash.copy_from_slice(&bytes[16..48]);
        trace!(offset = 16, hash = %hex::encode(zac_file_hash), "parsed zac_file_hash");

        let mut vk_fingerprint = [0u8; 32];
        vk_fingerprint.copy_from_slice(&bytes[48..80]);
        trace!(offset = 48, hash = %hex::encode(vk_fingerprint), "parsed vk_fingerprint");

        let mut proof = [0u8; PROOF_SIZE];
        proof.copy_from_slice(&bytes[80..80 + PROOF_SIZE]);
        trace!(
            offset = 80,
            size = PROOF_SIZE,
            "parsed proof block (Phase 2 validates)"
        );

        // public inputs
        let expected_len = PROOF_PREFIX_SIZE + 32 * public_input_count as usize;
        if bytes.len() != expected_len {
            trace!(
                actual = bytes.len(),
                expected = expected_len,
                "rejecting: zacp size != 0xD0 + 32*N"
            );
            return Err(ZacError::Truncated {
                offset: PROOF_PREFIX_SIZE,
                need: expected_len - PROOF_PREFIX_SIZE.min(bytes.len()),
                have: bytes.len().saturating_sub(PROOF_PREFIX_SIZE),
            });
        }
        let mut public_inputs = Vec::with_capacity(public_input_count as usize);
        for i in 0..public_input_count as usize {
            let off = PROOF_PREFIX_SIZE + i * 32;
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes[off..off + 32]);
            trace!(offset = off, input = i, value = %hex::encode(buf), "parsed Fr (opaque)");
            public_inputs.push(buf);
        }

        Ok(ZacProofFile {
            header: ProofHeader {
                version_major: major,
                version_minor: minor,
                version_patch: patch,
                flags,
                public_input_count,
                zac_file_hash,
                vk_fingerprint,
            },
            proof,
            public_inputs,
        })
    }

    /// Encode an in-memory `ZacProofFile` to a fresh byte vector. The
    /// `public_input_count` field is taken from `self.public_inputs.len()`
    /// so the count always matches reality.
    pub fn encode(&self) -> Vec<u8> {
        let n = self.public_inputs.len();
        let mut out = vec![0u8; PROOF_PREFIX_SIZE + 32 * n];
        out[0..4].copy_from_slice(MAGIC_ZACP);
        out[4] = self.header.version_major;
        out[5] = self.header.version_minor;
        out[6] = self.header.version_patch;
        out[7] = self.header.flags;
        LittleEndian::write_u32(&mut out[8..12], n as u32);
        // 12..16 reserved zero
        out[16..48].copy_from_slice(&self.header.zac_file_hash);
        out[48..80].copy_from_slice(&self.header.vk_fingerprint);
        out[80..80 + PROOF_SIZE].copy_from_slice(&self.proof);
        for (i, pi) in self.public_inputs.iter().enumerate() {
            let off = PROOF_PREFIX_SIZE + i * 32;
            out[off..off + 32].copy_from_slice(pi);
        }
        out
    }
}
