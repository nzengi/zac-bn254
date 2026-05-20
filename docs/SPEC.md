# ZAC Container Format — Specification v1.0

Status: Stable v1.0.0. Curve: BN254 (alt_bn128). System: Groth16.
Extensions: `.zac` (verifier setup), `.zacp` (proof).

## 1. Overview and Design Principles

ZAC is a binary container for Groth16/BN254 artifacts. `.zac` carries
the verifying key (VKEY), public-input interface, R1CS digest, and
optional metadata; `.zacp` carries a tight proof bundle bound to a
`.zac`. Principles: fail fast (magic, version, index, CRC32 before EC
math); no JSON on the verifier hot path (fixed-width LE or arkworks-
canonical group bytes; metadata is opt-in deterministic CBOR per RFC
8949 §4.2); cryptographic binding mandatory in the header, not META;
single curve and proof system in v1.0; snarkjs wire-compatible —
implementations MUST consume snarkjs `.zkey` (group-1) and `.wtns` and
emit proofs verifiable by snarkjs `groth16.verify`. This SPEC documents
only ZAC's own format. Wire authority: `ark-bn254 0.4`, `ark-groth16
0.4` canonical compressed.

## 2. Notation

RFC 2119 keywords apply. Multi-byte integers are little-endian.
`BLAKE3(domain || data)` is the 32-byte BLAKE3 hash; domain tags are
NUL-terminated ASCII (the trailing `\0` is hashed). Byte ranges `[a, b)`
are half-open.

## 3. `.zac` Binary Layout

A `.zac` is: 32 B header, 16 B-per-entry section index, section bodies
(8 B aligned, zero-padded), 40 B trailer.

### 3.1 Header

```
off  sz  field          value
0x00  4  magic          "ZAC1" (5A 41 43 31)
0x04  1  version_major  0x01
0x05  1  version_minor  0x00
0x06  1  version_patch  0x00
0x07  1  flags          0x00  (non-zero MUST reject; E003)
0x08  2  section_count  u16, 1..=16
0x0A  2  _reserved      0
0x0C  4  index_offset   u32, MUST equal 0x20
0x10  4  body_offset    u32, first section body
0x14  4  body_size      u32, total bodies + padding
0x18  8  _reserved2     zero
```

Reserved bytes MUST be zero. Header size is exactly 32 B.

### 3.2 Section Index

```
off  sz  field   notes
0x00  1  type    §5
0x01  1  flags   0x00 in v1.0
0x02  2  _pad    0
0x04  4  offset  u32, absolute
0x08  4  size    u32, body length
0x0C  4  crc32   u32, IEEE CRC-32 of body
```

Invariants (verifier MUST enforce): (1) `section_count <= 16`; (2) each
`type` appears at most once; (3) `type` ∉ {`0x00`, `0xFF`}; (4) entries
sorted by `offset`, strictly increasing; (5) `offset[i] + size[i] <=
offset[i+1]` (no overlap); (6) `offset[i]` is a multiple of 8, padding
bytes zero; (7) `offset[0] == body_offset`; (8) last section ends at
`body_offset + body_size`.

### 3.3 Section Bodies

Defined per type in §5.

### 3.4 Trailer

```
off  sz  field          notes
0x00  4  trailer_magic  "ZACT"
0x04  4  _reserved      0
0x08  32 file_hash      BLAKE3, §6
```

MUST be the final 40 B of the file.

## 4. `.zacp` Binary Layout

Flat, fixed-prefix. No section index, no CBOR.

### 4.1 Header

```
off   sz  field               value
0x00   4  magic               "ZAP1"
0x04   1  version_major       0x01
0x05   1  version_minor       0x00
0x06   1  version_patch       0x00
0x07   1  flags               0x00 (non-zero MUST reject)
0x08   4  public_input_count  u32, 0..=4096
0x0C   4  _reserved           0
0x10  32  zac_file_hash       BLAKE3 of bound .zac, §6
0x30  32  vk_fingerprint      BLAKE3 of VKEY body, §6
```

### 4.2 Proof Block (128 B, arkworks 0.4 canonical compressed)

```
off   sz  field
0x50  32  pi_a  (G1)
0x70  64  pi_b  (G2)
0xB0  32  pi_c  (G1)
```

### 4.3 Public Inputs

From offset `0xD0`: `public_input_count` × 32 B Fr LE canonical (§8).
File size MUST equal `0xD0 + 32 * public_input_count`. No trailer;
binding is via header fields.

## 5. Section Types

| Tag          | Name        | Req | Body                         |
|--------------|-------------|-----|------------------------------|
| `0x00`       | forbidden   | —   | MUST reject (E007)           |
| `0x01`       | `VKEY`      | M   | arkworks compressed vk       |
| `0x02`       | `INTERFACE` | M   | typed binary, §5.2           |
| `0x03`       | `R1CS_HASH` | M   | 32 B BLAKE3                  |
| `0x04`       | `META_CBOR` | O   | deterministic CBOR, ≤ 64 KiB |
| `0x05..0x7F` | reserved    | —   | MUST reject if present       |
| `0x80..0xFE` | vendor      | O   | opaque; unknown skipped      |
| `0xFF`       | forbidden   | —   | MUST reject (E007)           |

The three sections marked `Req: M` (`VKEY`, `INTERFACE`, `R1CS_HASH`) are
mandatory. If any of them is absent from the index, parsers MUST reject
with E016 (`MissingMandatorySection`) naming the first missing type in
the order `VKEY → INTERFACE → R1CS_HASH`.

**VKEY (0x01).** `ark-groth16 0.4` canonical compressed vk, verbatim.
Subgroup membership MUST be checked on every group element at parse.

**INTERFACE (0x02).**
```
off  sz   field
0x00  4    public_input_count  u32 (= VKEY IC length - 1)
0x04  var  names[]             u16 length + UTF-8 bytes, per entry
```
Names: valid UTF-8, no `0x00`, SHOULD ≤ 64 B. Name count MUST equal
`public_input_count`.

**R1CS_HASH (0x03).** 32 B `BLAKE3("zac1.r1cs.v1\0" || r1cs_bytes)`,
where `r1cs_bytes` is the canonical iden3 R1CS binary.

**META_CBOR (0x04).** OPTIONAL single deterministic CBOR item (RFC 8949
§4.2), ≤ 64 KiB. Verifiers MUST NOT need META; producers MUST NOT place
verifier-relevant fields here.

**Vendor (0x80..0xFE).** Opaque. Unknown vendor sections MUST be skipped
silently (CRC32 still validated) and MUST NOT alter verification.

## 6. Cryptographic Binding

All hashes are 32 B BLAKE3 with mandatory domain separation; the
trailing NUL of each tag is part of the hash input.

```
file_hash      = BLAKE3("zac1.file.v1\0" || version_bytes || body_bytes)
vk_fingerprint = BLAKE3("zac1.vkey.v1\0" || vkey_bytes)
r1cs_hash      = BLAKE3("zac1.r1cs.v1\0" || r1cs_bytes)
```

`version_bytes` = `[0x04, 0x08)` of the `.zac`. `body_bytes` = file from
`0x20` up to (excluding) the trailer (index + all bodies + padding).
`vkey_bytes` = body of section `0x01`, verbatim. `r1cs_bytes` = the
canonical iden3 R1CS binary.

A `.zacp` is bound to a `.zac` iff (1) `zac_file_hash ==
trailer.file_hash`, (2) `vk_fingerprint == BLAKE3("zac1.vkey.v1\0" ||
VKEY.body)`, and (3) `public_input_count ==
INTERFACE.public_input_count`. Mismatches yield E014 or E013; verifiers
MUST NOT proceed to pairing.

## 7. Group Element Encoding (G1, G2)

`ark-bn254 0.4` canonical compressed. G1 (32 B): LE affine x-coordinate;
the two flag bits live in the most-significant byte of the LE encoding
(byte at offset 31), matching `ark-serialize 0.4` `SWFlags`:
**bit 6 = `infinity_flag`, bit 7 = `y_is_negative`** (set when `y >
q - y`, i.e. the lexicographically larger of the two roots). If
`infinity_flag` is set, `y_is_negative` and every other bit, plus all
coordinate bytes, MUST be zero. G2 (64 B): Fq2 x-coordinate `c0 || c1`
(32 B each, LE); the same flag scheme applies to the high byte of `c1`
(offset 63). Setting both flag bits in the same byte is a forbidden
combination and MUST be rejected as E010. Verifiers MUST reject:
non-canonical representations whose integer ≥ Fq modulus (E010);
off-curve points (E010); points outside the prime-order subgroup (E011);
inconsistent infinity flag (E010).

## 8. Field Element Encoding (Fr Public Inputs)

Each public input is 32 B LE in `[0, r)` where `r =
21888242871839275222246405745257275088548364400416034343698204186575808495617`.
Values ≥ `r` MUST be rejected (E012). `MAX_PUBLIC_INPUTS = 4096`; excess
MUST be rejected (E013).

## 9. snarkjs Interop (Informative)

Non-normative. `.zkey` Groth16 group-1: extract the vk segment and
re-serialize via `ark-groth16 0.4` canonical compressed bytes to
populate VKEY. The R1CS used to build `.zkey` MUST be hashed identically
for `R1CS_HASH`. `.wtns` is a proving input only and does not appear in
any ZAC artifact. `.zacp` proofs verify under snarkjs `groth16.verify`
after decompressing `pi_a/pi_b/pi_c` and presenting public inputs as
decimal Fr values. No normative requirements bind snarkjs.

## 10. Error Code Registry

| Code | Name                     | Trigger                                    |
|------|--------------------------|--------------------------------------------|
| E001 | BadMagic                 | First 4 B not `ZAC1` / `ZAP1`              |
| E002 | UnsupportedVersion       | `version_major` ≠ 0x01                     |
| E003 | BadFlags                 | `flags` ≠ 0 or reserved bytes non-zero     |
| E004 | BadAlignment             | Offset not 8-aligned or non-zero padding   |
| E005 | SectionOverlap           | Index entries overlap or not monotonic     |
| E006 | DuplicateSectionType     | Same `type` appears more than once         |
| E007 | ForbiddenSectionType     | `0x00`, `0xFF`, or reserved `0x05..0x7F`   |
| E008 | BadCrc32                 | Section CRC32 mismatch                     |
| E009 | BadFileHash              | Trailer `file_hash` ≠ recomputed BLAKE3    |
| E010 | NonCanonicalPoint        | Group element non-canonical or off-curve   |
| E011 | SubgroupCheckFailed      | Point not in prime-order subgroup          |
| E012 | NonCanonicalFr           | Fr scalar ≥ field modulus                  |
| E013 | PublicInputCountMismatch | `.zacp` count ≠ INTERFACE count, or > 4096 |
| E014 | VkFingerprintMismatch    | `.zacp.vk_fingerprint` ≠ BLAKE3(VKEY)      |
| E015 | TruncatedInput           | Read past EOF or size exceeds file         |
| E016 | MissingMandatorySection  | A `Req: M` section in §5 is not in index   |
| E017 | ProofRejected            | Proof structurally valid but the Groth16 pairing equation does not hold |

Vendors MAY emit `V***` codes but MUST NOT redefine `E001..E017`.

## 11. Versioning Policy

Patch (`1.0.x`): editorial only, no wire change. Minor (`1.x.0`):
backward-compatible additions only — new vendor/reserved section types,
new META keys, new error codes ≥ `E100`; v1.0 verifiers MUST keep
parsing v1.x files. Major (`x.0.0`): any wire change bumps
`version_major` and the magic suffix digit (`ZAC2`/`ZAP2`); v1.x
verifiers MUST reject with E002. v1.0 verifiers MUST reject any non-zero
`flags`; minors that define flag bits MUST gate semantics on
`version_minor`.

## 12. Worked Example: Minimal `.zac`

Three sections — VKEY (length `Lv`), INTERFACE (1 input `"out"`),
R1CS_HASH. `Cv/Ci/Cr` are CRC32 placeholders.

```
0x0000  Header (32 B)
  "ZAC1" | 01 00 00 00 | 03 00 | 00 00
  20 00 00 00 | 60 00 00 00 | XX XX XX XX | 00*8

0x0020  Index (3 * 16 B)
  01 00 00 00  60 00 00 00  Lv Lv Lv Lv  Cv Cv Cv Cv  ; VKEY
  02 00 00 00  Ov Ov Ov Ov  09 00 00 00  Ci Ci Ci Ci  ; INTERFACE
  03 00 00 00  Oi Oi Oi Oi  20 00 00 00  Cr Cr Cr Cr  ; R1CS_HASH
0x0050  pad to body_offset

0x0060  VKEY body (Lv B), zero-pad to 8 B
Ov      INTERFACE body (9 B): 01 00 00 00 | 03 00 "out" ; zero-pad
Oi      R1CS_HASH body (32 B BLAKE3); zero-pad

end-40  Trailer: "ZACT" | 00 00 00 00 | 32 B BLAKE3 file_hash
```

Verifier procedure: (1) validate header; (2) walk index, enforcing
alignment, uniqueness, monotonicity, non-overlap; (3) CRC32 each
section; (4) recompute and compare `file_hash`; (5) parse VKEY with
subgroup checks; (6) read INTERFACE; (7) compare `R1CS_HASH`.

End of ZAC SPEC v1.0.
