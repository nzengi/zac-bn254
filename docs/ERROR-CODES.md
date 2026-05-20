# ZAC Error Code Registry

This document is the canonical enumeration of every spec-level error
code emitted by a conforming ZAC implementation. SPEC §10 is the
authoritative reference; this document is the longer-form companion that
binary-protocol architects, integrators, and SDK authors reach for when
they need the trigger condition, the file type that produces it, and the
parse stage at which it surfaces.

The Rust reference implementation maps each code 1:1 to a variant of
`zac::ZacError`. Other implementations are expected to surface the same
codes via whatever error mechanism their language provides; the codes
themselves are part of the wire-format contract.

## Code Index

| Code | Name                     | File             | Stage          | Severity |
|------|--------------------------|------------------|----------------|----------|
| E000 | Io                       | any              | any            | tool     |
| E001 | BadMagic                 | `.zac` / `.zacp` | header parse   | parse    |
| E002 | UnsupportedVersion       | `.zac` / `.zacp` | header parse   | parse    |
| E003 | BadFlags                 | `.zac` / `.zacp` | header parse   | parse    |
| E004 | BadAlignment             | `.zac`           | section index  | parse    |
| E005 | SectionOverlap           | `.zac`           | section index  | parse    |
| E006 | DuplicateSectionType     | `.zac`           | section index  | parse    |
| E007 | ForbiddenSectionType     | `.zac`           | section index  | parse    |
| E008 | BadCrc32                 | `.zac`           | section body   | parse    |
| E009 | BadFileHash              | `.zac`           | trailer        | binding  |
| E010 | NonCanonicalPoint        | `.zac` / `.zacp` | crypto decode  | crypto   |
| E011 | SubgroupCheckFailed      | `.zac` / `.zacp` | crypto decode  | crypto   |
| E012 | NonCanonicalFr           | `.zacp`          | public inputs  | crypto   |
| E013 | PublicInputCountMismatch | `.zacp`          | binding        | binding  |
| E014 | VkFingerprintMismatch    | `.zacp`          | binding        | binding  |
| E015 | TruncatedInput           | `.zac` / `.zacp` | any            | parse    |
| E016 | MissingMandatorySection  | `.zac`           | section index  | parse    |
| E017 | ProofRejected            | `.zacp`          | verify         | crypto   |
| E018 | IdentityNotAllowed       | `.zac` / `.zacp` | crypto decode  | crypto   |

**Severity classes** are advisory:

- **parse** — structural well-formedness; an unmutated artifact from a
  conforming producer should never emit these.
- **binding** — the proof and its container do not refer to each other
  (mismatched hashes / counts). A producer or transport bug.
- **crypto** — the bytes parsed, but the cryptographic invariant the
  format protects (canonical encoding, subgroup membership, pairing
  equation) fails. Treat as adversarial input until proven otherwise.
- **tool** — host I/O error; not the format's fault.

## Per-code detail

### E000 — Io (`std::io::Error` passthrough)

Surfaces when the host reader/writer fails (file truncated mid-read,
disk full, permission denied). The format itself is not implicated. The
Rust reference passes the underlying `std::io::Error` through verbatim
as `ZacError::Io(_)` so the caller can match on `io::ErrorKind`.

### E001 — BadMagic

First four bytes of a `.zac` are not `ZAC1` (0x5A 0x41 0x43 0x31), or the
first four bytes of a `.zacp` are not `ZAP1` (0x5A 0x41 0x50 0x31).

### E002 — UnsupportedVersion

`version_major` is not 0x01. v1 implementations refuse any artifact
whose major version exceeds their own (forward-compatibility is
explicitly opt-in via a future `ZAC2` / `ZAP2` magic, per §11).

### E003 — BadFlags

`flags` byte is non-zero, or any reserved byte (filling out to the
header size) is non-zero. The latter check defends against
forward-compatibility smuggling: a future minor version might assign
meaning to a currently-reserved bit, and a v1 reader must reject those
artifacts rather than silently ignoring the unknown bit.

### E004 — BadAlignment

A section body offset is not 8-aligned, or zero-padding bytes between
sections are non-zero.

### E005 — SectionOverlap

Two section index entries describe ranges that overlap (one ends after
the next starts), or the entries are not in monotonically increasing
offset order. The constraint enforces a single canonical layout.

### E006 — DuplicateSectionType

The same `type` byte appears more than once in the section index.

### E007 — ForbiddenSectionType

A reserved section type byte appears: `0x00`, `0xFF`, or any of
`0x05..0x7F` (reserved range; vendor extensions live in `0x80..0xFE`).

### E008 — BadCrc32

The CRC32 the index recorded for a section does not match the CRC32
recomputed over the section body bytes.

### E009 — BadFileHash

The 32-byte `file_hash` in the trailer of a `.zac` does not match the
BLAKE3 hash recomputed over `domain_tag || version_bytes || body_bytes`.
Domain tag is `zac1.file.v1\0`.

### E010 — NonCanonicalPoint

A G1 or G2 element was encoded badly. Concretely: the x-coordinate
integer is ≥ Fq modulus; the point is off-curve; the SW flag byte has
both `infinity_flag` and `y_is_negative` set (forbidden combination);
`infinity_flag` is set but coordinate bytes are non-zero.

### E011 — SubgroupCheckFailed

The point is on the curve but not in the prime-order subgroup. BN254
G1 has cofactor 1, so off-subgroup G1 is mathematically impossible — a
G1 hit on this code indicates a tooling bug. BN254 G2 has cofactor
≈ 2²⁵⁴, so off-subgroup G2 is constructible and is part of the forgery
corpus (see `examples/forgery_vectors.rs`, cases 2, 16, 17).

### E012 — NonCanonicalFr

A 32-byte LE Fr value in the `.zacp` public input array is ≥ `r`
(`r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`).

### E013 — PublicInputCountMismatch

The `public_input_count` field in the `.zacp` header does not match the
`public_input_count` in the bound `.zac`'s INTERFACE section, or the
count exceeds `MAX_PUBLIC_INPUTS = 4096`.

### E014 — VkFingerprintMismatch

The 32-byte `vk_fingerprint` in the `.zacp` header does not match
`BLAKE3("zac1.vkey.v1\0" || vkey_bytes)` for the bound `.zac`'s VKEY
section.

### E015 — TruncatedInput

A read demanded more bytes than the artifact supplies, or a declared
section size extends past the body region. **Implementations MUST map
input-length-exhaustion conditions to E015**, not E010 — the former is
"the bytes ran out"; the latter is "the bytes were complete but
malformed". v1.0.0 had a `classify_deser_err` mapping bug that
mis-categorized truncation as E010; fixed in v1.0.1.

### E016 — MissingMandatorySection

A section listed as `Req: M` in §5 (VKEY, INTERFACE, R1CS_HASH) is not
present in the section index.

### E017 — ProofRejected

The proof passed every structural and binding check but the Groth16
pairing equation `e(pi_a, pi_b) = e(α, β) · e(Σ IC, γ) · e(pi_c, δ)`
does not hold. The producer did not know a satisfying witness, the
proof was tampered after the binding fields were set, or the witness
disagrees with the asserted public inputs.

### E018 — IdentityNotAllowed (v1.0.1)

A group element at one of the seven positions forbidden by §7.1 was the
point at infinity:

- `pi_a, pi_b, pi_c` in the proof block
- `alpha_g1, beta_g2, gamma_g2, delta_g2` in the VKEY

Identity at any of these positions makes the Groth16 pairing equation
trivially satisfiable, so a verifier that does not pre-check would
accept a forged proof. Rejection is at decode time, before subgroup
membership.

Identity is **permitted** on `gamma_abc_g1[i]` (sparse-VKEY pattern,
§7.1) and an implementation MUST NOT raise E018 there.

## Vendor extensions

Implementations MAY define vendor-specific codes of the form `V***`
where `***` is a three-digit decimal. Vendor codes MUST NOT collide
with `E001..E018`, and SHOULD document their semantics in a sidecar
specification.

## Compatibility

This registry has been stable since v1.0.0 except for the addition of
E018 in v1.0.1 (a soundness-driven additive change, not a wire-format
change — same magic bytes, same versions, additional rejection
condition). Future additions follow the same pattern: a new code may
appear in a patch release if it tightens rejection without breaking the
wire format; code renumbering or removal is a major version bump.
