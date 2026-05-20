// Phase 3 Step 4 — bidirectional cross-verify between ZAC and snarkjs.
//
// Direction A: snarkjs → ZAC (handled by the Rust example
//   `cargo run --example verify_snarkjs_proof`, spawned via subprocess).
// Direction B: ZAC → snarkjs (this script): read fixtures/multiplier.zacp,
//   decompress the ark-bn254 proof, format as snarkjs JSON, run
//   snarkjs.groth16.verify(vKey, publicSignals, proof).
//
// Both directions MUST print `true`. If either is `false`, exit non-zero.

import { promises as fs } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..", "..");
const FIX = path.join(ROOT, "fixtures");

// -----------------------------------------------------------------------------
// Direction A — spawn the Rust verifier for the snarkjs reference proof.
// -----------------------------------------------------------------------------
async function directionA() {
    console.log("[A] snarkjs proof → ZAC verifier");
    return new Promise((resolve, reject) => {
        const child = spawn(
            "cargo",
            ["run", "--quiet", "--example", "verify_snarkjs_proof"],
            { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, RUST_LOG: "warn" } },
        );
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (b) => (stdout += b.toString()));
        child.stderr.on("data", (b) => (stderr += b.toString()));
        child.on("close", (code) => {
            const ok = code === 0 && stdout.includes("[OK] snarkjs proof verified by ZAC");
            console.log("  stdout:");
            for (const line of stdout.split("\n")) {
                if (line.trim()) console.log("    " + line);
            }
            if (!ok && stderr.trim()) {
                console.log("  stderr:");
                for (const line of stderr.split("\n")) {
                    if (line.trim()) console.log("    " + line);
                }
            }
            console.log(`[ZAC] verifying snarkjs-produced proof: ${ok}`);
            ok ? resolve() : reject(new Error("direction A failed"));
        });
    });
}

// -----------------------------------------------------------------------------
// Direction B — load fixtures/multiplier.zacp and feed it to snarkjs.verify.
// -----------------------------------------------------------------------------

function leBytesToBigInt(bytes) {
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
        n = (n << 8n) | BigInt(bytes[i]);
    }
    return n;
}

const BN254_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

function modInv(a, m) {
    let [old_r, r] = [a % m, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    if (old_r !== 1n) throw new Error("not invertible");
    return ((old_s % m) + m) % m;
}

// Decompress an arkworks canonical compressed G1 (32 bytes LE, high-byte
// flags per ark-ec-0.4.2 SWFlags: bit 6 = infinity, bit 7 = YIsNegative
// (1 = y > -y in lex order, i.e. negative branch).
function decompressG1(bytes) {
    if (bytes.length !== 32) throw new Error("G1: bad length");
    const buf = new Uint8Array(bytes);
    const flagHigh = buf[31];
    const isInf = (flagHigh & 0x40) !== 0;
    const yIsNegative = (flagHigh & 0x80) !== 0;
    buf[31] = flagHigh & 0x3f;
    const x = leBytesToBigInt(buf);
    if (isInf) {
        return ["0", "0", "0"];
    }
    if (x >= BN254_Q) throw new Error("G1: x >= q");
    // y^2 = x^3 + 3 (BN254 b = 3)
    const x3 = (x * x * x) % BN254_Q;
    const rhs = (x3 + 3n) % BN254_Q;
    let y = tonelliShanks(rhs, BN254_Q);
    // arkworks SWFlags::from_y_coordinate: y <= -y → YIsPositive (bit7=0)
    // i.e. encoder sets bit 7 iff (computed y > q/2). Decoder picks the
    // root such that this relation holds.
    const negY = (BN254_Q - y) % BN254_Q;
    // Pick the y that satisfies the YIsNegative bit.
    const candYIsNegative = y > negY;
    if (candYIsNegative !== yIsNegative) {
        y = negY;
    }
    return [x.toString(), y.toString(), "1"];
}

// Decompress an arkworks canonical compressed G2 (64 bytes: x = c0 || c1 LE,
// flags in high byte of c1 — same SWFlags convention as G1).
function decompressG2(bytes) {
    if (bytes.length !== 64) throw new Error("G2: bad length");
    const c0 = new Uint8Array(bytes.slice(0, 32));
    const c1 = new Uint8Array(bytes.slice(32, 64));
    const flagHigh = c1[31];
    const isInf = (flagHigh & 0x40) !== 0;
    const yIsNegative = (flagHigh & 0x80) !== 0;
    c1[31] = flagHigh & 0x3f;
    if (isInf) {
        return [
            ["0", "0"],
            ["0", "0"],
            ["0", "0"],
        ];
    }
    const x0 = leBytesToBigInt(c0);
    const x1 = leBytesToBigInt(c1);
    // y² = x³ + 3/(9+u) ;  for BN254, b' = (Fq2(3) * (Fq2(9, 1))^(-1))
    // We need: rhs = x^3 + b'  ∈ Fq2
    const xCube = fq2Mul([x0, x1], fq2Mul([x0, x1], [x0, x1]));
    const bPrime = fq2BPrime();
    const rhs = fq2Add(xCube, bPrime);
    let y = fq2Sqrt(rhs);
    // arkworks SWFlags::from_y_coordinate uses lex comparison y <= -y → positive.
    // For Fq2, Field::PartialOrd is lex on limbs (c1 then c0). We replicate.
    const negY = fq2Neg(y);
    const yIsNegativeNow = fq2LexGreater(y, negY);
    if (yIsNegativeNow !== yIsNegative) {
        y = negY;
    }
    return [
        [x0.toString(), x1.toString()],
        [y[0].toString(), y[1].toString()],
        ["1", "0"],
    ];
}

function fq2Add([a0, a1], [b0, b1]) {
    return [(a0 + b0) % BN254_Q, (a1 + b1) % BN254_Q];
}
function fq2Sub([a0, a1], [b0, b1]) {
    return [(a0 - b0 + BN254_Q) % BN254_Q, (a1 - b1 + BN254_Q) % BN254_Q];
}
function fq2Mul([a0, a1], [b0, b1]) {
    const v0 = (a0 * b0) % BN254_Q;
    const v1 = (a1 * b1) % BN254_Q;
    // (a0+a1)(b0+b1) = v0 + v1 + (a0*b1 + a1*b0)
    const c1 = ((a0 + a1) % BN254_Q) * ((b0 + b1) % BN254_Q) % BN254_Q;
    const c0 = (v0 - v1 + BN254_Q) % BN254_Q;
    const cross = (c1 - v0 - v1 + 2n * BN254_Q) % BN254_Q;
    return [c0, cross];
}
function fq2Neg([a, b]) {
    return [(BN254_Q - a) % BN254_Q, (BN254_Q - b) % BN254_Q];
}
function fq2Inv([a, b]) {
    const denom = (a * a + b * b) % BN254_Q;
    const inv = modInv(denom, BN254_Q);
    return [(a * inv) % BN254_Q, (BN254_Q - (b * inv) % BN254_Q) % BN254_Q];
}
function fq2BPrime() {
    // b' = 3 / (9 + u) = 3 * (9+u)^-1  ∈ Fq2
    return fq2Mul([3n, 0n], fq2Inv([9n, 1n]));
}

// Lexicographic greater for Fq2 in arkworks ordering.
//
// arkworks 0.4 (`ark-ff/src/fields/models/quadratic_extension.rs`) implements
// `Ord` for `QuadExtField` as: compare `c1` first, then `c0` on tie.
// SWFlags::from_y_coordinate calls `y <= -y` which routes through this Ord,
// so the y-sign flag written by `serialize_compressed` for G2 is determined
// by the `(c1, c0)`-lex order of `y` vs `-y`. Match that convention here.
function fq2LexGreater([a0, a1], [b0, b1]) {
    if (a1 > b1) return true;
    if (a1 < b1) return false;
    return a0 > b0;
}

// Tonelli-Shanks for Fq (p ≡ 3 mod 4 → sqrt(a) = a^((p+1)/4))
function tonelliShanks(n, p) {
    // BN254 Fq has p ≡ 3 mod 4 → easy formula.
    const e = (p + 1n) / 4n;
    return modPow(n, e, p);
}
function modPow(a, e, m) {
    let r = 1n;
    a = a % m;
    while (e > 0n) {
        if (e & 1n) r = (r * a) % m;
        a = (a * a) % m;
        e >>= 1n;
    }
    return r;
}

// Fq2 square root for BN254. p² ≡ 9 (mod 16). Standard algorithm: if
// p ≡ 3 (mod 4), then sqrt(α) = α^((p+1)/4) when α is a residue in Fq, but in
// Fq2 we use: α^((p²+7)/16) candidate. For BN254 we use the following: let
// α = (a,b). Compute β = α^((p²-1)/4). If β = 1, sqrt = α^((p+1)/4) doesn't
// work directly; standard is Adleman-Manders-Miller. For simplicity we use
// the formula from libff:
//   1. compute w = α^((p-3)/4) in Fq
//   2. y0 = α * w
//   3. y1 = y0² / α
//   Hmm that's for Fq, not Fq2.
//
// Simpler: use the trick that if α = (a, b) ∈ Fq2 and we know sqrt exists,
// then sqrt = (s, t) where
//   N = a² + b²  in Fq (since |α|² = N for α = a + bu, u² = -1 ... in our
//      twist case u² = -1 too because Fq2 = Fq[u]/(u²+1) — verify).
// For BN254 Fq2 = Fq(u) with u² = -1 (i.e. non-residue is -1):
//   |α|² = (a + bu)(a − bu) = a² + b²
// So Norm(α) = a² + b². If √Norm(α) = s exists, then
//   y0 = √((a + s) / 2), y1 = b / (2*y0).
// Fall back to "search" if numerator is non-residue: pick the other sign.
function fq2Sqrt([a, b]) {
    const norm = (a * a + b * b) % BN254_Q;
    const s = sqrtFq(norm); // sqrt in Fq
    // try (a+s)/2 first
    const inv2 = modInv(2n, BN254_Q);
    let num = (a + s) % BN254_Q;
    let y0Sq = (num * inv2) % BN254_Q;
    let y0 = isResidue(y0Sq) ? sqrtFq(y0Sq) : null;
    if (y0 === null) {
        num = (a - s + BN254_Q) % BN254_Q;
        y0Sq = (num * inv2) % BN254_Q;
        y0 = sqrtFq(y0Sq);
    }
    if (y0 === 0n) {
        // α purely imaginary
        return [0n, sqrtFq(b)];
    }
    const y1 = (b * modInv((2n * y0) % BN254_Q, BN254_Q)) % BN254_Q;
    return [y0, y1];
}

function sqrtFq(n) {
    const e = (BN254_Q + 1n) / 4n;
    return modPow(n, e, BN254_Q);
}
function isResidue(n) {
    // Euler's criterion
    if (n === 0n) return true;
    const e = (BN254_Q - 1n) / 2n;
    return modPow(n, e, BN254_Q) === 1n;
}

async function directionB() {
    console.log("[B] ZAC proof → snarkjs verifier");
    const zacpBytes = await fs.readFile(path.join(FIX, "multiplier.zacp"));
    const zac = new Uint8Array(zacpBytes);
    // Header layout (SPEC §4):
    //   0x00 magic "ZAP1"
    //   0x08 public_input_count u32 LE
    //   0x10 zac_file_hash 32 B
    //   0x30 vk_fingerprint 32 B
    //   0x50 pi_a (32 G1 compressed)
    //   0x70 pi_b (64 G2 compressed)
    //   0xB0 pi_c (32 G1 compressed)
    //   0xD0 public_inputs[public_input_count] (32 B Fr LE each)
    if (zac[0] !== 0x5a || zac[1] !== 0x41 || zac[2] !== 0x50 || zac[3] !== 0x31) {
        throw new Error("not a ZAP1 file");
    }
    const pic = new DataView(zac.buffer, zac.byteOffset, zac.byteLength).getUint32(0x08, true);
    console.log(`  public_input_count = ${pic}`);

    const piA = decompressG1(zac.slice(0x50, 0x70));
    const piB = decompressG2(zac.slice(0x70, 0xb0));
    const piC = decompressG1(zac.slice(0xb0, 0xd0));
    const proof = { pi_a: piA, pi_b: piB, pi_c: piC, protocol: "groth16", curve: "bn128" };

    const publics = [];
    for (let i = 0; i < pic; i++) {
        const off = 0xd0 + i * 32;
        publics.push(leBytesToBigInt(zac.slice(off, off + 32)).toString());
    }
    console.log(`  decoded public inputs: [${publics.join(", ")}]`);

    const vKey = JSON.parse(await fs.readFile(path.join(FIX, "multiplier.vkey.json"), "utf8"));
    const ok = await snarkjs.groth16.verify(vKey, publics, proof);
    console.log(`[snarkjs] verifying ZAC-produced proof: ${ok}`);
    if (!ok) {
        throw new Error("direction B failed");
    }
}

await directionA();
await directionB();
console.log();
console.log("[OK] both directions verified");
process.exit(0);
