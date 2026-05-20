// Phase 3 — snarkjs-side fixture builder.
//
// Consumes fixtures/multiplier.r1cs + fixtures/multiplier.wtns produced by
// `cargo run --example build_fixtures` and emits:
//   * fixtures/multiplier.zkey         (Groth16 proving + verifying key)
//   * fixtures/multiplier.vkey.json    (snarkjs JSON view of the VK)
//   * fixtures/snarkjs_proof.json      (reference proof on x=3,y=11)
//   * fixtures/snarkjs_public.json     (public signals = ["33"])
//
// The powers-of-tau ceremony is run from scratch in-memory (8 constraints
// max — `2^3` ptau, more than enough for our 1-constraint circuit).

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..", "..");
const FIX = path.join(ROOT, "fixtures");

async function main() {
    const r1cs = path.join(FIX, "multiplier.r1cs");
    const wtns = path.join(FIX, "multiplier.wtns");
    for (const p of [r1cs, wtns]) {
        await fs.access(p).catch(() => {
            throw new Error(`missing ${p} — run \`cargo run --example build_fixtures\` first`);
        });
    }

    const ptau0 = path.join(FIX, "pot7_0000.ptau");
    const ptau1 = path.join(FIX, "pot7_0001.ptau");
    const ptauFinal = path.join(FIX, "pot7_final.ptau");
    const zkey = path.join(FIX, "multiplier.zkey");
    const vkeyJson = path.join(FIX, "multiplier.vkey.json");
    const proofJson = path.join(FIX, "snarkjs_proof.json");
    const publicJson = path.join(FIX, "snarkjs_public.json");

    console.log("[snarkjs] step 1/6: powersoftau new (BN128, 2^7 = 128 constraints)");
    const curve = await snarkjs.curves.getCurveFromName("bn128");
    await snarkjs.powersOfTau.newAccumulator(curve, 7, ptau0);

    console.log("[snarkjs] step 2/6: powersoftau contribute (deterministic entropy)");
    await snarkjs.powersOfTau.contribute(
        ptau0,
        ptau1,
        "zac-phase3-fixture",
        "0".repeat(64),
    );

    console.log("[snarkjs] step 3/6: powersoftau prepare phase 2");
    await snarkjs.powersOfTau.preparePhase2(ptau1, ptauFinal);

    console.log("[snarkjs] step 4/6: groth16 setup (r1cs + ptau → zkey)");
    await snarkjs.zKey.newZKey(r1cs, ptauFinal, zkey);

    console.log("[snarkjs] step 5/6: zkey export verificationkey");
    const vKey = await snarkjs.zKey.exportVerificationKey(zkey);
    await fs.writeFile(vkeyJson, JSON.stringify(vKey, null, 2));
    console.log(`  → wrote ${path.relative(ROOT, vkeyJson)}`);

    console.log("[snarkjs] step 6/6: groth16 prove (snarkjs self-baseline)");
    const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns);
    await fs.writeFile(proofJson, JSON.stringify(proof, null, 2));
    await fs.writeFile(publicJson, JSON.stringify(publicSignals, null, 2));
    console.log(`  → wrote ${path.relative(ROOT, proofJson)}`);
    console.log(`  → wrote ${path.relative(ROOT, publicJson)}`);

    console.log("[snarkjs] groth16.verify on its own proof:");
    const ok = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    console.log(`[snarkjs] groth16.verify: ${ok}`);
    if (!ok) {
        process.exit(1);
    }

    // Cleanup intermediates (keep .zkey + .vkey.json + proofs).
    for (const f of [ptau0, ptau1, ptauFinal]) {
        await fs.unlink(f).catch(() => {});
    }
}

main().catch((e) => {
    console.error("[snarkjs] FATAL:", e);
    process.exit(1);
}).then(() => {
    // snarkjs leaves worker threads alive; force exit so npm run completes.
    process.exit(0);
});
