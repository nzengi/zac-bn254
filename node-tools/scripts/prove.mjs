// snarkjs prover helper, invoked by zac::prover::prove as a subprocess.
//
// Usage: node prove.mjs <zkey> <wtns> <proof.json> <public.json>

import { promises as fs } from "node:fs";
import * as snarkjs from "snarkjs";

const [, , zkey, wtns, proofOut, publicOut] = process.argv;
if (!zkey || !wtns || !proofOut || !publicOut) {
    console.error("usage: node prove.mjs <zkey> <wtns> <proof.json> <public.json>");
    process.exit(2);
}

const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns);
await fs.writeFile(proofOut, JSON.stringify(proof, null, 2));
await fs.writeFile(publicOut, JSON.stringify(publicSignals, null, 2));
process.exit(0);
