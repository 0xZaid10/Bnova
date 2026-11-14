// Cross-check: our rules vs the real circuit, on random inputs.
// The circuit asserts that `decision` is correct, so it tells us the right answer.
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { evaluate, type GatekeeperInput } from "../src/decision";
import { buildCircuitInput, taskIdToField } from "../src/prover";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");
const wasm = path.join(__dirname, "../circuits/gatekeeper.wasm");

async function circuitAccepts(input: Record<string, string>): Promise<boolean> {
  try {
    await snarkjs.wtns.calculate(input, wasm, "/tmp/oracle.wtns");
    return true;
  } catch {
    return false;
  }
}

// small seeded PRNG so failures are reproducible
let s = 123456789;
const rnd = () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
const pick = <T,>(a: T[]) => a[Math.floor(rnd() * a.length)];
const hex = (n: number) => "0x" + n.toString(16).padStart(40, "0");

test("our decision always matches what the circuit accepts (2000 random cases)", async () => {
  let approves = 0;
  for (let i = 0; i < 2000; i++) {
    const minimum = Math.floor(rnd() * 3000);
    const balance = pick([minimum, minimum - 1, minimum + 1, Math.floor(rnd() * 5000)]);
    const expiry = 1000 + Math.floor(rnd() * 100);
    const current = pick([expiry - 1, expiry, expiry + 1, Math.floor(rnd() * 2000)]);
    const cap = Math.floor(rnd() * 2000);
    const amount = pick([cap, cap - 1, cap + 1, Math.floor(rnd() * 3000)]);
    const rec = Math.floor(rnd() * 5);
    const vk = Math.floor(rnd() * 3);
    const input: GatekeeperInput = {
      registered_vk: hex(vk),
      proof_vk: hex(pick([vk, vk, vk, vk + 1])),
      minimum: String(Math.max(0, minimum)),
      public_balance: String(Math.max(0, balance)),
      expiry_block: expiry,
      current_block: Math.max(0, current),
      recipient: hex(rec),
      condition_recipient: hex(pick([rec, rec, rec, rec + 1])),
      amount: String(Math.max(0, amount)),
      max_transfer: String(cap),
      proof_tx: "0x" + (i + 1).toString(16),
    };
    const v = evaluate(input, () => false);
    assert.ok(v.parsed, "parsed");
    const tid = taskIdToField("keccak", "t" + i);
    const ours = buildCircuitInput(v.parsed!, v.decision, tid, 5n);
    const flipped = buildCircuitInput(v.parsed!, v.decision === "APPROVE" ? "REJECT" : "APPROVE", tid, 5n);
    const okOurs = await circuitAccepts(ours);
    const okFlipped = await circuitAccepts(flipped);
    assert.ok(okOurs, `circuit refused our decision (case ${i}): ${JSON.stringify(input)}`);
    assert.ok(!okFlipped, `circuit would also accept the opposite (case ${i})`);
    if (v.decision === "APPROVE") approves++;
  }
  assert.ok(approves > 100 && approves < 1900, `mix of outcomes looks wrong: ${approves}`);
});
