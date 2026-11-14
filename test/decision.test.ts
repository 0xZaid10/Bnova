import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, type GatekeeperInput } from "../src/decision";

const base = (): GatekeeperInput => ({
  registered_vk: "0x7d3a000000000000000000000000000000000000000000000000000000000f291",
  proof_vk: "0x7d3a000000000000000000000000000000000000000000000000000000000f291",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 8430000,
  current_block: 8420000,
  recipient: "0xDe42000000000000000000000000000000009f01",
  condition_recipient: "0xDe42000000000000000000000000000000009f01",
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xa8000000000000000000000000000000000000000000000000000000000002c",
});
const none = () => false;
const run = (over: Partial<GatekeeperInput>, seen: (r: string) => boolean = none) =>
  evaluate({ ...base(), ...over }, seen);

test("valid condition is approved", () => {
  const v = run({});
  assert.equal(v.decision, "APPROVE");
  assert.equal(v.reason, "VALID_CONDITION");
});

test("each published trap is rejected with its code", () => {
  assert.equal(run({ proof_vk: "0xa4c1" }).reason, "VK_SUBSTITUTION");
  assert.equal(run({ public_balance: "999" }).reason, "THRESHOLD_MISMATCH");
  assert.equal(run({}, () => true).reason, "PROOF_REUSED");
  assert.equal(run({ current_block: 8430001 }).reason, "EXPIRED_CONDITION");
  assert.equal(run({ recipient: "0xDe42000000000000000000000000000000009f02" }).reason, "RECIPIENT_MISMATCH");
  assert.equal(run({ amount: "1001" }).reason, "AMOUNT_OVERFLOW");
});

test("boundaries match the circuit", () => {
  assert.equal(run({ public_balance: "1000" }).decision, "APPROVE"); // balance == minimum
  assert.equal(run({ amount: "1000" }).decision, "APPROVE"); // amount == cap
  assert.equal(run({ current_block: 8430000 }).decision, "REJECT"); // block == expiry
  assert.equal(run({ current_block: 8429999 }).decision, "APPROVE");
});

test("hex case and leading zeros do not cause false rejects", () => {
  const v = run({
    recipient: "0xDE42000000000000000000000000000000009F01",
    condition_recipient: "0xde42000000000000000000000000000000009f01",
  });
  assert.equal(v.decision, "APPROVE");
  const w = run({ registered_vk: "0x0007d3", proof_vk: "0x7d3" });
  assert.equal(w.decision, "APPROVE");
});

test("numbers can arrive as strings or numbers, decimal or hex", () => {
  assert.equal(run({ minimum: 1000, public_balance: 1460, amount: 500, max_transfer: 1000 }).decision, "APPROVE");
  assert.equal(run({ minimum: "0x3e8" }).decision, "APPROVE");
  // huge values are compared exactly, not as floats
  assert.equal(
    run({ public_balance: "99999999999999999999999999", minimum: "99999999999999999999999998" }).decision,
    "APPROVE",
  );
  assert.equal(
    run({ public_balance: "99999999999999999999999998", minimum: "99999999999999999999999999" }).reason,
    "THRESHOLD_MISMATCH",
  );
});

test("proof reference key ignores case and leading zeros", () => {
  const keys: string[] = [];
  run({ proof_tx: "0x00AbC" }, (r) => (keys.push(r), false));
  run({ proof_tx: "0xabc" }, (r) => (keys.push(r), false));
  assert.equal(keys[0], keys[1]);
});

test("anything malformed fails closed", () => {
  assert.equal(evaluate(undefined, none).decision, "REJECT");
  assert.equal(evaluate(null, none).decision, "REJECT");
  assert.equal(run({ minimum: "abc" }).reason, "INVALID_INPUT");
  assert.equal(run({ minimum: "-5" }).reason, "INVALID_INPUT");
  assert.equal(run({ minimum: "1.5" }).reason, "INVALID_INPUT");
  assert.equal(run({ amount: undefined }).reason, "INVALID_INPUT");
  assert.equal(run({ recipient: "not-hex" }).reason, "INVALID_INPUT");
  assert.equal(run({ proof_tx: undefined }).reason, "INVALID_INPUT");
  assert.equal(run({ expiry_block: 1.5 }).reason, "INVALID_INPUT");
  assert.equal(run({ current_block: "9".repeat(500) }).reason, "INVALID_INPUT");
});
