import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type http from "node:http";
import { createHmac } from "node:crypto";
import { loadConfig, type Config } from "../src/config";
import { Agent } from "../src/agent";
import { Prover } from "../src/prover";
import { Store } from "../src/store";
import { createServer } from "../src/server";
import { setLogLevel } from "../src/log";

const SECRET = "test-secret-not-real";
let cfg: Config, store: Store, prover: Prover, server: http.Server, url: string, dir: string;

const sign = (b: string) => createHmac("sha256", SECRET).update(b).digest("hex");

async function post(body: string, opts: { sig?: string | null; path?: string } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const sig = opts.sig === undefined ? sign(body) : opts.sig;
  if (sig !== null) headers["x-agent-games-signature"] = sig;
  const res = await fetch(url + (opts.path ?? "/agent"), { method: "POST", headers, body });
  const text = await res.text();
  return { status: res.status, text, sig: res.headers.get("x-agent-games-signature"), json: safe(text) };
}
const safe = (t: string) => {
  try { return JSON.parse(t); } catch { return undefined; }
};

const validInput = () => ({
  registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
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
let n = 0;
const task = (over: Record<string, unknown> = {}, id?: string) =>
  JSON.stringify({
    type: "agent-games.proof-gatekeeper.v1",
    task_id: id ?? `gk_test_${++n}`,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: { ...validInput(), proof_tx: "0x" + (1000 + n).toString(16), ...over },
  });

before(async () => {
  setLogLevel("error");
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "gk-"));
  cfg = loadConfig({ secret: SECRET, dbPath: path.join(dir, "t.db"), circuitDir: path.join(__dirname, "../circuits") });
  store = new Store(cfg.dbPath);
  prover = new Prover(cfg);
  await prover.init();
  server = createServer(cfg, new Agent(cfg, store, prover));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  url = `http://127.0.0.1:${(server.address() as any).port}`;
});

after(async () => {
  server.close();
  await prover.close();
  store.close();
  fs.rmSync(dir, { recursive: true, force: true });
  setTimeout(() => process.exit(0), 100).unref();
});

test("preflight returns ok and a valid signature", async () => {
  const body = JSON.stringify({ type: "agent-games.preflight.v1", agent_id: "agt_x", issued_at: "now", nonce: "abc" });
  const r = await post(body);
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
  assert.equal(r.sig, sign(r.text));
});

test("bad or missing signature is refused before parsing", async () => {
  const body = task();
  assert.equal((await post(body, { sig: "00".repeat(32) })).status, 401);
  assert.equal((await post(body, { sig: null })).status, 401);
  assert.equal((await post("{not json", { sig: sign("{not json") })).status, 400);
});

test("wrong path is a 404, health works", async () => {
  assert.equal((await post(task(), { path: "/" })).status, 404);
  assert.equal((await fetch(url + "/health")).status, 200);
});

test("valid task: APPROVE with a proof that verifies and matches the inputs", async () => {
  const r = await post(task());
  assert.equal(r.status, 200);
  assert.equal(r.json.decision, "APPROVE");
  assert.equal(r.json.reason_code, "VALID_CONDITION");
  assert.equal(r.sig, sign(r.text));
  assert.equal(await prover.verify(r.json.proof, r.json.public_signals), true);
  assert.equal(r.json.public_signals.length, 13);
  assert.equal(r.json.public_signals[11], "1"); // decision
  assert.equal(r.json.public_signals[3], "1000"); // minimum
  assert.equal(r.json.public_signals[4], "1460"); // public balance
});

const traps: [string, Record<string, unknown>][] = [
  ["VK_SUBSTITUTION", { proof_vk: "0x13aa" }],
  ["THRESHOLD_MISMATCH", { public_balance: "900" }],
  ["EXPIRED_CONDITION", { current_block: 8430001 }],
  ["RECIPIENT_MISMATCH", { recipient: "0xDe42000000000000000000000000000000009f02" }],
  ["AMOUNT_OVERFLOW", { amount: "1001" }],
];
for (const [code, over] of traps) {
  test(`${code}: REJECT with a verifying proof`, async () => {
    const r = await post(task(over));
    assert.equal(r.json.decision, "REJECT");
    assert.equal(r.json.reason_code, code);
    assert.equal(r.json.public_signals[11], "0");
    assert.equal(await prover.verify(r.json.proof, r.json.public_signals), true);
  });
}

test("PROOF_REUSED: second task with the same proof_tx is rejected (no proof possible)", async () => {
  const ref = "0xfeed01";
  const a = await post(task({ proof_tx: ref }));
  assert.equal(a.json.decision, "APPROVE");
  const b = await post(task({ proof_tx: ref }));
  assert.equal(b.json.decision, "REJECT");
  assert.equal(b.json.reason_code, "PROOF_REUSED");
  assert.equal(b.json.proof, undefined);
  // case and leading zeros do not let a reuse slip through
  const c = await post(task({ proof_tx: "0x000FEED01" }));
  assert.equal(c.json.reason_code, "PROOF_REUSED");
});

test("retry of the same task_id returns the identical answer and does not trip reuse", async () => {
  const body = task({}, "gk_retry_1");
  const a = await post(body);
  const b = await post(body);
  assert.equal(a.json.decision, "APPROVE");
  assert.equal(b.text, a.text);
  assert.equal(b.sig, sign(b.text));
});

test("concurrent duplicates of one task produce one decision", async () => {
  const body = task({}, "gk_dupe_1");
  const rs = await Promise.all([post(body), post(body), post(body), post(body)]);
  assert.ok(rs.every((r) => r.text === rs[0].text));
});

test("burst of 16 different tasks all get answered correctly", async () => {
  const bodies = Array.from({ length: 16 }, (_, i) =>
    task(i % 2 ? { amount: "5000" } : {}),
  );
  const t0 = Date.now();
  const rs = await Promise.all(bodies.map((b) => post(b)));
  rs.forEach((r, i) => assert.equal(r.json.decision, i % 2 ? "REJECT" : "APPROVE"));
  assert.ok(Date.now() - t0 < 30_000, "burst took too long");
});

test("malformed input is rejected without crashing", async () => {
  const r = await post(task({ minimum: "abc" }));
  assert.equal(r.status, 200);
  assert.equal(r.json.decision, "REJECT");
  assert.equal(r.json.reason_code, "INVALID_INPUT");
  const noId = await post(JSON.stringify({ type: "agent-games.proof-gatekeeper.v1", input: validInput() }));
  assert.equal(noId.status, 400);
});

test("seen-set survives a restart", async () => {
  const ref = "0xabcdef99";
  const a = await post(task({ proof_tx: ref }));
  assert.equal(a.json.decision, "APPROVE");
  // new store + agent on the same database file = a process restart
  const store2 = new Store(cfg.dbPath);
  const server2 = createServer(cfg, new Agent(cfg, store2, prover));
  await new Promise<void>((r) => server2.listen(0, "127.0.0.1", r));
  const u2 = `http://127.0.0.1:${(server2.address() as any).port}`;
  const body = task({ proof_tx: ref });
  const res = await fetch(u2 + "/agent", {
    method: "POST",
    headers: { "x-agent-games-signature": sign(body) },
    body,
  });
  const j = (await res.json()) as any;
  assert.equal(j.reason_code, "PROOF_REUSED");
  server2.close();
  store2.close();
});
