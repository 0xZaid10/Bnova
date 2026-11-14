// Usage: AGENT_GAMES_HMAC_SECRET=... npx tsx scripts/selftest.ts https://your.domain/agent
// Sends a signed preflight and one signed sample task to a running agent and checks the replies.
import { createHmac } from "node:crypto";

const url = process.argv[2];
const secret = process.env.AGENT_GAMES_HMAC_SECRET ?? "";
if (!url || !secret) {
  console.error("usage: AGENT_GAMES_HMAC_SECRET=... tsx scripts/selftest.ts <full agent url>");
  process.exit(2);
}
const sign = (b: string) => createHmac("sha256", secret).update(b).digest("hex");

async function send(body: string) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(body) },
    body,
  });
  const text = await res.text();
  const sig = res.headers.get("x-agent-games-signature") ?? "";
  const sigOk = sig.replace(/^sha256=/, "") === sign(text);
  return { status: res.status, text, sigOk };
}

(async () => {
  const pre = await send(JSON.stringify({ type: "agent-games.preflight.v1", agent_id: "selftest", issued_at: new Date().toISOString(), nonce: "n1" }));
  console.log("preflight:", pre.status, pre.text, "response signature ok:", pre.sigOk);

  const vk = "0x" + "ab".repeat(32);
  const task = JSON.stringify({
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "selftest_" + Date.now(),
    mode: "selftest",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: vk, proof_vk: vk, minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000,
      recipient: "0x" + "11".repeat(20), condition_recipient: "0x" + "11".repeat(20),
      amount: "500", max_transfer: "1000", proof_tx: "0x" + Date.now().toString(16),
    },
  });
  const t0 = Date.now();
  const r = await send(task);
  const j = JSON.parse(r.text);
  console.log("task:", r.status, j.decision, j.reason_code, "proof:", !!j.proof, `${Date.now() - t0}ms`, "signature ok:", r.sigOk);
  const pass = pre.status === 200 && pre.sigOk && r.status === 200 && r.sigOk && j.decision === "APPROVE" && !!j.proof;
  console.log(pass ? "SELFTEST PASSED" : "SELFTEST FAILED");
  process.exit(pass ? 0 : 1);
})();
