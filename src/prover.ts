import path from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import type { Config, TaskIdMode } from "./config";
import type { Decision, Parsed } from "./decision";
import { vkHash } from "./vkhash";
import { log } from "./log";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { getCurveFromName } = require("ffjavascript");

// BN254 scalar field
export const FIELD_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function taskIdToField(mode: TaskIdMode, taskId: string): bigint {
  const bytes = Buffer.from(taskId, "utf8");
  switch (mode) {
    case "sha256":
      return BigInt("0x" + createHash("sha256").update(bytes).digest("hex")) % FIELD_P;
    case "utf8":
      return BigInt("0x" + bytes.toString("hex")) % FIELD_P;
    case "hex-tail": {
      const stripped = taskId.replace(/^[a-zA-Z]+_/, "").replace(/_/g, "");
      if (/^[0-9a-fA-F]+$/.test(stripped)) return BigInt("0x" + stripped) % FIELD_P;
      return BigInt("0x" + Buffer.from(keccak_256(bytes)).toString("hex")) % FIELD_P;
    }
    default:
      return BigInt("0x" + Buffer.from(keccak_256(bytes)).toString("hex")) % FIELD_P;
  }
}

export interface ProofResult {
  proof: unknown;
  publicSignals: string[];
}

export function buildCircuitInput(
  p: Parsed,
  decision: Decision,
  taskIdField: bigint,
  salt: bigint,
): Record<string, string> {
  const f = (v: bigint) => (v % FIELD_P).toString();
  return {
    registeredVkHash: f(p.registeredVk),
    proofVkHash: f(p.proofVk),
    minimum: f(p.minimum),
    publicBalance: f(p.publicBalance),
    expiryBlock: f(p.expiryBlock),
    currentBlock: f(p.currentBlock),
    recipient: f(p.recipient),
    conditionRecipient: f(p.conditionRecipient),
    amount: f(p.amount),
    maxTransfer: f(p.maxTransfer),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: taskIdField.toString(),
    salt: salt.toString(),
  };
}

export class Prover {
  private wasm: string;
  private zkey: string;
  private vk: any;

  constructor(private cfg: Config) {
    this.wasm = path.join(cfg.circuitDir, "gatekeeper.wasm");
    this.zkey = path.join(cfg.circuitDir, "gatekeeper_final.zkey");
  }

  /** Loads the key, checks it is the registered one, and runs a warm-up proof. */
  async init(): Promise<void> {
    this.vk = await snarkjs.zKey.exportVerificationKey(this.zkey);
    const h = vkHash(this.vk);
    if (h.toLowerCase() !== this.cfg.expectedVkHash.toLowerCase()) {
      throw new Error(`zkey vk hash ${h} does not match the registered ${this.cfg.expectedVkHash}`);
    }
    const t0 = Date.now();
    await this.prove(
      {
        registeredVk: 1n, proofVk: 1n, minimum: 1n, publicBalance: 2n, expiryBlock: 10n,
        currentBlock: 5n, recipient: 7n, conditionRecipient: 7n, amount: 1n, maxTransfer: 2n,
        refKey: "warmup",
      },
      "APPROVE",
      "warmup",
    );
    log.info("prover ready", { vk_hash: h, warmup_ms: Date.now() - t0 });
  }

  /** Throws if the circuit does not accept this decision for these inputs. */
  async prove(p: Parsed, decision: Decision, taskId: string): Promise<ProofResult> {
    const salt = BigInt("0x" + randomBytes(31).toString("hex"));
    const input = buildCircuitInput(p, decision, taskIdToField(this.cfg.taskIdMode, taskId), salt);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, this.wasm, this.zkey);
    const ok = await snarkjs.groth16.verify(this.vk, publicSignals, proof);
    if (!ok) throw new Error("local verification of the fresh proof failed");
    return { proof, publicSignals };
  }

  async verify(proof: unknown, publicSignals: string[]): Promise<boolean> {
    return snarkjs.groth16.verify(this.vk, publicSignals, proof);
  }

  async close(): Promise<void> {
    try {
      const curve = await getCurveFromName("bn128");
      await curve.terminate();
    } catch {
      /* ignore */
    }
  }
}
