// Deterministic Gatekeeper decision engine. No I/O, no randomness, no model.
// Every comparison is done on exact BigInt values, never on raw strings.

export type Decision = "APPROVE" | "REJECT";

export type ReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "THRESHOLD_MISMATCH"
  | "PROOF_REUSED"
  | "EXPIRED_CONDITION"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW"
  | "INVALID_INPUT"
  | "INTERNAL_ERROR";

export interface GatekeeperInput {
  registered_vk: unknown;
  proof_vk: unknown;
  minimum: unknown;
  public_balance: unknown;
  expiry_block: unknown;
  current_block: unknown;
  recipient: unknown;
  condition_recipient: unknown;
  amount: unknown;
  max_transfer: unknown;
  proof_tx: unknown;
}

export interface Parsed {
  registeredVk: bigint;
  proofVk: bigint;
  minimum: bigint;
  publicBalance: bigint;
  expiryBlock: bigint;
  currentBlock: bigint;
  recipient: bigint;
  conditionRecipient: bigint;
  amount: bigint;
  maxTransfer: bigint;
  refKey: string;
}

export interface Verdict {
  decision: Decision;
  reason: ReasonCode;
  detail?: string;
  parsed?: Parsed;
}

const MAX_LEN = 140;

export function parseUint(v: unknown, name: string): bigint {
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0) throw new Error(`${name}: bad number`);
    return BigInt(v);
  }
  if (typeof v === "bigint") {
    if (v < 0n) throw new Error(`${name}: negative`);
    return v;
  }
  if (typeof v !== "string") throw new Error(`${name}: missing or wrong type`);
  const s = v.trim();
  if (s.length === 0 || s.length > MAX_LEN) throw new Error(`${name}: bad length`);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  throw new Error(`${name}: not an unsigned integer`);
}

export function parseHex(v: unknown, name: string): bigint {
  if (typeof v !== "string") throw new Error(`${name}: missing or wrong type`);
  const s = v.trim();
  if (!/^0x[0-9a-fA-F]+$/.test(s) || s.length > MAX_LEN) throw new Error(`${name}: not hex`);
  return BigInt(s);
}

/** Canonical key for the "proof reference was already used" check. */
export function normalizeRef(v: unknown): string {
  if (typeof v !== "string") throw new Error("proof_tx: missing or wrong type");
  const s = v.trim();
  if (s.length === 0 || s.length > MAX_LEN) throw new Error("proof_tx: bad length");
  if (/^0x[0-9a-fA-F]+$/.test(s)) return "0x" + BigInt(s).toString(16);
  return s.toLowerCase();
}

export function parseInput(input: GatekeeperInput): Parsed {
  return {
    registeredVk: parseHex(input.registered_vk, "registered_vk"),
    proofVk: parseHex(input.proof_vk, "proof_vk"),
    minimum: parseUint(input.minimum, "minimum"),
    publicBalance: parseUint(input.public_balance, "public_balance"),
    expiryBlock: parseUint(input.expiry_block, "expiry_block"),
    currentBlock: parseUint(input.current_block, "current_block"),
    recipient: parseHex(input.recipient, "recipient"),
    conditionRecipient: parseHex(input.condition_recipient, "condition_recipient"),
    amount: parseUint(input.amount, "amount"),
    maxTransfer: parseUint(input.max_transfer, "max_transfer"),
    refKey: normalizeRef(input.proof_tx),
  };
}

/**
 * APPROVE only when every check passes. Anything unparseable or unexpected is a REJECT.
 * Order of checks follows the published trap list. Each trap in the competition
 * is expected to appear alone, so the order only matters for multi-trap inputs.
 */
export function evaluate(
  input: GatekeeperInput | undefined | null,
  isRefSeen: (refKey: string) => boolean,
): Verdict {
  if (!input || typeof input !== "object") {
    return { decision: "REJECT", reason: "INVALID_INPUT", detail: "no input object" };
  }
  let p: Parsed;
  try {
    p = parseInput(input);
  } catch (e) {
    return { decision: "REJECT", reason: "INVALID_INPUT", detail: (e as Error).message };
  }

  const reject = (reason: ReasonCode): Verdict => ({ decision: "REJECT", reason, parsed: p });

  if (p.registeredVk !== p.proofVk) return reject("VK_SUBSTITUTION");
  if (p.publicBalance < p.minimum) return reject("THRESHOLD_MISMATCH");
  if (isRefSeen(p.refKey)) return reject("PROOF_REUSED");
  if (p.currentBlock >= p.expiryBlock) return reject("EXPIRED_CONDITION");
  if (p.recipient !== p.conditionRecipient) return reject("RECIPIENT_MISMATCH");
  if (p.amount > p.maxTransfer) return reject("AMOUNT_OVERFLOW");

  return { decision: "APPROVE", reason: "VALID_CONDITION", parsed: p };
}
