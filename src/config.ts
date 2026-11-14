export type SignatureFormat = "hex" | "sha256-prefixed" | "base64";
export type SecretEncoding = "utf8" | "hex";
export type TaskIdMode = "keccak" | "sha256" | "utf8" | "hex-tail";

export interface Config {
  port: number;
  agentPath: string;
  secret: string;
  secretEncoding: SecretEncoding;
  signatureFormat: SignatureFormat;
  taskIdMode: TaskIdMode;
  dbPath: string;
  circuitDir: string;
  hardDeadlineMs: number;
  logLevel: "debug" | "info" | "warn" | "error";
  expectedVkHash: string;
}

// vk_hash of the Gatekeeper circuit as registered on zkVerify mainnet.
export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

function pick<T extends string>(name: string, allowed: readonly T[], dflt: T): T {
  const v = (process.env[name] ?? dflt) as T;
  if (!allowed.includes(v)) {
    throw new Error(`${name} must be one of ${allowed.join(", ")} (got "${v}")`);
  }
  return v;
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  const secret = overrides.secret ?? process.env.AGENT_GAMES_HMAC_SECRET ?? "";
  if (!secret) {
    throw new Error("AGENT_GAMES_HMAC_SECRET is not set. Use Rotate Secret on the dashboard and put it in .env");
  }
  const cfg: Config = {
    port: Number(process.env.PORT ?? 8080),
    agentPath: process.env.AGENT_PATH ?? "/agent",
    secret,
    secretEncoding: pick("SECRET_ENCODING", ["utf8", "hex"], "utf8"),
    signatureFormat: pick("SIGNATURE_FORMAT", ["hex", "sha256-prefixed", "base64"], "hex"),
    taskIdMode: pick("TASK_ID_MODE", ["keccak", "sha256", "utf8", "hex-tail"], "keccak"),
    dbPath: process.env.DB_PATH ?? "./data/agent.db",
    circuitDir: process.env.CIRCUIT_DIR ?? "./circuits",
    hardDeadlineMs: Number(process.env.HARD_DEADLINE_MS ?? 50000),
    logLevel: pick("LOG_LEVEL", ["debug", "info", "warn", "error"], "info"),
    expectedVkHash: GATEKEEPER_VK_HASH,
    ...overrides,
  };
  return cfg;
}
