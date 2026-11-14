import { createHmac, timingSafeEqual } from "node:crypto";
import type { Config } from "./config";

function key(cfg: Pick<Config, "secret" | "secretEncoding">): Buffer {
  return cfg.secretEncoding === "hex"
    ? Buffer.from(cfg.secret.replace(/^0x/i, ""), "hex")
    : Buffer.from(cfg.secret, "utf8");
}

export function signBody(cfg: Config, raw: Buffer | string): string {
  const mac = createHmac("sha256", key(cfg)).update(raw);
  switch (cfg.signatureFormat) {
    case "base64":
      return mac.digest("base64");
    case "sha256-prefixed":
      return "sha256=" + mac.digest("hex");
    default:
      return mac.digest("hex");
  }
}

/**
 * Verify the inbound signature over the RAW body, before any JSON parsing.
 * Accepts hex (with or without a "sha256=" prefix) and base64, so a format
 * difference on the platform side cannot lock us out.
 */
export function verifySignature(cfg: Config, raw: Buffer, header: string | undefined): boolean {
  if (!header) return false;
  const mac = createHmac("sha256", key(cfg)).update(raw).digest();
  const h = header.trim();
  const candidates: Buffer[] = [];
  const hex = h.replace(/^sha256=/i, "");
  if (/^[0-9a-fA-F]{64}$/.test(hex)) candidates.push(Buffer.from(hex, "hex"));
  try {
    const b = Buffer.from(h.replace(/^sha256=/i, ""), "base64");
    if (b.length === 32) candidates.push(b);
  } catch {
    /* ignore */
  }
  return candidates.some((c) => c.length === mac.length && timingSafeEqual(c, mac));
}
