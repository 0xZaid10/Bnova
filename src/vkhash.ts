import { keccak_256 } from "@noble/hashes/sha3";

// Rebuilds the zkVerify vk hash from a snarkjs verification key (BN254, Groth16):
// keccak256 of the SCALE encoded key. Used at startup to prove that the zkey on
// disk is the one registered on zkVerify.

function le32(dec: string): Buffer {
  let x = BigInt(dec);
  const b = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}
const g1 = (p: string[]) => Buffer.concat([le32(p[0]), le32(p[1])]);
const g2 = (p: string[][]) =>
  Buffer.concat([le32(p[0][0]), le32(p[0][1]), le32(p[1][0]), le32(p[1][1])]);

function compact(n: number): Buffer {
  if (n < 64) return Buffer.from([n << 2]);
  if (n < 16384) {
    const v = (n << 2) | 1;
    return Buffer.from([v & 0xff, v >> 8]);
  }
  throw new Error("too many items");
}
const withLen = (b: Buffer) => Buffer.concat([compact(b.length), b]);

export function vkHash(vk: any): string {
  const parts: Buffer[] = [Buffer.from([0])]; // curve: Bn254
  parts.push(withLen(g1(vk.vk_alpha_1)));
  parts.push(withLen(g2(vk.vk_beta_2)));
  parts.push(withLen(g2(vk.vk_gamma_2)));
  parts.push(withLen(g2(vk.vk_delta_2)));
  parts.push(compact(vk.IC.length));
  for (const p of vk.IC) parts.push(withLen(g1(p)));
  const digest = keccak_256(Buffer.concat(parts));
  return "0x" + Buffer.from(digest).toString("hex");
}
