import http from "node:http";
import { loadConfig, type Config } from "./config";
import { signBody, verifySignature } from "./hmac";
import { Agent, type AgentResult } from "./agent";
import { Prover } from "./prover";
import { Store } from "./store";
import { log, setLogLevel } from "./log";

const MAX_BODY = 1_000_000;
const SIG_HEADER = "x-agent-games-signature";

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export function createServer(cfg: Config, agent: Agent, started = Date.now()): http.Server {
  const sendSigned = (res: http.ServerResponse, r: AgentResult) => {
    res.writeHead(r.status, {
      "content-type": "application/json",
      [SIG_HEADER]: signBody(cfg, r.body),
    });
    res.end(r.body);
  };
  const sendPlain = (res: http.ServerResponse, status: number, obj: unknown) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };

  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      if (req.method === "GET" && url.pathname === "/health") {
        return sendPlain(res, 200, { ok: true, uptime_s: Math.round((Date.now() - started) / 1000) });
      }
      if (req.method !== "POST" || url.pathname !== cfg.agentPath) {
        return sendPlain(res, 404, { error: "not found" });
      }

      const raw = await readBody(req);
      const header = req.headers[SIG_HEADER];
      const sig = Array.isArray(header) ? header[0] : header;

      // 1. signature over the raw bytes, before anything is parsed
      if (!verifySignature(cfg, raw, sig)) {
        log.warn("bad signature", { bytes: raw.length, has_header: !!sig });
        return sendPlain(res, 401, { error: "bad signature" });
      }

      let env: any;
      try {
        env = JSON.parse(raw.toString("utf8"));
      } catch {
        return sendPlain(res, 400, { error: "invalid json" });
      }

      const type: unknown = env?.type;
      if (type === "agent-games.preflight.v1") {
        log.info("preflight ok");
        return sendSigned(res, agent.preflight());
      }
      if (typeof type === "string" && type.startsWith("agent-games.proof-gatekeeper")) {
        return sendSigned(res, await agent.gatekeeper(raw.toString("utf8"), env));
      }
      if (env?.eventId === "steal-the-vfy") {
        log.warn("steal-the-vfy turn received but not implemented in this service");
        return sendPlain(res, 501, { error: "not implemented" });
      }
      log.warn("unknown envelope", { type: String(type) });
      return sendPlain(res, 400, { error: "unknown type" });
    } catch (e) {
      log.error("request failed", { err: String((e as Error)?.message ?? e) });
      if (!res.headersSent) sendPlain(res, 500, { error: "internal error" });
    }
  });
}

async function main() {
  const cfg = loadConfig();
  setLogLevel(cfg.logLevel);
  const store = new Store(cfg.dbPath);
  const prover = new Prover(cfg);
  await prover.init();
  const agent = new Agent(cfg, store, prover);
  const server = createServer(cfg, agent);
  server.keepAliveTimeout = 65_000;
  const host = process.env.HOST ?? "127.0.0.1";
  server.listen(cfg.port, host, () =>
    log.info("listening", { host, port: cfg.port, path: cfg.agentPath, db: store.stats() }),
  );

  const stop = async (sig: string) => {
    log.info("shutting down", { sig });
    server.close();
    await prover.close();
    store.close();
    process.exit(0);
  };
  process.on("SIGTERM", () => void stop("SIGTERM"));
  process.on("SIGINT", () => void stop("SIGINT"));
}

if (require.main === module) {
  main().catch((e) => {
    log.error("fatal", { err: String(e?.message ?? e) });
    process.exit(1);
  });
}
