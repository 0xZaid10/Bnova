import type { Config } from "./config";
import { evaluate, type Decision, type ReasonCode } from "./decision";
import type { Prover, ProofResult } from "./prover";
import type { Store } from "./store";
import { log } from "./log";

export interface AgentResult {
  status: number;
  body: string;
}

const json = (status: number, obj: unknown): AgentResult => ({ status, body: JSON.stringify(obj) });

export class Agent {
  private chain: Promise<unknown> = Promise.resolve();
  private inflight = new Map<string, Promise<AgentResult>>();

  constructor(
    private cfg: Config,
    private store: Store,
    private prover: Prover,
  ) {}

  preflight(): AgentResult {
    return json(200, { ok: true, protocolVersion: "v1" });
  }

  /** One task at a time, so the seen-set check and the write can never interleave. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => undefined);
    return run;
  }

  private budgetMs(deadlineAt: unknown): number {
    const hard = this.cfg.hardDeadlineMs;
    if (typeof deadlineAt !== "string") return hard;
    const t = Date.parse(deadlineAt);
    if (Number.isNaN(t)) return hard;
    const left = t - Date.now() - 3000;
    return Math.max(2000, Math.min(hard, left));
  }

  async gatekeeper(rawBody: string, env: any): Promise<AgentResult> {
    const taskId = env?.task_id;
    if (typeof taskId !== "string" || taskId.length === 0 || taskId.length > 200) {
      return json(400, { error: "missing task_id" });
    }

    const cached = this.store.getTask(taskId);
    if (cached) {
      log.info("task replay", { task_id: taskId });
      return { status: 200, body: cached.response_json };
    }
    const running = this.inflight.get(taskId);
    if (running) return running;

    const work = this.serial(() => this.decide(rawBody, env, taskId));
    const guarded = this.withDeadline(work, this.budgetMs(env.deadline_at), env, taskId);
    this.inflight.set(taskId, guarded);
    try {
      return await guarded;
    } finally {
      this.inflight.delete(taskId);
    }
  }

  private withDeadline(
    work: Promise<AgentResult>,
    ms: number,
    env: any,
    taskId: string,
  ): Promise<AgentResult> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        log.error("deadline reached, failing closed", { task_id: taskId, ms });
        const proofTx = typeof env?.input?.proof_tx === "string" ? env.input.proof_tx : undefined;
        resolve(
          json(200, {
            decision: "REJECT",
            reason_code: "INTERNAL_ERROR" satisfies ReasonCode,
            ...(proofTx ? { proof_tx: proofTx } : {}),
          }),
        );
      }, ms);
      work.then(
        (r) => {
          clearTimeout(timer);
          resolve(r);
        },
        (e) => {
          clearTimeout(timer);
          log.error("task failed, failing closed", { task_id: taskId, err: String(e?.message ?? e) });
          resolve(json(200, { decision: "REJECT", reason_code: "INTERNAL_ERROR" }));
        },
      );
    });
  }

  private async decide(rawBody: string, env: any, taskId: string): Promise<AgentResult> {
    const t0 = Date.now();
    const mode = typeof env.mode === "string" ? env.mode : "unknown";
    const verdict = evaluate(env.input, (ref) => this.store.isRefSeen(mode, ref));

    let decision: Decision = verdict.decision;
    let reason: ReasonCode = verdict.reason;
    let proof: ProofResult | undefined;

    if (verdict.parsed) {
      try {
        proof = await this.prover.prove(verdict.parsed, decision, taskId);
      } catch (e) {
        const msg = String((e as Error)?.message ?? e).split("\n")[0];
        if (decision === "APPROVE") {
          // The circuit refuses to prove our APPROVE. The circuit is the referee,
          // so fail closed and prove a REJECT instead.
          log.warn("circuit disagrees with APPROVE, rejecting", { task_id: taskId, err: msg });
          decision = "REJECT";
          reason = "INVALID_INPUT";
          try {
            proof = await this.prover.prove(verdict.parsed, "REJECT", taskId);
          } catch {
            /* no provable form of this task */
          }
        } else if (reason !== "PROOF_REUSED") {
          // Expected only for PROOF_REUSED (the circuit cannot see reuse).
          log.warn("no proof for REJECT", { task_id: taskId, reason, err: msg });
        }
      }
    }

    const proofTx = typeof env.input?.proof_tx === "string" ? env.input.proof_tx : undefined;
    const response: Record<string, unknown> = { decision, reason_code: reason };
    if (proof) {
      response.proof = proof.proof;
      response.public_signals = proof.publicSignals;
    }
    if (proofTx) response.proof_tx = proofTx;
    const responseJson = JSON.stringify(response);

    this.store.commit({
      taskId,
      mode,
      refKey: verdict.parsed?.refKey ?? null,
      rawBody,
      responseJson,
      decision,
      reason,
      hasProof: !!proof,
    });

    log.info("task done", {
      task_id: taskId, mode, decision, reason, proof: !!proof, ms: Date.now() - t0,
    });
    return { status: 200, body: responseJson };
  }
}
