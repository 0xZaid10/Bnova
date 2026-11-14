import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";

export interface StoredTask {
  task_id: string;
  response_json: string;
}

export interface CommitArgs {
  taskId: string;
  mode: string;
  refKey: string | null;
  rawBody: string;
  responseJson: string;
  decision: string;
  reason: string;
  hasProof: boolean;
}

/**
 * Durable state. Two jobs:
 *  1. idempotency: the same task_id always gets the same answer back
 *  2. the seen-set of proof references, which must survive restarts
 * Raw bodies and responses are kept so any dispute can be answered later.
 */
export class Store {
  private db: Database.Database;

  constructor(file: string) {
    if (file !== ":memory:") fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
    this.db = new Database(file);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tasks (
        task_id       TEXT PRIMARY KEY,
        mode          TEXT NOT NULL,
        decision      TEXT NOT NULL,
        reason        TEXT NOT NULL,
        has_proof     INTEGER NOT NULL,
        raw_body      TEXT NOT NULL,
        response_json TEXT NOT NULL,
        created_at    TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS refs (
        mode     TEXT NOT NULL,
        ref      TEXT NOT NULL,
        task_id  TEXT NOT NULL,
        PRIMARY KEY (mode, ref)
      );
    `);
  }

  getTask(taskId: string): StoredTask | undefined {
    return this.db
      .prepare("SELECT task_id, response_json FROM tasks WHERE task_id = ?")
      .get(taskId) as StoredTask | undefined;
  }

  isRefSeen(mode: string, ref: string): boolean {
    return !!this.db.prepare("SELECT 1 FROM refs WHERE mode = ? AND ref = ?").get(mode, ref);
  }

  commit(a: CommitArgs): void {
    const tx = this.db.transaction(() => {
      if (a.refKey) {
        this.db
          .prepare("INSERT OR IGNORE INTO refs (mode, ref, task_id) VALUES (?, ?, ?)")
          .run(a.mode, a.refKey, a.taskId);
      }
      this.db
        .prepare(
          `INSERT OR IGNORE INTO tasks
           (task_id, mode, decision, reason, has_proof, raw_body, response_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          a.taskId, a.mode, a.decision, a.reason, a.hasProof ? 1 : 0,
          a.rawBody, a.responseJson, new Date().toISOString(),
        );
    });
    tx();
  }

  stats(): { tasks: number; refs: number } {
    const t = this.db.prepare("SELECT COUNT(*) AS n FROM tasks").get() as { n: number };
    const r = this.db.prepare("SELECT COUNT(*) AS n FROM refs").get() as { n: number };
    return { tasks: t.n, refs: r.n };
  }

  close(): void {
    this.db.close();
  }
}
