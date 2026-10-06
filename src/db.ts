// SQLite 存储层：保存教学实验、密文记录与运算关系，支持原子提交与失败回滚。
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { PARAMS_VERSION } from "./paillier.js";

export const MAX_CIPHERTEXTS = 1000; // 输入条数限制
export const MAX_STEPS = 200; // 单次操作解释步骤规模限制

export interface CiphertextRow {
  id: number;
  experiment_id: string;
  params_version: string;
  m: string;
  r: string;
  c: string;
  created_at: string;
}

export interface OperationRow {
  id: number;
  experiment_id: string;
  params_version: string;
  type: string;
  inputs: string; // JSON
  result_c: string | null;
  result_m: string | null;
  steps: string; // JSON
  created_at: string;
}

export class Store {
  private db: DatabaseSync;

  constructor(dbPath: string) {
    if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ciphertexts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        experiment_id TEXT NOT NULL,
        params_version TEXT NOT NULL,
        m TEXT NOT NULL,
        r TEXT NOT NULL,
        c TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        experiment_id TEXT NOT NULL,
        params_version TEXT NOT NULL,
        type TEXT NOT NULL,
        inputs TEXT NOT NULL,
        result_c TEXT,
        result_m TEXT,
        steps TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
  }

  close(): void {
    this.db.close();
  }

  private count(table: string): number {
    const row = this.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as {
      n: number;
    };
    return row.n;
  }

  saveCiphertext(
    experimentId: string,
    m: bigint,
    r: bigint,
    c: bigint,
  ): CiphertextRow {
    if (this.count("ciphertexts") >= MAX_CIPHERTEXTS)
      throw new Error(`LIMIT_EXCEEDED: 密文记录数已达上限 ${MAX_CIPHERTEXTS}`);
    const stmt = this.db.prepare(
      `INSERT INTO ciphertexts (experiment_id, params_version, m, r, c) VALUES (?, ?, ?, ?, ?)`,
    );
    const info = stmt.run(experimentId, PARAMS_VERSION, String(m), String(r), String(c));
    return this.getCiphertext(Number(info.lastInsertRowid))!;
  }

  getCiphertext(id: number): CiphertextRow | undefined {
    return this.db
      .prepare(`SELECT * FROM ciphertexts WHERE id = ?`)
      .get(id) as CiphertextRow | undefined;
  }

  listCiphertexts(experimentId?: string): CiphertextRow[] {
    if (experimentId)
      return this.db
        .prepare(`SELECT * FROM ciphertexts WHERE experiment_id = ? ORDER BY id`)
        .all(experimentId) as unknown as CiphertextRow[];
    return this.db
      .prepare(`SELECT * FROM ciphertexts ORDER BY id`)
      .all() as unknown as CiphertextRow[];
  }

  saveOperation(
    experimentId: string,
    type: string,
    inputs: unknown,
    resultC: bigint | null,
    resultM: bigint | null,
    steps: { text: string }[],
  ): OperationRow {
    if (steps.length > MAX_STEPS)
      throw new Error(`LIMIT_EXCEEDED: 解释步骤数超过上限 ${MAX_STEPS}`);
    const stmt = this.db.prepare(
      `INSERT INTO operations (experiment_id, params_version, type, inputs, result_c, result_m, steps)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    const info = stmt.run(
      experimentId,
      PARAMS_VERSION,
      type,
      JSON.stringify(inputs),
      resultC === null ? null : String(resultC),
      resultM === null ? null : String(resultM),
      JSON.stringify(steps),
    );
    return this.getOperation(Number(info.lastInsertRowid))!;
  }

  getOperation(id: number): OperationRow | undefined {
    return this.db.prepare(`SELECT * FROM operations WHERE id = ?`).get(id) as
      | OperationRow
      | undefined;
  }

  listOperations(experimentId?: string): OperationRow[] {
    if (experimentId)
      return this.db
        .prepare(`SELECT * FROM operations WHERE experiment_id = ? ORDER BY id`)
        .all(experimentId) as unknown as OperationRow[];
    return this.db
      .prepare(`SELECT * FROM operations ORDER BY id`)
      .all() as unknown as OperationRow[];
  }

  /**
   * 原子地保存一次组合运算及其结果密文：任一失败整体回滚，不留下成功节点。
   */
  saveCombination(
    experimentId: string,
    type: string,
    inputs: unknown,
    resultC: bigint,
    resultM: bigint | null,
    steps: { text: string }[],
    combined: { m: bigint | null; r: bigint | null },
  ): { op: OperationRow; ct: CiphertextRow } {
    this.db.exec("BEGIN");
    try {
      const op = this.saveOperation(experimentId, type, inputs, resultC, resultM, steps);
      const ct = this.saveCiphertext(
        experimentId,
        combined.m ?? -1n, // 组合密文原始明文未知时用 -1 占位标注
        combined.r ?? -1n,
        resultC,
      );
      this.db.exec("COMMIT");
      return { op, ct };
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  exportExperiment(experimentId: string) {
    return {
      params_version: PARAMS_VERSION,
      experiment_id: experimentId,
      ciphertexts: this.listCiphertexts(experimentId),
      operations: this.listOperations(experimentId),
    };
  }
}
