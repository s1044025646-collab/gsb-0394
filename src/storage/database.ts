import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  PARAMETER_VERSION,
  addCiphertexts,
  decrypt,
  encrypt,
  multiplyCiphertext
} from "../crypto/paillier.js";

export const MAX_EXPERIMENT_INPUTS = 100;

export interface EncryptionRecordInput {
  experimentId: string;
  label?: string;
  plaintext: number;
  fixedR?: number;
}

export interface CombinationInput {
  experimentId: string;
  label?: string;
  operation: "add" | "scalar";
  leftRecordId: string;
  rightRecordId?: string;
  scalar?: number;
}

export interface CiphertextRecord {
  id: string;
  experiment_id: string;
  label: string | null;
  parameter_version: string;
  plaintext: number;
  r: number;
  r_mode: "fixed" | "random";
  ciphertext: number;
  kind: "encryption" | "add" | "scalar";
  source_record_ids: string;
  scalar: number | null;
  created_at: string;
}

export class ValidationError extends Error {
  constructor(public code: string, message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

function nowId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

export class PaillierStore {
  private readonly db: DatabaseSync;

  constructor(dbPath: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA foreign_keys = ON");
    this.db.exec("PRAGMA journal_mode = WAL");
    this.init();
  }

  close(): void {
    this.db.close();
  }

  private init(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS experiments (
        id TEXT PRIMARY KEY,
        parameter_version TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '教学实验：公开固定小参数，无真实秘密',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS ciphertext_records (
        id TEXT PRIMARY KEY,
        experiment_id TEXT NOT NULL REFERENCES experiments(id) ON DELETE RESTRICT,
        label TEXT,
        parameter_version TEXT NOT NULL,
        plaintext INTEGER NOT NULL,
        r INTEGER NOT NULL,
        r_mode TEXT NOT NULL CHECK(r_mode IN ('fixed','random')),
        ciphertext INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('encryption','add','scalar')),
        source_record_ids TEXT NOT NULL DEFAULT '[]',
        scalar INTEGER,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS operation_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        result_record_id TEXT NOT NULL REFERENCES ciphertext_records(id) ON DELETE CASCADE,
        step_order INTEGER NOT NULL,
        title TEXT NOT NULL,
        expression TEXT NOT NULL,
        result TEXT NOT NULL,
        UNIQUE(result_record_id, step_order)
      );
    `);
  }

  createExperiment(id = nowId("exp"), note?: string): { id: string; parameterVersion: string; createdAt: string | null } {
    this.db
      .prepare(
        `INSERT INTO experiments(id, parameter_version, note)
         VALUES (?, ?, ?)`
      )
      .run(
        id,
        PARAMETER_VERSION,
        note ?? "教学实验：公开固定小参数，无真实秘密；禁止保存真实 API Key 或凭据"
      );
    return this.getExperimentOrThrow(id);
  }

  getExperimentOrThrow(experimentId: string) {
    const row = this.db
      .prepare("SELECT id, parameter_version AS parameterVersion, created_at AS createdAt FROM experiments WHERE id=?")
      .get(experimentId) as { id: string; parameterVersion: string; createdAt: string | null } | undefined;
    if (!row) throw new ValidationError("EXPERIMENT_NOT_FOUND", "实验不存在");
    return row;
  }

  private countInputs(experimentId: string): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS count FROM ciphertext_records WHERE experiment_id=?")
      .get(experimentId) as { count: number };
    return Number(row.count);
  }

  addEncryption(input: EncryptionRecordInput): CiphertextRecord {
    return this.transaction(() => {
      this.getExperimentOrThrow(input.experimentId);
      if (this.countInputs(input.experimentId) >= MAX_EXPERIMENT_INPUTS) {
        throw new ValidationError("EXPERIMENT_INPUT_LIMIT", `每个实验最多 ${MAX_EXPERIMENT_INPUTS} 条密文记录`);
      }
      const encrypted = encrypt({ m: input.plaintext, fixedR: input.fixedR });
      const id = nowId("ct");
      const timestamp = new Date().toISOString();
      this.insertRecord({
        id,
        experiment_id: input.experimentId,
        label: input.label ?? null,
        parameter_version: PARAMETER_VERSION,
        plaintext: encrypted.plaintext,
        r: encrypted.r,
        r_mode: input.fixedR === undefined ? "random" : "fixed",
        ciphertext: encrypted.ciphertext,
        kind: "encryption",
        source_record_ids: "[]",
        scalar: null,
        created_at: timestamp
      });
      this.insertSteps(id, [
        { title: "明文范围", expression: `m ∈ Z/${encrypted.modulus}Z`, result: String(encrypted.plaintext) },
        { title: "随机数", expression: "1 ≤ r < n 且 gcd(r,n)=1", result: String(encrypted.r) },
        { title: "加密", expression: "c = g^m r^n mod n^2", result: String(encrypted.ciphertext) }
      ]);
      return this.getRecordOrThrow(id);
    });
  }

  combine(input: CombinationInput): CiphertextRecord {
    return this.transaction(() => {
      this.getExperimentOrThrow(input.experimentId);
      if (this.countInputs(input.experimentId) >= MAX_EXPERIMENT_INPUTS) {
        throw new ValidationError("EXPERIMENT_INPUT_LIMIT", `每个实验最多 ${MAX_EXPERIMENT_INPUTS} 条密文记录`);
      }
      const left = this.getRecordInExperiment(input.leftRecordId, input.experimentId);
      let outputCiphertext: number;
      let outputPlaintext: number;
      let scalar: number | null = null;
      let sourceIds: string[] = [left.id];
      let steps: { title: string; expression: string; result: string }[];

      if (input.operation === "add") {
        if (!input.rightRecordId) throw new ValidationError("RIGHT_RECORD_REQUIRED", "同态相加需要右侧密文记录");
        const right = this.getRecordInExperiment(input.rightRecordId, input.experimentId);
        if (left.parameter_version !== PARAMETER_VERSION || right.parameter_version !== PARAMETER_VERSION ||
            left.parameter_version !== right.parameter_version) {
          throw new ValidationError("PARAMETER_VERSION_MISMATCH", "两份密文的参数版本不兼容");
        }
        outputCiphertext = addCiphertexts(left.ciphertext, right.ciphertext, left.parameter_version, right.parameter_version);
        outputPlaintext = decrypt(outputCiphertext).plaintext;
        sourceIds = [left.id, right.id];
        steps = [
          { title: "参数兼容检查", expression: "version(left)=version(right)=固定教学版本", result: PARAMETER_VERSION },
          { title: "同态相乘", expression: "c_add = c1 c2 mod n^2", result: String(outputCiphertext) },
          { title: "模 n 解密", expression: "Dec(c_add)=(m1+m2) mod n", result: `${outputPlaintext} ∈ Z/323Z` }
        ];
      } else {
        if (input.scalar === undefined || !Number.isSafeInteger(input.scalar)) {
          throw new ValidationError("SCALAR_REQUIRED", "标量倍乘需要非负整数标量");
        }
        if (left.parameter_version !== PARAMETER_VERSION) {
          throw new ValidationError("PARAMETER_VERSION_MISMATCH", "密文参数版本不兼容");
        }
        outputCiphertext = multiplyCiphertext(left.ciphertext, input.scalar, left.parameter_version);
        outputPlaintext = decrypt(outputCiphertext).plaintext;
        scalar = input.scalar;
        steps = [
          { title: "参数兼容检查", expression: "version(c)=固定教学版本", result: left.parameter_version },
          { title: "标量模幂", expression: "c_scalar = c^k mod n^2", result: String(outputCiphertext) },
          { title: "模 n 解密", expression: "Dec(c_scalar)=(k*m) mod n", result: `${outputPlaintext} ∈ Z/323Z` }
        ];
      }

      const id = nowId("ct");
      const timestamp = new Date().toISOString();
      this.insertRecord({
        id,
        experiment_id: input.experimentId,
        label: input.label ?? null,
        parameter_version: PARAMETER_VERSION,
        plaintext: outputPlaintext,
        r: 0,
        r_mode: "fixed",
        ciphertext: outputCiphertext,
        kind: input.operation,
        source_record_ids: JSON.stringify(sourceIds),
        scalar,
        created_at: timestamp
      });
      this.insertSteps(id, steps);
      return this.getRecordOrThrow(id);
    });
  }

  private transaction<T>(work: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private insertRecord(record: CiphertextRecord): void {
    this.db
      .prepare(`INSERT INTO ciphertext_records(
        id, experiment_id, label, parameter_version, plaintext, r, r_mode,
        ciphertext, kind, source_record_ids, scalar, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        record.id,
        record.experiment_id,
        record.label,
        record.parameter_version,
        record.plaintext,
        record.r,
        record.r_mode,
        record.ciphertext,
        record.kind,
        record.source_record_ids,
        record.scalar,
        record.created_at
      );
  }

  private insertSteps(recordId: string, steps: { title: string; expression: string; result: string }[]): void {
    const statement = this.db.prepare(
      "INSERT INTO operation_steps(result_record_id, step_order, title, expression, result) VALUES (?, ?, ?, ?, ?)"
    );
    steps.forEach((step, index) => statement.run(recordId, index, step.title, step.expression, step.result));
  }

  private getRecordInExperiment(recordId: string, experimentId: string): CiphertextRecord {
    const record = this.getRecord(recordId);
    if (record.experiment_id !== experimentId) {
      throw new ValidationError("RECORD_EXPERIMENT_MISMATCH", "密文记录不属于指定实验");
    }
    return record;
  }

  getRecord(recordId: string): CiphertextRecord {
    const row = this.db
      .prepare("SELECT * FROM ciphertext_records WHERE id=?")
      .get(recordId) as CiphertextRecord | undefined;
    if (!row) throw new ValidationError("RECORD_NOT_FOUND", "密文记录不存在");
    return row;
  }

  getRecordOrThrow(recordId: string): CiphertextRecord {
    return this.getRecord(recordId);
  }

  listRecords(experimentId: string): CiphertextRecord[] {
    this.getExperimentOrThrow(experimentId);
    return this.db
      .prepare("SELECT * FROM ciphertext_records WHERE experiment_id=? ORDER BY created_at ASC, id ASC")
      .all(experimentId) as unknown as CiphertextRecord[];
  }

  getSteps(recordId: string) {
    this.getRecord(recordId);
    return this.db
      .prepare(
        `SELECT step_order AS stepOrder, title, expression, result
         FROM operation_steps WHERE result_record_id=? ORDER BY step_order ASC`
      )
      .all(recordId) as { stepOrder: number; title: string; expression: string; result: string }[];
  }

  exportExperiment(experimentId: string) {
    const experiment = this.getExperimentOrThrow(experimentId);
    const records = this.listRecords(experimentId);
    return {
      exportedAt: new Date().toISOString(),
      teachingOnly: true,
      securityNotice: "固定公开小参数，仅用于教学；不要存放真实凭据或秘密。",
      experiment,
      records: records.map((record) => ({
        ...record,
        source_record_ids: JSON.parse(record.source_record_ids) as string[],
        steps: this.getSteps(record.id)
      }))
    };
  }
}
