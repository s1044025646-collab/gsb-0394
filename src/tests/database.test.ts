import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { PaillierStore } from "../storage/database.js";

describe("SQLite 实验存储", () => {
  let directory: string;
  let store: PaillierStore;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "paillier-teaching-"));
    store = new PaillierStore(join(directory, "test.db"));
  });

  afterEach(() => store.close());

  it("一次组合原子保存并可重启重算读取", () => {
    const experiment = store.createExperiment("exp-fixed");
    const first = store.addEncryption({ experimentId: experiment.id, plaintext: 12, fixedR: 1 });
    const second = store.addEncryption({ experimentId: experiment.id, plaintext: 34, fixedR: 1 });
    const combined = store.combine({
      experimentId: experiment.id,
      operation: "add",
      leftRecordId: first.id,
      rightRecordId: second.id
    });
    assert.equal(combined.ciphertext, Number((3877n * 10983n) % (323n * 323n)));
    assert.equal(combined.plaintext, 46);

    store.close();
    store = new PaillierStore(join(directory, "test.db"));
    const reloaded = store.listRecords("exp-fixed");
    assert.equal(reloaded.length, 3);
    assert.equal(store.getSteps(combined.id).length, 3);
  });

  it("组合失败时回滚，不留下成功节点", () => {
    const experimentA = store.createExperiment("exp-a");
    const experimentB = store.createExperiment("exp-b");
    const first = store.addEncryption({ experimentId: experimentA.id, plaintext: 12, fixedR: 1 });
    const other = store.addEncryption({ experimentId: experimentB.id, plaintext: 34, fixedR: 1 });
    assert.throws(() => store.combine({
      experimentId: experimentA.id,
      operation: "add",
      leftRecordId: first.id,
      rightRecordId: other.id
    }), (error: unknown) => error instanceof Error && error.message === "密文记录不属于指定实验");
    assert.deepEqual(store.listRecords(experimentA.id).map((record) => record.kind), ["encryption"]);
  });

  it("参数版本不能仅凭记录编号跳过数学校验", () => {
    const experiment = store.createExperiment();
    const first = store.addEncryption({ experimentId: experiment.id, plaintext: 1, fixedR: 1 });
    assert.throws(() => store.combine({
      experimentId: experiment.id,
      operation: "add",
      leftRecordId: first.id,
      rightRecordId: "missing-record"
    }), (error: unknown) => error instanceof Error && error.message === "密文记录不存在");
    assert.equal(store.listRecords(experiment.id).length, 1);
  });
});
