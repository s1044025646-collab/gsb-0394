import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import type { AddressInfo } from "node:net";
import { createApp } from "../server.js";
import { PaillierStore } from "../storage/database.js";

describe("HTTP API", () => {
  let baseUrl: string;
  let dbPath: string;
  let server: import("node:http").Server;
  let store: PaillierStore;

  before(async () => {
    const directory = mkdtempSync(join(tmpdir(), "paillier-api-"));
    dbPath = join(directory, "api.db");
    store = new PaillierStore(dbPath);
    await new Promise<void>((resolve) => {
      server = createApp(store).listen(0, "127.0.0.1", () => {
        const address = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    store.close();
  });

  async function post(path: string, body: unknown): Promise<{ status: number; json: unknown }> {
    const response = await fetch(new URL(path, baseUrl), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
    return { status: response.status, json: await response.json() };
  }

  it("返回公开教学参数和安全提示", async () => {
    const response = await fetch(new URL("/api/parameters", baseUrl));
    const body = await response.json() as { n: number; securityNotice: string };
    assert.equal(body.n, 323);
    assert.match(body.securityNotice, /课堂演示/);
  });

  it("完整执行固定实验、相加和导出", async () => {
    const created = await post("/api/experiments", {});
    assert.equal(created.status, 201);
    const experimentId = (created.json as { id: string }).id;
    const first = await post("/api/experiments/encrypt", { experimentId, m: 12, fixedR: 1 });
    const second = await post("/api/experiments/encrypt", { experimentId, m: 34, fixedR: 1 });
    const added = await post("/api/experiments/add", {
      experimentId,
      leftRecordId: (first.json as { id: string }).id,
      rightRecordId: (second.json as { id: string }).id
    });
    assert.equal((added.json as { plaintext: number }).plaintext, 46);
    const exportResponse = await fetch(new URL(`/api/experiments/${experimentId}/export`, baseUrl));
    const exported = await exportResponse.json() as { teachingOnly: boolean; records: unknown[] };
    assert.equal(exported.teachingOnly, true);
    assert.equal(exported.records.length, 3);
  });

  it("返回明确错误码且失败不伪造零明文", async () => {
    const response = await post("/api/encrypt", { m: 323 });
    assert.equal(response.status, 400);
    assert.equal((response.json as { error: { code: string } }).error.code, "PLAINTEXT_OUT_OF_RANGE");
  });
});
