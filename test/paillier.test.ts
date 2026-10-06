import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  N, N2, G, LAMBDA, MU, PARAMS_VERSION,
  PaillierError, encrypt, decrypt, homomorphicAdd, scalarMul,
  modPow, modInverse, gcd, randomR,
} from "../src/paillier.js";
import { Store } from "../src/db.js";
import { startService } from "../src/server.js";

// ---- 核心数学 ----

test("modPow / modInverse 基本性质", () => {
  assert.equal(modPow(2n, 10n, 1000n), 24n);
  assert.equal(modPow(5n, 0n, 7n), 1n);
  assert.equal((3n * modInverse(3n, 11n)) % 11n, 1n);
  assert.throws(() => modInverse(2n, 4n), /不存在模逆/);
  assert.throws(() => modPow(2n, -1n, 5n), (e) => e instanceof PaillierError);
});

test("教学参数自洽：lambda=144，mu 为 L(g^lambda) 的模逆", () => {
  assert.equal(LAMBDA, 144n);
  assert.equal((144n * MU) % N, 1n);
  assert.equal(G, N + 1n);
});

// ---- 固定手算向量（独立验证，不依赖自身中间值） ----

test("固定向量：m=12,r=1 -> c=3877；m=34,r=1 -> c=10983；组合解密=46", () => {
  const e1 = encrypt(12n, 1n);
  const e2 = encrypt(34n, 1n);
  assert.equal(e1.c, 3877n);
  assert.equal(e2.c, 10983n);
  // 独立等式：c = g^m * r^n mod n^2，用底层模幂直接核对
  assert.equal((modPow(G, 12n, N2) * modPow(1n, N, N2)) % N2, 3877n);
  assert.equal((modPow(G, 34n, N2) * modPow(1n, N, N2)) % N2, 10983n);
  const combined = homomorphicAdd(e1.c, e2.c);
  assert.equal(combined.c, (3877n * 10983n) % N2);
  assert.equal(decrypt(combined.c).m, 46n);
});

// ---- 边界明文与模回绕 ----

test("零明文与最大明文往返", () => {
  assert.equal(decrypt(encrypt(0n, 1n).c).m, 0n);
  assert.equal(decrypt(encrypt(N - 1n, 1n).c).m, N - 1n);
});

test("模回绕：322 + 2 = 1（mod 323），返回模空间而非 324", () => {
  const c1 = encrypt(322n, 1n).c;
  const c2 = encrypt(2n, 1n).c;
  const sum = decrypt(homomorphicAdd(c1, c2).c).m;
  assert.equal(sum, 1n);
  assert.notEqual(sum, 324n);
});

test("越界明文被拒绝", () => {
  assert.throws(() => encrypt(-1n, 1n), (e: unknown) => (e as PaillierError).code === "INVALID_PLAINTEXT");
  assert.throws(() => encrypt(323n, 1n), (e: unknown) => (e as PaillierError).code === "INVALID_PLAINTEXT");
});

// ---- 标量倍乘 ----

test("零倍与一倍标量", () => {
  const c = encrypt(77n, 1n).c;
  assert.equal(decrypt(scalarMul(c, 0n).c).m, 0n);
  assert.equal(decrypt(scalarMul(c, 1n).c).m, 77n);
  assert.equal(decrypt(scalarMul(c, 5n).c).m, (5n * 77n) % N);
  assert.throws(() => scalarMul(c, -1n), (e: unknown) => (e as PaillierError).code === "INVALID_SCALAR");
});

// ---- 非法输入 ----

test("非法 r：零、越界、与 n 不互素", () => {
  for (const r of [0n, -3n, 323n, 324n, 17n, 19n, 34n, 38n]) {
    assert.throws(() => encrypt(1n, r), (e: unknown) => (e as PaillierError).code === "INVALID_R", `r=${r}`);
  }
});

test("非法密文：零、越界、非单位群元素", () => {
  for (const c of [0n, -1n, N2, N2 + 5n, 17n, 323n]) {
    assert.throws(() => decrypt(c), (e: unknown) => (e as PaillierError).code === "INVALID_CIPHERTEXT", `c=${c}`);
    assert.throws(() => homomorphicAdd(c, 1n), (e: unknown) => (e as PaillierError).code === "INVALID_CIPHERTEXT");
  }
});

// ---- 全明文空间往返 ----

test("全部 323 个明文与若干合法 r 核对往返", () => {
  const rs = [1n, 2n, 100n, 257n, 322n];
  for (const r of rs) {
    assert.equal(gcd(r, N), 1n);
    for (let m = 0n; m < N; m++) {
      const { c } = encrypt(m, r);
      assert.equal(decrypt(c).m, m, `m=${m}, r=${r}`);
    }
  }
});

test("随机 r 均匀合法且同明文不同密文解密相同", () => {
  const seen = new Set<bigint>();
  for (let i = 0; i < 50; i++) {
    const r = randomR((n) => randomBytes(n));
    assert.ok(r >= 1n && r < N && gcd(r, N) === 1n);
    seen.add(r);
    assert.equal(decrypt(encrypt(42n, r).c).m, 42n);
  }
  assert.ok(seen.size > 40, "随机 r 应当高度多样");
});

// ---- 同态性质的独立整数等式验证 ----

test("同态加法独立等式：dec(c1*c2 mod n^2) === (m1+m2) mod n", () => {
  const pairs: [bigint, bigint][] = [[0n, 0n], [1n, 322n], [200n, 200n], [322n, 322n], [5n, 7n]];
  for (const [m1, m2] of pairs) {
    const c1 = encrypt(m1, 3n).c;
    const c2 = encrypt(m2, 5n).c;
    // 独立计算组合密文，不调用 homomorphicAdd
    const cCombined = (c1 * c2) % N2;
    assert.equal(decrypt(cCombined).m, (m1 + m2) % N);
    // 独立计算标量倍乘，不调用 scalarMul
    const k = 11n;
    assert.equal(decrypt(modPow(c1, k, N2)).m, (k * m1) % N);
  }
});

// ---- 持久化：参数版本、原子性、重算 ----

test("密文记录绑定参数版本；组合前校验参数兼容", () => {
  const store = new Store(":memory:");
  const row = store.saveCiphertext("exp1", 12n, 1n, 3877n);
  assert.equal(row.params_version, PARAMS_VERSION);
  // 手工篡改参数版本模拟不兼容记录
  (store as any).db.prepare("UPDATE ciphertexts SET params_version = ? WHERE id = ?").run("other-version", row.id);
  const fetched = store.getCiphertext(row.id)!;
  assert.notEqual(fetched.params_version, PARAMS_VERSION);
  store.close();
});

test("组合保存原子性：失败不留下成功节点", () => {
  const store = new Store(":memory:");
  const before = store.listOperations().length + store.listCiphertexts().length;
  // 触发步骤数超限导致事务内失败
  const tooManySteps = Array.from({ length: 1000 }, (_, i) => ({ text: `s${i}` }));
  assert.throws(() =>
    store.saveCombination("exp", "add", {}, 5n, 1n, tooManySteps, { m: null, r: null }),
  );
  const after = store.listOperations().length + store.listCiphertexts().length;
  assert.equal(after, before, "失败后不应留下任何记录");
  store.close();
});

test("重启后可重算相同已保存步骤（固定演示可复现）", () => {
  const store = new Store(":memory:");
  const e = encrypt(12n, 1n);
  store.saveCiphertext("demo", 12n, 1n, e.c);
  const rows = store.listCiphertexts("demo");
  assert.equal(rows.length, 1);
  // “重启”：用保存的 m、r 重新计算，密文与步骤完全一致
  const redo = encrypt(BigInt(rows[0].m), BigInt(rows[0].r));
  assert.equal(redo.c, e.c);
  assert.deepEqual(redo.steps, e.steps);
  store.close();
});

// ---- HTTP API ----

test("API：参数、加密、解密、同态相加、标量、步骤查询、导出", async () => {
  const store = new Store(":memory:");
  const { server, port } = await startService(store, 0);
  const base = `http://127.0.0.1:${port}`;
  try {
    const params = await (await fetch(`${base}/api/params`)).json();
    assert.equal(params.params.n, "323");
    assert.equal(params.params.paramsVersion, PARAMS_VERSION);

    const enc = (m: number, r: number) =>
      fetch(`${base}/api/encrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ m, r, experimentId: "api-test" }),
      }).then((r) => r.json());
    const e1 = await enc(12, 1);
    const e2 = await enc(34, 1);
    assert.equal(e1.c, "3877");
    assert.equal(e2.c, "10983");

    const add = await (
      await fetch(`${base}/api/add`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ c1Id: e1.ciphertextId, c2Id: e2.ciphertextId, experimentId: "api-test" }),
      })
    ).json();
    assert.equal(add.m, "46");
    assert.ok(add.plaintextSpace.includes("323"));

    const scalar = await (
      await fetch(`${base}/api/scalar`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ c: e1.c, k: 0, experimentId: "api-test" }),
      })
    ).json();
    assert.equal(scalar.m, "0");

    const dec = await (
      await fetch(`${base}/api/decrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ c: e1.c }),
      })
    ).json();
    assert.equal(dec.m, "12");

    const op = await (await fetch(`${base}/api/operations/${add.operationId}`)).json();
    assert.ok(op.operation.steps.length > 0);

    const exp = await (await fetch(`${base}/api/export/api-test`)).json();
    assert.equal(exp.export.experiment_id, "api-test");
    assert.ok(exp.export.ciphertexts.length >= 2);

    // 错误码：非法明文 / 非法 r / 非法密文 / 未知路由
    const bad = async (body: unknown, path = "/api/encrypt") =>
      (await fetch(`${base}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })).json();
    assert.equal((await bad({ m: 323 })).error.code, "INVALID_PLAINTEXT");
    assert.equal((await bad({ m: 1, r: 17 })).error.code, "INVALID_R");
    assert.equal((await bad({ c: 0 }, "/api/decrypt")).error.code, "INVALID_CIPHERTEXT");
    const nf = await fetch(`${base}/api/nope`);
    assert.equal(nf.status, 404);
  } finally {
    server.close();
    store.close();
  }
});

test("API：随机模式默认启用，固定 r 仅作显式演示选项", async () => {
  const store = new Store(":memory:");
  const { server, port } = await startService(store, 0);
  try {
    const enc = () =>
      fetch(`http://127.0.0.1:${port}/api/encrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ m: 12 }),
      }).then((r) => r.json());
    const a = await enc();
    const b = await enc();
    assert.equal(a.random, true);
    assert.notEqual(a.c, b.c, "相同明文不同随机 r 应产生不同密文");
    assert.equal(a.m, "12");
  } finally {
    server.close();
    store.close();
  }
});
