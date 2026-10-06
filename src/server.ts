// HTTP API 服务：仅本机教学用途，不处理任何真实凭据或生产密钥。
import { createServer, IncomingMessage, ServerResponse, Server } from "node:http";
import { randomBytes } from "node:crypto";
import {
  P, Q, N, N2, G, LAMBDA, MU, PARAMS_VERSION,
  PaillierError, encrypt, decrypt, homomorphicAdd, scalarMul, randomR,
} from "./paillier.js";
import { Store } from "./db.js";

export const MAX_SCALAR = 10000n; // 标量范围限制
const MAX_BODY = 64 * 1024; // 请求体大小限制

export interface ServiceOptions {
  store: Store;
  randomBytes?: (n: number) => Uint8Array;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(data);
}

function fail(res: ServerResponse, status: number, code: string, message: string): void {
  json(res, status, { ok: false, error: { code, message } });
}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new PaillierError("LIMIT_EXCEEDED", "请求体过大"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new PaillierError("BAD_JSON", "请求体不是合法 JSON"));
      }
    });
    req.on("error", reject);
  });
}

function toBigInt(v: unknown, field: string): bigint {
  if (typeof v === "number" && Number.isInteger(v)) return BigInt(v);
  if (typeof v === "string" && /^-?\d+$/.test(v)) return BigInt(v);
  throw new PaillierError("BAD_INPUT", `字段 ${field} 必须是整数（十进制数字或字符串）`);
}

function optBigInt(v: unknown, field: string): bigint | undefined {
  if (v === undefined || v === null) return undefined;
  return toBigInt(v, field);
}

function experimentIdOf(body: Record<string, unknown>): string {
  const id = body.experimentId;
  if (id === undefined) return "default";
  if (typeof id !== "string" || id.length === 0 || id.length > 64)
    throw new PaillierError("BAD_INPUT", "experimentId 必须是 1..64 字符的字符串");
  return id;
}

export function createService(opts: ServiceOptions) {
  const store = opts.store;
  const rand = opts.randomBytes ?? ((n: number) => randomBytes(n));

  /** 解析密文：直接给 c，或给 ciphertextId 从库中读取并校验参数版本。 */
  function resolveCiphertext(body: Record<string, unknown>, key: string): bigint {
    const idKey = `${key}Id`;
    if (body[idKey] !== undefined) {
      const id = Number(toBigInt(body[idKey], idKey));
      const row = store.getCiphertext(id);
      if (!row)
        throw new PaillierError("NOT_FOUND", `密文记录 #${id} 不存在`);
      if (row.params_version !== PARAMS_VERSION)
        throw new PaillierError(
          "PARAM_MISMATCH",
          `密文记录 #${id} 参数版本 ${row.params_version} 与当前 ${PARAMS_VERSION} 不兼容`,
        );
      return BigInt(row.c);
    }
    return toBigInt(body[key], key);
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    if (method === "GET" && path === "/api/params") {
      return json(res, 200, {
        ok: true,
        params: {
          p: String(P), q: String(Q), n: String(N), n2: String(N2), g: String(G),
          lambda: String(LAMBDA), mu: String(MU),
          paramsVersion: PARAMS_VERSION,
          plaintextSpace: `Z_${N}（0..${N - 1n}，无符号，不编码负数）`,
          notice:
            "教学演示参数，全部公开。小参数不提供任何生产安全；密文可被静默修改，可解密不代表来源可信。",
        },
      });
    }

    if (method === "POST" && path === "/api/encrypt") {
      const body = (await readBody(req)) as Record<string, unknown>;
      const m = toBigInt(body.m, "m");
      const fixedR = optBigInt(body.r, "r");
      const r = fixedR ?? randomR(rand);
      const result = encrypt(m, r);
      const expId = experimentIdOf(body);
      const row = store.saveCiphertext(expId, m, r, result.c);
      const op = store.saveOperation(expId, "encrypt", { m: String(m), r: String(r) }, result.c, m, result.steps);
      return json(res, 200, {
        ok: true,
        ciphertextId: row.id,
        operationId: op.id,
        experimentId: expId,
        paramsVersion: PARAMS_VERSION,
        m: String(m), r: String(r), c: String(result.c),
        random: fixedR === undefined,
        steps: result.steps,
      });
    }

    if (method === "POST" && path === "/api/decrypt") {
      const body = (await readBody(req)) as Record<string, unknown>;
      const c = resolveCiphertext(body, "c");
      const result = decrypt(c);
      const expId = experimentIdOf(body);
      const op = store.saveOperation(expId, "decrypt", { c: String(c) }, null, result.m, result.steps);
      return json(res, 200, {
        ok: true,
        operationId: op.id,
        c: String(c),
        m: String(result.m),
        modulus: String(N),
        plaintextSpace: `Z_${N}`,
        steps: result.steps,
      });
    }

    if (method === "POST" && path === "/api/add") {
      const body = (await readBody(req)) as Record<string, unknown>;
      const c1 = resolveCiphertext(body, "c1");
      const c2 = resolveCiphertext(body, "c2");
      const combined = homomorphicAdd(c1, c2);
      const dec = decrypt(combined.c);
      const expId = experimentIdOf(body);
      const steps = [...combined.steps, ...dec.steps];
      const { op, ct } = store.saveCombination(
        expId, "add", { c1: String(c1), c2: String(c2) }, combined.c, dec.m, steps,
        { m: null, r: null },
      );
      return json(res, 200, {
        ok: true,
        operationId: op.id,
        ciphertextId: ct.id,
        c: String(combined.c),
        m: String(dec.m),
        modulus: String(N),
        plaintextSpace: `Z_${N}`,
        meaning: `解密结果为 (m1 + m2) mod ${N}，模回绕是预期行为`,
        steps,
      });
    }

    if (method === "POST" && path === "/api/scalar") {
      const body = (await readBody(req)) as Record<string, unknown>;
      const c = resolveCiphertext(body, "c");
      const k = toBigInt(body.k, "k");
      if (k > MAX_SCALAR)
        throw new PaillierError("LIMIT_EXCEEDED", `标量 k 不能超过 ${MAX_SCALAR}`);
      const scaled = scalarMul(c, k);
      const dec = decrypt(scaled.c);
      const expId = experimentIdOf(body);
      const steps = [...scaled.steps, ...dec.steps];
      const { op, ct } = store.saveCombination(
        expId, "scalar", { c: String(c), k: String(k) }, scaled.c, dec.m, steps,
        { m: null, r: null },
      );
      return json(res, 200, {
        ok: true,
        operationId: op.id,
        ciphertextId: ct.id,
        c: String(scaled.c),
        m: String(dec.m),
        modulus: String(N),
        plaintextSpace: `Z_${N}`,
        meaning: `解密结果为 (k * m) mod ${N}`,
        steps,
      });
    }

    const opMatch = path.match(/^\/api\/operations\/(\d+)$/);
    if (method === "GET" && opMatch) {
      const op = store.getOperation(Number(opMatch[1]));
      if (!op) throw new PaillierError("NOT_FOUND", `运算记录 #${opMatch[1]} 不存在`);
      return json(res, 200, {
        ok: true,
        operation: { ...op, inputs: JSON.parse(op.inputs), steps: JSON.parse(op.steps) },
      });
    }

    const expMatch = path.match(/^\/api\/export\/([^/]+)$/);
    if (method === "GET" && expMatch) {
      return json(res, 200, { ok: true, export: store.exportExperiment(decodeURIComponent(expMatch[1])) });
    }

    if (method === "GET" && path === "/api/ciphertexts") {
      const expId = url.searchParams.get("experimentId") ?? undefined;
      return json(res, 200, { ok: true, ciphertexts: store.listCiphertexts(expId) });
    }

    throw new PaillierError("NOT_FOUND", `未知路由：${method} ${path}`);
  }

  const server: Server = createServer((req, res) => {
    handle(req, res).catch((err) => {
      if (err instanceof PaillierError) {
        const status =
          err.code === "NOT_FOUND" ? 404 :
          err.code === "LIMIT_EXCEEDED" ? 413 :
          err.code === "PARAM_MISMATCH" ? 409 : 400;
        fail(res, status, err.code, err.message);
      } else if (err instanceof Error && err.message.startsWith("LIMIT_EXCEEDED")) {
        fail(res, 413, "LIMIT_EXCEEDED", err.message);
      } else {
        fail(res, 500, "INTERNAL", err instanceof Error ? err.message : String(err));
      }
    });
  });
  return server;
}

/** 启动服务；port 为 0 时由系统分配空闲端口（默认行为）。 */
export function startService(store: Store, port = 0): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createService({ store });
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      resolve({ server, port: typeof addr === "object" && addr ? addr.port : port });
    });
  });
}
