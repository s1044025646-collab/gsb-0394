import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { join } from "node:path";
import {
  addCiphertexts,
  decryptionSteps,
  decrypt,
  encryptionSteps,
  encrypt,
  multiplyCiphertext,
  publicParameters
} from "./crypto/paillier.js";
import { PaillierStore, ValidationError } from "./storage/database.js";

const DEFAULT_DB_PATH = join(process.cwd(), "data", "paillier-teaching.db");

interface ApiContext {
  store: PaillierStore;
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body, null, 2);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });
  response.end(payload);
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 65_536) {
      throw new ValidationError("REQUEST_TOO_LARGE", "请求体不能超过 64 KiB");
    }
    chunks.push(buffer);
  }
  if (chunks.length === 0) return {};
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new ValidationError("INVALID_JSON_BODY", "请求体必须是 JSON 对象");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    throw new ValidationError("INVALID_JSON", "JSON 无法解析");
  }
}

function integerField(body: Record<string, unknown>, key: string): number {
  const value = body[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new ValidationError(`${key.toUpperCase()}_NOT_INTEGER`, `${key} 必须是安全整数`);
  }
  return value;
}

function optionalIntegerField(body: Record<string, unknown>, key: string): number | undefined {
  if (body[key] === undefined) return undefined;
  return integerField(body, key);
}

function stringField(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  if (typeof value !== "string" || value.length === 0 || value.length > 120) {
    throw new ValidationError(`${key.toUpperCase()}_INVALID`, `${key} 必须是 1 到 120 个字符的字符串`);
  }
  return value;
}

function optionalStringField(body: Record<string, unknown>, key: string): string | undefined {
  if (body[key] === undefined) return undefined;
  return stringField(body, key);
}

async function route(request: IncomingMessage, response: ServerResponse, context: ApiContext): Promise<void> {
  const url = new URL(request.url ?? "/", "http://localhost");
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method ?? "GET";

  if (method === "GET" && path === "/health") {
    sendJson(response, 200, { ok: true, mode: "teaching-only" });
    return;
  }
  if (method === "GET" && path === "/api/parameters") {
    sendJson(response, 200, publicParameters());
    return;
  }

  if (method === "GET") {
    const queryExport = /^\/api\/experiments\/([^/]+)\/export$/.exec(path);
    if (queryExport && queryExport[1]) {
      sendJson(response, 200, context.store.exportExperiment(queryExport[1]));
      return;
    }
    const queryRecords = /^\/api\/experiments\/([^/]+)\/records$/.exec(path);
    if (queryRecords && queryRecords[1]) {
      sendJson(response, 200, { records: context.store.listRecords(queryRecords[1]) });
      return;
    }
    const querySteps = /^\/api\/records\/([^/]+)\/steps$/.exec(path);
    if (querySteps && querySteps[1]) {
      sendJson(response, 200, { steps: context.store.getSteps(querySteps[1]) });
      return;
    }
    throw new ValidationError("NOT_FOUND", "接口不存在");
  }

  if (method !== "POST") {
    throw new ValidationError("METHOD_NOT_ALLOWED", "只支持列出的 GET/POST 接口");
  }
  const body = await readJson(request);

  if (path === "/api/encrypt") {
    const fixedR = optionalIntegerField(body, "fixedR");
    sendJson(response, 200, {
      ...encrypt({ m: integerField(body, "m"), ...(fixedR === undefined ? {} : { fixedR }) }),
      modularNotice: "明文结果始终位于 Z/323Z；不同合法 r 可产生不同密文。"
    });
    return;
  }
  if (path === "/api/decrypt") {
    sendJson(response, 200, { ...decrypt(integerField(body, "c")), modularSpace: "Z/323Z" });
    return;
  }
  if (path === "/api/add") {
    const c = addCiphertexts(integerField(body, "c1"), integerField(body, "c2"));
    sendJson(response, 200, {
      ciphertext: c,
      decrypted: decrypt(c).plaintext,
      modularSpace: "Z/323Z",
      identityWarning: "可解密不代表密文来源经过认证；篡改不一定可检测。"
    });
    return;
  }
  if (path === "/api/scalar-multiply") {
    const c = multiplyCiphertext(integerField(body, "c"), integerField(body, "k"));
    sendJson(response, 200, {
      ciphertext: c,
      decrypted: decrypt(c).plaintext,
      modularSpace: "Z/323Z"
    });
    return;
  }
  if (path === "/api/steps/encrypt") {
    const fixedR = optionalIntegerField(body, "fixedR");
    sendJson(response, 200, {
      steps: encryptionSteps(integerField(body, "m"), ...(fixedR === undefined ? [] : [fixedR]))
    });
    return;
  }
  if (path === "/api/steps/decrypt") {
    sendJson(response, 200, decryptionSteps(integerField(body, "c")));
    return;
  }
  if (path === "/api/experiments") {
    const note = optionalStringField(body, "note");
    sendJson(response, 201, context.store.createExperiment(body.id === undefined ? undefined : stringField(body, "id"), note));
    return;
  }
  if (path === "/api/experiments/encrypt") {
    const fixedR = optionalIntegerField(body, "fixedR");
    sendJson(response, 201, context.store.addEncryption({
      experimentId: stringField(body, "experimentId"),
      label: optionalStringField(body, "label"),
      plaintext: integerField(body, "m"),
      ...(fixedR === undefined ? {} : { fixedR })
    }));
    return;
  }
  if (path === "/api/experiments/add") {
    sendJson(response, 201, context.store.combine({
      experimentId: stringField(body, "experimentId"),
      label: optionalStringField(body, "label"),
      operation: "add",
      leftRecordId: stringField(body, "leftRecordId"),
      rightRecordId: stringField(body, "rightRecordId")
    }));
    return;
  }
  if (path === "/api/experiments/scalar-multiply") {
    sendJson(response, 201, context.store.combine({
      experimentId: stringField(body, "experimentId"),
      label: optionalStringField(body, "label"),
      operation: "scalar",
      leftRecordId: stringField(body, "recordId"),
      scalar: integerField(body, "k")
    }));
    return;
  }

  throw new ValidationError("NOT_FOUND", "接口不存在");
}

export function createApp(store = new PaillierStore(process.env.PAILLIER_DB_PATH ?? DEFAULT_DB_PATH)): Server {
  return createServer((request, response) => {
    route(request, response, { store }).catch((error: unknown) => {
      if (error instanceof ValidationError || error instanceof Error && /^[A-Z_]+$/.test(error.message)) {
        const code = error instanceof ValidationError ? error.code : error.message;
        const status = code === "NOT_FOUND" || code === "EXPERIMENT_NOT_FOUND" || code === "RECORD_NOT_FOUND"
          ? 404
          : code === "METHOD_NOT_ALLOWED" ? 405 : 400;
        sendJson(response, status, {
          error: {
            code,
            message: error instanceof ValidationError ? error.message : "输入未通过教学参数校验"
          }
        });
        return;
      }
      console.error(error);
      sendJson(response, 500, { error: { code: "INTERNAL_ERROR", message: "服务器内部错误" } });
    });
  });
}

const invokedPath = process.argv[1] ? new URL(`file:///${process.argv[1].replace(/\\/g, "/")}`).pathname : "";
if (invokedPath.endsWith("/dist/server.js")) {
  const requestedPort = Number.parseInt(process.env.PORT ?? "0", 10);
  const port = Number.isInteger(requestedPort) && requestedPort >= 0 && requestedPort <= 65535 ? requestedPort : 0;
  const server = createApp();
  server.listen(port, "127.0.0.1", () => {
    const address = server.address();
    const actualPort = typeof address === "object" && address ? address.port : port;
    console.log(`Paillier 教学后端: http://127.0.0.1:${actualPort}`);
    console.log(`SQLite: ${process.env.PAILLIER_DB_PATH ?? DEFAULT_DB_PATH}`);
  });
}
