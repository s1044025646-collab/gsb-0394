// 命令行入口：params / encrypt / decrypt / add / scalar / steps / export / demo / serve
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import {
  P, Q, N, N2, G, LAMBDA, MU, PARAMS_VERSION,
  PaillierError, encrypt, decrypt, homomorphicAdd, scalarMul, randomR,
} from "./paillier.js";
import { Store, MAX_CIPHERTEXTS, MAX_STEPS } from "./db.js";
import { startService, MAX_SCALAR } from "./server.js";

const DB_PATH = process.env.PAILLIER_DB ?? join(process.cwd(), "data", "paillier.db");

function parseArgs(argv: string[]): { cmd: string; flags: Map<string, string> } {
  const [cmd = "help", ...rest] = argv;
  const flags = new Map<string, string>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags.set(key, next);
        i++;
      } else {
        flags.set(key, "true");
      }
    }
  }
  return { cmd, flags };
}

function needBig(flags: Map<string, string>, name: string): bigint {
  const v = flags.get(name);
  if (v === undefined || !/^-?\d+$/.test(v))
    throw new PaillierError("BAD_INPUT", `缺少或非法参数 --${name}（需为十进制整数）`);
  return BigInt(v);
}

function printSteps(steps: { text: string }[]): void {
  steps.forEach((s, i) => console.log(`  步骤${i + 1}: ${s.text}`));
}

const HELP = `教学用 Paillier 加法同态实验 CLI（固定公开参数 p=17, q=19，仅教学用途）

用法：node dist/cli.js <命令> [选项]

命令：
  params                          查看教学参数与限制说明
  encrypt --m <整数> [--r <整数>] [--experiment <id>]
                                  加密明文（默认随机 r；--r 为固定演示选项）
  decrypt --c <密文>              解密密文并展示模运算步骤
  add --c1 <密文> --c2 <密文> [--experiment <id>]
                                  同态相加并解密，结果为 (m1+m2) mod ${N}
  scalar --c <密文> --k <非负整数> [--experiment <id>]
                                  标量倍乘并解密，结果为 (k*m) mod ${N}
  steps --op <运算编号>           查询已保存运算的公式步骤
  export --experiment <id>        导出实验（JSON）
  demo                            运行固定演示（m=12,34, r=1）与随机演示
  serve [--port <端口>]           启动 HTTP API（默认自动选择空闲端口）

限制：密文记录上限 ${MAX_CIPHERTEXTS} 条，标量 k <= ${MAX_SCALAR}，单次解释步骤 <= ${MAX_STEPS}。
数据库文件：${DB_PATH}（可用环境变量 PAILLIER_DB 覆盖）
`;

async function main(): Promise<void> {
  const { cmd, flags } = parseArgs(process.argv.slice(2));

  if (cmd === "help" || cmd === "--help" || cmd === "-h") {
    console.log(HELP);
    return;
  }

  if (cmd === "params") {
    console.log(`教学参数（全部公开，仅教学用途，不提供生产安全）：`);
    console.log(`  p=${P}  q=${Q}  n=p*q=${N}  n^2=${N2}  g=n+1=${G}`);
    console.log(`  lambda=lcm(p-1,q-1)=${LAMBDA}  mu=${MU}`);
    console.log(`  参数版本：${PARAMS_VERSION}`);
    console.log(`  明文空间：Z_${N}（0..${N - 1n}，无符号整数，不编码负数）`);
    console.log(`  密文空间：Z_${N2} 的单位群（1..${N2 - 1n} 且与 n^2 互素）`);
    console.log(`  注意：密文可被静默修改，可解密不代表来源可信；本服务不保存任何真实凭据。`);
    return;
  }

  const store = new Store(DB_PATH);
  try {
    const expId = flags.get("experiment") ?? "default";

    if (cmd === "encrypt") {
      const m = needBig(flags, "m");
      const fixedR = flags.has("r") ? needBig(flags, "r") : undefined;
      const r = fixedR ?? randomR((n) => randomBytes(n));
      const result = encrypt(m, r);
      const row = store.saveCiphertext(expId, m, r, result.c);
      const op = store.saveOperation(expId, "encrypt", { m: String(m), r: String(r) }, result.c, m, result.steps);
      console.log(`密文 c=${result.c}（记录 #${row.id}，运算 #${op.id}，参数版本 ${PARAMS_VERSION}）`);
      console.log(`明文 m=${m}，随机数 r=${r}${fixedR === undefined ? "（系统随机源抽取）" : "（固定演示值）"}`);
      printSteps(result.steps);
      return;
    }

    if (cmd === "decrypt") {
      const c = needBig(flags, "c");
      const result = decrypt(c);
      const op = store.saveOperation(expId, "decrypt", { c: String(c) }, null, result.m, result.steps);
      console.log(`明文 m=${result.m}（模 n=${N} 的明文空间 Z_${N}，运算 #${op.id}）`);
      printSteps(result.steps);
      return;
    }

    if (cmd === "add") {
      const c1 = needBig(flags, "c1");
      const c2 = needBig(flags, "c2");
      const combined = homomorphicAdd(c1, c2);
      const dec = decrypt(combined.c);
      const steps = [...combined.steps, ...dec.steps];
      const { op, ct } = store.saveCombination(expId, "add", { c1: String(c1), c2: String(c2) }, combined.c, dec.m, steps, { m: null, r: null });
      console.log(`组合密文 c=${combined.c}（记录 #${ct.id}，运算 #${op.id}）`);
      console.log(`解密结果 m=${dec.m} = (m1 + m2) mod ${N}，模空间 Z_${N}`);
      printSteps(steps);
      return;
    }

    if (cmd === "scalar") {
      const c = needBig(flags, "c");
      const k = needBig(flags, "k");
      if (k > MAX_SCALAR) throw new PaillierError("LIMIT_EXCEEDED", `标量 k 不能超过 ${MAX_SCALAR}`);
      const scaled = scalarMul(c, k);
      const dec = decrypt(scaled.c);
      const steps = [...scaled.steps, ...dec.steps];
      const { op, ct } = store.saveCombination(expId, "scalar", { c: String(c), k: String(k) }, scaled.c, dec.m, steps, { m: null, r: null });
      console.log(`结果密文 c=${scaled.c}（记录 #${ct.id}，运算 #${op.id}）`);
      console.log(`解密结果 m=${dec.m} = (${k} * m) mod ${N}，模空间 Z_${N}`);
      printSteps(steps);
      return;
    }

    if (cmd === "steps") {
      const opId = Number(needBig(flags, "op"));
      const op = store.getOperation(opId);
      if (!op) throw new PaillierError("NOT_FOUND", `运算记录 #${opId} 不存在`);
      console.log(`运算 #${op.id}（${op.type}，实验 ${op.experiment_id}，参数版本 ${op.params_version}）：`);
      (JSON.parse(op.steps) as { text: string }[]).forEach((s, i) => console.log(`  步骤${i + 1}: ${s.text}`));
      return;
    }

    if (cmd === "export") {
      const id = flags.get("experiment");
      if (!id) throw new PaillierError("BAD_INPUT", "缺少参数 --experiment <id>");
      console.log(JSON.stringify(store.exportExperiment(id), null, 2));
      return;
    }

    if (cmd === "demo") {
      console.log("=== 固定演示（可手算复现）：m1=12, m2=34, r=1 ===");
      const e1 = encrypt(12n, 1n);
      const e2 = encrypt(34n, 1n);
      console.log(`c1 = Enc(12, 1) = ${e1.c}（期望 3877）`);
      console.log(`c2 = Enc(34, 1) = ${e2.c}（期望 10983）`);
      const combined = homomorphicAdd(e1.c, e2.c);
      const dec = decrypt(combined.c);
      console.log(`c = (c1*c2) mod n^2 = ${combined.c}，解密得 m=${dec.m} = (12+34) mod ${N}（期望 46）`);
      console.log("");
      console.log("=== 随机演示：相同明文、不同随机 r 产生不同密文，但解密相同 ===");
      const r1 = randomR((n) => randomBytes(n));
      const r2 = randomR((n) => randomBytes(n));
      const a = encrypt(12n, r1);
      const b = encrypt(12n, r2);
      console.log(`Enc(12, r=${r1}) = ${a.c}`);
      console.log(`Enc(12, r=${r2}) = ${b.c}`);
      console.log(`两者密文${a.c === b.c ? "相同（巧合）" : "不同"}，解密均为 ${decrypt(a.c).m} 与 ${decrypt(b.c).m}`);
      console.log("");
      console.log("=== 模回绕演示：322 + 2 = 324 ≡ 1 (mod 323) ===");
      const w1 = encrypt(322n, 1n);
      const w2 = encrypt(2n, 1n);
      const wc = homomorphicAdd(w1.c, w2.c);
      console.log(`解密 (Enc(322)*Enc(2) mod n^2) = ${decrypt(wc.c).m}（模空间 Z_${N}，结果为 1 而非 324）`);
      return;
    }

    if (cmd === "serve") {
      const port = flags.has("port") ? Number(flags.get("port")) : 0;
      if (!Number.isInteger(port) || port < 0 || port > 65535)
        throw new PaillierError("BAD_INPUT", "--port 必须是 0..65535 的整数（0 表示自动选择空闲端口）");
      const { port: actual } = await startService(store, port);
      console.log(`教学 Paillier API 已启动：http://127.0.0.1:${actual}`);
      console.log(`端点：GET /api/params, POST /api/encrypt, POST /api/decrypt, POST /api/add, POST /api/scalar, GET /api/operations/:id, GET /api/export/:experimentId, GET /api/ciphertexts`);
      return;
    }

    throw new PaillierError("BAD_INPUT", `未知命令 "${cmd}"，运行不带参数查看帮助`);
  } finally {
    if (cmd !== "serve") store.close();
  }
}

main().catch((err) => {
  if (err instanceof PaillierError) {
    console.error(`错误 [${err.code}] ${err.message}`);
  } else {
    console.error(`错误 ${err instanceof Error ? err.message : String(err)}`);
  }
  process.exitCode = 1;
});
