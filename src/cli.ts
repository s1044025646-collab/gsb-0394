#!/usr/bin/env node
import { writeFileSync } from "node:fs";
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

const dbPath = process.env.PAILLIER_DB_PATH ?? join(process.cwd(), "data", "paillier-teaching.db");

function print(value: unknown): void {
  console.log(JSON.stringify(value, null, 2));
}

function numberArg(name: string, value: string | undefined): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new ValidationError(`${name.toUpperCase()}_NOT_INTEGER`, `${name} 必须是整数`);
  return parsed;
}

function requireArg(args: string[], index: number, name: string): string {
  const value = args[index];
  if (value === undefined) throw new ValidationError("MISSING_ARGUMENT", `缺少参数 ${name}`);
  return value;
}

function demo(): void {
  const first = encrypt({ m: 12, fixedR: 1 });
  const second = encrypt({ m: 34, fixedR: 1 });
  const combined = addCiphertexts(first.ciphertext, second.ciphertext);
  const decrypted = decrypt(combined);
  const randomA = encrypt({ m: 12 });
  const randomB = encrypt({ m: 12 });
  const wrap = decrypt(addCiphertexts(encrypt({ m: 322, fixedR: 1 }).ciphertext, encrypt({ m: 2, fixedR: 1 }).ciphertext));
  print({
    notice: "公开固定小参数，仅用于教学；不提供生产安全或来源认证。",
    fixedVector: {
      m1: 12,
      m2: 34,
      r1: 1,
      r2: 1,
      c1: first.ciphertext,
      c2: second.ciphertext,
      cAdd: combined,
      decrypted: decrypted.plaintext,
      modularSpace: "Z/323Z"
    },
    randomSamePlaintextDifferentCiphertext: {
      plaintext: 12,
      first: { r: randomA.r, ciphertext: randomA.ciphertext },
      second: { r: randomB.r, ciphertext: randomB.ciphertext },
      decryptToSame: decrypt(randomA.ciphertext).plaintext === 12 && decrypt(randomB.ciphertext).plaintext === 12
    },
    moduloWrap: {
      expression: "322 + 2 mod 323",
      plaintext: wrap.plaintext,
      note: "结果是 1，不是 324"
    }
  });
}

async function main(): Promise<number> {
  const [command, ...args] = process.argv.slice(2);
  try {
    switch (command) {
      case "params":
        print(publicParameters());
        return 0;
      case "encrypt": {
        const m = numberArg("m", requireArg(args, 0, "m"));
        const fixedROption = args.indexOf("--r");
        const fixedR = fixedROption >= 0 ? numberArg("r", args[fixedROption + 1]) : undefined;
        print(encrypt({ m, ...(fixedR === undefined ? {} : { fixedR }) }));
        return 0;
      }
      case "decrypt":
        print(decrypt(numberArg("c", requireArg(args, 0, "c"))));
        return 0;
      case "add": {
        const c = addCiphertexts(numberArg("c1", requireArg(args, 0, "c1")), numberArg("c2", requireArg(args, 1, "c2")));
        print({ ciphertext: c, plaintext: decrypt(c).plaintext, modularSpace: "Z/323Z" });
        return 0;
      }
      case "scalar": {
        const c = multiplyCiphertext(numberArg("c", requireArg(args, 0, "c")), numberArg("k", requireArg(args, 1, "k")));
        print({ ciphertext: c, plaintext: decrypt(c).plaintext, modularSpace: "Z/323Z" });
        return 0;
      }
      case "steps": {
        const kind = requireArg(args, 0, "encrypt|decrypt");
        const value = numberArg("value", requireArg(args, 1, "value"));
        if (kind === "encrypt") print({ steps: encryptionSteps(value) });
        else if (kind === "decrypt") print(decryptionSteps(value));
        else throw new ValidationError("UNKNOWN_STEP_KIND", "步骤类型必须是 encrypt 或 decrypt");
        return 0;
      }
      case "experiment-demo": {
        const store = new PaillierStore(dbPath);
        try {
          const experiment = store.createExperiment();
          const first = store.addEncryption({ experimentId: experiment.id, label: "m=12", plaintext: 12, fixedR: 1 });
          const second = store.addEncryption({ experimentId: experiment.id, label: "m=34", plaintext: 34, fixedR: 1 });
          const combined = store.combine({
            experimentId: experiment.id,
            label: "12+34",
            operation: "add",
            leftRecordId: first.id,
            rightRecordId: second.id
          });
          print(store.exportExperiment(experiment.id));
          return 0;
        } finally {
          store.close();
        }
      }
      case "export": {
        const experimentId = requireArg(args, 0, "experimentId");
        const output = args[1] ?? join(process.cwd(), "data", `export-${experimentId}.json`);
        const store = new PaillierStore(dbPath);
        try {
          const payload = store.exportExperiment(experimentId);
          writeFileSync(output, JSON.stringify(payload, null, 2), "utf8");
          print({ exported: output });
          return 0;
        } finally {
          store.close();
        }
      }
      case "demo":
        demo();
        return 0;
      default:
        console.log(`用法:
  npm run build
  npm test
  npm start
  npm run demo
  npm run cli -- params
  npm run cli -- encrypt 12 --r 1
  npm run cli -- decrypt 3877
  npm run cli -- add 3877 10983
  npm run cli -- scalar 3877 2
  npm run cli -- steps encrypt 12
  npm run cli -- experiment-demo
  npm run cli -- export <experimentId> [output.json]`);
        return command === undefined ? 0 : 2;
    }
  } catch (error) {
    if (error instanceof Error) {
      console.error(JSON.stringify({ error: { code: error instanceof ValidationError ? error.code : error.name, message: error.message } }, null, 2));
    }
    return 1;
  }
}

void main().then((code) => process.exitCode = code);
