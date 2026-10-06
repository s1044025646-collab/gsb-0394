import { randomBytes } from "node:crypto";

export const PARAMETER_VERSION = "paillier-p17-q19-n323-g324-v1";

export const P = 17n;
export const Q = 19n;
export const N = P * Q;
export const N_SQUARED = N * N;
export const G = N + 1n;
export const LAMBDA = lcm(P - 1n, Q - 1n);
export const MU = modInverse(L((G ** LAMBDA) % N_SQUARED), N);

export const MAX_PLAINTEXT = Number(N - 1n);
export const MAX_SCALAR = 100_000;

export interface EncryptionInput {
  m: number | string | bigint;
  fixedR?: number | string | bigint;
}

export interface EncryptionResult {
  parameterVersion: string;
  plaintext: number;
  r: number;
  rMode: "random" | "fixed";
  ciphertext: number;
  modulus: number;
  ciphertextModulus: number;
}

export interface DecryptionResult {
  parameterVersion: string;
  ciphertext: number;
  plaintext: number;
  modulus: number;
}

export interface Step {
  title: string;
  expression: string;
  result: string;
}

function lcm(a: bigint, b: bigint): bigint {
  return (a / gcd(a, b)) * b;
}

export function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) {
    [x, y] = [y, x % y];
  }
  return x;
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new Error("MODULUS_NON_POSITIVE");
  if (exponent < 0n) throw new Error("EXPONENT_NEGATIVE");
  let result = 1n % modulus;
  let current = base % modulus;
  if (current < 0n) current += modulus;
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = (result * current) % modulus;
    remaining >>= 1n;
    if (remaining > 0n) current = (current * current) % modulus;
  }
  return result;
}

export function extendedGcd(a: bigint, b: bigint): { gcd: bigint; x: bigint; y: bigint } {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
    [oldT, t] = [t, oldT - quotient * t];
  }
  return { gcd: oldR, x: oldS, y: oldT };
}

export function modInverse(value: bigint, modulus: bigint): bigint {
  const candidate = ((value % modulus) + modulus) % modulus;
  const { gcd: common, x } = extendedGcd(candidate, modulus);
  if (common !== 1n) throw new Error("NO_MODULAR_INVERSE");
  return ((x % modulus) + modulus) % modulus;
}

export function L(value: bigint): bigint {
  return (value - 1n) / N;
}

export function toParameterBigInt(value: number | string | bigint, errorCode: string): bigint {
  if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error(errorCode);
  let parsed: bigint;
  try {
    parsed = typeof value === "bigint" ? value : BigInt(value);
  } catch {
    throw new Error(errorCode);
  }
  return parsed;
}

export function validatePlaintext(m: number | string | bigint): bigint {
  const value = toParameterBigInt(m, "PLAINTEXT_NOT_INTEGER");
  if (value < 0n || value >= N) throw new Error("PLAINTEXT_OUT_OF_RANGE");
  return value;
}

export function validateRandomness(r: number | string | bigint): bigint {
  const value = toParameterBigInt(r, "RANDOMNESS_NOT_INTEGER");
  if (value <= 0n || value >= N) throw new Error("RANDOMNESS_OUT_OF_RANGE");
  if (gcd(value, N) !== 1n) throw new Error("RANDOMNESS_NOT_COPRIME");
  return value;
}

export function validateCiphertext(c: number | string | bigint): bigint {
  const value = toParameterBigInt(c, "CIPHERTEXT_NOT_INTEGER");
  if (value <= 0n || value >= N_SQUARED) throw new Error("CIPHERTEXT_OUT_OF_RANGE");
  if (gcd(value, N_SQUARED) !== 1n) throw new Error("CIPHERTEXT_NOT_UNIT_MOD_N2");
  return value;
}

export function validateScalar(k: number | string | bigint): bigint {
  const value = toParameterBigInt(k, "SCALAR_NOT_INTEGER");
  if (value < 0n || value > BigInt(MAX_SCALAR)) throw new Error("SCALAR_OUT_OF_RANGE");
  return value;
}

function randomBelow(limitExclusive: bigint): bigint {
  const bitLength = limitExclusive.toString(2).length;
  const byteLength = Math.ceil(bitLength / 8);
  const extraBits = BigInt(byteLength * 8 - bitLength);
  const mask = (1n << BigInt(bitLength)) - 1n;
  for (;;) {
    const bytes = randomBytes(byteLength);
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    value = (value >> extraBits) & mask;
    if (value < limitExclusive) return value;
  }
}

export function randomCoprimeR(): bigint {
  for (;;) {
    const candidate = randomBelow(N - 1n) + 1n;
    if (gcd(candidate, N) === 1n) return candidate;
  }
}

export function encrypt(input: EncryptionInput): EncryptionResult {
  const m = validatePlaintext(input.m);
  const r = input.fixedR === undefined ? randomCoprimeR() : validateRandomness(input.fixedR);
  const gm = modPow(G, m, N_SQUARED);
  const rn = modPow(r, N, N_SQUARED);
  const c = (gm * rn) % N_SQUARED;
  return {
    parameterVersion: PARAMETER_VERSION,
    plaintext: Number(m),
    r: Number(r),
    rMode: input.fixedR === undefined ? "random" : "fixed",
    ciphertext: Number(c),
    modulus: Number(N),
    ciphertextModulus: Number(N_SQUARED)
  };
}

export function decrypt(c: number | string | bigint): DecryptionResult {
  const ciphertext = validateCiphertext(c);
  const powered = modPow(ciphertext, LAMBDA, N_SQUARED);
  const plaintext = (L(powered) * MU) % N;
  return {
    parameterVersion: PARAMETER_VERSION,
    ciphertext: Number(ciphertext),
    plaintext: Number(plaintext),
    modulus: Number(N)
  };
}

export function addCiphertexts(
  c1: number | string | bigint,
  c2: number | string | bigint,
  version1 = PARAMETER_VERSION,
  version2 = PARAMETER_VERSION
): number {
  if (version1 !== PARAMETER_VERSION || version2 !== PARAMETER_VERSION) {
    throw new Error("PARAMETER_VERSION_MISMATCH");
  }
  const left = validateCiphertext(c1);
  const right = validateCiphertext(c2);
  return Number((left * right) % N_SQUARED);
}

export function multiplyCiphertext(
  c: number | string | bigint,
  k: number | string | bigint,
  version = PARAMETER_VERSION
): number {
  if (version !== PARAMETER_VERSION) throw new Error("PARAMETER_VERSION_MISMATCH");
  const ciphertext = validateCiphertext(c);
  const scalar = validateScalar(k);
  return Number(modPow(ciphertext, scalar, N_SQUARED));
}

export function publicParameters() {
  return {
    parameterVersion: PARAMETER_VERSION,
    scheme: "Paillier additive homomorphism, fixed teaching parameters",
    p: Number(P),
    q: Number(Q),
    n: Number(N),
    g: Number(G),
    nSquared: Number(N_SQUARED),
    lambda: Number(LAMBDA),
    mu: Number(MU),
    plaintextRange: { min: 0, max: MAX_PLAINTEXT },
    randomnessRange: { min: 1, max: MAX_PLAINTEXT },
    scalarRange: { min: 0, max: MAX_SCALAR },
    securityNotice: "参数固定且非常小，仅用于课堂演示，不提供生产安全或真实密钥管理。"
  };
}

export function encryptionSteps(m: number | string | bigint, fixedR?: number | string | bigint): Step[] {
  const result = encrypt({ m, fixedR });
  const plaintext = result.plaintext;
  const r = result.r;
  const gm = modPow(G, BigInt(plaintext), N_SQUARED);
  const rn = modPow(BigInt(r), N, N_SQUARED);
  return [
    {
      title: "检查明文",
      expression: `0 <= m < n，n=${Number(N)}`,
      result: `m=${plaintext}`
    },
    {
      title: "选择随机数",
      expression: "1 <= r < n 且 gcd(r,n)=1",
      result: `r=${r}，来源=${result.rMode === "fixed" ? "固定演示值" : "系统随机源拒绝采样"}`
    },
    {
      title: "计算 g^m mod n^2",
      expression: `${Number(G)}^${plaintext} mod ${Number(N_SQUARED)}`,
      result: Number(gm).toString()
    },
    {
      title: "计算 r^n mod n^2",
      expression: `${r}^${Number(N)} mod ${Number(N_SQUARED)}`,
      result: Number(rn).toString()
    },
    {
      title: "组合密文",
      expression: "c = g^m * r^n mod n^2",
      result: result.ciphertext.toString()
    }
  ];
}

export function decryptionSteps(c: number | string | bigint): { result: DecryptionResult; steps: Step[] } {
  const ciphertext = validateCiphertext(c);
  const powered = modPow(ciphertext, LAMBDA, N_SQUARED);
  const lifted = L(powered);
  const plaintext = (lifted * MU) % N;
  return {
    result: {
      parameterVersion: PARAMETER_VERSION,
      ciphertext: Number(ciphertext),
      plaintext: Number(plaintext),
      modulus: Number(N)
    },
    steps: [
      {
        title: "检查密文",
        expression: `1 <= c < n^2 且 gcd(c,n^2)=1，n^2=${Number(N_SQUARED)}`,
        result: `c=${Number(ciphertext)}`
      },
      {
        title: "私钥指数模幂",
        expression: `u = c^lambda mod n^2，lambda=${Number(LAMBDA)}`,
        result: Number(powered).toString()
      },
      {
        title: "L 函数是整数除法",
        expression: "L(u)=(u-1)/n",
        result: Number(lifted).toString()
      },
      {
        title: "恢复模 n 明文",
        expression: "m = L(u) * mu mod n",
        result: `${Number(plaintext)}（模空间 Z/${Number(N)}Z）`
      }
    ]
  };
}
