// 教学用 Paillier 加法同态核心实现（固定公开小参数，不提供生产安全）。
// 所有模运算均基于 BigInt，自行实现模幂与模逆，不依赖任何现成 Paillier 库。

export const P = 17n;
export const Q = 19n;
export const N = P * Q; // 323
export const N2 = N * N; // 104329
export const G = N + 1n; // 324

export const PARAMS_VERSION = "paillier-teach-v1-p17-q19";

export class PaillierError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = "PaillierError";
  }
}

export function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b !== 0n) {
    const t = a % b;
    a = b;
    b = t;
  }
  return a;
}

export function lcm(a: bigint, b: bigint): bigint {
  return (a / gcd(a, b)) * b;
}

/** 模幂：base^exp mod mod，exp >= 0，重复平方法。 */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod <= 0n) throw new PaillierError("INVALID_MODULUS", "模数必须为正");
  if (exp < 0n) throw new PaillierError("INVALID_EXPONENT", "指数必须非负");
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/** 模逆：返回 x 使 a*x ≡ 1 (mod m)，不存在时抛错。扩展欧几里得算法。 */
export function modInverse(a: bigint, m: bigint): bigint {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n)
    throw new PaillierError("NO_INVERSE", `${a} 在模 ${m} 下不存在模逆`);
  return ((oldS % m) + m) % m;
}

// 私钥指数 lambda = lcm(p-1, q-1)，全部参数公开，仅用于教学演示。
export const LAMBDA = lcm(P - 1n, Q - 1n); // lcm(16,18) = 144

/** L(u) = (u-1)/n，此处为精确整数除法（u ≡ 1 mod n），不是普通近似除法。 */
export function L(u: bigint): bigint {
  return (u - 1n) / N;
}

// mu = L(g^lambda mod n^2)^(-1) mod n。
export const MU = modInverse(L(modPow(G, LAMBDA, N2)), N);

export interface Step {
  text: string;
}

export function validatePlaintext(m: bigint): void {
  if (m < 0n || m >= N)
    throw new PaillierError(
      "INVALID_PLAINTEXT",
      `明文 m 必须满足 0 <= m < n=${N}，收到 ${m}`,
    );
}

export function validateR(r: bigint): void {
  if (r < 1n || r >= N)
    throw new PaillierError(
      "INVALID_R",
      `随机数 r 必须满足 1 <= r < n=${N}，收到 ${r}`,
    );
  if (gcd(r, N) !== 1n)
    throw new PaillierError(
      "INVALID_R",
      `随机数 r=${r} 与 n=${N} 不互素（gcd=${gcd(r, N)}）`,
    );
}

export function validateCiphertext(c: bigint): void {
  if (c < 1n || c >= N2)
    throw new PaillierError(
      "INVALID_CIPHERTEXT",
      `密文 c 必须满足 1 <= c < n^2=${N2}，收到 ${c}`,
    );
  if (gcd(c, N2) !== 1n)
    throw new PaillierError(
      "INVALID_CIPHERTEXT",
      `密文 c=${c} 不属于模 n^2 的单位群（与 n^2=${N2} 不互素）`,
    );
}

/** 在 [1, n-1] 且与 n 互素的范围内均匀抽取 r，拒绝采样避免取模偏差。 */
export function randomR(randomBytes: (n: number) => Uint8Array): bigint {
  for (;;) {
    const buf = randomBytes(2);
    const candidate = (BigInt(buf[0]) << 8n) | BigInt(buf[1]); // [0, 65535]
    if (candidate < 1n || candidate >= N) continue; // 拒绝采样，保证均匀
    if (gcd(candidate, N) !== 1n) continue;
    return candidate;
  }
}

export interface EncryptResult {
  c: bigint;
  m: bigint;
  r: bigint;
  steps: Step[];
}

export function encrypt(m: bigint, r: bigint): EncryptResult {
  validatePlaintext(m);
  validateR(r);
  const gm = modPow(G, m, N2);
  const rn = modPow(r, N, N2);
  const c = (gm * rn) % N2;
  return {
    c,
    m,
    r,
    steps: [
      { text: `参数：p=${P}, q=${Q}, n=p*q=${N}, n^2=${N2}, g=n+1=${G}` },
      { text: `校验明文：0 <= m=${m} < n=${N}` },
      { text: `校验随机数：1 <= r=${r} < n 且 gcd(r, n)=1` },
      { text: `计算 g^m mod n^2 = ${G}^${m} mod ${N2} = ${gm}` },
      { text: `计算 r^n mod n^2 = ${r}^${N} mod ${N2} = ${rn}` },
      { text: `密文 c = (g^m * r^n) mod n^2 = (${gm} * ${rn}) mod ${N2} = ${c}` },
    ],
  };
}

export interface DecryptResult {
  m: bigint;
  steps: Step[];
}

export function decrypt(c: bigint): DecryptResult {
  validateCiphertext(c);
  const u = modPow(c, LAMBDA, N2);
  const lu = L(u);
  const m = (lu * MU) % N;
  return {
    m,
    steps: [
      { text: `校验密文：1 <= c=${c} < n^2=${N2} 且 gcd(c, n^2)=1` },
      { text: `lambda = lcm(p-1, q-1) = lcm(16, 18) = ${LAMBDA}` },
      { text: `u = c^lambda mod n^2 = ${c}^${LAMBDA} mod ${N2} = ${u}` },
      { text: `L(u) = (u-1)/n = (${u}-1)/${N} = ${lu}（精确整数除法）` },
      { text: `mu = L(g^lambda mod n^2)^(-1) mod n = ${MU}` },
      { text: `m = L(u)*mu mod n = (${lu} * ${MU}) mod ${N} = ${m}` },
      { text: `结果位于模 n=${N} 的明文空间 Z_${N}，即 0..${N - 1n}` },
    ],
  };
}

export interface CombineResult {
  c: bigint;
  steps: Step[];
}

/** 同态加法：c = c1*c2 mod n^2，解密得 (m1+m2) mod n。 */
export function homomorphicAdd(c1: bigint, c2: bigint): CombineResult {
  validateCiphertext(c1);
  validateCiphertext(c2);
  const c = (c1 * c2) % N2;
  return {
    c,
    steps: [
      { text: `同态加法：c = (c1 * c2) mod n^2` },
      { text: `c = (${c1} * ${c2}) mod ${N2} = ${c}` },
      { text: `解密该密文得到 (m1 + m2) mod n，模空间为 Z_${N}` },
    ],
  };
}

/** 标量倍乘：c' = c^k mod n^2，解密得 (k*m) mod n，k 为非负整数。 */
export function scalarMul(c: bigint, k: bigint): CombineResult {
  validateCiphertext(c);
  if (k < 0n)
    throw new PaillierError("INVALID_SCALAR", `标量 k 必须为非负整数，收到 ${k}`);
  const out = modPow(c, k, N2);
  return {
    c: out,
    steps: [
      { text: `标量倍乘：c' = c^k mod n^2，对应明文 (k*m) mod n` },
      { text: `c' = ${c}^${k} mod ${N2} = ${out}` },
      ...(k === 0n ? [{ text: `k=0 时 c'=1，对应明文 0` }] : []),
    ],
  };
}
