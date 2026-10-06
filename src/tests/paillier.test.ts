import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  G,
  MAX_SCALAR,
  N,
  N_SQUARED,
  addCiphertexts,
  decrypt,
  encrypt,
  gcd,
  modInverse,
  modPow,
  multiplyCiphertext
} from "../crypto/paillier.js";

describe("BigInt Paillier 数学", () => {
  it("使用固定手算向量加密 12 和 34", () => {
    assert.equal(encrypt({ m: 12, fixedR: 1 }).ciphertext, 3877);
    assert.equal(encrypt({ m: 34, fixedR: 1 }).ciphertext, 10983);
  });

  it("组合后解密为模 n 的和", () => {
    const c = addCiphertexts(3877, 10983);
    assert.equal(c, Number((3877n * 10983n) % N_SQUARED));
    assert.equal(decrypt(c).plaintext, 46);
  });

  it("三百二十二加二在 Z/323Z 中回绕到一", () => {
    const c = addCiphertexts(
      encrypt({ m: 322, fixedR: 1 }).ciphertext,
      encrypt({ m: 2, fixedR: 1 }).ciphertext
    );
    assert.equal(decrypt(c).plaintext, 1);
  });

  it("覆盖全部三百二十三个明文与多个合法 r 的往返", () => {
    for (let m = 0; m < Number(N); m += 1) {
      for (const r of [1, 2, 3, 5, 7, 16, 321, 322]) {
        if (gcd(BigInt(r), N) !== 1n) continue;
        assert.equal(decrypt(encrypt({ m, fixedR: r }).ciphertext).plaintext, m);
      }
    }
  });

  it("随机模式允许相同明文产生不同密文但解密相同", () => {
    const seen = new Set<number>();
    for (let i = 0; i < 8; i += 1) seen.add(encrypt({ m: 123 }).ciphertext);
    assert.ok(seen.size > 1);
    for (const ciphertext of seen) assert.equal(decrypt(ciphertext).plaintext, 123);
  });

  it("零倍得到加密零，一倍保持明文", () => {
    const c = encrypt({ m: 77, fixedR: 23 }).ciphertext;
    assert.equal(decrypt(multiplyCiphertext(c, 0)).plaintext, 0);
    assert.equal(decrypt(multiplyCiphertext(c, 1)).plaintext, 77);
  });

  it("用独立整数等式验证同态标量结果", () => {
    const m = 100n;
    const k = 7n;
    const r = 23n;
    const c = (modPow(G, m, N_SQUARED) * modPow(r, N, N_SQUARED)) % N_SQUARED;
    const scalarCiphertext = modPow(c, k, N_SQUARED);
    const expectedCiphertext = (modPow(G, (m * k) % N, N_SQUARED) * modPow(r, N * k, N_SQUARED)) % N_SQUARED;
    assert.equal(scalarCiphertext, expectedCiphertext);
    assert.equal(decrypt(scalarCiphertext).plaintext, Number((m * k) % N));
  });

  it("拒绝零、非互素和越界 r", () => {
    assert.throws(() => encrypt({ m: 1, fixedR: 0 }), /RANDOMNESS_OUT_OF_RANGE/);
    assert.throws(() => encrypt({ m: 1, fixedR: 323 }), /RANDOMNESS_OUT_OF_RANGE/);
    assert.throws(() => encrypt({ m: 1, fixedR: 17 }), /RANDOMNESS_NOT_COPRIME/);
  });

  it("拒绝越界明文、非法密文范围和非单位群元素", () => {
    assert.throws(() => encrypt({ m: -1 }), /PLAINTEXT_OUT_OF_RANGE/);
    assert.throws(() => encrypt({ m: 323 }), /PLAINTEXT_OUT_OF_RANGE/);
    assert.throws(() => decrypt(0), /CIPHERTEXT_OUT_OF_RANGE/);
    assert.throws(() => decrypt(Number(N_SQUARED)), /CIPHERTEXT_OUT_OF_RANGE/);
    assert.throws(() => decrypt(17), /CIPHERTEXT_NOT_UNIT_MOD_N2/);
  });

  it("模逆和模幂不使用浮点或普通除法", () => {
    assert.equal((modInverse(7n, N) * 7n) % N, 1n);
    assert.equal(modPow(3n, 100n, N_SQUARED), 3n ** 100n % N_SQUARED);
    assert.throws(() => modInverse(17n, N), /NO_MODULAR_INVERSE/);
  });

  it("强制检查标量上限", () => {
    assert.throws(() => multiplyCiphertext(3877, MAX_SCALAR + 1), /SCALAR_OUT_OF_RANGE/);
  });
});
