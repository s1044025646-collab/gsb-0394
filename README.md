# 教学用 Paillier 加法同态实验后端（TypeScript + Node.js + SQLite）

一个**仅用于教学演示**的 Paillier 加法同态小服务：对小整数加密，把两份密文相乘组合后解密，得到明文和的**模 n 结果**，并逐步解释每一步模运算。只提供 API 与 CLI，无前端。

## 重要声明（请先读）

- **固定公开小参数**：p=17、q=19、n=323、g=n+1=324，连“私钥”指数 lambda=144 也全部公开。**小参数不提供任何生产安全**，任何人都能解密所有密文。
- 本项目**不接入真实密钥管理，不处理、不索取、不存储任何真实凭据**（如 API Key、口令、生产私钥）。请勿通过本接口提交任何真实秘密。
- 密文**没有完整性/来源认证**：密文可被静默修改，修改后仍可能“正常解密”。**能解密不代表密文来自可信来源**。
- 明文空间是 `Z_323`（0..322 的无符号整数），**没有有符号整数编码**。因此 `322 + 2 = 1 (mod 323)`，而不是 324。所有返回值都标注了模空间。
- 同一明文每次加密使用新的随机 r，**密文字节不要求相同**；不同密文可以解密出同一明文，这是方案的正常特性。

## 数学原理（全部自行实现，未使用任何现成 Paillier 库）

- 加密：`c = g^m * r^n mod n^2`，其中 `0 <= m < n`，`1 <= r < n` 且 `gcd(r, n) = 1`。
- 解密：`m = L(c^lambda mod n^2) * mu mod n`，其中 `L(u) = (u-1)/n`（精确整数除法），`lambda = lcm(p-1, q-1) = 144`，`mu = L(g^lambda mod n^2)^(-1) mod n`。
- 同态加法：`c = c1 * c2 mod n^2`，解密得 `(m1 + m2) mod n`。
- 标量倍乘：`c' = c^k mod n^2`（k 为非负整数），解密得 `(k * m) mod n`。
- 模幂（重复平方）与模逆（扩展欧几里得）均基于 BigInt 自行实现，见 `src/paillier.ts`。**绝不**用普通整数除法或浮点幂冒充模运算。

## 随机性

- 默认从系统随机源（`crypto.randomBytes`）在合法范围内**均匀**抽取 r：拒绝采样（拒绝 `[0,1]` 与 `[323, 65535]` 及与 n 不互素的候选），避免取模偏差。
- 固定 r（如 `--r 1`）仅作为**显式演示选项**，便于手算复现；接口返回中会标注 `random: false`。

## 环境要求

- Windows 本地，Node.js >= 22.5（使用内置 `node:sqlite`，无需原生编译、Docker、WSL 或任何外部在线服务）。

## 快速开始

```powershell
npm install        # 安装开发依赖（typescript、@types/node）
npm run build      # 编译 TypeScript 到 dist/
npm test           # 构建并运行全部测试
npm run demo       # 固定演示 + 随机演示 + 模回绕演示
npm start          # 启动 HTTP API（默认自动选择空闲端口）
```

## CLI 用法

```powershell
node dist/src/cli.js params                          # 查看教学参数与限制
node dist/src/cli.js encrypt --m 12                  # 随机 r 加密
node dist/src/cli.js encrypt --m 12 --r 1            # 固定 r 演示（可手算复现）
node dist/src/cli.js decrypt --c 3877
node dist/src/cli.js add --c1 3877 --c2 10983        # 同态相加，解密得 46
node dist/src/cli.js scalar --c 3877 --k 5           # 标量倍乘，解密得 60
node dist/src/cli.js steps --op 1                    # 查看某次运算的公式步骤
node dist/src/cli.js export --experiment default     # 导出实验 JSON
node dist/src/cli.js serve --port 8080               # 指定端口；省略则自动选空闲端口
node dist/src/cli.js demo                            # 内置演示
```

固定演示向量：`Enc(12, r=1) = 3877`，`Enc(34, r=1) = 10983`，组合密文 `(3877*10983) mod 104329 = 14859`，解密得 `46`。

## HTTP API

默认监听 `127.0.0.1` 的**空闲端口**（可用 `--port` 或启动参数指定）。所有响应为 JSON；错误统一为 `{ ok: false, error: { code, message } }`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/params` | 查看教学参数、明文空间与安全提示 |
| POST | `/api/encrypt` | `{ m, r?, experimentId? }`，省略 r 时系统随机抽取 |
| POST | `/api/decrypt` | `{ c }` 或 `{ cId }`，返回明文与逐步解释 |
| POST | `/api/add` | `{ c1, c2 }` 或 `{ c1Id, c2Id }`，同态相加并解密 |
| POST | `/api/scalar` | `{ c, k }` 或 `{ cId, k }`，标量倍乘并解密 |
| GET | `/api/operations/:id` | 查询某次运算的公式步骤 |
| GET | `/api/ciphertexts?experimentId=` | 列出密文记录 |
| GET | `/api/export/:experimentId` | 导出实验（参数版本、密文、运算、步骤） |

错误码：`INVALID_PLAINTEXT`、`INVALID_R`、`INVALID_CIPHERTEXT`、`INVALID_SCALAR`、`PARAM_MISMATCH`、`NOT_FOUND`、`LIMIT_EXCEEDED`、`BAD_INPUT` 等。

## 持久化与一致性

- SQLite 数据库默认在项目内 `data/paillier.db`（可用环境变量 `PAILLIER_DB` 覆盖）。
- 每条密文记录绑定**参数版本**（`paillier-teach-v1-p17-q19`）与实验编号；按记录编号取密文组合前会校验参数版本兼容，不匹配返回 `PARAM_MISMATCH`，绝不凭编号相同就跳过数学校验。
- 一次组合（运算记录 + 结果密文）在**单事务**中原子保存：任一步失败整体回滚，不留下“成功节点”。
- 固定 r 的演示记录重启后可用保存的 `(m, r)` 重算出完全相同的密文与步骤。

## 限制（教学边界）

- 密文记录上限 1000 条；标量 `k <= 10000`；单次解释步骤 <= 200 条；请求体 <= 64KB。
- 不实现生产密钥生成、门限恢复、随机种子恢复、签名或通用多项式同态，不调用外部密码服务。

## 测试

`npm test` 覆盖：零与最大明文、模回绕（322+2=1）、零倍/一倍标量、非法 r（0、越界、不互素）、非法密文（0、越界、非单位群）、参数版本不匹配、组合失败回滚、全部 323 个明文 × 多个合法 r 的往返、固定手算向量（3877/10983/46）、以及用独立整数等式（不经过被测函数）验证同态结果。

## 目录结构

```
src/paillier.ts   核心数学：modPow/modInverse/加解密/同态运算/校验/步骤解释
src/db.ts         SQLite 存储（node:sqlite），原子事务与导出
src/server.ts     HTTP API（node:http，仅本机）
src/cli.ts        命令行入口
test/paillier.test.ts  全部测试
```
