# Windows 本地 Paillier 加法同态教学后端

这是一个只包含 API 与 CLI 的 TypeScript/Node.js/SQLite 教学项目。项目从零用 `bigint` 实现 Paillier 的模幂、模逆、加密、解密、密文乘法和标量模幂，不调用现成 Paillier 密码库。

## 教学范围与安全边界

- 固定公开参数：`p=17`、`q=19`、`n=323`、`g=n+1=324`、`n²=104329`。
- 私钥推导也在教学接口中公开：`lambda=lcm(p-1,q-1)=144`，`mu=L(g^lambda mod n²)^-1 mod n`。
- 所有值很小，任何人都能手工或用程序反推，不提供生产安全、真实密钥管理或秘密保护。
- 不要通过本服务提交或保存现有 API Key、密码、私钥、令牌等真实凭据。
- 不同合法随机数 `r` 会让同一明文产生不同密文；解密相同不代表密文字节相同。
- Paillier 本身不提供来源认证或完整性保护，密文被篡改后仍可能解密，不能把“能解密”当成可信来源证明。
- 明文空间是 `Z/323Z`，没有有符号整数编码；`322 + 2 = 1 (mod 323)`，不是 `324`。

## 数学公式

明文要求：

```text
0 <= m < n
1 <= r < n
gcd(r,n)=1
1 <= c < n²
gcd(c,n²)=1
```

加密：

```text
c = g^m * r^n mod n²
```

私钥指数：

```text
lambda = lcm(p-1,q-1)
```

解密：

```text
u = c^lambda mod n²
L(u) = (u-1)/n
m = L(u) * mu mod n
mu = L(g^lambda mod n²)^-1 mod n
```

这里的除法是 BigInt 精确整数除法，幂运算使用自行实现的平方乘模幂，不使用浮点幂。

## 环境要求

- Windows 本地 PowerShell
- Node.js 22.5 或更新版本（本项目在 Node.js 25 上验证，使用内置 `node:sqlite`）
- npm
- 不需要 Docker、WSL、付费服务或在线 API

## 构建与测试

```powershell
npm install
npm run build
npm test
```

## 启动 API

默认端口号为 `0`，操作系统会选择一个空闲端口：

```powershell
npm start
```

指定端口：

```powershell
$env:PORT="3230"
npm start
```

指定项目内数据库路径：

```powershell
$env:PAILLIER_DB_PATH="$PWD\data\demo.db"
npm start
```

服务只监听 `127.0.0.1`。

## API

### 查看参数

```powershell
Invoke-RestMethod http://127.0.0.1:3230/api/parameters
```

### 固定 r 加密

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:3230/api/encrypt `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"m":12,"fixedR":1}'
```

期望密文为 `3877`。`m=34,r=1` 的密文为 `10983`。

### 解密

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:3230/api/decrypt `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"c":3877}'
```

### 同态相加

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:3230/api/add `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"c1":3877,"c2":10983}'
```

组合密文为 `c1*c2 mod n²`，解密结果为 `46 ∈ Z/323Z`。

### 标量倍乘

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:3230/api/scalar-multiply `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"c":3877,"k":2}'
```

### 查询公式步骤

- `POST /api/steps/encrypt`，JSON：`{"m":12,"fixedR":1}`
- `POST /api/steps/decrypt`，JSON：`{"c":3877}`

### 实验与导出

- `POST /api/experiments`：创建实验
- `POST /api/experiments/encrypt`：保存加密节点
- `POST /api/experiments/add`：原子保存相加节点
- `POST /api/experiments/scalar-multiply`：原子保存倍乘节点
- `GET /api/experiments/{id}/records`：查询记录
- `GET /api/records/{id}/steps`：查询已保存步骤
- `GET /api/experiments/{id}/export`：导出完整实验

每个实验最多保存 100 条密文节点，标量范围是 `0..100000`，请求体最大 64 KiB。组合操作在一个 SQLite 事务中完成；数学或跨实验校验失败会回滚，不会留下新的成功节点。

## CLI

```powershell
npm run demo
npm run cli -- params
npm run cli -- encrypt 12 --r 1
npm run cli -- decrypt 3877
npm run cli -- add 3877 10983
npm run cli -- scalar 3877 2
npm run cli -- steps encrypt 12
npm run cli -- steps decrypt 3877
npm run cli -- experiment-demo
npm run cli -- export <experimentId> .\data\experiment.json
```

`npm run demo` 同时展示：

- `m=12,r=1 -> c=3877`
- `m=34,r=1 -> c=10983`
- 相加解密为 `46`
- 默认系统随机模式下相同明文对应不同密文
- `322 + 2 mod 323 = 1`

## 随机数

默认使用 Node.js `crypto.randomBytes` 作为系统随机源，在 `1..322` 上使用拒绝采样得到均匀分布，避免直接对上限取模造成偏差。只有请求显式提供 `fixedR` 时才使用固定随机数，用于课堂手算和复现实验。

## 错误码

常见错误码包括：

- `PLAINTEXT_OUT_OF_RANGE`：明文不在 `0..322`
- `RANDOMNESS_OUT_OF_RANGE`：随机数不在 `1..322`
- `RANDOMNESS_NOT_COPRIME`：随机数与 `n` 不互素
- `CIPHERTEXT_OUT_OF_RANGE`：密文不在 `1..104328`
- `CIPHERTEXT_NOT_UNIT_MOD_N2`：密文不属于模 `n²` 单位群
- `SCALAR_OUT_OF_RANGE`：标量超出允许范围
- `PARAMETER_VERSION_MISMATCH`：参数版本不兼容
- `RECORD_NOT_FOUND` / `EXPERIMENT_NOT_FOUND`：记录不存在
- `RECORD_EXPERIMENT_MISMATCH`：记录不属于指定实验
- `EXPERIMENT_INPUT_LIMIT`：超过实验节点数量限制

## 数据

SQLite 数据库默认位于：

```text
data\paillier-teaching.db
```

数据库保存教学明文、公开参数、密文、随机数和运算关系。因为固定参数没有真实秘密，这些内容只用于复现教学步骤，不应当作秘密存储。

## 明确不实现

- 不实现生产密钥生成
- 不实现随机种子恢复
- 不实现门限密钥恢复
- 不实现签名或来源认证
- 不实现通用多项式同态
- 不接入外部密码服务
- 不提供前端页面
