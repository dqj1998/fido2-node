# FIDO2-Node Test Suite

FIDO2-Node 的完整测试框架，包括 **单元测试** 和 **性能测试**。

---

## 📋 目录

- [测试类型区别](#测试类型区别)
- [快速开始](#快速开始)
- [单元测试](#单元测试)
- [性能测试](#性能测试)
- [文件结构](#文件结构)

---

## 测试类型区别

### 🧪 单元测试 (Unit Tests)

**目的**: 验证代码正确性和安全性

| 特性 | 描述 |
|------|------|
| **范围** | 单个函数和模块 |
| **依赖** | 无实际数据库依赖（使用 Mock） |
| **速度** | 快速（毫秒级） |
| **覆盖** | SQL 注入防护、参数验证、边界情况 |
| **重点** | 功能正确性和安全性 |

**文件列表**:
- `sql-injection.unit.test.js` - SQL 注入漏洞修复验证
- `functions.unit.test.js` - 修复后函数的集成测试

**运行场景**:
- ✅ 开发期间验证代码修改
- ✅ CI/CD 流程中的快速反馈
- ✅ 代码审查前的质量检查
- ✅ 安全审计和漏洞验证

---

### ⚡ 性能测试 (Performance Tests)

**目的**: 测量和监控系统性能

| 特性 | 描述 |
|------|------|
| **范围** | 完整的业务流程（注册、认证等） |
| **依赖** | Mock 数据库 + 延迟模拟 |
| **速度** | 较慢（秒级到分钟级） |
| **覆盖** | 吞吐量、响应时间分布、并发能力 |
| **重点** | 性能指标和优化建议 |

**文件列表**:
- `register.performance.test.js` - 注册性能测试
- `authenticate.performance.test.js` - 认证性能测试
- `concurrency.performance.test.js` - 并发和压力测试
- `performance-report.js` - 报告生成
- `run-performance-tests.sh` - 性能测试执行脚本

**运行场景**:
- ✅ 版本发布前的性能评估
- ✅ 优化修改的效果验证
- ✅ 定期性能基准建立
- ✅ 容量规划和资源评估

---

## 快速开始

### 前置条件

```bash
cd /Users/dqj/HDD/fido2Prjs/fido2-node
npm install mocha --save-dev  # 用于单元测试
```

### 安装测试依赖

```bash
npm install
# 或使用提供的配置
npm --prefix . install --save-dev mocha nyc
```

---

## 单元测试

### 📝 运行所有单元测试

```bash
# 方法1: 使用 bash 脚本
bash UT/run-unit-tests.sh

# 方法2: 使用 mocha 直接运行
npx mocha UT/**/*.unit.test.js --reporter spec --timeout 5000

# 方法3: 使用 npm scripts
npm run test:unit
```

### 🔍 运行特定单元测试

```bash
# 仅运行 SQL 注入防护测试
bash UT/run-unit-tests.sh sql-injection
npx mocha UT/sql-injection.unit.test.js --reporter spec

# 仅运行函数集成测试
bash UT/run-unit-tests.sh functions
npx mocha UT/functions.unit.test.js --reporter spec
```

### 📊 单元测试覆盖率

```bash
# 使用 nyc 生成覆盖率报告
npx nyc mocha UT/**/*.unit.test.js --reporter spec
```

### ✅ 测试内容

#### sql-injection.unit.test.js

验证 SQL 注入漏洞修复：

1. **buildInClause Helper 函数测试**
   - ✓ 正常域名列表
   - ✓ 单一域名
   - ✓ 空数组处理
   - ✓ 注入尝试防护

2. **Search 参数参数化测试**
   - ✓ 带引号的字符串
   - ✓ SQL 注释
   - ✓ LIKE 通配符
   - ✓ Unicode 字符

3. **时间戳验证测试**
   - ✓ 正确格式验证
   - ✓ 注入尝试拒绝
   - ✓ 格式错误检测

4. **真实攻击场景测试**
   - ✓ UNION 注入防护
   - ✓ 子查询注入防护
   - ✓ 盲 SQL 注入防护

#### functions.unit.test.js

测试修复后的函数行为：

1. **getDomainData 函数**
   - ✓ 单个域名参数化
   - ✓ 多个域名参数化
   - ✓ 空列表处理
   - ✓ 注入防护

2. **listUsers 函数**
   - ✓ Search 参数化
   - ✓ 时间戳验证
   - ✓ 参数组合

3. **delUser/delDevice 函数**
   - ✓ 域名验证
   - ✓ 参数安全

### 📋 单元测试输出示例

```
  SQL Injection Fix - Unit Tests
    buildInClause Helper Function
      ✓ should handle normal domain list
      ✓ should handle single domain
      ✓ should handle empty array safely
      ✓ should handle null safely
      ✓ should not be vulnerable to injection in domain values
      ✓ should handle special characters in domains
    
    Search Parameter Parameterization
      ✓ should safely handle search strings with quotes
      ✓ should safely handle search strings with SQL comments
      ...

  SQL Injection Fixed Functions - Integration Tests
    getDomainData Function - Domain Parameterization
      ✓ should build parameterized query for single domain
      ✓ should build parameterized query for multiple domains
      ...

  13 passing (45ms)
```

---

## 性能测试

### ⚡ 运行所有性能测试

```bash
# 方法1: 使用提供的脚本
bash UT/run-performance-tests.sh

# 方法2: 使用 npm scripts  
npm run test:performance
```

### 📈 运行特定性能测试

```bash
# 运行注册性能测试
node UT/register.performance.test.js

# 运行认证性能测试
node UT/authenticate.performance.test.js

# 运行并发压力测试
node UT/concurrency.performance.test.js
```

### 📊 生成性能报告

```bash
# 运行所有性能测试并生成综合报告
bash UT/run-performance-tests.sh

# 报告输出位置
ls UT/results/reports/
```

### 📋 性能测试模块

#### 1. register.performance.test.js

测试注册流程性能：

| 测试 | 描述 | 迭代 |
|-----|------|------|
| preRegister | Challenge 生成和凭证查询 | 100 |
| register | 证明对象验证和存储 | 50 |
| 算法对比 | ES256, RS256, EdDSA | 各 50 |
| excludeCredentials | 数据库查询性能 | 多凭证 |

```bash
node UT/register.performance.test.js
```

#### 2. authenticate.performance.test.js

测试认证流程性能：

| 测试 | 描述 | 迭代 |
|-----|------|------|
| preAuthenticate | Challenge 生成和检索 | 100 |
| authenticate | 签名验证和计数更新 | 50 |
| 凭证列表 | 不同凭证数量影响 | 1-20 |
| 算法对比 | 验证算法性能 | 各 50 |

```bash
node UT/authenticate.performance.test.js
```

#### 3. concurrency.performance.test.js

测试并发和压力能力：

| 测试 | 描述 | 并发数 |
|-----|------|--------|
| 并发注册 | 同时注册 | 10, 25, 50 |
| 并发认证 | 同时认证 | 10, 25, 50 |
| 混合操作 | 注册+认证 | 40 |
| 连接池压力 | 超过池大小 | 30 |
| 吞吐量 | 持续负载 | 轻、中、重 |

```bash
node UT/concurrency.performance.test.js
```

### 📁 结果文件

```
UT/results/
├── reports/
│   ├── performance-report-2024-01-15T10-30-45.json
│   └── performance-report-2024-01-15T10-30-45.md
├── register.results.json
├── authenticate.results.json
└── concurrency.results.json
```

---

## 文件结构

```
UT/
├── 📝 单元测试文件
│   ├── sql-injection.unit.test.js      # SQL 注入防护测试
│   ├── functions.unit.test.js          # 函数集成测试
│   └── run-unit-tests.sh               # 单元测试运行脚本
│
├── ⚡ 性能测试文件
│   ├── register.performance.test.js    # 注册性能测试
│   ├── authenticate.performance.test.js # 认证性能测试
│   ├── concurrency.performance.test.js  # 并发压力测试
│   ├── performance-report.js           # 报告生成器
│   └── run-performance-tests.sh        # 性能测试运行脚本
│
├── 🔧 支持文件
│   ├── mockDatabase.js                 # Mock 数据库
│   ├── mockData.js                     # Mock 数据生成器
│   └── PERFORMANCE-SUMMARY.js          # 性能汇总
│
├── 📁 结果目录
│   ├── results/
│   │   ├── reports/                    # 生成的报告
│   │   ├── register.results.json
│   │   ├── authenticate.results.json
│   │   └── concurrency.results.json
│   │
│   └── .gitignore                      # 忽略结果文件
│
└── 📚 文档
    └── README.md (本文件)
```

---

## 常见命令

### 单元测试命令

```bash
# 快速运行所有单元测试
bash UT/run-unit-tests.sh all

# 运行特定类型
bash UT/run-unit-tests.sh sql-injection
bash UT/run-unit-tests.sh functions

# 使用 npm
npm run test:unit
npm run test:sql-injection
npm run test:functions
```

### 性能测试命令

```bash
# 运行所有性能测试
bash UT/run-performance-tests.sh

# 运行特定测试
node UT/register.performance.test.js
node UT/authenticate.performance.test.js
node UT/concurrency.performance.test.js

# 使用 npm
npm run test:performance
```

### 综合测试

```bash
# 运行所有测试（单元 + 性能）
npm run test:all
```

---

## 💡 最佳实践

### 单元测试

✅ **何时运行**:
- 代码修改后立即运行
- 提交前必须通过
- CI/CD 流程中自动运行

✅ **如何解读**:
- 看测试名称理解验证内容
- 查看断言了解预期行为
- 注意边界情况和安全考虑

❌ **常见错误**:
- 跳过单元测试直接运行性能测试
- 忽视安全相关的单元测试
- 修改代码后不运行单元测试

### 性能测试

✅ **何时运行**:
- 功能实现完成后
- 代码优化之前和之后
- 版本发布前

✅ **如何使用结果**:
- 建立性能基准
- 对比优化效果
- 识别性能瓶颈

❌ **常见错误**:
- 在机器性能变化时忽视基准差异
- 不比较相同条件下的测试结果
- 过度优化非关键路径

---

## 🔍 调试

### 单元测试调试

```bash
# 使用 Node 调试器
node inspect UT/sql-injection.unit.test.js

# 或使用 VSCode 调试
# 在 .vscode/launch.json 中配置调试选项
```

### 性能测试调试

```bash
# 添加详细日志
DEBUG=* node UT/register.performance.test.js

# 或修改代码中的 console.log 输出
```

---

## 📊 性能指标解释

| 指标 | 含义 | 目标值 |
|-----|------|--------|
| **Min** | 最小响应时间 | - |
| **Max** | 最大响应时间 | 应合理 |
| **Avg** | 平均响应时间 | < 50ms |
| **P50** | 中位数 | < 30ms |
| **P95** | 95 百分位 | < 150ms |
| **P99** | 99 百分位 | < 200ms |
| **RPS** | 吞吐量 | > 1000 |

---

## 📚 更多信息

### Mock 数据库配置

修改 `mockDatabase.js` 中的延迟模拟：

```javascript
// 高性能数据库
{ query: 5, insert: 10, update: 8, select: 4 }

// 正常性能
{ query: 10, insert: 15, update: 12, select: 8 }

// 低性能数据库
{ query: 20, insert: 30, update: 25, select: 15 }
```

### 添加自定义测试

在 `UT/` 目录创建 `*.unit.test.js` 或 `*.performance.test.js` 文件，脚本会自动包含。

---

## 许可证

参见项目主目录的 LICENSE 文件。

---

## 更新日志

**2024-01-15**: 
- ✨ 添加单元测试框架
- 🔒 SQL 注入防护测试
- 📚 完整文档

## 测试模块

### 1. Mock 数据库 (`mockDatabase.js`)
- **MockConnection**: 单个数据库连接，支持可配置延迟
- **MockConnectionPool**: 模拟 MySQL 连接池（默认 10 个连接）
- **延迟配置**:
  - Query: 10ms
  - Insert: 15ms
  - Update: 12ms
  - Select: 8ms
- **支持的操作**: SELECT, INSERT, UPDATE, DELETE

### 2. Mock 数据生成器 (`mockData.js`)
- **MockDataGenerator**: 生成 FIDO2 注册和认证的模拟请求/响应数据
- **支持的算法**: ES256, RS256, EdDSA
- **生成器方法**:
  - `generateRegistrationResponse()`: 生成注册响应
  - `generateAuthenticationResponse()`: 生成认证响应
  - `generateRegistrationBatch()`: 批量生成注册数据
  - `generateAuthenticationBatch()`: 批量生成认证数据
  - `generateMultiAlgorithmDataset()`: 多算法数据集

### 3. 注册性能测试 (`register.performance.test.js`)

#### 测试场景

| 测试 | 描述 | 测量点 |
|-----|------|--------|
| **preRegister** | Challenge 生成和凭证查询 | 100 次迭代 |
| **register** | 证明对象验证和凭证存储 | 50 次迭代 |
| **算法对比** | 不同签名算法的性能 | ES256, RS256, EdDSA |
| **excludeCredentials** | 数据库查询性能 | 5 个凭证 |

#### 输出示例
```
preRegister Performance: {
  operation: 'preRegister',
  iterations: 100,
  min: 15.5,
  max: 45.2,
  avg: 22.3,
  p50: 21.0,
  p95: 35.2,
  p99: 42.1
}
```

### 4. 认证性能测试 (`authenticate.performance.test.js`)

#### 测试场景

| 测试 | 描述 | 测量点 |
|-----|------|--------|
| **preAuthenticate** | Challenge 生成和凭证检索 | 100 次迭代，3 个凭证 |
| **authenticate** | 签名验证和计数器更新 | 50 次迭代 |
| **凭证计数对比** | 凭证列表大小的影响 | 1, 5, 10, 20 个凭证 |
| **算法对比** | 签名验证算法性能 | ES256, RS256, EdDSA |
| **计数器更新** | 数据库写入性能 | 100 次迭代 |

### 5. 并发和压力测试 (`concurrency.performance.test.js`)

#### 测试场景

| 测试 | 描述 | 负载 |
|-----|------|------|
| **并发注册** | 同时注册请求 | 10, 25, 50 个并发 |
| **并发认证** | 同时认证请求 | 10, 25, 50 个并发 |
| **混合操作** | 注册和认证混合 | 40 个并发（各 20） |
| **连接池压力** | 超过连接池大小 | 30 个请求（池大小 10） |
| **吞吐量测试** | 持续负载下的吞吐率 | 轻、中、重负载 |

### 6. 性能报告生成器 (`performance-report.js`)

#### 功能
- 聚合所有测试结果
- 生成 JSON 和 Markdown 报告
- 包含统计分析（Min, Max, Avg, P50, P95, P99）
- 提供性能优化建议

#### 报告输出
```
UT/results/
  ├── reports/
  │   ├── performance-report-<timestamp>.json
  │   └── performance-report-<timestamp>.md
  ├── register.results.json
  ├── authenticate.results.json
  └── concurrency.results.json
```

## 快速开始

### 安装依赖
```bash
cd /Users/dqj/HDD/fido2Prjs/fido2-node
npm install
```

### 运行所有性能测试
```bash
npm run test:performance
```

### 运行特定测试
```bash
# 仅注册性能测试
npm run test:register

# 仅认证性能测试
npm run test:authenticate

# 仅并发压力测试
npm run test:concurrency
```

### 生成性能报告
```bash
npm run test:report
```

### 监视模式（自动重新运行）
```bash
npm run test:performance:watch
```

## 测试结果和报告

### 结果文件位置
- 注册测试结果: `UT/results/register.results.json`
- 认证测试结果: `UT/results/authenticate.results.json`
- 并发测试结果: `UT/results/concurrency.results.json`
- 生成的报告: `UT/results/reports/`

### 报告格式

#### JSON 报告结构
```json
{
  "metadata": {
    "timestamp": "2024-01-01T12:00:00.000Z",
    "platform": "darwin",
    "nodeVersion": "v18.x.x"
  },
  "summary": { /* 汇总统计 */ },
  "registration": [ /* 注册测试结果 */ ],
  "authentication": [ /* 认证测试结果 */ ],
  "concurrency": [ /* 并发测试结果 */ ]
}
```

#### Markdown 报告包含
- Executive Summary（执行摘要）
- Registration Performance（注册性能）
- Authentication Performance（认证性能）
- Concurrency and Load Testing（并发和负载测试）
- Performance Recommendations（性能优化建议）

## 性能指标解释

### 响应时间分布

| 指标 | 含义 | 用途 |
|-----|------|------|
| **Min** | 最小响应时间 | 最佳情况 |
| **Max** | 最大响应时间 | 最坏情况 |
| **Avg** | 平均响应时间 | 整体性能 |
| **P50** | 中位数 | 典型用户体验 |
| **P95** | 95 百分位数 | 大多数用户可接受的上限 |
| **P99** | 99 百分位数 | 监控异常情况 |

### 吞吐量 (RPS)

Requests Per Second - 单位时间内处理的请求数，衡量最大承载能力。

## Mock 数据库延迟配置

可通过修改 `mockDatabase.js` 中的延迟配置来模拟不同的数据库性能：

```javascript
const mockPool = new MockConnectionPool({
  query: 10,    // 默认查询延迟
  insert: 15,   // INSERT 操作延迟
  update: 12,   // UPDATE 操作延迟
  select: 8     // SELECT 操作延迟
});
```

调整这些值以模拟：
- **高性能数据库**: query: 5, insert: 10, update: 8, select: 4
- **正常性能**: query: 10, insert: 15, update: 12, select: 8
- **低性能数据库**: query: 20, insert: 30, update: 25, select: 15

## 完全隔离优势

### 测试隔离
✓ 不依赖真实数据库  
✓ 每次测试独立运行  
✓ 无需测试数据清理  
✓ 快速反复运行  
✓ 可在任何环境运行  

### 可重现性
✓ 确定性结果  
✓ 一致的延迟模拟  
✓ 无网络波动  
✓ 便于 CI/CD 集成  

## 扩展测试

### 添加自定义测试
1. 在 `UT/` 目录创建 `*.performance.test.js` 文件
2. 导入 `MockConnectionPool` 和 `MockDataGenerator`
3. 使用 Jest 的 `describe()` 和 `test()` 编写测试

### 自定义 Mock 延迟
修改 `mockDatabase.js` 中的 `_simulateDelay()` 方法以实现更复杂的延迟模式。

### 集成测试
若需要测试真实数据库，建议在单独的 integration 目录中创建集成测试，使用真实数据库连接。

## 常见问题

### Q: 为什么使用 Mock 数据库而不是真实数据库？
A: Mock 数据库提供以下优势：
- 完全隔离，无数据污染
- 快速反复运行
- 可在任何环境运行
- 一致的性能基线

### Q: 如何验证测试结果的有效性？
A: 
- 对比 Mock 延迟设置与实际数据库性能
- 在 integration 环境中进行补充测试
- 定期对标真实环境的性能数据

### Q: 如何监测生产环境性能？
A: 建议：
- 在 fido2-node 应用中添加性能日志（使用现有的 log4js）
- 记录每个请求的响应时间
- 汇总 P95 和 P99 指标
- 与本测试套件的基准值对比

## 性能优化建议

### 注册优化
- Pre-register 应在 150ms 以内（P95）
- 优化 excludeCredentials 查询
- 考虑缓存常用凭证列表

### 认证优化
- Pre-authenticate 应在 150ms 以内（P95）
- 使用 ES256 算法平衡性能和安全性
- 监控签名计数器更新性能

### 数据库优化
- 为 username 和 credential_id 添加索引
- 使用连接池避免连接创建开销
- 定期分析慢查询日志

### 并发优化
- 根据预期峰值并发数调整连接池大小
- 实现请求队列防止连接池溢出
- 监控池中活动连接数

## sysbench 
Using these commands to get the performance of the server:
sysbench cpu run: events per second: NNNNN
sysbench memory run: NNNNN MiB transferred (NNN MiB/sec)

## 许可证

See parent project LICENSE file.

## 联系方式

有问题或建议，请提交 Issue 或 Pull Request。
