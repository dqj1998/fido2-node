# FIDO2-Node Performance Testing Suite

完整的性能测试框架用于 fido2-node FIDO2 认证服务器。

## 概述

本测试套件测量 FIDO2 注册和认证操作在各种负载条件下的响应时间。所有测试使用 **Mock 数据库 + 带延迟模拟的 Mock MySQL 连接池**，确保测试完全隔离，不依赖真实数据库。

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
