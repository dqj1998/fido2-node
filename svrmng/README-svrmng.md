# FIDO2 集群部署工具

一套完整的Shell脚本工具包，用于在4台Ubuntu 24服务器上自动部署FIDO2认证系统集群。

## 📋 目录

- [系统架构](#系统架构)
- [先决条件](#先决条件)
- [快速开始](#快速开始)
- [配置详解](#配置详解)
- [部署命令](#部署命令)
- [管理命令](#管理命令)
- [运维指南](#运维指南)
- [故障排查](#故障排查)
- [安全建议](#安全建议)

## 🏗️ 系统架构

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                      互联网                              │
                    └─────────────────────────┬───────────────────────────────┘
                                              │
                                              ▼
                    ┌─────────────────────────────────────────────────────────┐
                    │              服务器1: Nginx + Portal                     │
                    │  ┌─────────────────┐  ┌─────────────────┐               │
                    │  │     Nginx       │  │   fido2-portal  │               │
                    │  │ (负载均衡+SSL)  │  │   (管理门户)    │               │
                    │  │   :80/:443      │  │     :8065       │               │
                    │  └────────┬────────┘  └─────────────────┘               │
                    │           │ ip_hash                                      │
                    └───────────┼──────────────────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│   服务器2: App    │ │   服务器3: App    │ │ 服务器4: MySQL主  │
│ ┌───────────────┐ │ │ ┌───────────────┐ │ │ ┌───────────────┐ │
│ │  fido2-node   │ │ │ │  fido2-node   │ │ │ │  MySQL Master │ │
│ │   (PM2集群)   │ │ │ │   (PM2集群)   │ │ │ │   server-id=1 │ │
│ │    :8060      │ │ │ │    :8060      │ │ │ │    :3306      │ │
│ └───────────────┘ │ │ ├───────────────┤ │ │ └───────┬───────┘ │
│ ┌───────────────┐ │ │ │ MySQL Replica │ │ │         │         │
│ │ fido2-node-ex │ │ │ │  server-id=2  │◄┼─┼─────────┘复制     │
│ │   (扩展模块)  │ │ │ │    :3306      │ │ │ ┌───────────────┐ │
│ └───────────────┘ │ │ └───────────────┘ │ │ │   备份存储    │ │
└───────────────────┘ └───────────────────┘ │ │ /var/backups  │ │
                                            │ └───────────────┘ │
                                            └───────────────────┘
```

### 组件说明

| 服务器 | 角色 | 组件 | 端口 |
|--------|------|------|------|
| 服务器1 | Nginx + Portal | Nginx, Certbot, fido2-portal | 80, 443, 8065 |
| 服务器2 | App Node 1 | fido2-node, fido2-node-ex | 8060 |
| 服务器3 | App Node 2 + DB Replica | fido2-node, fido2-node-ex, MySQL | 8060, 3306 |
| 服务器4 | MySQL Master | MySQL, 备份脚本 | 3306 |

## ⚙️ 先决条件

### 服务器要求

- **操作系统**: Ubuntu 24.04 LTS (AMD64)
- **最低配置**: 2核CPU, 4GB内存, 50GB磁盘
- **网络**: 服务器之间内网互通，Nginx服务器需要公网IP
- **权限**: 具有sudo权限的普通用户（推荐：不要直接使用root）

### 域名和DNS配置

在开始部署前，请确保：

1. 拥有一个域名（如 `example.com`）
2. DNS已配置以下记录指向Nginx服务器的公网IP：
   - `fido2.example.com` → Nginx服务器IP
   - `portal.example.com` → Nginx服务器IP

### 本地环境要求（部署机器）

部署机器（通常是你的开发机）需要安装：

```bash
# macOS
brew install yq

# Ubuntu/Debian
sudo snap install yq

# 或使用pip
pip install yq
```

同时确保已安装 `ssh`、`rsync`（macOS/Linux默认已安装）。

## 🚀 快速开始

### 1. 准备配置文件

```bash
cd /path/to/fido2-node/svrmng

# 复制示例配置
cp config/cluster.yaml.example config/cluster.yaml

# 编辑配置文件
vim config/cluster.yaml
```

**必须修改的配置项：**

```yaml
cluster:
  domain: your-domain.com    # 你的域名
  ssh:
    user: deploy             # SSH用户名

servers:
  nginx:
    ip: 192.168.1.10         # Nginx服务器IP
  nodejs:
    - ip: 192.168.1.21       # Node.js服务器1 IP
    - ip: 192.168.1.22       # Node.js服务器2 IP（兼MySQL从）
  mysql_master:
    ip: 192.168.1.30         # MySQL主服务器IP

mysql:
  root_password: "安全的密码"
  fido2_node_db:
    password: "安全的密码"
  fido2_portal_db:
    password: "安全的密码"
  replication:
    password: "安全的密码"

ssl:
  email: your-email@example.com  # Let's Encrypt通知邮箱
  # 注意：Nginx按子域名区分服务（fido2.{domain}和portal.{domain}）
  domains:
    - fido2.your-domain.com
    - portal.your-domain.com
```

### 2. 初始化SSH密钥

首次部署需要分发SSH密钥到所有服务器：

```bash
./cluster-deploy.sh --init
```

此命令会：
- 生成ED25519 SSH密钥对
- 提示输入每台服务器的密码
- 自动分发公钥到所有服务器

### 3. 验证配置

```bash
./cluster-deploy.sh --check
```

此命令会验证：
- 配置文件语法
- 本地项目路径存在
- SSH连接到所有服务器

### 4. 执行部署

```bash
./cluster-deploy.sh --deploy
```

完整部署流程（约10-20分钟）：
1. MySQL主服务器安装和配置
2. MySQL从服务器配置复制
3. Node.js服务器安装和应用部署
4. Nginx安装、Portal部署、SSL证书申请

### 5. 验证部署

```bash
# 健康检查
./health-check.sh

# 查看集群状态
./cluster-manage.sh status
```

## 📖 配置详解

### cluster.yaml 完整结构

```yaml
# =============================================================================
# 集群基本信息
# =============================================================================
cluster:
  name: fido2-production       # 集群名称（用于标识）
  domain: example.com          # 主域名
  
  ssh:
    user: deploy               # SSH用户名（需要sudo权限）
    key_file: ~/.ssh/fido2_cluster  # SSH私钥路径
    port: 22                   # SSH端口
  
  # 本地项目路径（rsync源目录）
  local_paths:
    fido2_node: /path/to/fido2-node
    fido2_node_ex: /path/to/fido2-node-ex
    fido2_portal: /path/to/fido2-portal

# =============================================================================
# 服务器配置
# =============================================================================
servers:
  # Nginx负载均衡器（同时运行Portal）
  nginx:
    ip: 192.168.1.10
    hostname: nginx-lb
    run_portal: true           # 是否在此服务器运行Portal
  
  # Node.js应用服务器
  nodejs:
    - ip: 192.168.1.21
      hostname: app-node-1
      db_replica: false        # 是否同时作为MySQL从服务器
    
    - ip: 192.168.1.22
      hostname: app-node-2
      db_replica: true         # 此服务器同时运行MySQL从服务器
  
  # MySQL主服务器
  mysql_master:
    ip: 192.168.1.30
    hostname: db-master

# =============================================================================
# MySQL配置
# =============================================================================
mysql:
  root_password: "SecureRootPass123!"
  
  fido2_node_db:
    name: fido2_node_db
    user: fido2_node
    password: "Fido2NodePass123!"
  
  fido2_portal_db:
    name: fido2_portal_db
    user: fido2_portal
    password: "Fido2PortalPass123!"
  
  replication:
    user: repl_user
    password: "ReplPass123!"
  
  backup:
    path: /var/backups/mysql
    retention_days: 7          # 备份保留天数
    schedule: "0 3"            # Cron格式：每天凌晨3点

# =============================================================================
# 应用配置
# =============================================================================
apps:
  fido2_node:
    port: 8060                 # 应用端口
    instances: "max"           # PM2实例数："max"或具体数字
    storage: mysql             # 存储类型：mysql或mem
    mng_api_token: "your-api-token"
    enable_ex: true            # 启用扩展模块
  
  fido2_portal:
    port: 8065
    instances: 2
    session:
      secret: "your-session-secret"
      timeout_minutes: 30

# =============================================================================
# SSL证书配置
# =============================================================================
ssl:
  email: admin@example.com     # Let's Encrypt通知邮箱
  # 注意：Nginx按子域名区分服务，需要为以下子域名申请证书：
  #   - fido2.{domain} -> FIDO2 API服务
  #   - portal.{domain} -> Portal管理界面
  # 可选方案：1.分别列出子域名(HTTP验证) 2.通配符*.{domain}(需DNS验证)
  domains:
    - fido2.example.com
    - portal.example.com
  staging: false               # true=使用测试环境（首次建议true）
```

## 🔧 部署命令

### cluster-deploy.sh

主部署脚本，用于初始安装和完整部署。

```bash
# 显示帮助
./cluster-deploy.sh --help

# 初始化SSH密钥
./cluster-deploy.sh --init

# 验证配置和连通性
./cluster-deploy.sh --check

# 完整部署（所有组件）
./cluster-deploy.sh --deploy

# 部署指定组件
./cluster-deploy.sh --deploy-component mysql-master
./cluster-deploy.sh --deploy-component mysql-replica
./cluster-deploy.sh --deploy-component nodejs
./cluster-deploy.sh --deploy-component nginx
./cluster-deploy.sh --deploy-component portal

# 仅更新应用代码（快速部署）
./cluster-deploy.sh --update-app
```

### 部署流程说明

完整部署（`--deploy`）按以下顺序执行：

1. **MySQL主服务器**
   - 安装MySQL 8
   - 创建数据库和用户
   - 导入表结构
   - 配置复制用户
   - 设置定时备份

2. **MySQL从服务器**
   - 安装MySQL 8
   - 配置主从复制
   - 启动复制

3. **Node.js服务器**
   - 安装Node.js 20 LTS
   - 安装PM2
   - rsync代码到服务器
   - 生成.env配置
   - 启动应用

4. **Nginx服务器**
   - 安装Nginx
   - 安装Certbot
   - 配置upstream负载均衡
   - 部署Portal应用
   - 申请SSL证书
   - 配置自动续期

## 🛠️ 管理命令

### cluster-manage.sh

日常运维管理脚本。

```bash
# 查看集群状态
./cluster-manage.sh status

# 添加Node.js节点
./cluster-manage.sh add nodejs 192.168.1.25

# 移除Node.js节点
./cluster-manage.sh remove nodejs 192.168.1.25

# 添加MySQL从服务器
./cluster-manage.sh add mysql-replica 192.168.1.26

# MySQL主从切换
./cluster-manage.sh switch-db 192.168.1.22

# 重启服务
./cluster-manage.sh restart nodejs   # 重启所有Node.js
./cluster-manage.sh restart nginx    # 重启Nginx
./cluster-manage.sh restart mysql    # 重启MySQL
./cluster-manage.sh restart portal   # 重启Portal
./cluster-manage.sh restart all      # 重启所有

# 查看日志
./cluster-manage.sh logs 192.168.1.21              # 所有应用日志
./cluster-manage.sh logs 192.168.1.21 fido2-node   # 指定应用日志

# 立即备份数据库
./cluster-manage.sh backup-now

# 更新应用代码
./cluster-manage.sh update-app
```

### health-check.sh

健康检查脚本。

```bash
# 完整健康检查
./health-check.sh

# 仅显示异常项
./health-check.sh --quiet

# JSON格式输出（用于监控集成）
./health-check.sh --json
```

检查项目：
- SSH连接
- Nginx进程和端口
- PM2应用状态
- MySQL进程和端口
- MySQL复制状态和延迟
- HTTP端点响应

## 📘 运维指南

### 日常代码更新

当本地代码有更新时：

```bash
./cluster-manage.sh update-app
```

此命令会：
1. rsync同步代码到所有服务器（排除node_modules、logs等）
2. PM2 reload重启应用（零停机）

### 添加Node.js节点

扩展应用层处理能力：

```bash
# 1. 添加新节点
./cluster-manage.sh add nodejs 192.168.1.25

# 2. 手动更新配置文件
vim config/cluster.yaml
# 在servers.nodejs下添加新服务器

# 3. 验证
./cluster-manage.sh status
```

### MySQL主从切换

当需要将从服务器提升为主服务器时：

```bash
./cluster-manage.sh switch-db 192.168.1.22
```

此命令会：
1. 将原主服务器设为只读
2. 等待从服务器同步完成
3. 提升从服务器为新主
4. 将原主服务器配置为新从
5. 更新所有应用的数据库连接

**注意**：执行后需手动更新`cluster.yaml`中的`mysql_master.ip`。

### 数据库备份与恢复

**自动备份**：每天凌晨3点自动执行，保留7天。

**手动备份**：
```bash
./cluster-manage.sh backup-now
```

**恢复数据**：
```bash
# SSH到MySQL主服务器
ssh deploy@192.168.1.30

# 解压并恢复
gunzip < /var/backups/mysql/fido2_backup_20260131.sql.gz | mysql -uroot -p
```

### SSL证书管理

Let's Encrypt证书自动续期（每月1日）。

**首次部署SSL证书推荐流程**：

1. **测试环境验证**（避免触发速率限制）：
   ```yaml
   # cluster.yaml
   ssl:
     staging: true  # 使用测试证书
   ```
   ```bash
   ./cluster-deploy.sh --deploy  # 完整部署
   ```

2. **验证配置**：检查所有服务是否正常（忽略证书不受信任的警告）

3. **切换正式证书**：
   ```yaml
   # cluster.yaml
   ssl:
     staging: false  # 切换为正式证书
   ```
   ```bash
   # 仅重新部署Nginx和SSL证书（不影响数据库和应用）
   ./cluster-deploy.sh --deploy-component nginx
   ```

> ⚠️ **注意**：从 `staging: true` 切换到 `staging: false` 后，使用 `--deploy-component nginx` 只会更新SSL证书和Nginx配置，**不会影响已部署的数据库、应用服务器和现有数据**。

**手动续期**：
```bash
ssh deploy@nginx-server "sudo certbot renew"
```

**查看证书状态**：
```bash
ssh deploy@nginx-server "sudo certbot certificates"
```

## 🔍 故障排查

### 常见问题

#### 1. SSH连接失败

```
错误: ✗ 192.168.1.21 - 无法连接
```

**解决方案**：
```bash
# 检查SSH服务
ssh deploy@192.168.1.21 -v

# 重新初始化密钥
./cluster-deploy.sh --init
```

#### 2. MySQL复制延迟

```
复制状态: error (IO:No SQL:Yes)
```

**解决方案**：
```bash
# SSH到从服务器检查
ssh deploy@192.168.1.22
mysql -uroot -p -e "SHOW SLAVE STATUS\G"

# 常见原因：网络问题、主服务器负载过高
# 重新配置复制
./cluster-deploy.sh --deploy-component mysql-replica
```

#### 3. PM2应用未启动

```
PM2: not_found
```

**解决方案**：
```bash
# SSH到服务器检查
ssh deploy@192.168.1.21
pm2 list
pm2 logs fido2-node --lines 100

# 重新部署
./cluster-deploy.sh --deploy-component nodejs
```

#### 4. Nginx 502错误

**解决方案**：
```bash
# 检查后端服务
./health-check.sh

# 检查Nginx错误日志
ssh deploy@nginx-server "tail -f /var/log/nginx/fido2.error.log"

# 检查upstream配置
ssh deploy@nginx-server "cat /etc/nginx/conf.d/fido2-upstream.conf"
```

#### 5. Let's Encrypt证书申请失败

```
警告: SSL证书申请失败
```

**解决方案**：
```bash
# 1. 确认DNS已生效
dig fido2.your-domain.com

# 2. 确认80端口可访问
curl http://fido2.your-domain.com/.well-known/acme-challenge/test

# 3. 手动申请
ssh deploy@nginx-server
sudo certbot certonly --nginx -d fido2.your-domain.com -d portal.your-domain.com
```

### 日志位置

| 组件 | 日志路径 |
|------|----------|
| fido2-node | `/opt/fido2-node/logs/` |
| fido2-portal | `/opt/fido2-portal/logs/` |
| PM2 | `pm2 logs` |
| Nginx | `/var/log/nginx/` |
| MySQL | `/var/log/mysql/` |
| 备份 | `/var/log/mysql-backup.log` |

## 🔒 安全建议

### 1. 防火墙配置

在每台服务器上配置UFW：

```bash
# Nginx服务器
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Node.js服务器（仅允许内网）
sudo ufw allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 8060
sudo ufw enable

# MySQL服务器（仅允许内网）
sudo ufw allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 3306
sudo ufw enable
```

### 2. SSH加固

```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
```

### 3. 敏感信息保护

- **不要**将`cluster.yaml`提交到版本控制
- 使用强密码（16位以上，混合字符）
- 定期轮换API令牌和密码

### 4. 定期更新

```bash
# 系统更新
sudo apt update && sudo apt upgrade -y

# Node.js依赖更新
cd /opt/fido2-node && npm audit fix
```

## 📁 文件结构

```
svrmng/
├── cluster-deploy.sh          # 主部署脚本
├── cluster-manage.sh          # 集群管理脚本
├── health-check.sh            # 健康检查脚本
├── README.md                  # 本文档
├── config/
│   ├── cluster.yaml           # 集群配置（需创建）
│   └── cluster.yaml.example   # 配置示例
├── scripts/
│   ├── init-ssh-keys.sh       # SSH密钥初始化
│   ├── install-base.sh        # 基础环境安装
│   ├── install-mysql-master.sh# MySQL主服务器安装
│   ├── install-mysql-replica.sh# MySQL从服务器安装
│   ├── install-nodejs.sh      # Node.js安装
│   ├── install-nginx.sh       # Nginx安装
│   ├── deploy-fido2-node.sh   # fido2-node部署
│   ├── deploy-fido2-portal.sh # fido2-portal部署
│   └── backup-mysql.sh        # MySQL备份脚本
└── templates/
    ├── nginx-upstream.conf    # Nginx upstream模板
    ├── nginx-site.conf        # Nginx站点配置模板
    ├── fido2-node.env         # fido2-node环境变量模板
    ├── fido2-portal.env       # fido2-portal环境变量模板
    ├── pm2-fido2-node.json    # PM2配置
    ├── pm2-fido2-portal.json  # PM2配置
    ├── mysql-master.cnf       # MySQL主服务器配置
    └── mysql-replica.cnf      # MySQL从服务器配置
```

## 📞 支持

如遇问题，请检查：
1. 本文档的故障排查部分
2. 各组件的日志文件
3. `./health-check.sh` 输出

---

**版本**: 1.0.0  
**最后更新**: 2026-01-31
