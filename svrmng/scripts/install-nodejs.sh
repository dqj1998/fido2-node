#!/bin/bash
# =============================================================================
# Node.js 和 PM2 安装脚本
# =============================================================================
# 安装 Node.js 20 LTS 和 PM2 进程管理器
# =============================================================================

set -e

echo "=== 安装 Node.js 环境 ==="

# 检查是否已安装Node.js
if command -v node &> /dev/null; then
    echo "Node.js已安装，检查版本..."
    node --version
    CURRENT_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    if [[ "$CURRENT_VERSION" -ge 20 ]]; then
        echo "Node.js版本满足要求"
    else
        echo "Node.js版本过低，需要升级..."
        NEED_INSTALL=true
    fi
else
    NEED_INSTALL=true
fi

# 安装Node.js 20 LTS
if [[ "$NEED_INSTALL" == "true" ]]; then
    echo "安装 Node.js 20 LTS..."
    
    # 使用NodeSource安装
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

echo "Node.js版本: $(node --version)"
echo "npm版本: $(npm --version)"

# 安装PM2
if command -v pm2 &> /dev/null; then
    echo "PM2已安装，检查版本..."
    pm2 --version
else
    echo "安装 PM2..."
    sudo npm install -g pm2
fi

# 配置PM2开机启动
echo "配置PM2开机启动..."
pm2 startup systemd -u "$(whoami)" --hp "$HOME" 2>/dev/null || true

# 创建应用目录
echo "创建应用目录..."
mkdir -p /opt/fido2-node
mkdir -p /opt/fido2-node-ex
mkdir -p /opt/fido2-node/logs

echo "=== Node.js 环境安装完成 ==="
