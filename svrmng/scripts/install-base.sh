#!/bin/bash
# =============================================================================
# Ubuntu基础环境安装脚本
# =============================================================================
# 在目标服务器上执行，安装基础工具和配置
# =============================================================================

set -e

echo "=== 安装基础环境 ==="

# 更新包列表
echo "更新包列表..."
sudo apt-get update -y

# 安装基础工具
echo "安装基础工具..."
sudo apt-get install -y \
    curl \
    wget \
    git \
    jq \
    unzip \
    htop \
    net-tools \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release

# 配置时区（亚洲/东京）
echo "配置时区..."
sudo timedatectl set-timezone Asia/Tokyo

# 配置系统限制
echo "配置系统限制..."
cat << 'EOF' | sudo tee /etc/security/limits.d/fido2.conf
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOF

# 配置sysctl
echo "配置内核参数..."
cat << 'EOF' | sudo tee /etc/sysctl.d/99-fido2.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
EOF

sudo sysctl --system

# 创建应用目录
echo "创建应用目录..."
sudo mkdir -p /opt/fido2-node
sudo mkdir -p /opt/fido2-node-ex
sudo mkdir -p /opt/fido2-portal
sudo mkdir -p /opt/scripts

# 设置目录权限
DEPLOY_USER=${1:-$(whoami)}
sudo chown -R "$DEPLOY_USER:$DEPLOY_USER" /opt/fido2-node
sudo chown -R "$DEPLOY_USER:$DEPLOY_USER" /opt/fido2-node-ex
sudo chown -R "$DEPLOY_USER:$DEPLOY_USER" /opt/fido2-portal
sudo chown -R "$DEPLOY_USER:$DEPLOY_USER" /opt/scripts

echo "=== 基础环境安装完成 ==="
