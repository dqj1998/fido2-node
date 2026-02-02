#!/bin/bash
# =============================================================================
# SSH密钥初始化脚本
# =============================================================================
# 此脚本生成SSH密钥对并分发到所有目标服务器
# =============================================================================

set -e

KEY_FILE=$1
SERVERS=$2
USER=$3
PORT=${4:-22}

# 颜色
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== SSH密钥初始化 ===${NC}"

# 生成密钥（如果不存在）
if [[ ! -f "$KEY_FILE" ]]; then
    echo -e "${YELLOW}生成新的SSH密钥对...${NC}"
    mkdir -p "$(dirname "$KEY_FILE")"
    ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "fido2-cluster-deploy"
    echo -e "${GREEN}密钥已生成: $KEY_FILE${NC}"
else
    echo -e "${YELLOW}使用现有密钥: $KEY_FILE${NC}"
fi

# 分发密钥
echo -e "${YELLOW}开始分发密钥到服务器...${NC}"
echo -e "${YELLOW}将会提示输入每台服务器的密码${NC}"
echo ""

IFS=',' read -ra SERVER_ARRAY <<< "$SERVERS"

for server in "${SERVER_ARRAY[@]}"; do
    server=$(echo "$server" | tr -d ' ')
    echo -e "分发密钥到: ${GREEN}$server${NC}"
    
    if ssh-copy-id -p "$PORT" -i "${KEY_FILE}.pub" "${USER}@${server}"; then
        echo -e "${GREEN}✓ $server 密钥分发成功${NC}"
    else
        echo -e "${RED}✗ $server 密钥分发失败${NC}"
    fi
    echo ""
done

echo -e "${GREEN}=== SSH密钥初始化完成 ===${NC}"
