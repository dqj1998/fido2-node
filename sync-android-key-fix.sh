#!/bin/bash

# Android-Key 认证格式修复 - 文件同步脚本
# 用途：备份并同步修改文件到远程服务器（不重启服务）
# 日期：2026-02-04

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 服务器配置
SSH_KEY="~/.ssh/fido2_cluster"
SSH_PORT="22"
SERVERS=(
    "ubuntu@153.126.159.43"
    "ubuntu@153.127.20.133"
)

# 远程路径
REMOTE_BASE_PATH="/opt/fido2-node"

# 本地文件路径
LOCAL_BASE_PATH="/Users/dqj/HDD/fido2Prjs/fido2-node"
FILES_TO_SYNC=(
    "fido2-node-lib/attestations/androidKey.js"
    "fido2-node-lib/main.js"
)

# 时间戳用于备份
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_SUFFIX="_backup_${TIMESTAMP}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Android-Key 修复 - 文件同步${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 函数：在远程服务器执行命令
remote_exec() {
    local server=$1
    local command=$2
    ssh -i ${SSH_KEY} -p ${SSH_PORT} ${server} "${command}" 2>/dev/null
}

# 函数：检测远程路径
detect_remote_path() {
    local server=$1
    
    # 尝试的路径列表
    local paths=(
        "/opt/fido2-node"
        "/home/ubuntu/fido2-node"
        "/var/www/fido2-node"
        "~/fido2-node"
    )
    
    for path in "${paths[@]}"; do
        if remote_exec ${server} "test -f ${path}/main.js"; then
            echo "${path}"
            return 0
        fi
    done
    
    return 1
}

# 函数：备份远程文件
backup_remote_file() {
    local server=$1
    local remote_base=$2
    local file_path=$3
    local remote_full_path="${remote_base}/${file_path}"
    
    echo -e "${YELLOW}[${server}]${NC} 备份: ${file_path}"
    
    # 检查文件是否存在
    if remote_exec ${server} "test -f ${remote_full_path}"; then
        # 创建备份
        remote_exec ${server} "cp ${remote_full_path} ${remote_full_path}${BACKUP_SUFFIX}"
        echo -e "${GREEN}[${server}]${NC} ✓ 已备份: ${file_path}${BACKUP_SUFFIX}"
        return 0
    else
        echo -e "${YELLOW}[${server}]${NC} - 文件不存在（新文件）: ${file_path}"
        return 0
    fi
}

# 函数：同步文件到远程服务器
sync_file() {
    local server=$1
    local remote_base=$2
    local file_path=$3
    local local_full_path="${LOCAL_BASE_PATH}/${file_path}"
    local remote_full_path="${remote_base}/${file_path}"
    local remote_dir=$(dirname ${remote_full_path})
    
    echo -e "${YELLOW}[${server}]${NC} 同步: ${file_path}"
    
    # 确保本地文件存在
    if [ ! -f "${local_full_path}" ]; then
        echo -e "${RED}[${server}]${NC} ✗ 本地文件不存在: ${local_full_path}"
        return 1
    fi
    
    # 确保远程目录存在
    remote_exec ${server} "mkdir -p ${remote_dir}"
    
    # 使用 rsync 同步文件
    rsync -avz -e "ssh -i ${SSH_KEY} -p ${SSH_PORT}" \
        "${local_full_path}" \
        "${server}:${remote_full_path}"
    
    echo -e "${GREEN}[${server}]${NC} ✓ 同步成功: ${file_path}"
    return 0
}

# 函数：同步到单个服务器
sync_to_server() {
    local server=$1
    
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}服务器: ${server}${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # 检测远程路径
    echo -e "${YELLOW}[${server}]${NC} 检测部署路径..."
    local remote_base=$(detect_remote_path ${server})
    if [ $? -ne 0 ] || [ -z "${remote_base}" ]; then
        echo -e "${RED}[${server}]${NC} ✗ 未找到部署路径，跳过此服务器"
        return 1
    fi
    echo -e "${GREEN}[${server}]${NC} ✓ 找到部署路径: ${remote_base}"
    
    # 1. 备份文件
    echo ""
    echo -e "${BLUE}步骤 1/2: 备份现有文件${NC}"
    for file in "${FILES_TO_SYNC[@]}"; do
        backup_remote_file ${server} ${remote_base} ${file}
    done
    
    # 2. 同步新文件
    echo ""
    echo -e "${BLUE}步骤 2/2: 同步新文件${NC}"
    for file in "${FILES_TO_SYNC[@]}"; do
        sync_file ${server} ${remote_base} ${file}
    done
    
    # 验证
    echo ""
    echo -e "${BLUE}验证文件${NC}"
    echo -e "${YELLOW}[${server}]${NC} 检查 androidKey.js:"
    remote_exec ${server} "ls -lh ${remote_base}/fido2-node-lib/attestations/androidKey.js"
    
    echo -e "${GREEN}[${server}]${NC} ✓ 同步完成"
    echo -e "${YELLOW}[${server}]${NC} 📝 请手动重启服务以应用更改"
    
    return 0
}

# 函数：创建回滚脚本
create_rollback_script() {
    local rollback_script="rollback-android-key-${TIMESTAMP}.sh"
    
    echo -e "${BLUE}创建回滚脚本: ${rollback_script}${NC}"
    
    cat > "${rollback_script}" << 'ROLLBACK_EOF'
#!/bin/bash

# Android-Key 修复回滚脚本
# 生成时间: TIMESTAMP_PLACEHOLDER

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SSH_KEY="~/.ssh/fido2_cluster"
SSH_PORT="22"
SERVERS=(
    "ubuntu@153.126.159.43"
    "ubuntu@153.127.20.133"
)

BACKUP_SUFFIX="BACKUP_SUFFIX_PLACEHOLDER"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}回滚 Android-Key 修复${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

read -p "确认要回滚所有服务器吗？(yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "已取消"
    exit 0
fi

detect_path() {
    local server=$1
    local paths=("/opt/fido2-node" "/home/ubuntu/fido2-node" "/var/www/fido2-node")
    for path in "${paths[@]}"; do
        if ssh -i ${SSH_KEY} -p ${SSH_PORT} ${server} "test -f ${path}/main.js" 2>/dev/null; then
            echo "${path}"
            return 0
        fi
    done
    return 1
}

for server in "${SERVERS[@]}"; do
    echo ""
    echo -e "${BLUE}回滚服务器: ${server}${NC}"
    
    remote_base=$(detect_path ${server})
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}[${server}]${NC} 未找到部署路径，跳过"
        continue
    fi
    
    echo -e "${YELLOW}[${server}]${NC} 使用路径: ${remote_base}"
    
    # 恢复 main.js
    file="${remote_base}/fido2-node-lib/main.js"
    backup="${file}${BACKUP_SUFFIX}"
    echo -e "${YELLOW}[${server}]${NC} 恢复 main.js"
    ssh -i ${SSH_KEY} -p ${SSH_PORT} ${server} \
        "if [ -f ${backup} ]; then cp ${backup} ${file} && echo '✓ 已恢复'; else echo '✗ 备份不存在'; fi"
    
    # 删除 androidKey.js
    echo -e "${YELLOW}[${server}]${NC} 删除 androidKey.js"
    ssh -i ${SSH_KEY} -p ${SSH_PORT} ${server} \
        "rm -f ${remote_base}/fido2-node-lib/attestations/androidKey.js && echo '✓ 已删除'"
    
    echo -e "${GREEN}[${server}]${NC} ✓ 回滚完成"
    echo -e "${YELLOW}[${server}]${NC} 📝 请手动重启服务"
done

echo ""
echo -e "${GREEN}回滚完成！请手动重启各服务器的服务${NC}"
ROLLBACK_EOF

    # 替换占位符
    sed -i '' "s/TIMESTAMP_PLACEHOLDER/${TIMESTAMP}/g" "${rollback_script}"
    sed -i '' "s/BACKUP_SUFFIX_PLACEHOLDER/${BACKUP_SUFFIX}/g" "${rollback_script}"
    
    chmod +x "${rollback_script}"
    echo -e "${GREEN}✓ 回滚脚本已创建: ${rollback_script}${NC}"
}

# 主流程
main() {
    echo "准备同步到 ${#SERVERS[@]} 个服务器节点"
    echo "备份时间戳: ${TIMESTAMP}"
    echo ""
    echo -e "${YELLOW}文件列表:${NC}"
    for file in "${FILES_TO_SYNC[@]}"; do
        echo "  - ${file}"
    done
    echo ""
    
    # 确认
    read -p "确认开始同步？(yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "已取消同步"
        exit 0
    fi
    
    # 创建回滚脚本
    echo ""
    create_rollback_script
    echo ""
    
    # 同步到每个服务器
    local success_count=0
    local fail_count=0
    
    for server in "${SERVERS[@]}"; do
        if sync_to_server ${server}; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        echo ""
    done
    
    # 完成总结
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}同步完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BLUE}同步摘要：${NC}"
    echo -e "  - 同步时间: ${TIMESTAMP}"
    echo -e "  - 成功: ${success_count} 台"
    echo -e "  - 失败: ${fail_count} 台"
    echo -e "  - 备份后缀: ${BACKUP_SUFFIX}"
    echo ""
    echo -e "${YELLOW}⚠️  重要提醒：${NC}"
    echo -e "${YELLOW}   请手动到各服务器重启 FIDO2 服务以应用更改${NC}"
    echo ""
    echo -e "${BLUE}重启命令参考：${NC}"
    echo -e "  pm2 restart fido2-node"
    echo -e "  或"
    echo -e "  pkill -f 'node.*main.js' && nohup node main.js >> logs/start.log 2>&1 &"
    echo ""
}

# 执行主流程
main
