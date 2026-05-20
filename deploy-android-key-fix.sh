#!/bin/bash

# Android-Key 认证格式修复部署脚本
# 用途：将修改同步到远程服务器并重启服务
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

# 远程路径（根据实际情况调整）
REMOTE_BASE_PATH="/home/ubuntu/fido2-node"

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
echo -e "${BLUE}Android-Key 认证格式修复部署${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 函数：在远程服务器执行命令
remote_exec() {
    local server=$1
    local command=$2
    echo -e "${YELLOW}[${server}]${NC} 执行: ${command}"
    ssh -i ${SSH_KEY} -p ${SSH_PORT} ${server} "${command}"
}

# 函数：备份远程文件
backup_remote_file() {
    local server=$1
    local file_path=$2
    local remote_full_path="${REMOTE_BASE_PATH}/${file_path}"
    
    echo -e "${YELLOW}[${server}]${NC} 备份: ${file_path}"
    
    # 检查文件是否存在
    if ssh -i ${SSH_KEY} -p ${SSH_PORT} ${server} "test -f ${remote_full_path}"; then
        # 创建备份
        remote_exec ${server} "cp ${remote_full_path} ${remote_full_path}${BACKUP_SUFFIX}"
        echo -e "${GREEN}[${server}]${NC} ✓ 备份成功: ${file_path}${BACKUP_SUFFIX}"
    else
        echo -e "${YELLOW}[${server}]${NC} ⚠ 文件不存在，跳过备份: ${file_path}"
    fi
}

# 函数：同步文件到远程服务器
sync_file() {
    local server=$1
    local file_path=$2
    local local_full_path="${LOCAL_BASE_PATH}/${file_path}"
    local remote_full_path="${REMOTE_BASE_PATH}/${file_path}"
    local remote_dir=$(dirname ${remote_full_path})
    
    echo -e "${YELLOW}[${server}]${NC} 同步: ${file_path}"
    
    # 确保远程目录存在
    remote_exec ${server} "mkdir -p ${remote_dir}"
    
    # 使用 rsync 同步文件
    rsync -avz -e "ssh -i ${SSH_KEY} -p ${SSH_PORT}" \
        ${local_full_path} \
        ${server}:${remote_full_path}
    
    echo -e "${GREEN}[${server}]${NC} ✓ 同步成功: ${file_path}"
}

# 函数：在服务器上部署
deploy_to_server() {
    local server=$1
    
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}部署到服务器: ${server}${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # 1. 备份文件
    echo -e "${BLUE}步骤 1/4: 备份现有文件${NC}"
    for file in "${FILES_TO_SYNC[@]}"; do
        backup_remote_file ${server} ${file}
    done
    
    # 2. 同步新文件
    echo ""
    echo -e "${BLUE}步骤 2/4: 同步新文件${NC}"
    for file in "${FILES_TO_SYNC[@]}"; do
        sync_file ${server} ${file}
    done
    
    # 3. 验证文件
    echo ""
    echo -e "${BLUE}步骤 3/4: 验证文件${NC}"
    remote_exec ${server} "ls -lh ${REMOTE_BASE_PATH}/fido2-node-lib/attestations/androidKey.js"
    
    # 4. 重启服务
    echo ""
    echo -e "${BLUE}步骤 4/4: 重启 FIDO2 服务${NC}"
    
    # 尝试使用 pm2 重启
    echo -e "${YELLOW}[${server}]${NC} 尝试使用 pm2 重启服务..."
    if remote_exec ${server} "command -v pm2 > /dev/null 2>&1"; then
        # pm2 存在，尝试重启
        remote_exec ${server} "cd ${REMOTE_BASE_PATH} && pm2 restart fido2-node || pm2 restart all || true"
        echo -e "${GREEN}[${server}]${NC} ✓ PM2 重启命令已执行"
    else
        echo -e "${YELLOW}[${server}]${NC} PM2 未安装，尝试查找并重启 Node 进程..."
        
        # 查找 main.js 进程并重启
        remote_exec ${server} "pkill -f 'node.*main.js' || true"
        sleep 2
        remote_exec ${server} "cd ${REMOTE_BASE_PATH} && nohup node main.js >> logs/start.log 2>&1 &"
        echo -e "${GREEN}[${server}]${NC} ✓ 服务已重启"
    fi
    
    # 等待服务启动
    echo -e "${YELLOW}[${server}]${NC} 等待服务启动..."
    sleep 3
    
    # 检查进程状态
    echo -e "${YELLOW}[${server}]${NC} 检查服务状态..."
    if remote_exec ${server} "pgrep -f 'node.*main.js' > /dev/null 2>&1"; then
        echo -e "${GREEN}[${server}]${NC} ✓ 服务运行正常"
    else
        echo -e "${RED}[${server}]${NC} ✗ 警告：未检测到服务进程"
    fi
    
    echo -e "${GREEN}[${server}]${NC} ✓ 部署完成"
}

# 函数：创建回滚脚本
create_rollback_script() {
    local rollback_script="rollback-android-key-${TIMESTAMP}.sh"
    
    echo -e "${BLUE}创建回滚脚本: ${rollback_script}${NC}"
    
    cat > ${rollback_script} << 'ROLLBACK_EOF'
#!/bin/bash

# Android-Key 修复回滚脚本
# 生成时间: TIMESTAMP_PLACEHOLDER

set -e

RED='\033[0;31m'
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

REMOTE_BASE_PATH="/home/ubuntu/fido2-node"
BACKUP_SUFFIX="BACKUP_SUFFIX_PLACEHOLDER"

FILES=(
    "fido2-node-lib/main.js"
)

echo -e "${RED}========================================${NC}"
echo -e "${RED}回滚 Android-Key 修复${NC}"
echo -e "${RED}========================================${NC}"
echo ""

read -p "确认要回滚所有服务器吗？(yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "已取消"
    exit 0
fi

for server in "${SERVERS[@]}"; do
    echo ""
    echo -e "${BLUE}回滚服务器: ${server}${NC}"
    
    for file in "${FILES[@]}"; do
        remote_file="${REMOTE_BASE_PATH}/${file}"
        backup_file="${remote_file}${BACKUP_SUFFIX}"
        
        echo -e "${YELLOW}[${server}]${NC} 恢复: ${file}"
        ssh -i ${SSH_KEY} -p ${SSH_PORT} ${server} \
            "if [ -f ${backup_file} ]; then cp ${backup_file} ${remote_file}; echo '✓ 已恢复'; else echo '✗ 备份文件不存在'; fi"
    done
    
    # 删除 androidKey.js
    echo -e "${YELLOW}[${server}]${NC} 删除: fido2-node-lib/attestations/androidKey.js"
    ssh -i ${SSH_KEY} -p ${SSH_PORT} ${server} \
        "rm -f ${REMOTE_BASE_PATH}/fido2-node-lib/attestations/androidKey.js"
    
    # 重启服务
    echo -e "${YELLOW}[${server}]${NC} 重启服务..."
    ssh -i ${SSH_KEY} -p ${SSH_PORT} ${server} \
        "cd ${REMOTE_BASE_PATH} && (pm2 restart fido2-node || pm2 restart all || (pkill -f 'node.*main.js' && nohup node main.js >> logs/start.log 2>&1 &))"
    
    echo -e "${GREEN}[${server}]${NC} ✓ 回滚完成"
done

echo ""
echo -e "${GREEN}所有服务器回滚完成${NC}"
ROLLBACK_EOF

    # 替换占位符
    sed -i '' "s/TIMESTAMP_PLACEHOLDER/${TIMESTAMP}/g" ${rollback_script}
    sed -i '' "s/BACKUP_SUFFIX_PLACEHOLDER/${BACKUP_SUFFIX}/g" ${rollback_script}
    
    chmod +x ${rollback_script}
    echo -e "${GREEN}✓ 回滚脚本已创建: ${rollback_script}${NC}"
    echo -e "${YELLOW}如需回滚，请执行: ./${rollback_script}${NC}"
}

# 主流程
main() {
    echo "准备部署到 ${#SERVERS[@]} 个服务器节点"
    echo "备份后缀: ${BACKUP_SUFFIX}"
    echo ""
    
    # 确认
    read -p "确认开始部署？(yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "已取消部署"
        exit 0
    fi
    
    # 创建回滚脚本
    create_rollback_script
    echo ""
    
    # 部署到每个服务器
    for server in "${SERVERS[@]}"; do
        deploy_to_server ${server}
        echo ""
    done
    
    # 完成
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}部署完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BLUE}部署摘要：${NC}"
    echo -e "  - 部署时间: ${TIMESTAMP}"
    echo -e "  - 服务器数量: ${#SERVERS[@]}"
    echo -e "  - 备份后缀: ${BACKUP_SUFFIX}"
    echo ""
    echo -e "${YELLOW}测试建议：${NC}"
    echo -e "  1. 在各服务器测试 Android 设备认证"
    echo -e "  2. 检查服务器日志是否有错误"
    echo -e "  3. 如有问题，使用回滚脚本恢复"
    echo ""
}

# 执行主流程
main
