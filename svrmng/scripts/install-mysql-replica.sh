#!/bin/bash
# =============================================================================
# MySQL从服务器安装脚本
# =============================================================================
# 参数:
#   $1 - root密码
#   $2 - 主服务器IP
#   $3 - 复制用户名
#   $4 - 复制用户密码
# =============================================================================

set -e

ROOT_PASS=$1
MASTER_IP=$2
REPL_USER=$3
REPL_PASS=$4

echo "=== 安装 MySQL 从服务器 ==="

# 检查是否已安装MySQL
if command -v mysql &> /dev/null; then
    echo "MySQL已安装，检查版本..."
    mysql --version
else
    # 安装MySQL 8
    echo "安装 MySQL 8..."
    sudo apt-get update -y
    sudo apt-get install -y mysql-server mysql-client
fi

# 停止MySQL以进行配置
sudo systemctl stop mysql

# 复制从服务器配置
echo "配置MySQL从服务器参数..."
if [[ -f /tmp/mysql-replica.cnf ]]; then
    sudo cp /tmp/mysql-replica.cnf /etc/mysql/conf.d/replica.cnf
fi

# 启动MySQL
echo "启动MySQL..."
sudo systemctl start mysql
sudo systemctl enable mysql

# 等待MySQL启动
sleep 5

# 设置root密码
echo "配置root密码..."
sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$ROOT_PASS';" 2>/dev/null || true

# 获取主服务器的binlog位置
echo "获取主服务器binlog位置..."
MASTER_STATUS=$(mysql -h"$MASTER_IP" -u"$REPL_USER" -p"$REPL_PASS" -e "SHOW MASTER STATUS\G" 2>/dev/null)
MASTER_LOG_FILE=$(echo "$MASTER_STATUS" | grep "File:" | awk '{print $2}')
MASTER_LOG_POS=$(echo "$MASTER_STATUS" | grep "Position:" | awk '{print $2}')

if [[ -z "$MASTER_LOG_FILE" ]]; then
    echo "警告: 无法获取主服务器binlog位置，使用默认值"
    MASTER_LOG_FILE="mysql-bin.000001"
    MASTER_LOG_POS=4
fi

echo "主服务器binlog: $MASTER_LOG_FILE, 位置: $MASTER_LOG_POS"

# 配置复制
echo "配置复制..."
mysql -uroot -p"$ROOT_PASS" << EOF
STOP SLAVE;
CHANGE MASTER TO
    MASTER_HOST='$MASTER_IP',
    MASTER_USER='$REPL_USER',
    MASTER_PASSWORD='$REPL_PASS',
    MASTER_LOG_FILE='$MASTER_LOG_FILE',
    MASTER_LOG_POS=$MASTER_LOG_POS;
START SLAVE;
EOF

# 等待复制启动
sleep 3

# 显示从服务器状态
echo ""
echo "=== MySQL 从服务器状态 ==="
mysql -uroot -p"$ROOT_PASS" -e "SHOW SLAVE STATUS\G" | grep -E "Slave_IO_Running|Slave_SQL_Running|Seconds_Behind_Master|Last_Error"

echo ""
echo "=== MySQL 从服务器安装完成 ==="
