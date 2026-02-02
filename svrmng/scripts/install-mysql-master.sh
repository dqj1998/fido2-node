#!/bin/bash
# =============================================================================
# MySQL主服务器安装脚本
# =============================================================================
# 参数:
#   $1  - root密码
#   $2  - 复制用户名
#   $3  - 复制用户密码
#   $4  - fido2_node数据库名
#   $5  - fido2_node用户名
#   $6  - fido2_node密码
#   $7  - fido2_portal数据库名
#   $8  - fido2_portal用户名
#   $9  - fido2_portal密码
#   $10 - 备份路径
#   $11 - 备份保留天数
#   $12 - 备份计划 (cron格式：分 时)
# =============================================================================

set -e

ROOT_PASS=$1
REPL_USER=$2
REPL_PASS=$3
FIDO2_NODE_DB=$4
FIDO2_NODE_USER=$5
FIDO2_NODE_PASS=$6
FIDO2_PORTAL_DB=$7
FIDO2_PORTAL_USER=$8
FIDO2_PORTAL_PASS=$9
BACKUP_PATH=${10}
BACKUP_RETENTION=${11}
BACKUP_SCHEDULE=${12}

echo "=== 安装 MySQL 主服务器 ==="

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

# 复制主服务器配置
echo "配置MySQL主服务器参数..."
if [[ -f /tmp/mysql-master.cnf ]]; then
    sudo cp /tmp/mysql-master.cnf /etc/mysql/conf.d/master.cnf
fi

# 确保数据目录权限正确
sudo chown -R mysql:mysql /var/lib/mysql

# 启动MySQL
echo "启动MySQL..."
sudo systemctl start mysql
sudo systemctl enable mysql

# 等待MySQL启动
sleep 5

# 设置root密码（MySQL 8）
echo "配置root密码..."
if ! sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$ROOT_PASS';" 2>/dev/null; then
    # MySQL已有密码，尝试使用debian-sys-maint
    DEBIAN_MYSQL_PASS=$(sudo cat /etc/mysql/debian.cnf | grep -A1 'client]' | grep password | cut -d'=' -f2)
    sudo mysql -u debian-sys-maint -p"$DEBIAN_MYSQL_PASS" -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$ROOT_PASS';" 2>/dev/null
fi

# 创建复制用户
echo "创建复制用户..."
mysql -uroot -p"$ROOT_PASS" << EOF
CREATE USER IF NOT EXISTS '$REPL_USER'@'%' IDENTIFIED WITH mysql_native_password BY '$REPL_PASS';
GRANT REPLICATION SLAVE ON *.* TO '$REPL_USER'@'%';
FLUSH PRIVILEGES;
EOF

# 创建fido2_node数据库和用户
echo "创建 $FIDO2_NODE_DB 数据库..."
mysql -uroot -p"$ROOT_PASS" << EOF
CREATE DATABASE IF NOT EXISTS $FIDO2_NODE_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$FIDO2_NODE_USER'@'%' IDENTIFIED WITH mysql_native_password BY '$FIDO2_NODE_PASS';
GRANT ALL PRIVILEGES ON $FIDO2_NODE_DB.* TO '$FIDO2_NODE_USER'@'%';
FLUSH PRIVILEGES;
EOF

# 导入fido2_node_db DDL
if [[ -f /tmp/create_db_mysql.sql ]]; then
    echo "导入 fido2_node_db 表结构..."
    mysql -uroot -p"$ROOT_PASS" "$FIDO2_NODE_DB" < /tmp/create_db_mysql.sql
fi

# 创建fido2_portal数据库和用户
echo "创建 $FIDO2_PORTAL_DB 数据库..."
mysql -uroot -p"$ROOT_PASS" << EOF
CREATE DATABASE IF NOT EXISTS $FIDO2_PORTAL_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$FIDO2_PORTAL_USER'@'%' IDENTIFIED WITH mysql_native_password BY '$FIDO2_PORTAL_PASS';
GRANT ALL PRIVILEGES ON $FIDO2_PORTAL_DB.* TO '$FIDO2_PORTAL_USER'@'%';
FLUSH PRIVILEGES;
EOF

# 导入fido2_portal_db DDL
if [[ -f /tmp/create_portal_db_mysql.sql ]]; then
    echo "导入 fido2_portal_db 表结构..."
    mysql -uroot -p"$ROOT_PASS" "$FIDO2_PORTAL_DB" < /tmp/create_portal_db_mysql.sql
fi

# 创建备份目录
echo "配置备份..."
sudo mkdir -p "$BACKUP_PATH"
sudo chown mysql:mysql "$BACKUP_PATH"

# 复制备份脚本
if [[ -f /tmp/backup-mysql.sh ]]; then
    sudo cp /tmp/backup-mysql.sh /opt/scripts/backup-mysql.sh
    sudo chmod +x /opt/scripts/backup-mysql.sh
    
    # 更新备份脚本中的变量
    sudo sed -i "s|BACKUP_DIR=.*|BACKUP_DIR=\"$BACKUP_PATH\"|" /opt/scripts/backup-mysql.sh
    sudo sed -i "s|MYSQL_PASS=.*|MYSQL_PASS=\"$ROOT_PASS\"|" /opt/scripts/backup-mysql.sh
    sudo sed -i "s|RETENTION_DAYS=.*|RETENTION_DAYS=$BACKUP_RETENTION|" /opt/scripts/backup-mysql.sh
fi

# 配置cron备份任务
echo "配置定时备份..."
CRON_MIN=$(echo "$BACKUP_SCHEDULE" | awk '{print $1}')
CRON_HOUR=$(echo "$BACKUP_SCHEDULE" | awk '{print $2}')
(crontab -l 2>/dev/null | grep -v "backup-mysql.sh"; echo "$CRON_MIN $CRON_HOUR * * * /opt/scripts/backup-mysql.sh >> /var/log/mysql-backup.log 2>&1") | crontab -

# 显示主服务器状态
echo ""
echo "=== MySQL 主服务器状态 ==="
mysql -uroot -p"$ROOT_PASS" -e "SHOW MASTER STATUS\G"

echo ""
echo "=== MySQL 主服务器安装完成 ==="
