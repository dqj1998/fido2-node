#!/bin/bash
# =============================================================================
# MySQL 数据库备份脚本
# =============================================================================
# 此脚本在MySQL主服务器上执行，进行全量备份
# =============================================================================

set -e

# 配置（由install-mysql-master.sh更新）
BACKUP_DIR="/var/backups/mysql"
MYSQL_USER="root"
MYSQL_PASS=""
RETENTION_DAYS=7

# 日期格式
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/fido2_backup_${DATE}.sql"

echo "=== MySQL 数据库备份 ==="
echo "开始时间: $(date)"
echo "备份文件: ${BACKUP_FILE}.gz"

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 执行备份
echo "导出所有数据库..."
mysqldump -u"$MYSQL_USER" -p"$MYSQL_PASS" \
    --single-transaction \
    --routines \
    --triggers \
    --events \
    --all-databases \
    > "$BACKUP_FILE"

# 压缩备份
echo "压缩备份文件..."
gzip "$BACKUP_FILE"

# 显示备份大小
BACKUP_SIZE=$(ls -lh "${BACKUP_FILE}.gz" | awk '{print $5}')
echo "备份大小: $BACKUP_SIZE"

# 清理过期备份
echo "清理${RETENTION_DAYS}天前的备份..."
find "$BACKUP_DIR" -name "fido2_backup_*.sql.gz" -mtime +$RETENTION_DAYS -delete

# 显示当前备份文件
echo ""
echo "当前备份文件:"
ls -lh "$BACKUP_DIR"/*.gz 2>/dev/null || echo "暂无备份文件"

echo ""
echo "完成时间: $(date)"
echo "=== 备份完成 ==="
