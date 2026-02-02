#!/bin/bash
# =============================================================================
# FIDO2 集群管理脚本
# =============================================================================
# 用法: ./cluster-manage.sh <命令> [参数]
# 命令:
#   status                    显示集群状态
#   add <层> <IP>             添加服务器节点
#   remove <层> <IP>          移除服务器节点
#   switch-db <新主IP>        MySQL主从切换
#   restart <层|all>          重启服务
#   logs <服务器IP> [应用名]   查看日志
#   backup-now                立即执行数据库备份
#   update-app                更新应用代码
# =============================================================================

set -e

# 脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/cluster.yaml"
SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
TEMPLATES_DIR="${SCRIPT_DIR}/templates"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# 日志函数
# -----------------------------------------------------------------------------
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# -----------------------------------------------------------------------------
# YAML解析
# -----------------------------------------------------------------------------
get_yaml_value() {
    local path=$1
    if command -v yq &> /dev/null; then
        yq e "$path" "$CONFIG_FILE"
    else
        log_error "需要安装 yq"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# SSH函数
# -----------------------------------------------------------------------------
get_scp_opts() {
    local key_file=$(get_yaml_value '.cluster.ssh.key_file')
    local port=$(get_yaml_value '.cluster.ssh.port')

    local opts="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

    if [[ -n "$key_file" && "$key_file" != "null" && -f "${key_file/#\~/$HOME}" ]]; then
        opts="$opts -i ${key_file/#\~/$HOME}"
    fi

    if [[ -n "$port" && "$port" != "null" ]]; then
        opts="$opts -P $port"
    fi

    echo "$opts"
}

get_ssh_opts() {
    local key_file=$(get_yaml_value '.cluster.ssh.key_file')
    local port=$(get_yaml_value '.cluster.ssh.port')

    local opts="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

    if [[ -n "$key_file" && "$key_file" != "null" && -f "${key_file/#\~/$HOME}" ]]; then
        opts="$opts -i ${key_file/#\~/$HOME}"
    fi

    if [[ -n "$port" && "$port" != "null" ]]; then
        opts="$opts -p $port"
    fi

    echo "$opts"
}

remote_exec() {
    local host=$1
    local cmd=$2
    local user=$(get_yaml_value '.cluster.ssh.user')
    local ssh_opts=$(get_ssh_opts)

    ssh $ssh_opts "${user}@${host}" "$cmd" 2>/dev/null
}

remote_exec_script() {
    local host=$1
    local script=$2
    shift 2
    local args="$@"
    local user=$(get_yaml_value '.cluster.ssh.user')
    local ssh_opts=$(get_ssh_opts)
    
    ssh $ssh_opts "${user}@${host}" "bash -s $args" < "$script"
}

rsync_to() {
    local src=$1
    local host=$2
    local dest=$3
    local user=$(get_yaml_value '.cluster.ssh.user')
    local key_file=$(get_yaml_value '.cluster.ssh.key_file')
    
    local rsync_opts="-avz --delete"
    
    if [[ -n "$key_file" && "$key_file" != "null" && -f "${key_file/#\~/$HOME}" ]]; then
        rsync_opts="$rsync_opts -e \"ssh -i ${key_file/#\~/$HOME}\""
    fi
    
    rsync_opts="$rsync_opts --exclude 'node_modules' --exclude 'logs/*' --exclude '.env' --exclude '*.log' --exclude 'svrmng'"
    
    eval rsync $rsync_opts "${src}/" "${user}@${host}:${dest}/"
}

# -----------------------------------------------------------------------------
# 状态检查
# -----------------------------------------------------------------------------
check_server_status() {
    local ip=$1
    local timeout=5
    
    if timeout $timeout ssh $(get_ssh_opts) "$(get_yaml_value '.cluster.ssh.user')@${ip}" "echo ok" &>/dev/null; then
        echo "online"
    else
        echo "offline"
    fi
}

check_pm2_status() {
    local ip=$1
    local app_name=$2
    
    local result=$(remote_exec "$ip" "pm2 jlist 2>/dev/null" || echo "[]")
    
    if echo "$result" | grep -q "\"name\":\"$app_name\""; then
        local status=$(echo "$result" | grep -o "\"name\":\"$app_name\"[^}]*\"status\":\"[^\"]*\"" | grep -o "\"status\":\"[^\"]*\"" | cut -d'"' -f4)
        echo "$status"
    else
        echo "not_found"
    fi
}

check_mysql_status() {
    local ip=$1
    
    if remote_exec "$ip" "systemctl is-active mysql" 2>/dev/null | grep -q "active"; then
        echo "running"
    else
        echo "stopped"
    fi
}

check_mysql_replication() {
    local ip=$1
    local root_pass=$(get_yaml_value '.mysql.root_password')
    
    local result=$(remote_exec "$ip" "mysql -uroot -p'$root_pass' -e 'SHOW SLAVE STATUS\G' 2>/dev/null" || echo "")
    
    if [[ -z "$result" ]]; then
        echo "not_configured"
        return
    fi
    
    local io_running=$(echo "$result" | grep "Slave_IO_Running:" | awk '{print $2}')
    local sql_running=$(echo "$result" | grep "Slave_SQL_Running:" | awk '{print $2}')
    local behind=$(echo "$result" | grep "Seconds_Behind_Master:" | awk '{print $2}')
    
    if [[ "$io_running" == "Yes" && "$sql_running" == "Yes" ]]; then
        echo "ok (延迟: ${behind}s)"
    else
        echo "error (IO:$io_running SQL:$sql_running)"
    fi
}

check_nginx_status() {
    local ip=$1
    
    if remote_exec "$ip" "systemctl is-active nginx" 2>/dev/null | grep -q "active"; then
        echo "running"
    else
        echo "stopped"
    fi
}

# -----------------------------------------------------------------------------
# 显示集群状态
# -----------------------------------------------------------------------------
show_status() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      FIDO2 集群状态                                  ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    
    local cluster_name=$(get_yaml_value '.cluster.name')
    local domain=$(get_yaml_value '.cluster.domain')
    echo -e "${CYAN}║${NC} 集群名称: ${GREEN}$cluster_name${NC}"
    echo -e "${CYAN}║${NC} 域名: ${GREEN}$domain${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    
    # Nginx状态
    echo -e "${CYAN}║${NC} ${YELLOW}【Nginx 负载均衡器】${NC}"
    local nginx_ip=$(get_yaml_value '.servers.nginx.ip')
    local nginx_status=$(check_server_status "$nginx_ip")
    local nginx_svc=$(check_nginx_status "$nginx_ip" 2>/dev/null || echo "unknown")
    local portal_status=$(check_pm2_status "$nginx_ip" "fido2-portal" 2>/dev/null || echo "unknown")
    
    if [[ "$nginx_status" == "online" ]]; then
        echo -e "${CYAN}║${NC}   $nginx_ip: ${GREEN}●${NC} 在线 | Nginx: ${GREEN}$nginx_svc${NC} | Portal: ${GREEN}$portal_status${NC}"
    else
        echo -e "${CYAN}║${NC}   $nginx_ip: ${RED}●${NC} 离线"
    fi
    
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    
    # Node.js状态
    echo -e "${CYAN}║${NC} ${YELLOW}【Node.js 应用服务器】${NC}"
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    for ((i=0; i<nodejs_count; i++)); do
        local ip=$(get_yaml_value ".servers.nodejs[$i].ip")
        local hostname=$(get_yaml_value ".servers.nodejs[$i].hostname")
        local is_replica=$(get_yaml_value ".servers.nodejs[$i].db_replica")
        local status=$(check_server_status "$ip")
        local pm2_status=$(check_pm2_status "$ip" "fido2-node" 2>/dev/null || echo "unknown")
        
        local extra=""
        if [[ "$is_replica" == "true" ]]; then
            extra=" [+MySQL从]"
        fi
        
        if [[ "$status" == "online" ]]; then
            echo -e "${CYAN}║${NC}   $ip ($hostname)$extra: ${GREEN}●${NC} 在线 | PM2: ${GREEN}$pm2_status${NC}"
        else
            echo -e "${CYAN}║${NC}   $ip ($hostname)$extra: ${RED}●${NC} 离线"
        fi
    done
    
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    
    # MySQL状态
    echo -e "${CYAN}║${NC} ${YELLOW}【MySQL 数据库】${NC}"
    local master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    local master_status=$(check_server_status "$master_ip")
    local mysql_status=$(check_mysql_status "$master_ip" 2>/dev/null || echo "unknown")
    
    if [[ "$master_status" == "online" ]]; then
        echo -e "${CYAN}║${NC}   主服务器 $master_ip: ${GREEN}●${NC} 在线 | MySQL: ${GREEN}$mysql_status${NC}"
    else
        echo -e "${CYAN}║${NC}   主服务器 $master_ip: ${RED}●${NC} 离线"
    fi
    
    # 从服务器
    for ((i=0; i<nodejs_count; i++)); do
        local is_replica=$(get_yaml_value ".servers.nodejs[$i].db_replica")
        if [[ "$is_replica" == "true" ]]; then
            local replica_ip=$(get_yaml_value ".servers.nodejs[$i].ip")
            local replica_status=$(check_server_status "$replica_ip")
            local repl_status=$(check_mysql_replication "$replica_ip" 2>/dev/null || echo "unknown")
            
            if [[ "$replica_status" == "online" ]]; then
                echo -e "${CYAN}║${NC}   从服务器 $replica_ip: ${GREEN}●${NC} 在线 | 复制: ${GREEN}$repl_status${NC}"
            else
                echo -e "${CYAN}║${NC}   从服务器 $replica_ip: ${RED}●${NC} 离线"
            fi
        fi
    done
    
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# -----------------------------------------------------------------------------
# 添加服务器节点
# -----------------------------------------------------------------------------
add_node() {
    local layer=$1
    local ip=$2
    
    if [[ -z "$layer" || -z "$ip" ]]; then
        log_error "用法: $0 add <层> <IP>"
        log_info "层: nodejs, mysql-replica"
        exit 1
    fi
    
    case "$layer" in
        nodejs)
            add_nodejs_node "$ip"
            ;;
        mysql-replica)
            add_mysql_replica "$ip"
            ;;
        *)
            log_error "未知层: $layer"
            log_info "支持的层: nodejs, mysql-replica"
            exit 1
            ;;
    esac
}

add_nodejs_node() {
    local ip=$1
    
    log_info "添加Node.js节点: $ip"
    
    # 检查连通性
    if [[ $(check_server_status "$ip") != "online" ]]; then
        log_error "无法连接到服务器 $ip"
        exit 1
    fi
    
    # 安装Node.js
    log_info "安装Node.js环境..."
    remote_exec_script "$ip" "${SCRIPTS_DIR}/install-nodejs.sh"
    
    # 同步代码
    local fido2_node_path=$(get_yaml_value '.cluster.local_paths.fido2_node')
    local fido2_node_ex_path=$(get_yaml_value '.cluster.local_paths.fido2_node_ex')
    local enable_ex=$(get_yaml_value '.apps.fido2_node.enable_ex')
    
    log_info "同步应用代码..."
    rsync_to "${fido2_node_path/#\~/$HOME}" "$ip" "/opt/fido2-node"
    
    if [[ "$enable_ex" == "true" ]]; then
        rsync_to "${fido2_node_ex_path/#\~/$HOME}" "$ip" "/opt/fido2-node-ex"
    fi
    
    # 部署应用
    local app_port=$(get_yaml_value '.apps.fido2_node.port')
    local app_instances=$(get_yaml_value '.apps.fido2_node.instances')
    local storage=$(get_yaml_value '.apps.fido2_node.storage')
    local mng_token=$(get_yaml_value '.apps.fido2_node.mng_api_token')
    local mysql_master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    local db_name=$(get_yaml_value '.mysql.fido2_node_db.name')
    local db_user=$(get_yaml_value '.mysql.fido2_node_db.user')
    local db_pass=$(get_yaml_value '.mysql.fido2_node_db.password')
    local domain=$(get_yaml_value '.cluster.domain')
    
    local user=$(get_yaml_value '.cluster.ssh.user')
    local ssh_opts=$(get_ssh_opts)
    scp $(get_scp_opts) "${TEMPLATES_DIR}/pm2-fido2-node.json" "${user}@${ip}:/tmp/"
    
    log_info "启动应用..."
    remote_exec_script "$ip" "${SCRIPTS_DIR}/deploy-fido2-node.sh" \
        "$app_port" "$app_instances" "$storage" "$mng_token" "$enable_ex" \
        "$mysql_master_ip" "$db_name" "$db_user" "$db_pass" "$domain"
    
    # 更新Nginx upstream
    log_info "更新Nginx负载均衡配置..."
    update_nginx_upstream
    
    log_success "Node.js节点 $ip 添加完成"
    log_warn "请手动更新 config/cluster.yaml 添加此节点配置"
}

add_mysql_replica() {
    local ip=$1
    
    log_info "添加MySQL从服务器: $ip"
    
    if [[ $(check_server_status "$ip") != "online" ]]; then
        log_error "无法连接到服务器 $ip"
        exit 1
    fi
    
    local master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    local root_pass=$(get_yaml_value '.mysql.root_password')
    local repl_user=$(get_yaml_value '.mysql.replication.user')
    local repl_pass=$(get_yaml_value '.mysql.replication.password')
    
    local user=$(get_yaml_value '.cluster.ssh.user')
    local ssh_opts=$(get_ssh_opts)
    scp $(get_scp_opts) "${TEMPLATES_DIR}/mysql-replica.cnf" "${user}@${ip}:/tmp/"
    
    log_info "安装MySQL从服务器..."
    remote_exec_script "$ip" "${SCRIPTS_DIR}/install-mysql-replica.sh" \
        "$root_pass" "$master_ip" "$repl_user" "$repl_pass"
    
    log_success "MySQL从服务器 $ip 添加完成"
}

# -----------------------------------------------------------------------------
# 移除服务器节点
# -----------------------------------------------------------------------------
remove_node() {
    local layer=$1
    local ip=$2
    
    if [[ -z "$layer" || -z "$ip" ]]; then
        log_error "用法: $0 remove <层> <IP>"
        exit 1
    fi
    
    case "$layer" in
        nodejs)
            remove_nodejs_node "$ip"
            ;;
        *)
            log_error "未知层: $layer"
            exit 1
            ;;
    esac
}

remove_nodejs_node() {
    local ip=$1
    
    log_info "移除Node.js节点: $ip"
    
    # 停止PM2应用
    log_info "停止应用..."
    remote_exec "$ip" "pm2 delete fido2-node 2>/dev/null || true"
    
    # 更新Nginx
    log_info "更新Nginx配置..."
    update_nginx_upstream
    
    log_success "Node.js节点 $ip 已移除"
    log_warn "请手动更新 config/cluster.yaml 移除此节点配置"
}

# -----------------------------------------------------------------------------
# 更新Nginx upstream配置
# -----------------------------------------------------------------------------
update_nginx_upstream() {
    local nginx_ip=$(get_yaml_value '.servers.nginx.ip')
    local app_port=$(get_yaml_value '.apps.fido2_node.port')
    
    # 获取所有Node.js服务器
    local upstream_servers=""
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    for ((i=0; i<nodejs_count; i++)); do
        local server_ip=$(get_yaml_value ".servers.nodejs[$i].ip")
        upstream_servers="${upstream_servers}    server ${server_ip}:${app_port};\n"
    done
    
    # 生成upstream配置
    local upstream_config="upstream fido2_backend {\n    ip_hash;\n${upstream_servers}}"
    
    # 更新服务器上的配置
    remote_exec "$nginx_ip" "echo -e '$upstream_config' | sudo tee /etc/nginx/conf.d/fido2-upstream.conf"
    remote_exec "$nginx_ip" "sudo nginx -t && sudo systemctl reload nginx"
    
    log_success "Nginx upstream配置已更新"
}

# -----------------------------------------------------------------------------
# MySQL主从切换
# -----------------------------------------------------------------------------
switch_db() {
    local new_master_ip=$1
    
    if [[ -z "$new_master_ip" ]]; then
        log_error "用法: $0 switch-db <新主服务器IP>"
        exit 1
    fi
    
    log_warn "警告: MySQL主从切换是高风险操作!"
    log_info "新主服务器: $new_master_ip"
    read -p "确认执行? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        log_info "操作已取消"
        exit 0
    fi
    
    local old_master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    local root_pass=$(get_yaml_value '.mysql.root_password')
    local repl_user=$(get_yaml_value '.mysql.replication.user')
    local repl_pass=$(get_yaml_value '.mysql.replication.password')
    
    log_info "步骤1: 停止旧主服务器写入..."
    remote_exec "$old_master_ip" "mysql -uroot -p'$root_pass' -e 'SET GLOBAL read_only = ON; FLUSH TABLES WITH READ LOCK;'"
    
    log_info "步骤2: 等待从服务器同步完成..."
    sleep 5
    
    log_info "步骤3: 停止从服务器复制..."
    remote_exec "$new_master_ip" "mysql -uroot -p'$root_pass' -e 'STOP SLAVE;'"
    
    log_info "步骤4: 提升从服务器为主服务器..."
    remote_exec "$new_master_ip" "mysql -uroot -p'$root_pass' -e 'RESET SLAVE ALL; SET GLOBAL read_only = OFF;'"
    
    log_info "步骤5: 获取新主服务器binlog位置..."
    local master_status=$(remote_exec "$new_master_ip" "mysql -uroot -p'$root_pass' -e 'SHOW MASTER STATUS\G'")
    local log_file=$(echo "$master_status" | grep "File:" | awk '{print $2}')
    local log_pos=$(echo "$master_status" | grep "Position:" | awk '{print $2}')
    
    log_info "步骤6: 将旧主服务器配置为从服务器..."
    remote_exec "$old_master_ip" "mysql -uroot -p'$root_pass' -e \"UNLOCK TABLES; CHANGE MASTER TO MASTER_HOST='$new_master_ip', MASTER_USER='$repl_user', MASTER_PASSWORD='$repl_pass', MASTER_LOG_FILE='$log_file', MASTER_LOG_POS=$log_pos; START SLAVE; SET GLOBAL read_only = ON;\""
    
    log_info "步骤7: 更新应用数据库连接..."
    update_app_db_connection "$new_master_ip"
    
    log_success "MySQL主从切换完成"
    log_warn "请手动更新 config/cluster.yaml 中的 mysql_master.ip 为 $new_master_ip"
}

update_app_db_connection() {
    local new_db_ip=$1
    
    # 更新所有Node.js服务器的环境变量
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    for ((i=0; i<nodejs_count; i++)); do
        local ip=$(get_yaml_value ".servers.nodejs[$i].ip")
        log_info "更新 $ip 的数据库连接..."
        remote_exec "$ip" "sed -i 's/MYSQL_HOST=.*/MYSQL_HOST=$new_db_ip/' /opt/fido2-node/.env && pm2 reload fido2-node"
    done
    
    # 更新Portal
    local nginx_ip=$(get_yaml_value '.servers.nginx.ip')
    remote_exec "$nginx_ip" "sed -i 's/MYSQL_HOST=.*/MYSQL_HOST=$new_db_ip/' /opt/fido2-portal/.env && pm2 reload fido2-portal"
}

# -----------------------------------------------------------------------------
# 重启服务
# -----------------------------------------------------------------------------
restart_service() {
    local layer=$1
    
    if [[ -z "$layer" ]]; then
        log_error "用法: $0 restart <层|all>"
        log_info "层: nodejs, nginx, mysql, portal, all"
        exit 1
    fi
    
    case "$layer" in
        nodejs)
            restart_nodejs
            ;;
        nginx)
            restart_nginx
            ;;
        mysql)
            restart_mysql
            ;;
        portal)
            restart_portal
            ;;
        all)
            restart_mysql
            restart_nodejs
            restart_portal
            restart_nginx
            ;;
        *)
            log_error "未知层: $layer"
            exit 1
            ;;
    esac
}

restart_nodejs() {
    log_info "重启Node.js应用..."
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    for ((i=0; i<nodejs_count; i++)); do
        local ip=$(get_yaml_value ".servers.nodejs[$i].ip")
        log_info "重启 $ip..."
        remote_exec "$ip" "pm2 reload fido2-node"
    done
    log_success "Node.js应用已重启"
}

restart_nginx() {
    log_info "重启Nginx..."
    local nginx_ip=$(get_yaml_value '.servers.nginx.ip')
    remote_exec "$nginx_ip" "sudo systemctl reload nginx"
    log_success "Nginx已重启"
}

restart_mysql() {
    log_info "重启MySQL..."
    local master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    remote_exec "$master_ip" "sudo systemctl restart mysql"
    log_success "MySQL已重启"
}

restart_portal() {
    log_info "重启Portal..."
    local nginx_ip=$(get_yaml_value '.servers.nginx.ip')
    remote_exec "$nginx_ip" "pm2 reload fido2-portal"
    log_success "Portal已重启"
}

# -----------------------------------------------------------------------------
# 查看日志
# -----------------------------------------------------------------------------
show_logs() {
    local server_ip=$1
    local app_name=${2:-"all"}
    
    if [[ -z "$server_ip" ]]; then
        log_error "用法: $0 logs <服务器IP> [应用名]"
        log_info "应用名: fido2-node, fido2-portal, all(默认)"
        exit 1
    fi
    
    log_info "显示 $server_ip 上的 $app_name 日志..."
    
    if [[ "$app_name" == "all" ]]; then
        remote_exec "$server_ip" "pm2 logs --lines 100 --nostream"
    else
        remote_exec "$server_ip" "pm2 logs $app_name --lines 100 --nostream"
    fi
}

# -----------------------------------------------------------------------------
# 立即备份
# -----------------------------------------------------------------------------
backup_now() {
    log_info "执行数据库备份..."
    
    local master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    local backup_path=$(get_yaml_value '.mysql.backup.path')
    
    remote_exec "$master_ip" "sudo /opt/scripts/backup-mysql.sh"
    
    log_success "数据库备份完成"
    log_info "备份位置: $master_ip:$backup_path"
}

# -----------------------------------------------------------------------------
# 更新应用
# -----------------------------------------------------------------------------
update_app() {
    log_info "更新应用代码..."
    
    # 调用deploy脚本的update功能
    "${SCRIPT_DIR}/cluster-deploy.sh" --update-app
}

# -----------------------------------------------------------------------------
# 显示帮助
# -----------------------------------------------------------------------------
show_help() {
    cat << EOF
FIDO2 集群管理脚本

用法: $0 <命令> [参数]

命令:
  status                    显示集群状态概览
  add <层> <IP>             添加服务器节点
                           层: nodejs, mysql-replica
  remove <层> <IP>          移除服务器节点
                           层: nodejs
  switch-db <新主IP>        MySQL主从切换（提升从服务器为主）
  restart <层|all>          重启服务
                           层: nodejs, nginx, mysql, portal, all
  logs <服务器IP> [应用名]   查看PM2日志
                           应用名: fido2-node, fido2-portal, all
  backup-now                立即执行数据库备份
  update-app                更新应用代码（rsync + reload）
  help                      显示此帮助信息

示例:
  $0 status                     # 查看集群状态
  $0 add nodejs 192.168.1.25    # 添加Node.js节点
  $0 remove nodejs 192.168.1.25 # 移除Node.js节点
  $0 switch-db 192.168.1.22     # 切换MySQL主服务器
  $0 restart all                # 重启所有服务
  $0 logs 192.168.1.21 fido2-node  # 查看日志
  $0 backup-now                 # 立即备份数据库
  $0 update-app                 # 更新代码

EOF
}

# -----------------------------------------------------------------------------
# 主入口
# -----------------------------------------------------------------------------
main() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "配置文件不存在: $CONFIG_FILE"
        exit 1
    fi
    
    case "${1:-}" in
        status)
            show_status
            ;;
        add)
            add_node "$2" "$3"
            ;;
        remove)
            remove_node "$2" "$3"
            ;;
        switch-db)
            switch_db "$2"
            ;;
        restart)
            restart_service "$2"
            ;;
        logs)
            show_logs "$2" "$3"
            ;;
        backup-now)
            backup_now
            ;;
        update-app)
            update_app
            ;;
        help|--help|"")
            show_help
            ;;
        *)
            log_error "未知命令: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
