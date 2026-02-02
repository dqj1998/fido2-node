#!/bin/bash
# =============================================================================
# FIDO2 集群部署脚本
# =============================================================================
# 用法: ./cluster-deploy.sh <命令> [选项]
# 命令:
#   --init              初始化SSH密钥并分发到所有服务器
#   --check             验证配置文件和服务器连通性
#   --deploy            完整部署整个集群
#   --deploy-component  部署指定组件 (mysql-master|mysql-replica|nodejs|nginx|portal)
#   --update-app        仅更新应用代码（不重新安装依赖）
#   --help              显示帮助信息
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
NC='\033[0m' # No Color

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

log_step() {
    echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# -----------------------------------------------------------------------------
# YAML解析函数（使用yq或纯bash）
# -----------------------------------------------------------------------------
parse_yaml() {
    local yaml_file=$1
    local prefix=$2
    
    if command -v yq &> /dev/null; then
        # 使用yq解析
        eval $(yq e '.. | select(. == "*") | {(path | join("_")): .}' "$yaml_file" 2>/dev/null | \
            sed 's/: /="/;s/$/"/' | sed "s/^/${prefix}_/")
    else
        # 简单的bash解析（仅支持基本结构）
        local s='[[:space:]]*'
        local w='[a-zA-Z0-9_]*'
        sed -ne "s|^\($s\)\($w\)$s:$s\"\(.*\)\"$s\$|\1\2=\"\3\"|p" \
            -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1\2=\"\3\"|p" "$yaml_file" | \
        sed -e 's/^[[:space:]]*//' | \
        while IFS='=' read -r key value; do
            echo "${prefix}_${key}=${value}"
        done
    fi
}

# 获取YAML值的函数
get_yaml_value() {
    local path=$1
    if command -v yq &> /dev/null; then
        yq e "$path" "$CONFIG_FILE"
    else
        log_error "需要安装 yq 来解析YAML配置文件"
        log_info "安装方法: brew install yq (macOS) 或 sudo snap install yq (Ubuntu)"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# SSH和远程执行函数
# -----------------------------------------------------------------------------
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

remote_exec() {
    local host=$1
    local cmd=$2
    local user=$(get_yaml_value '.cluster.ssh.user')
    local ssh_opts=$(get_ssh_opts)
    
    ssh $ssh_opts "${user}@${host}" "$cmd"
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
    local exclude=$4
    local user=$(get_yaml_value '.cluster.ssh.user')
    local key_file=$(get_yaml_value '.cluster.ssh.key_file')
    local port=$(get_yaml_value '.cluster.ssh.port')

    local ssh_cmd="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10"
    if [[ -n "$key_file" && "$key_file" != "null" && -f "${key_file/#\~/$HOME}" ]]; then
        ssh_cmd="$ssh_cmd -i ${key_file/#\~/$HOME}"
    fi
    if [[ -n "$port" && "$port" != "null" ]]; then
        ssh_cmd="$ssh_cmd -p $port"
    fi

    local rsync_opts="-avz --delete -e \"$ssh_cmd\""
    rsync_opts="$rsync_opts --exclude 'node_modules' --exclude 'logs/*' --exclude '.env' --exclude '*.log' --exclude 'svrmng'"

    if [[ -n "$exclude" ]]; then
        rsync_opts="$rsync_opts --exclude '$exclude'"
    fi

    eval rsync $rsync_opts "${src}/" "${user}@${host}:${dest}/"
}

# -----------------------------------------------------------------------------
# 检查依赖
# -----------------------------------------------------------------------------
check_dependencies() {
    log_step "检查本地依赖"
    
    local missing=()
    
    if ! command -v yq &> /dev/null; then
        missing+=("yq")
    fi
    
    if ! command -v ssh &> /dev/null; then
        missing+=("ssh")
    fi
    
    if ! command -v rsync &> /dev/null; then
        missing+=("rsync")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少以下依赖: ${missing[*]}"
        log_info "请安装缺少的依赖后重试"
        log_info "  macOS: brew install ${missing[*]}"
        log_info "  Ubuntu: sudo apt install ${missing[*]}"
        exit 1
    fi
    
    log_success "所有依赖已安装"
}

# -----------------------------------------------------------------------------
# 检查配置文件
# -----------------------------------------------------------------------------
check_config() {
    log_step "检查配置文件"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "配置文件不存在: $CONFIG_FILE"
        log_info "请复制示例配置文件并修改:"
        log_info "  cp ${SCRIPT_DIR}/config/cluster.yaml.example ${CONFIG_FILE}"
        exit 1
    fi
    
    # 验证必要字段
    local required_fields=(
        ".cluster.name"
        ".cluster.domain"
        ".cluster.ssh.user"
        ".servers.nginx.ip"
        ".servers.mysql_master.ip"
        ".mysql.root_password"
    )
    
    for field in "${required_fields[@]}"; do
        local value=$(get_yaml_value "$field")
        if [[ -z "$value" || "$value" == "null" ]]; then
            log_error "配置文件缺少必要字段: $field"
            exit 1
        fi
    done
    
    # 检查本地项目路径
    local fido2_node_path=$(get_yaml_value '.cluster.local_paths.fido2_node')
    local fido2_portal_path=$(get_yaml_value '.cluster.local_paths.fido2_portal')
    
    if [[ ! -d "${fido2_node_path/#\~/$HOME}" ]]; then
        log_error "fido2-node 项目路径不存在: $fido2_node_path"
        exit 1
    fi
    
    if [[ ! -d "${fido2_portal_path/#\~/$HOME}" ]]; then
        log_error "fido2-portal 项目路径不存在: $fido2_portal_path"
        exit 1
    fi
    
    log_success "配置文件验证通过"
}

# -----------------------------------------------------------------------------
# 获取所有服务器IP
# -----------------------------------------------------------------------------
get_all_servers() {
    local servers=()
    
    # Nginx服务器
    servers+=($(get_yaml_value '.servers.nginx.ip'))
    
    # Node.js服务器
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    for ((i=0; i<nodejs_count; i++)); do
        servers+=($(get_yaml_value ".servers.nodejs[$i].ip"))
    done
    
    # MySQL主服务器
    servers+=($(get_yaml_value '.servers.mysql_master.ip'))
    
    # 去重
    printf '%s\n' "${servers[@]}" | sort -u
}

# -----------------------------------------------------------------------------
# 初始化SSH密钥
# -----------------------------------------------------------------------------
init_ssh_keys() {
    log_step "初始化SSH密钥"
    
    local key_file=$(get_yaml_value '.cluster.ssh.key_file')
    key_file="${key_file/#\~/$HOME}"
    
    # 如果密钥文件不存在，生成新密钥
    if [[ ! -f "$key_file" ]]; then
        log_info "生成新的SSH密钥对: $key_file"
        mkdir -p "$(dirname "$key_file")"
        ssh-keygen -t ed25519 -f "$key_file" -N "" -C "fido2-cluster-deploy"
        log_success "SSH密钥已生成"
    else
        log_info "使用现有SSH密钥: $key_file"
    fi
    
    # 分发密钥到所有服务器
    local user=$(get_yaml_value '.cluster.ssh.user')
    local port=$(get_yaml_value '.cluster.ssh.port')
    local port_opt=""
    if [[ -n "$port" && "$port" != "null" ]]; then
        port_opt="-p $port"
    fi
    
    log_info "开始分发SSH密钥到所有服务器..."
    log_warn "将会提示输入每台服务器的密码"
    
    for server in $(get_all_servers); do
        log_info "分发密钥到: $server"
        ssh-copy-id $port_opt -i "${key_file}.pub" "${user}@${server}" || {
            log_error "无法分发密钥到 $server"
            log_info "请确保:"
            log_info "  1. 服务器 $server 可以访问"
            log_info "  2. 用户 $user 存在且有sudo权限"
            log_info "  3. SSH服务正在运行"
            continue
        }
        log_success "密钥已分发到 $server"
    done
    
    log_success "SSH密钥初始化完成"
}

# -----------------------------------------------------------------------------
# 检查服务器连通性
# -----------------------------------------------------------------------------
check_connectivity() {
    log_step "检查服务器连通性"
    
    local all_ok=true
    
    for server in $(get_all_servers); do
        if remote_exec "$server" "echo 'OK'" &>/dev/null; then
            log_success "✓ $server - 连接正常"
        else
            log_error "✗ $server - 无法连接"
            all_ok=false
        fi
    done
    
    if [[ "$all_ok" != "true" ]]; then
        log_warn "部分服务器无法连接，将跳过不可达的服务器"
        # exit 1
    fi
    
    log_success "所有服务器连接正常"
}

# -----------------------------------------------------------------------------
# 部署MySQL主服务器
# -----------------------------------------------------------------------------
deploy_mysql_master() {
    log_step "部署 MySQL 主服务器"
    
    local master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    local root_pass=$(get_yaml_value '.mysql.root_password')
    local repl_user=$(get_yaml_value '.mysql.replication.user')
    local repl_pass=$(get_yaml_value '.mysql.replication.password')
    local fido2_node_db=$(get_yaml_value '.mysql.fido2_node_db.name')
    local fido2_node_user=$(get_yaml_value '.mysql.fido2_node_db.user')
    local fido2_node_pass=$(get_yaml_value '.mysql.fido2_node_db.password')
    local fido2_portal_db=$(get_yaml_value '.mysql.fido2_portal_db.name')
    local fido2_portal_user=$(get_yaml_value '.mysql.fido2_portal_db.user')
    local fido2_portal_pass=$(get_yaml_value '.mysql.fido2_portal_db.password')
    local backup_path=$(get_yaml_value '.mysql.backup.path')
    local backup_retention=$(get_yaml_value '.mysql.backup.retention_days')
    local backup_schedule=$(get_yaml_value '.mysql.backup.schedule')
    
    local fido2_node_path=$(get_yaml_value '.cluster.local_paths.fido2_node')
    local fido2_portal_path=$(get_yaml_value '.cluster.local_paths.fido2_portal')
    
    log_info "目标服务器: $master_ip"
    
    # 复制SQL文件到服务器
    local user=$(get_yaml_value '.cluster.ssh.user')

    log_info "复制数据库DDL文件..."
    scp $(get_scp_opts) "${fido2_node_path/#\~/$HOME}/SQLs/create_db_mysql.sql" "${user}@${master_ip}:/tmp/"
    scp $(get_scp_opts) "${fido2_portal_path/#\~/$HOME}/SQLs/create_portal_db_mysql.sql" "${user}@${master_ip}:/tmp/"
    
    # 复制MySQL配置模板
    scp $(get_scp_opts) "${TEMPLATES_DIR}/mysql-master.cnf" "${user}@${master_ip}:/tmp/"
    
    # 复制备份脚本
    scp $(get_scp_opts) "${SCRIPTS_DIR}/backup-mysql.sh" "${user}@${master_ip}:/tmp/"
    
    # 执行安装脚本
    log_info "执行MySQL主服务器安装..."
    remote_exec_script "$master_ip" "${SCRIPTS_DIR}/install-mysql-master.sh" \
        "$root_pass" "$repl_user" "$repl_pass" \
        "$fido2_node_db" "$fido2_node_user" "$fido2_node_pass" \
        "$fido2_portal_db" "$fido2_portal_user" "$fido2_portal_pass" \
        "$backup_path" "$backup_retention" "$backup_schedule"
    
    log_success "MySQL主服务器部署完成"
}

# -----------------------------------------------------------------------------
# 部署MySQL从服务器
# -----------------------------------------------------------------------------
deploy_mysql_replica() {
    log_step "部署 MySQL 从服务器"
    
    local master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    local root_pass=$(get_yaml_value '.mysql.root_password')
    local repl_user=$(get_yaml_value '.mysql.replication.user')
    local repl_pass=$(get_yaml_value '.mysql.replication.password')
    
    # 找到标记为db_replica的Node.js服务器
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    local replica_ip=""
    
    for ((i=0; i<nodejs_count; i++)); do
        local is_replica=$(get_yaml_value ".servers.nodejs[$i].db_replica")
        if [[ "$is_replica" == "true" ]]; then
            replica_ip=$(get_yaml_value ".servers.nodejs[$i].ip")
            break
        fi
    done
    
    if [[ -z "$replica_ip" ]]; then
        log_warn "未配置MySQL从服务器，跳过"
        return 0
    fi
    
    log_info "目标服务器: $replica_ip (复用Node.js服务器)"
    
    # 复制MySQL配置模板
    local user=$(get_yaml_value '.cluster.ssh.user')
    local ssh_opts=$(get_ssh_opts)
    scp $(get_scp_opts) "${TEMPLATES_DIR}/mysql-replica.cnf" "${user}@${replica_ip}:/tmp/"
    
    # 执行安装脚本
    log_info "执行MySQL从服务器安装..."
    remote_exec_script "$replica_ip" "${SCRIPTS_DIR}/install-mysql-replica.sh" \
        "$root_pass" "$master_ip" "$repl_user" "$repl_pass"
    
    log_success "MySQL从服务器部署完成"
}

# -----------------------------------------------------------------------------
# 部署Node.js服务器
# -----------------------------------------------------------------------------
deploy_nodejs() {
    log_step "部署 Node.js 应用服务器"
    
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    local fido2_node_path=$(get_yaml_value '.cluster.local_paths.fido2_node')
    local fido2_node_ex_path=$(get_yaml_value '.cluster.local_paths.fido2_node_ex')
    local app_port=$(get_yaml_value '.apps.fido2_node.port')
    local app_instances=$(get_yaml_value '.apps.fido2_node.instances')
    local storage=$(get_yaml_value '.apps.fido2_node.storage')
    local mng_token=$(get_yaml_value '.apps.fido2_node.mng_api_token')
    local enable_ex=$(get_yaml_value '.apps.fido2_node.enable_ex')
    
    # 数据库配置
    local mysql_master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    local db_name=$(get_yaml_value '.mysql.fido2_node_db.name')
    local db_user=$(get_yaml_value '.mysql.fido2_node_db.user')
    local db_pass=$(get_yaml_value '.mysql.fido2_node_db.password')
    
    local domain=$(get_yaml_value '.cluster.domain')
    
    for ((i=0; i<nodejs_count; i++)); do
        local server_ip=$(get_yaml_value ".servers.nodejs[$i].ip")
        local hostname=$(get_yaml_value ".servers.nodejs[$i].hostname")
        
        log_info "部署到: $server_ip ($hostname)"
        
        # 安装Node.js和PM2
        log_info "安装Node.js环境..."
        remote_exec_script "$server_ip" "${SCRIPTS_DIR}/install-nodejs.sh"
        
        # rsync代码
        log_info "同步 fido2-node 代码..."
        rsync_to "${fido2_node_path/#\~/$HOME}" "$server_ip" "/opt/fido2-node"
        
        if [[ "$enable_ex" == "true" ]]; then
            log_info "同步 fido2-node-ex 代码..."
            rsync_to "${fido2_node_ex_path/#\~/$HOME}" "$server_ip" "/opt/fido2-node-ex"
        fi
        
        # 复制PM2配置
        local user=$(get_yaml_value '.cluster.ssh.user')
        local ssh_opts=$(get_ssh_opts)
        scp $(get_scp_opts) "${TEMPLATES_DIR}/pm2-fido2-node.json" "${user}@${server_ip}:/tmp/"
        
        # 部署应用
        log_info "配置和启动应用..."
        remote_exec_script "$server_ip" "${SCRIPTS_DIR}/deploy-fido2-node.sh" \
            "$app_port" "$app_instances" "$storage" "$mng_token" "$enable_ex" \
            "$mysql_master_ip" "$db_name" "$db_user" "$db_pass" "$domain"
        
        log_success "Node.js服务器 $server_ip 部署完成"
    done
    
    log_success "所有Node.js服务器部署完成"
}

# -----------------------------------------------------------------------------
# 部署Nginx服务器
# -----------------------------------------------------------------------------
deploy_nginx() {
    log_step "部署 Nginx 负载均衡器"
    
    local nginx_ip=$(get_yaml_value '.servers.nginx.ip')
    local domain=$(get_yaml_value '.cluster.domain')
    local ssl_email=$(get_yaml_value '.ssl.email')
    local ssl_staging=$(get_yaml_value '.ssl.staging')
    
    # 获取所有Node.js服务器IP用于upstream配置
    local nodejs_servers=""
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    for ((i=0; i<nodejs_count; i++)); do
        local server_ip=$(get_yaml_value ".servers.nodejs[$i].ip")
        nodejs_servers="$nodejs_servers $server_ip"
    done
    
    local app_port=$(get_yaml_value '.apps.fido2_node.port')
    local portal_port=$(get_yaml_value '.apps.fido2_portal.port')
    
    log_info "目标服务器: $nginx_ip"
    
    # 复制Nginx配置模板
    local user=$(get_yaml_value '.cluster.ssh.user')
    local ssh_opts=$(get_ssh_opts)
    scp $(get_scp_opts) "${TEMPLATES_DIR}/nginx-upstream.conf" "${user}@${nginx_ip}:/tmp/"
    scp $(get_scp_opts) "${TEMPLATES_DIR}/nginx-site.conf" "${user}@${nginx_ip}:/tmp/"
    
    # 获取SSL域名列表
    local ssl_domains=$(get_yaml_value '.ssl.domains | join(",")')
    
    # 执行安装脚本
    log_info "安装Nginx和Certbot..."
    remote_exec_script "$nginx_ip" "${SCRIPTS_DIR}/install-nginx.sh" \
        "$domain" "$ssl_email" "$ssl_staging" "$ssl_domains" \
        "$nodejs_servers" "$app_port" "$portal_port"
    
    log_success "Nginx服务器部署完成"
}

# -----------------------------------------------------------------------------
# 部署Portal应用
# -----------------------------------------------------------------------------
deploy_portal() {
    log_step "部署 fido2-portal 应用"
    
    local nginx_ip=$(get_yaml_value '.servers.nginx.ip')
    local run_portal=$(get_yaml_value '.servers.nginx.run_portal')
    
    if [[ "$run_portal" != "true" ]]; then
        log_warn "Portal未配置在Nginx服务器上运行，跳过"
        return 0
    fi
    
    local fido2_portal_path=$(get_yaml_value '.cluster.local_paths.fido2_portal')
    local portal_port=$(get_yaml_value '.apps.fido2_portal.port')
    local portal_instances=$(get_yaml_value '.apps.fido2_portal.instances')
    local session_secret=$(get_yaml_value '.apps.fido2_portal.session.secret')
    local session_timeout=$(get_yaml_value '.apps.fido2_portal.session.timeout_minutes')
    
    # 数据库配置
    local mysql_master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    local db_name=$(get_yaml_value '.mysql.fido2_portal_db.name')
    local db_user=$(get_yaml_value '.mysql.fido2_portal_db.user')
    local db_pass=$(get_yaml_value '.mysql.fido2_portal_db.password')
    
    local domain=$(get_yaml_value '.cluster.domain')
    local mng_token=$(get_yaml_value '.apps.fido2_node.mng_api_token')
    local fido2_port=$(get_yaml_value '.apps.fido2_node.port')
    
    log_info "目标服务器: $nginx_ip"
    
    # rsync代码
    log_info "同步 fido2-portal 代码..."
    rsync_to "${fido2_portal_path/#\~/$HOME}" "$nginx_ip" "/opt/fido2-portal"
    
    # 复制PM2配置
    local user=$(get_yaml_value '.cluster.ssh.user')
    local ssh_opts=$(get_ssh_opts)
    scp $(get_scp_opts) "${TEMPLATES_DIR}/pm2-fido2-portal.json" "${user}@${nginx_ip}:/tmp/"
    
    # 构建fido2 worker URLs
    local worker_urls=""
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    for ((i=0; i<nodejs_count; i++)); do
        local server_ip=$(get_yaml_value ".servers.nodejs[$i].ip")
        if [[ -n "$worker_urls" ]]; then
            worker_urls="${worker_urls},"
        fi
        worker_urls="${worker_urls}http://${server_ip}:${fido2_port}"
    done
    
    # 部署应用
    log_info "配置和启动应用..."
    remote_exec_script "$nginx_ip" "${SCRIPTS_DIR}/deploy-fido2-portal.sh" \
        "$portal_port" "$portal_instances" "$session_secret" "$session_timeout" \
        "$mysql_master_ip" "$db_name" "$db_user" "$db_pass" "$domain" \
        "$mng_token" "$worker_urls"
    
    log_success "Portal应用部署完成"
}

# -----------------------------------------------------------------------------
# 完整部署流程
# -----------------------------------------------------------------------------
deploy_all() {
    log_step "开始完整集群部署"
    
    local start_time=$(date +%s)
    
    # 1. 检查
    check_dependencies
    check_config
    check_connectivity
    
    # 2. 部署数据库层
    deploy_mysql_master
    deploy_mysql_replica
    
    # 3. 部署应用层
    deploy_nodejs
    
    # 4. 部署负载均衡层
    deploy_nginx
    deploy_portal
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_step "部署完成"
    log_success "总耗时: ${duration} 秒"
    log_info ""
    log_info "下一步操作:"
    log_info "  1. 运行健康检查: ./health-check.sh"
    log_info "  2. 查看集群状态: ./cluster-manage.sh status"
    log_info "  3. 访问应用: https://fido2.$(get_yaml_value '.cluster.domain')"
}

# -----------------------------------------------------------------------------
# 更新应用代码
# -----------------------------------------------------------------------------
update_app() {
    log_step "更新应用代码"
    
    check_config
    
    local fido2_node_path=$(get_yaml_value '.cluster.local_paths.fido2_node')
    local fido2_node_ex_path=$(get_yaml_value '.cluster.local_paths.fido2_node_ex')
    local fido2_portal_path=$(get_yaml_value '.cluster.local_paths.fido2_portal')
    local enable_ex=$(get_yaml_value '.apps.fido2_node.enable_ex')
    
    # 更新Node.js服务器
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    for ((i=0; i<nodejs_count; i++)); do
        local server_ip=$(get_yaml_value ".servers.nodejs[$i].ip")
        log_info "更新 $server_ip 上的 fido2-node..."
        rsync_to "${fido2_node_path/#\~/$HOME}" "$server_ip" "/opt/fido2-node"
        
        if [[ "$enable_ex" == "true" ]]; then
            rsync_to "${fido2_node_ex_path/#\~/$HOME}" "$server_ip" "/opt/fido2-node-ex"
        fi
        
        remote_exec "$server_ip" "cd /opt/fido2-node && pm2 reload fido2-node"
    done
    
    # 更新Portal
    local nginx_ip=$(get_yaml_value '.servers.nginx.ip')
    local run_portal=$(get_yaml_value '.servers.nginx.run_portal')
    if [[ "$run_portal" == "true" ]]; then
        log_info "更新 $nginx_ip 上的 fido2-portal..."
        rsync_to "${fido2_portal_path/#\~/$HOME}" "$nginx_ip" "/opt/fido2-portal"
        remote_exec "$nginx_ip" "cd /opt/fido2-portal && pm2 reload fido2-portal"
    fi
    
    log_success "应用代码更新完成"
}

# -----------------------------------------------------------------------------
# 显示帮助
# -----------------------------------------------------------------------------
show_help() {
    cat << EOF
FIDO2 集群部署脚本

用法: $0 <命令> [选项]

命令:
  --init                    初始化SSH密钥并分发到所有服务器
  --check                   验证配置文件和服务器连通性
  --deploy                  完整部署整个集群
  --deploy-component <组件> 部署指定组件
                           组件: mysql-master, mysql-replica, nodejs, nginx, portal
  --update-app              仅更新应用代码（快速部署）
  --help                    显示此帮助信息

示例:
  $0 --init                 # 首次使用，初始化SSH
  $0 --check                # 检查配置和连通性
  $0 --deploy               # 完整部署
  $0 --deploy-component nodejs  # 仅部署Node.js层
  $0 --update-app           # 代码更新后快速部署

配置文件: config/cluster.yaml
  首次使用请复制示例配置:
  cp config/cluster.yaml.example config/cluster.yaml

EOF
}

# -----------------------------------------------------------------------------
# 主入口
# -----------------------------------------------------------------------------
main() {
    case "${1:-}" in
        --init)
            check_dependencies
            check_config
            init_ssh_keys
            ;;
        --check)
            check_dependencies
            check_config
            check_connectivity
            ;;
        --deploy)
            deploy_all
            ;;
        --deploy-component)
            check_dependencies
            check_config
            case "${2:-}" in
                mysql-master)
                    deploy_mysql_master
                    ;;
                mysql-replica)
                    deploy_mysql_replica
                    ;;
                nodejs)
                    deploy_nodejs
                    ;;
                nginx)
                    deploy_nginx
                    ;;
                portal)
                    deploy_portal
                    ;;
                *)
                    log_error "未知组件: ${2:-}"
                    log_info "可用组件: mysql-master, mysql-replica, nodejs, nginx, portal"
                    exit 1
                    ;;
            esac
            ;;
        --update-app)
            update_app
            ;;
        --help|"")
            show_help
            ;;
        *)
            log_error "未知命令: $1"
            show_help
            exit 1
            ;;
    esac
}

# 仅在直接执行时调用main，source时不调用
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
