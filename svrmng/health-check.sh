#!/bin/bash
# =============================================================================
# FIDO2 集群健康检查脚本
# =============================================================================
# 用法: ./health-check.sh [选项]
# 选项:
#   --quiet     仅输出异常项
#   --json      JSON格式输出
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/cluster.yaml"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 参数
QUIET_MODE=false
JSON_MODE=false

# 检查结果
declare -A RESULTS

# -----------------------------------------------------------------------------
# 解析参数
# -----------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --quiet|-q)
                QUIET_MODE=true
                shift
                ;;
            --json|-j)
                JSON_MODE=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# YAML解析
# -----------------------------------------------------------------------------
get_yaml_value() {
    local path=$1
    yq e "$path" "$CONFIG_FILE" 2>/dev/null
}

# -----------------------------------------------------------------------------
# SSH函数
# -----------------------------------------------------------------------------
get_ssh_opts() {
    local key_file=$(get_yaml_value '.cluster.ssh.key_file')
    local port=$(get_yaml_value '.cluster.ssh.port')
    
    local opts="-o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes"
    
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
    
    timeout 10 ssh $ssh_opts "${user}@${host}" "$cmd" 2>/dev/null
}

# -----------------------------------------------------------------------------
# 检查函数
# -----------------------------------------------------------------------------
check_ssh() {
    local ip=$1
    if remote_exec "$ip" "echo ok" &>/dev/null; then
        echo "ok"
    else
        echo "fail"
    fi
}

check_nginx() {
    local ip=$1
    local status=$(remote_exec "$ip" "systemctl is-active nginx" 2>/dev/null || echo "inactive")
    if [[ "$status" == "active" ]]; then
        echo "ok"
    else
        echo "fail"
    fi
}

check_port() {
    local ip=$1
    local port=$2
    if remote_exec "$ip" "ss -tln | grep -q ':$port '" &>/dev/null; then
        echo "ok"
    else
        echo "fail"
    fi
}

check_pm2_app() {
    local ip=$1
    local app=$2
    local result=$(remote_exec "$ip" "pm2 jlist 2>/dev/null" || echo "[]")
    
    if echo "$result" | grep -q "\"name\":\"$app\".*\"status\":\"online\""; then
        echo "ok"
    else
        echo "fail"
    fi
}

check_mysql() {
    local ip=$1
    local status=$(remote_exec "$ip" "systemctl is-active mysql" 2>/dev/null || echo "inactive")
    if [[ "$status" == "active" ]]; then
        echo "ok"
    else
        echo "fail"
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
        echo "ok:$behind"
    else
        echo "fail:IO=$io_running,SQL=$sql_running"
    fi
}

check_http_endpoint() {
    local url=$1
    local status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null || echo "000")
    if [[ "$status" =~ ^[23] ]]; then
        echo "ok:$status"
    else
        echo "fail:$status"
    fi
}

# -----------------------------------------------------------------------------
# 输出函数
# -----------------------------------------------------------------------------
print_header() {
    if [[ "$JSON_MODE" == "true" || "$QUIET_MODE" == "true" ]]; then
        return
    fi
    
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    FIDO2 集群健康检查报告                            ║${NC}"
    echo -e "${BLUE}║                    $(date '+%Y-%m-%d %H:%M:%S')                              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_check() {
    local name=$1
    local status=$2
    local details=$3
    
    RESULTS["$name"]="$status"
    
    if [[ "$JSON_MODE" == "true" ]]; then
        return
    fi
    
    if [[ "$status" == "ok" ]]; then
        if [[ "$QUIET_MODE" != "true" ]]; then
            echo -e "  ${GREEN}✓${NC} $name ${GREEN}正常${NC} $details"
        fi
    else
        echo -e "  ${RED}✗${NC} $name ${RED}异常${NC} $details"
    fi
}

print_section() {
    local title=$1
    
    if [[ "$JSON_MODE" == "true" || "$QUIET_MODE" == "true" ]]; then
        return
    fi
    
    echo ""
    echo -e "${YELLOW}【$title】${NC}"
}

print_summary() {
    local total=0
    local failed=0
    
    for key in "${!RESULTS[@]}"; do
        ((total++))
        if [[ "${RESULTS[$key]}" != "ok" ]]; then
            ((failed++))
        fi
    done
    
    if [[ "$JSON_MODE" == "true" ]]; then
        echo "{"
        echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
        echo "  \"total_checks\": $total,"
        echo "  \"failed_checks\": $failed,"
        echo "  \"status\": \"$([ $failed -eq 0 ] && echo 'healthy' || echo 'unhealthy')\","
        echo "  \"checks\": {"
        local first=true
        for key in "${!RESULTS[@]}"; do
            if [[ "$first" != "true" ]]; then
                echo ","
            fi
            echo -n "    \"$key\": \"${RESULTS[$key]}\""
            first=false
        done
        echo ""
        echo "  }"
        echo "}"
        return
    fi
    
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  检查总数: $total"
    
    if [[ $failed -eq 0 ]]; then
        echo -e "  状态: ${GREEN}所有检查通过 ✓${NC}"
    else
        echo -e "  异常数: ${RED}$failed${NC}"
        echo -e "  状态: ${RED}存在异常 ✗${NC}"
    fi
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# -----------------------------------------------------------------------------
# 主检查流程
# -----------------------------------------------------------------------------
run_checks() {
    print_header
    
    # Nginx服务器检查
    print_section "Nginx 负载均衡器"
    local nginx_ip=$(get_yaml_value '.servers.nginx.ip')
    
    local ssh_status=$(check_ssh "$nginx_ip")
    print_check "nginx_ssh_${nginx_ip}" "$ssh_status" "SSH连接"
    
    if [[ "$ssh_status" == "ok" ]]; then
        local nginx_status=$(check_nginx "$nginx_ip")
        print_check "nginx_service_${nginx_ip}" "$nginx_status" "Nginx服务"
        
        local port80=$(check_port "$nginx_ip" "80")
        print_check "nginx_port80_${nginx_ip}" "$port80" "端口80"
        
        local port443=$(check_port "$nginx_ip" "443")
        print_check "nginx_port443_${nginx_ip}" "$port443" "端口443"
        
        local portal_status=$(check_pm2_app "$nginx_ip" "fido2-portal")
        print_check "portal_pm2_${nginx_ip}" "$portal_status" "Portal进程"
    fi
    
    # Node.js服务器检查
    print_section "Node.js 应用服务器"
    local nodejs_count=$(get_yaml_value '.servers.nodejs | length')
    local app_port=$(get_yaml_value '.apps.fido2_node.port')
    
    for ((i=0; i<nodejs_count; i++)); do
        local ip=$(get_yaml_value ".servers.nodejs[$i].ip")
        local hostname=$(get_yaml_value ".servers.nodejs[$i].hostname")
        
        local ssh_status=$(check_ssh "$ip")
        print_check "nodejs_ssh_${ip}" "$ssh_status" "SSH连接 ($hostname)"
        
        if [[ "$ssh_status" == "ok" ]]; then
            local pm2_status=$(check_pm2_app "$ip" "fido2-node")
            print_check "nodejs_pm2_${ip}" "$pm2_status" "fido2-node进程"
            
            local port_status=$(check_port "$ip" "$app_port")
            print_check "nodejs_port_${ip}" "$port_status" "端口$app_port"
        fi
    done
    
    # MySQL检查
    print_section "MySQL 数据库"
    local master_ip=$(get_yaml_value '.servers.mysql_master.ip')
    
    local ssh_status=$(check_ssh "$master_ip")
    print_check "mysql_master_ssh_${master_ip}" "$ssh_status" "SSH连接 (主服务器)"
    
    if [[ "$ssh_status" == "ok" ]]; then
        local mysql_status=$(check_mysql "$master_ip")
        print_check "mysql_master_service_${master_ip}" "$mysql_status" "MySQL服务"
        
        local port_status=$(check_port "$master_ip" "3306")
        print_check "mysql_master_port_${master_ip}" "$port_status" "端口3306"
    fi
    
    # MySQL从服务器检查
    for ((i=0; i<nodejs_count; i++)); do
        local is_replica=$(get_yaml_value ".servers.nodejs[$i].db_replica")
        if [[ "$is_replica" == "true" ]]; then
            local replica_ip=$(get_yaml_value ".servers.nodejs[$i].ip")
            
            local mysql_status=$(check_mysql "$replica_ip")
            print_check "mysql_replica_service_${replica_ip}" "$mysql_status" "MySQL服务 (从服务器)"
            
            if [[ "$mysql_status" == "ok" ]]; then
                local repl_status=$(check_mysql_replication "$replica_ip")
                local repl_result="${repl_status%%:*}"
                local repl_detail="${repl_status#*:}"
                
                if [[ "$repl_result" == "ok" ]]; then
                    print_check "mysql_replication_${replica_ip}" "ok" "复制状态 (延迟: ${repl_detail}s)"
                elif [[ "$repl_result" == "not_configured" ]]; then
                    print_check "mysql_replication_${replica_ip}" "ok" "复制未配置"
                else
                    print_check "mysql_replication_${replica_ip}" "fail" "复制异常: $repl_detail"
                fi
            fi
        fi
    done
    
    # HTTP端点检查（如果能访问外网）
    local domain=$(get_yaml_value '.cluster.domain')
    local ssl_domains=$(get_yaml_value '.ssl.domains[]' 2>/dev/null | head -1)
    
    if [[ -n "$ssl_domains" && "$ssl_domains" != "null" ]]; then
        print_section "HTTP 端点"
        
        local http_status=$(check_http_endpoint "https://${ssl_domains}")
        local http_result="${http_status%%:*}"
        local http_code="${http_status#*:}"
        print_check "http_endpoint_${ssl_domains}" "$http_result" "HTTPS (状态码: $http_code)"
    fi
    
    print_summary
}

# -----------------------------------------------------------------------------
# 主入口
# -----------------------------------------------------------------------------
main() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "错误: 配置文件不存在: $CONFIG_FILE"
        exit 1
    fi
    
    if ! command -v yq &> /dev/null; then
        echo "错误: 需要安装 yq"
        exit 1
    fi
    
    parse_args "$@"
    run_checks
    
    # 如果有失败的检查，返回非零退出码
    for key in "${!RESULTS[@]}"; do
        if [[ "${RESULTS[$key]}" != "ok" ]]; then
            exit 1
        fi
    done
    
    exit 0
}

main "$@"
