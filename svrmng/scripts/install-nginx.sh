#!/bin/bash
# =============================================================================
# Nginx 和 Certbot 安装脚本
# =============================================================================
# 参数:
#   $1 - 主域名
#   $2 - SSL证书邮箱
#   $3 - 是否使用staging环境 (true/false)
#   $4 - SSL域名列表 (逗号分隔)
#   $5 - Node.js服务器IP列表 (空格分隔)
#   $6 - fido2-node端口
#   $7 - fido2-portal端口
# =============================================================================

set -e

DOMAIN=$1
SSL_EMAIL=$2
SSL_STAGING=$3
SSL_DOMAINS=$4
NODEJS_SERVERS=$5
APP_PORT=$6
PORTAL_PORT=$7

echo "=== 安装 Nginx 和 Certbot ==="

# 安装Nginx
if command -v nginx &> /dev/null; then
    echo "Nginx已安装"
    nginx -v
else
    echo "安装 Nginx..."
    sudo apt-get update -y
    sudo apt-get install -y nginx
fi

# 安装Certbot
if command -v certbot &> /dev/null; then
    echo "Certbot已安装"
    certbot --version
else
    echo "安装 Certbot..."
    sudo apt-get install -y certbot python3-certbot-nginx
fi

# 安装Node.js（用于运行portal）
if ! command -v node &> /dev/null; then
    echo "安装 Node.js（用于Portal）..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

# 安装PM2
if ! command -v pm2 &> /dev/null; then
    echo "安装 PM2..."
    sudo npm install -g pm2
    pm2 startup systemd -u "$(whoami)" --hp "$HOME" 2>/dev/null || true
fi

# 生成upstream配置
echo "生成Nginx upstream配置..."
cat << EOF | sudo tee /etc/nginx/conf.d/fido2-upstream.conf
# FIDO2 Node.js Backend Upstream
upstream fido2_backend {
    ip_hash;
EOF

for server in $NODEJS_SERVERS; do
    echo "    server ${server}:${APP_PORT};" | sudo tee -a /etc/nginx/conf.d/fido2-upstream.conf
done

cat << EOF | sudo tee -a /etc/nginx/conf.d/fido2-upstream.conf
}

# FIDO2 Portal Backend
upstream portal_backend {
    server 127.0.0.1:${PORTAL_PORT};
}
EOF

# 复制站点配置模板
if [[ -f /tmp/nginx-site.conf ]]; then
    echo "配置Nginx站点..."
    
    # 替换变量
    sed -e "s/{{DOMAIN}}/${DOMAIN}/g" \
        -e "s/{{APP_PORT}}/${APP_PORT}/g" \
        -e "s/{{PORTAL_PORT}}/${PORTAL_PORT}/g" \
        /tmp/nginx-site.conf | sudo tee /etc/nginx/sites-available/fido2.conf
    
    # 启用站点
    sudo ln -sf /etc/nginx/sites-available/fido2.conf /etc/nginx/sites-enabled/
    
    # 禁用默认站点
    sudo rm -f /etc/nginx/sites-enabled/default
fi

# 测试Nginx配置
echo "测试Nginx配置..."
sudo nginx -t

# 启动/重启Nginx
echo "启动Nginx..."
sudo systemctl enable nginx
sudo systemctl restart nginx

# 申请SSL证书
if [[ -n "$SSL_DOMAINS" && "$SSL_DOMAINS" != "null" ]]; then
    echo "申请SSL证书..."
    
    # 构建certbot参数
    CERTBOT_ARGS=""
    IFS=',' read -ra DOMAIN_ARRAY <<< "$SSL_DOMAINS"
    for d in "${DOMAIN_ARRAY[@]}"; do
        CERTBOT_ARGS="$CERTBOT_ARGS -d $d"
    done
    
    if [[ "$SSL_STAGING" == "true" ]]; then
        CERTBOT_ARGS="$CERTBOT_ARGS --staging"
        echo "使用Let's Encrypt staging环境（测试）"
    fi
    
    # 运行certbot
    sudo certbot certonly --nginx \
        --non-interactive \
        --agree-tos \
        --email "$SSL_EMAIL" \
        $CERTBOT_ARGS || {
        echo "警告: SSL证书申请失败，请稍后手动运行:"
        echo "  sudo certbot certonly --nginx $CERTBOT_ARGS"
    }
    
    # 配置自动续期
    echo "配置SSL证书自动续期..."
    (crontab -l 2>/dev/null | grep -v "certbot renew"; echo "0 0 1 * * certbot renew --post-hook 'systemctl reload nginx' >> /var/log/certbot-renew.log 2>&1") | crontab -
fi

# 重新加载Nginx以应用SSL
sudo nginx -t && sudo systemctl reload nginx

echo "=== Nginx 安装完成 ==="
