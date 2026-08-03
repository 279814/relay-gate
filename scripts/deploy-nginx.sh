#!/bin/sh
# 在「已有 nginx + certbot 且 80/443 已被占用」的服务器上一键部署 relay-gate
#（§13 的脚本实现）。**不需要编辑任何文件**，默认值都在下面的环境变量里。
#
# 与项目自带 `docker compose --profile public`（Caddy）的区别：
# 那套要独占 80/443 并自己管证书；本机已有一个跑得好好的 nginx（含证书与
# 自动续期 cron），两套会打架。所以这里**不起 Caddy**，只把网关容器绑在
# 127.0.0.1:18787，由现有 nginx 反代出去 —— 网关容器对公网不可直连，
# 「绕过反代直连」不存在，安全性与 Caddy 方案等价。
#
# 流程：
#   1. clone / pull 仓库到 $HOME/relay-gate，生成 .env（三项必填凭据）
#   2. 构建并启动 relay-gate 容器（不启 Caddy）
#   3. 为 $DOMAINS[0]（默认 relay.ienvie.top）生成 nginx 反代配置并 reload
#      （先出 80 的 ACME 验证口，证书下来前 443 用的是现有证书，不影响老站）
#   4. certbot --expand 把新域名并入现有证书（老域名一个不少）
#   5. 自验证：健康检查 / 管理面 403 / 证书 SAN
#
# 用法（在服务器上执行，或先下载后执行）：
#   curl -sSL https://raw.githubusercontent.com/279814/relay-gate/main/scripts/deploy-nginx.sh | sh
#
# 可覆盖的默认值（前缀式环境变量，不想用默认就导出后再跑）：
#   RELAY_DOMAIN=relay.ienvie.top      # 对外域名
#   RELAY_ALLOW_IPS='203.0.113.4'      # 管理面 IP 白名单（**必填**，空格分隔，
#                                      # 支持 CIDR）。填的是你**自己电脑**的出口
#                                      # IP —— 在自己电脑上 curl -s ifconfig.me
#                                      # 查。脚本跑在服务器上，不能在服务器上取
#                                      # （那拿到的是服务器自己的 IP，管理面
#                                      # 白名单等于没配，你从家里访问会被 403）
#   RELAY_DIR="$HOME/relay-gate"       # 仓库目录
#   NGINX_CONTAINER=nginx              # nginx 容器名；空 = 宿主机 nginx
#   CERTBOT_CONTAINER=certbot          # certbot 容器名；空 = 宿主机 certbot
#   CERT_LIVE=/etc/letsencrypt/live/ienvie.top
#   CERT_DOMAINS='ienvie.top www.ienvie.top rag.ienvie.top sub2api.ienvie.top'

set -eu

RELAY_DOMAIN=${RELAY_DOMAIN:-relay.ienvie.top}
# 管理面白名单**必填**：填的是你自己电脑的出口 IP（在自己电脑上
# `curl -s ifconfig.me` 查），不能在这里默认取服务器自己的出口 IP ——
# 服务器上的 ifconfig.me 拿到的是服务器 IP，白名单等于没配，
# 你从家里/办公室访问管理界面必被 403。忘了配的后果应该是
# 「我进不去」（立刻发现），而不是「全世界都能进」。
# 多个 IP 空格分隔：RELAY_ALLOW_IPS='203.0.113.4 198.51.100.0/24'
RELAY_ALLOW_IPS=${RELAY_ALLOW_IPS:-}
RELAY_DIR=${RELAY_DIR:-"$HOME/relay-gate"}
NGINX_CONTAINER=${NGINX_CONTAINER:-nginx}
CERTBOT_CONTAINER=${CERTBOT_CONTAINER:-certbot}
CERT_LIVE=${CERT_LIVE:-/etc/letsencrypt/live/ienvie.top}

CONF_FILE=/etc/nginx/conf.d/relay-ienvie-top.conf
ACME_WEBROOT=/var/www/certbot

info() { printf '\033[1;32m[%s]\033[0m %s\n' "$1" "$2"; }
warn() { printf '\033[1;33m[%s]\033[0m %s\n' "$1" "$2"; }
die()  { printf '\033[1;31m[%s]\033[0m %s\n' "$1" "$2" >&2; exit 1; }

for c in curl docker git; do
    command -v "$c" >/dev/null 2>&1 || die "缺少依赖" "需要 $c，先装：sudo apt-get install -y $c"
done
# 白名单必填。空值直接中止 —— 绝不让「管理面默认全开放」的状态存在。
[ -n "$RELAY_ALLOW_IPS" ] || die "缺少白名单" \
'RELAY_ALLOW_IPS 未设置。在自己电脑上先 `curl -s ifconfig.me` 查出口 IP，
然后这样跑：
    RELAY_ALLOW_IPS="<你电脑的出口IP>" curl -sSL https://raw.githubusercontent.com/279814/relay-gate/main/scripts/deploy-nginx.sh | sh
多个 IP（或 CIDR）用空格分隔，例如：RELAY_ALLOW_IPS="203.0.113.4 198.51.100.0/24"'

# 容器检测：存在就叫 docker exec，不存在就走宿主机。两层分别检测，
# 因为有的服务器是「容器 nginx + 宿主 certbot」之类的混搭。
if [ -n "$NGINX_CONTAINER" ] && docker inspect "$NGINX_CONTAINER" >/dev/null 2>&1; then
    NGINX_CT=1
    info "nginx" "容器 $NGINX_CONTAINER，操作走 docker exec"
else
    NGINX_CT=0
    command -v nginx >/dev/null 2>&1 || die "nginx" "没有 nginx 容器也没有宿主机 nginx —— 本脚本是给「已有 nginx」的服务器用的"
    info "nginx" "宿主机 nginx"
fi
if [ -n "$CERTBOT_CONTAINER" ] && docker inspect "$CERTBOT_CONTAINER" >/dev/null 2>&1; then
    CERTBOT_CT=1
    info "certbot" "容器 $CERTBOT_CONTAINER，操作走 docker exec"
else
    CERTBOT_CT=0
    command -v certbot >/dev/null 2>&1 || die "certbot" "没有 certbot 容器也没有宿主机 certbot —— 证书没法签。先装：sudo apt-get install -y certbot"
    info "certbot" "宿主机 certbot"
fi

# 域名先确认解析到本机，再往下走。解析都还没生效就去签证书，只会白等。
pub_ip=$(curl -s ifconfig.me || true)
dns_ip=$(getent ahostsv4 "$RELAY_DOMAIN" | awk 'NR==1{print $1}' || true)
if [ -n "$dns_ip" ] && [ "$dns_ip" != "$pub_ip" ]; then
    die "DNS" "$RELAY_DOMAIN 解析到 $dns_ip，本机出口 IP 是 $pub_ip —— 先到 DNS 控制台把 A 记录指过来再跑"
fi
[ -n "$dns_ip" ] || warn "DNS" "$RELAY_DOMAIN 查不到解析记录，先确认已添加 A 记录（脚本会继续，失败时看 [证书] 步骤输出）"

info "步骤 1/5" "准备仓库 $RELAY_DIR"
if [ ! -d "$RELAY_DIR/.git" ]; then
    [ ! -e "$RELAY_DIR" ] || mv "$RELAY_DIR" "$RELAY_DIR.bak.$(date +%s)"
    git clone https://github.com/279814/relay-gate.git "$RELAY_DIR"
else
    git -C "$RELAY_DIR" pull --ff-only
fi
cd "$RELAY_DIR"

info "步骤 2/5" "生成 .env（三项必填凭据）"
if [ -f .env ]; then
    warn ".env" "已存在，跳过生成（现有上游 key 的加密密钥不能换，换 = 全部解不开）"
else
    cat > .env <<EOF
ENCRYPTION_KEY=$(openssl rand -hex 32)
RELAY_KEYS=rk-$(openssl rand -hex 24)
ADMIN_PASSWORD=$(openssl rand -base64 24)
RELAY_PORT=18787
TZ=Asia/Shanghai
VERSION=dev
EOF
    chmod 600 .env
fi

info "步骤 2/5" "构建并启动 relay-gate（镜像无 CGO，首次构建要几分钟）"
docker compose build
docker compose up -d

info "步骤 3/5" "等待网关就绪"
ready=0
for _ in $(seq 1 60); do
    if docker exec relay-gate wget -qO- http://127.0.0.1:18787/healthz >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 2
done
[ "$ready" -eq 1 ] || die "网关" "relay-gate 120 秒没就绪，看日志：docker logs --tail 50 relay-gate"

info "步骤 3/5" "生成 nginx 反代配置 $CONF_FILE"
# 模板里的 $host / $request_uri 是 nginx 变量，写文件时不能被这里展开，
# 所以转义成 \$。
# admin 白名单：allow 列表 + 兜底 deny all，与 Caddy 的
# `not remote_ip` 语义一致 —— 没配 IP 时拒绝一切而不是放行一切。
if [ -n "$RELAY_ALLOW_IPS" ]; then
    ALLOW_LINES=$(for ip in $RELAY_ALLOW_IPS; do echo "        allow $ip;"; done)
else
    ALLOW_LINES='        deny all;'
fi
tee "$CONF_FILE" >/dev/null <<EOF
# relay-gate 反代（由 scripts/deploy-nginx.sh 生成，改这里不如改脚本重跑）
# 网关容器只绑 127.0.0.1:18787，公网无法直连 —— 这里就是唯一入口。
# 管理面（/admin）按 IP 白名单收紧；转发端点不限 IP，靠 RELAY_KEYS 鉴权。
server {
    listen 80;
    listen [::]:80;
    server_name $RELAY_DOMAIN;

    # ACME HTTP-01 验证口，必须留在 80 上（续期也要用）
    location /.well-known/acme-challenge/ {
        root $ACME_WEBROOT;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $RELAY_DOMAIN;

    # 复用现有证书。证书刚扩完 SAN 之前指向它也没关系 ——
    # 文件存在，老站不会因此受影响。
    ssl_certificate     $CERT_LIVE/fullchain.pem;
    ssl_certificate_key $CERT_LIVE/privkey.pem;

    # 管理面：白名单
    location ^~ /admin {
$ALLOW_LINES
        deny all;
        proxy_pass http://127.0.0.1:18787;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # 转发端点：不限 IP，靠 relay key 鉴权
    location / {
        proxy_pass http://127.0.0.1:18787;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # 长思考首 Token 可达 20 分钟，期间连接上没有字节。
        # nginx 默认 60s 就会掐断 —— 必须放宽。
        proxy_read_timeout 35m;
        proxy_send_timeout 35m;

        # SSE 逐块透传。一旦缓冲，流式输出会变成
        # 「长时间无反应后一次性刷出」。
        proxy_buffering off;
        proxy_cache off;
    }
}
EOF

if [ "$NGINX_CT" -eq 1 ]; then
    docker cp "$CONF_FILE" "$NGINX_CONTAINER:$CONF_FILE"
    docker exec "$NGINX_CONTAINER" nginx -t
    docker exec "$NGINX_CONTAINER" nginx -s reload
else
    sudo nginx -t
    sudo systemctl reload nginx
fi
info "步骤 3/5" "nginx 已 reload（80 的 ACME 验证口已生效）"

info "步骤 4/5" "certbot --expand：把 $RELAY_DOMAIN 并入现有证书（老域名一个不少）"
# --cert-name 固定证书名：certbot 会读现有证书的域名集合，
# 把新域名加进去重新签发，续期 cron 不用改。
if [ "$CERTBOT_CT" -eq 1 ]; then
    docker exec "$CERTBOT_CONTAINER" certbot certonly --webroot \
        --cert-name ienvie.top \
        -w "$ACME_WEBROOT" \
        -d "$RELAY_DOMAIN" \
        --expand --keep-until-expiring --non-interactive
else
    sudo certbot certonly --webroot \
        --cert-name ienvie.top \
        -w "$ACME_WEBROOT" \
        -d "$RELAY_DOMAIN" \
        --expand --keep-until-expiring --non-interactive
fi

# 证书已含新域名，reload 让 443 用上。
if [ "$NGINX_CT" -eq 1 ]; then
    docker exec "$NGINX_CONTAINER" nginx -s reload
else
    sudo systemctl reload nginx
fi
info "步骤 4/5" "证书已更新并 reload"

info "步骤 5/5" "自验证"
sleep 2
code=$(curl -s -o /dev/null -w '%{http_code}' "https://$RELAY_DOMAIN/healthz")
[ "$code" = "200" ] || die "验证" "https://$RELAY_DOMAIN/healthz 返回 $code，期望 200。排障：docker logs --tail 50 relay-gate"
code=$(curl -s -o /dev/null -w '%{http_code}' "https://$RELAY_DOMAIN/admin/")
[ "$code" = "403" ] || warn "验证" "管理面返回 $code，期望 403（白名单外）—— 检查 $CONF_FILE 里的 allow 列表"
if openssl s_client -connect "$RELAY_DOMAIN:443" -servername "$RELAY_DOMAIN" </dev/null 2>/dev/null |
    openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -q "$RELAY_DOMAIN"; then
    info "验证" "证书 SAN 已含 $RELAY_DOMAIN"
else
    warn "验证" "证书 SAN 里没看到 $RELAY_DOMAIN —— 用 https:// 打开试试，或检查 certbot 日志"
fi

echo
info "完成" "转发端点：https://$RELAY_DOMAIN  （客户端 base_url 填这个）"
info "完成" "管理界面：https://$RELAY_DOMAIN/admin/  （口令在 $RELAY_DIR/.env 的 ADMIN_PASSWORD）"
info "完成" "管理面仅限白名单 IP：$RELAY_ALLOW_IPS（换 IP 后改 .env 无效 —— 直接编辑 $CONF_FILE 的 allow 行再 reload）"
echo "接下来到管理界面里配：上游（中转站）→ 模型（客户端要的 model 名）→ 路由（优先级）。"
