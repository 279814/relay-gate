# Linux 公网 IP HTTPS

默认 `./deploy.sh`、`deploy.ps1` 和 `compose.yaml` 仍提供 HTTP `IP:port` 安装。公网 HTTPS 使用独立的 `deploy-public.sh`、`deploy/compose.public.yaml` 和专用边缘容器；无需域名、ACME 邮箱或管理登录 IP 白名单。

准备稳定公网 IP、Linux、Docker Compose，以及可从公网访问的 TCP 80/443。签发期间需要出站 HTTPS。自动检测通过 HTTPS 查询 IPv4；IPv6 请显式传入。安装器还会通过确认的公网 IP 回读随机 HTTP-01 文件，因此 NAT 环境必须支持本机回访公网地址。80/443 已被其他服务占用或 Docker 子网 `172.30.187.0/28` 冲突时，先调整宿主环境再安装。

在仓库根目录交互执行，检查检测结果后输入完整 IP 确认：

```sh
sudo ./deploy.sh --public
```

自动化安装必须明确提供本机公网 IP，并重复确认目标。下面的占位符必须替换为实际地址：

```sh
PUBLIC_IP='<本机公网IP>'
sudo ./deploy.sh --public --ip "$PUBLIC_IP" --confirm-ip "$PUBLIC_IP"
```

不得将示例、测试夹具或其他机器的 IP 用作签发目标。传入私网、回环、保留地址、域名或不匹配的确认值会失败。确认前不启动 Docker/ACME；实际签发前，专用 Go 程序还会校验全球可路由 IP。重复安装须继续使用同一仓库路径和持久目录。

安装器构建并验证边缘镜像，移除本仓库旧默认 Compose 部署的 HTTP 18787 端口，然后启动独立公网项目。仅边缘容器发布 80/443；网关本体没有宿主机端口。首次启动的管理密码、Relay Key 和 Master Key 仍只在网关日志输出一次；安装成功后脚本会打印相应日志命令。凭据查看、备份和轮换遵循现有管理流程。

签发前，80 只提供 `/.well-known/acme-challenge/` 的 GET/HEAD；管理、模型、转发和健康业务路径均返回 503，443 不监听。签发后先验证 IP SAN、系统信任链、证书和私钥配对、私钥仅所有者可读、短期证书期限及至少 24 小时剩余效期，再测试 Nginx 配置、原子替换配置、reload，并通过本机真实 TLS 握手核对新证书指纹。验证成功后才记录 `live_https`：80 跳转到已确认 IP 的 HTTPS 地址，443 代理内部网关。

Nginx 关闭响应与请求缓冲，读写超时均为 35 分钟。它覆盖真实客户端 IP/HTTPS 元数据；网关只接受固定边缘 IP 的单一合法地址与 HTTPS 标记。管理 Cookie 使用 Secure，同源 CSRF 校验使用固定公网 origin。网关向上游发送请求前剥离所有外部 Forwarded 元数据。公网入口不能通过伪造转发头绕过这些约束。

状态和维护命令：

```sh
sudo ./deploy.sh --public --status
sudo ./deploy.sh --public --renew
```

已登录管理员可读取 `GET /admin/api/public-https`，返回证书到期时间、剩余小时数、最近尝试/成功/reload、续期次数、错误类别、剩余效期告警和是否保留旧证书。该接口不返回 PEM、私钥、ACME 账户材料或原始 Certbot 输出。

Certbot 的账户、lineage 与续期配置持久化保存；每 12 小时尝试正常 `renew`，不强制重复签发。每小时刷新状态，剩余效期低于 48 小时发出日志告警，并在到期时单独计时关闭业务监听。`--renew` 向已有边缘进程发送信号，不启动第二个证书管理器。网关暂停不影响边缘续期，边缘无需访问网关数据库或业务准入。

续期或候选验证失败时，当前仍有效的证书继续服务并记录错误。reload 失败时恢复旧配置并核对旧证书；无法证明旧配置仍安全时关闭业务。证书过期后保持 HTTP-01 路径，业务关闭；不会退回明文 HTTP。查阅边缘私有诊断日志后修复 80/443、IP 指向、系统时间、网络或 Certbot 问题，再请求续期。不要删除 ACME 状态反复尝试签发，以免丢失账户或触发 CA 速率限制。

`data-public/` 是独立的敏感持久目录，含 ACME 账户私钥和 TLS 私钥：目录权限 0700、安装元数据 0600、TLS 私钥 0600。只有不含密钥的 `status/` 子目录被只读挂给网关。整个目录已被 Git 与 Docker 构建上下文排除。SQLite/Keyring 备份不包含这个独立目录；灾备还须在边缘容器停止后，将整个 `data-public/`（包括 ACME archive/live 关系）备份到仓库外的受保护位置。恢复时停边缘、整组还原、保留权限，并继续使用相同确认 IP；启动后会重新校验证书。不能只复制一个 PEM 或单独 `live/` 目录。

实现固定使用官方 Certbot 5.8.0 镜像 digest，并在运行时探测 `--ip-address`、webroot 插件和 profile 参数。优先使用禁止回退的 `--required-profile shortlived`；仅在该参数不存在而 `--preferred-profile` 存在时使用后者，且仍拒绝长于 192 小时的候选。官方要求 IP 的 webroot 支持为 Certbot 5.4+，IP 短期证书通常有效 160 小时。依据：[Let’s Encrypt 的 Certbot IP 指南](https://letsencrypt.org/2026/03/11/shorter-certs-certbot/)、[短期 IP 证书正式可用说明](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability/)、[Certbot 官方使用文档](https://eff-certbot.readthedocs.io/en/stable/using.html)。

离线验证包含实际 Bash 安装脚本、实际子进程 Certbot/Nginx 双桩和本地 HTTP/TLS 校验。`public-edge` CI 构建真实镜像，使用真实 Nginx、本地测试 CA 和实际 Certbot 能力探测验证握手、SSE、重定向、续期故障及到期关闭；不会联系公共 CA。本次开发环境无 Docker、公网主机或真实签发凭据，因此不能将本地结果表述为已完成公网签发、外部网络验收、35 分钟真实长连接或多日生产验证。首次公网部署后仍须在真实环境记录这些验收证据。
