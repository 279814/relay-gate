# relay-gate 镜像（M7）。
#
# 两阶段：builder 编译静态二进制，运行阶段只带二进制 + CA 证书。
# 前端已经 go:embed 进二进制（§6），所以运行镜像里没有任何静态资源目录 ——
# 也就没有「忘了拷 static/」这类只在生产才现形的问题。

# ── 构建阶段 ─────────────────────────────────────────────
# 版本与 go.mod 的 toolchain 对齐。写死大版本而不是 latest：
# 一个能构建的镜像不该因为上游发了新版而在某天早上突然构建不出来。
FROM golang:1.26-alpine AS builder

WORKDIR /src

# 先只拷依赖清单再 download，让这一层能被缓存 ——
# 改一行代码就重下一遍全部依赖的话，每次构建都要多等一分钟。
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 是硬要求，不是优化：
# 驱动选的就是纯 Go 的 modernc.org/sqlite（§6），开着 CGO 反而会在
# alpine（musl）与 debian（glibc）之间产生动态链接差异 —— 而那类问题
# 的症状是「本地好好的，容器里起不来」。
#
# -trimpath 去掉构建机的绝对路径：否则 panic 栈里会带上
# /home/某人/go/src/... 这种与运行环境无关、且泄露目录结构的信息。
#
# -s -w 去掉符号表与 DWARF，二进制小一半。代价是 panic 栈没有行号 ——
# 可接受，因为这个服务的诊断主力是结构化日志与样本库，不是 core dump。
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/relay-gate ./cmd/relay-gate

# ── 运行阶段 ─────────────────────────────────────────────
FROM alpine:3.21

# ca-certificates 是必需的：出站要连公益站的 HTTPS，没有根证书链
# 一律 x509 校验失败。alpine 基础镜像默认不带它。
#
# tzdata 是为了让 TZ 环境变量真的生效。探活成本按「天」分桶（§5.2d），
# 没有 tzdata 时容器只认 UTC —— 于是「今日 L1 次数」在东八区会在
# 早上 8 点而不是午夜清零，一个说不清的计数器。
#
# su-exec 用于 entrypoint 里降权（见 deploy/entrypoint.sh）。
# 它比 gosu 小得多（约 10KB），做的是同一件事。
RUN apk add --no-cache ca-certificates tzdata su-exec

# 非 root 运行。容器逃逸不是主要威胁模型，真正的理由更直接：
# 库文件权限收到 0600（store.restrictPerms）之后，以 root 跑等于
# 那个 0600 只挡住了别人、挡不住这个容器里的任何进程 —— 而挂载出去的
# data/ 在宿主上会变成 root 拥有，你自己反而要 sudo 才能备份。
RUN addgroup -g 10001 -S relay && adduser -u 10001 -S relay -G relay

WORKDIR /app
COPY --from=builder /out/relay-gate /app/relay-gate
COPY deploy/entrypoint.sh /app/entrypoint.sh
# 显式 chmod：Windows 上检出的文件没有 Unix 执行位，
# 不加这一行会在启动时报 "permission denied" —— 而 §8 的主路径
# 恰恰是先在 Windows 上开发。
RUN chmod +x /app/entrypoint.sh

# 数据目录预先建好并归属 relay。
#
# 这一层在**具名卷**下有用（空卷会继承挂载点的属主）；
# 绑定挂载下会被宿主目录整个盖住，那种情形由 entrypoint 里的 chown 兜底。
RUN mkdir -p /app/data && chown -R relay:relay /app/data

# 刻意**不写 USER**：entrypoint 需要 root 才能修正挂载目录的属主，
# 修完立刻用 su-exec 降到 RELAY_UID。容器里 root 的存续时间只有那几行。
# 要跳过这一步就在 compose 里显式配 `user:` —— entrypoint 会识别出
# 自己已经不是 root，直接执行。
ENV RELAY_UID=10001 \
    RELAY_GID=10001

# 容器内监听 0.0.0.0：容器的网络命名空间是隔离的，绑 127.0.0.1 会让
# 端口映射打不进来。**对外的收紧在 compose 的 ports 上做**
# （127.0.0.1:18787:18787），§5.2f 要求的「只监听内网」由那一层保证。
ENV RELAY_ADDR=0.0.0.0:18787 \
    RELAY_DB=/app/data/relay-gate.db

EXPOSE 18787

# /healthz 报的是**进程活着**，不代表有可用上游（main.go 里写明了这个边界）。
# 这正是 healthcheck 该用的语义：所有上游都挂时重启进程治不了上游，
# 而编排器看到 unhealthy 就会重启。
#
# start-period 给 10s：启动要开库、跑 migrate、恢复成本快照，
# 冷启动比稳态慢得多，不给宽限期会在启动过程中先判一次 unhealthy。
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:18787/healthz >/dev/null 2>&1 || exit 1

# exec 形式（不经 shell）：SIGTERM 必须直达 Go 进程。
# 走 shell 形式的话 PID 1 是 /bin/sh，它不转发信号，于是优雅关闭
# （§4.8：不杀在途的流式连接）完全不会执行，docker stop 只会在
# 超时后 SIGKILL —— 表现为每次重启都掐断一次正在进行的对话。
#
# entrypoint.sh 自己也用 exec 交棒，所以最终 PID 1 仍是 relay-gate。
ENTRYPOINT ["/app/entrypoint.sh", "/app/relay-gate"]
