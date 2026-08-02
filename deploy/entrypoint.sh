#!/bin/sh
# 容器入口：把数据目录的属主修正到运行用户，然后降权执行。
#
# 为什么需要这一层，而不是在 Dockerfile 里 chown 就完事：
# Dockerfile 的 chown 只作用于**镜像里**那个目录，而绑定挂载
# （./data:/app/data）会用宿主的目录整个盖住它 —— 属主由宿主决定，
# 通常是 root。于是以 uid 10001 运行的进程建不了库文件，启动直接失败，
# 报的还是 `unable to open database file (14)`：一个完全看不出是权限
# 问题的错误。（实测踩到的，不是推测。）
#
# 也不用 compose 的 `user:` 指定宿主 uid：那在 Linux 上可行，
# 但 Windows/macOS 的 Docker Desktop 上 `id -u` 给出的是宿主 shell 的 uid，
# 与虚拟机里的挂载语义对不上，容器会起不来 —— 而 §8 的主路径正是
# 「先本地（Windows）后服务器（Linux）」，两边都得能跑。
#
# 所以：以 root 进入，修正属主，再用 su-exec 降权。容器里 root 的
# 存续时间只有这几行。

set -e

DB_PATH="${RELAY_DB:-/app/data/relay-gate.db}"
DATA_DIR="$(dirname "$DB_PATH")"

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"

    # 只修正数据库所在目录与 SQLite 的副产品，不递归 chown 整棵树。
    #
    # 无条件递归 chown 会在样本库长到几 GB、成千上万个文件时拖慢每次启动，
    # 也会把 RELAY_DB 之外的用户文件一并改掉。目录权限是创建数据库所需的
    # 最小集合；库文件本身则逐个收归 relay，覆盖「目录属主已经正确但从别处
    # 拷进来的 db 仍是 root-owned」这一种恢复场景。
    if [ -n "$DATA_DIR" ]; then
        if [ "$(stat -c '%u' "$DATA_DIR")" != "$RELAY_UID" ]; then
            echo "修正数据目录属主：$DATA_DIR -> $RELAY_UID:$RELAY_GID"
            chown "$RELAY_UID:$RELAY_GID" "$DATA_DIR"
        fi
        chmod 700 "$DATA_DIR"

        # SQLite 在 WAL 模式下会使用 db-wal / db-shm；回滚日志则叫
        # db-journal。它们都可能在容器重启时已经存在，必须和主库一起
        # 收归 relay，否则非 root 进程会在打开数据库前就被权限挡住。
        for suffix in '' '-wal' '-shm' '-journal'; do
            file="${DB_PATH}${suffix}"
            if [ -e "$file" ]; then
                chown "$RELAY_UID:$RELAY_GID" "$file"
            fi
        done
    fi

    # 降权。exec 让 relay-gate 接管 PID 1 —— 否则 SIGTERM 发给的是这个
    # shell，它不转发信号，于是优雅关闭（§4.8：不杀在途的流式连接）
    # 根本不会执行，docker stop 只能等超时后 SIGKILL。
    exec su-exec "$RELAY_UID:$RELAY_GID" "$@"
fi

# 已经是非 root（compose 里显式配了 user:，或用具名卷）：直接执行。
# 这条路径下属主由调用方负责，我们没有 chown 的权限，也不该有。
exec "$@"
