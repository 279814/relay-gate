#!/usr/bin/env bash
# M0 单站能力探测。一个物理中转站跑一次，一次性验证该站的多个模型。
# 输出人类可读结果 + 一行 TSV 供 probe-all.sh 汇总。
#
# 用法：
#   ./probe-upstream.sh <base_url> <api_key> <claude模型列表> <gpt模型列表> [name]
#
# 模型列表用英文逗号分隔（claude-opus-5,claude-fable-5），填 "-" 表示该站无此类模型。
# 测的就是你填的名字，脚本不猜、不替换、不补默认值。
# base_url 填根地址，不带 /v1。环境变量 TSV_OUT=<file> 时追加一行 TSV 汇总。

set -uo pipefail

BASE="${1:?需要 base_url，如 https://api.example.com}"
KEY="${2:?需要 api_key}"
CLAUDE_LIST="${3:--}"
GPT_LIST="${4:--}"
NAME="${5:-$BASE}"

BASE="${BASE%/}"
AV="anthropic-version: 2023-06-01"
CT="content-type: application/json"

# 以下三项照抄真实 Claude Code 的请求特征（抓包所得，见 §0 注释）。
# 部分站按 UA 前缀白名单拦截，非 CC 的 UA 一律 401；
# 部分站声明「只转发 Claude Code 流量」，请求越像 CC 越不容易被误拒。
UA_CLI='claude-cli/2.1.220 (external, sdk-cli)'
# 真实 CC 的 anthropic-beta 开关集合。注意其中**不含** context-1m
BETA_CC='claude-code-20250219,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advanced-tool-use-2025-11-20,effort-2025-11-24,fallback-credit-2026-06-01'
# 真实 CC 打的是 /v1/messages?beta=true，不是裸路径
MSG_Q='?beta=true'
# 1M 上下文开关：仅在探到站点强制要求时才追加（有的站不带就 400）
BETA_1M='context-1m-2025-08-07'
# 用于区分「key 无效」与「key 有效但站点故障」
BOGUS_KEY='sk-probe-invalid-000000000000000000'

BETA_REQ="$BETA_CC"   # 实际发送的 anthropic-beta 值，探到强制项时会追加
BETA_1M_REQ='no'      # 该站是否强制 context-1m
UA_REQ='no'           # 该站是否强制 claude-cli UA

# "-" / 空 / n/a 表示该站没有这类模型
has_model() { case "${1:-}" in ''|'-'|'n/a'|'N/A'|'无') return 1 ;; *) return 0 ;; esac; }

# 逗号分隔 → 数组，顺带剔除空白与占位符
IFS=',' read -ra CM_RAW <<< "$CLAUDE_LIST"
IFS=',' read -ra GM_RAW <<< "$GPT_LIST"
CMODELS=(); for m in "${CM_RAW[@]}"; do m="${m//[[:space:]]/}"; has_model "$m" && CMODELS+=("$m"); done
GMODELS=(); for m in "${GM_RAW[@]}"; do m="${m//[[:space:]]/}"; has_model "$m" && GMODELS+=("$m"); done

HAS_CLAUDE=0; [ ${#CMODELS[@]} -gt 0 ] && HAS_CLAUDE=1
HAS_GPT=0;    [ ${#GMODELS[@]} -gt 0 ] && HAS_GPT=1
if [ $HAS_CLAUDE = 0 ] && [ $HAS_GPT = 0 ]; then
  echo "错误：claude 与 gpt 模型列表都为空，无从探测。至少给一个。" >&2
  exit 2
fi
CMAIN="${CMODELS[0]:-}"   # 鉴权/流式等单模型检查用列表里的第一个
GMAIN="${GMODELS[0]:-}"

# 长思考题：实测真实负载下的首 Token 延迟，校验 20 分钟超时是否必要
THINK_Q='Prove that there are infinitely many primes p such that p+2 is also prime, or explain rigorously why this remains open. Then enumerate the first 12 twin prime pairs.'

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; }
info() { printf '  \033[36m·\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
sect() { printf '\n\033[1m%s\033[0m\n' "$1"; }

now_ms() { python3 -c 'import time;print(int(time.time()*1000))' 2>/dev/null \
        || python -c 'import time;print(int(time.time()*1000))' 2>/dev/null \
        || date +%s%3N; }

# 所有请求统一带上的头，照抄真实 Claude Code 的指纹。
# 缺 UA 会被按 UA 白名单拦截的站 401；其余头是为了让请求整体像 CC
# （有的站声明只转发 Claude Code 流量），代价只有几十字节。
common_headers() {
  printf '%s\n' -H "user-agent: $UA_CLI"
  printf '%s\n' -H "anthropic-beta: $BETA_REQ"
  printf '%s\n' -H "x-app: cli"
  printf '%s\n' -H "anthropic-dangerous-direct-browser-access: true"
  printf '%s\n' -H "accept: application/json"
  printf '%s\n' -H "X-Stainless-Lang: js"
  printf '%s\n' -H "X-Stainless-Package-Version: 0.94.0"
  printf '%s\n' -H "X-Stainless-OS: Windows"
  printf '%s\n' -H "X-Stainless-Arch: x64"
  printf '%s\n' -H "X-Stainless-Runtime: node"
  printf '%s\n' -H "X-Stainless-Retry-Count: 0"
}
# 把 common_headers 读进数组 CH
load_ch() { CH=(); while IFS= read -r x; do CH+=("$x"); done < <(common_headers); }
load_ch

# 只回状态码
code_of() { curl -sS --max-time "${T:-90}" -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }
# 回 body + 末行状态码
body_code() { curl -sS --max-time "${T:-90}" -w $'\n%{http_code}' "$@" 2>&1 || printf '\n000'; }

# 流式探测：回显 "结论|首token毫秒"
# 结论: ok | nostream | fake_empty | fake_error | http_<code> | timeout | neterr
#   nostream = 2xx 且有真实内容，但不是 SSE（忽略了 stream:true）。站可用，但测不到首 Token
# 用法: stream_probe <落盘前缀> <url> <payload> <delta正则> <超时秒> [curl额外参数...]
# 响应体落到 <前缀>，响应头落到 <前缀>.hdr —— 由调用方创建与清理（子 shell 传不回变量）
stream_probe() {
  local dump="$1" url="$2" payload="$3" delta_pat="$4" timeout="$5"; shift 5
  local t0 t1 rc hc verdict
  t0=$(now_ms)
  # -N 关闭缓冲逐块落盘；-D 单独存响应头
  curl -sS -N --max-time "$timeout" -D "$dump.hdr" -X POST "$url" \
    -H "$CT" "$@" -d "$payload" > "$dump" 2>"$dump.err"
  rc=$?
  t1=$(now_ms)

  hc=$(awk '/^HTTP\//{c=$2} END{print c+0}' "$dump.hdr" 2>/dev/null)
  hc=${hc:-0}

  if [ "$rc" = 28 ]; then
    verdict="timeout"
  elif [ "$rc" != 0 ] && [ "$hc" = 0 ]; then
    verdict="neterr"
  elif [ "$hc" -ge 400 ] 2>/dev/null; then
    verdict="http_${hc}"
  elif grep -qE "$delta_pat" "$dump"; then
    verdict="ok"
  elif grep -qiE '^event: *error|"error"[[:space:]]*:' "$dump"; then
    verdict="fake_error"
  elif ! grep -qi 'content-type:.*event-stream' "$dump.hdr" \
       && grep -qE '"(text|content|output_text)"[[:space:]]*:[[:space:]]*"[^"]' "$dump"; then
    # 非 SSE 但确实回了内容 —— 站可用，只是忽略了 stream:true
    verdict="nostream"
  else
    verdict="fake_empty"
  fi

  printf '%s|%s' "$verdict" "$((t1-t0))"
}

sect "═══ $NAME  ($BASE) ═══"
info "claude 模型：${CLAUDE_LIST}"
info "gpt 模型：${GPT_LIST}"

# ─── 0. 客户端指纹要求（UA / anthropic-beta）─────────────
# 必须先于所有其他检查：这两项探不出来，后面全部会误判成鉴权失败或 400。
#
# 基线（$UA_CLI / $BETA_CC / $MSG_Q）取自真实 Claude Code 的请求原文，实测特征：
#   POST /v1/messages?beta=true
#   user-agent: claude-cli/2.1.220 (external, sdk-cli)
#   anthropic-beta: claude-code-20250219,interleaved-thinking-…（9 个开关，**不含** context-1m）
# 此处只探两件基线之外的事：① 该站是否按 UA 拦截 ② 是否强制 context-1m。
sect "0. 客户端指纹要求（UA / anthropic-beta）"

# 0a. UA 白名单：有的站只放行 claude-cli/<ver> 前缀，其余一律 401
# 先在 /v1/models 上比对；该端点区分不出来（两者同码）时，再在真实模型端点上比对一次。
if [ $HAS_CLAUDE = 1 ]; then
  ua_body="{\"model\":\"$CMAIN\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}"
  ua_path="/v1/messages$MSG_Q"
else
  ua_body="{\"model\":\"$GMAIN\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}"
  ua_path=/v1/chat/completions
fi

T=30
c_plain=$(code_of -H "Authorization: Bearer $KEY" "$BASE/v1/models")
c_cli=$(code_of -H "Authorization: Bearer $KEY" -H "user-agent: $UA_CLI" "$BASE/v1/models")
if [ "$c_plain" = "$c_cli" ]; then
  # /v1/models 区分不出（如两者都 404 或都 401），改在真实端点上比
  T=60
  c_plain=$(code_of -X POST "$BASE$ua_path" -H "Authorization: Bearer $KEY" -H "$AV" -H "$CT" -d "$ua_body")
  c_cli=$(code_of -X POST "$BASE$ua_path" -H "Authorization: Bearer $KEY" -H "$AV" -H "$CT" \
          -H "user-agent: $UA_CLI" -d "$ua_body")
fi
if [ "$c_plain" != 200 ] && [ "$c_cli" = 200 ]; then
  warn "该站按 User-Agent 过滤：默认 UA → $c_plain，claude-cli UA → 200"
  info "→ 网关出站必须原样转发 Claude Code 的 user-agent（§3.3.3 已要求保留）"
  UA_REQ=yes
elif [ "$c_plain" = "$c_cli" ]; then
  info "UA 无影响（两种 UA 同为 $c_plain）"
else
  info "UA 影响不明确（默认 $c_plain / claude-cli $c_cli）"
fi

# 0b. context-1m 强制项：真实 CC 不发这个开关，但有的站不带就 400。
# 先按 CC 基线打一发，只有明确报「1m 上下文」才追加 —— 免得给不需要的站乱加开关。
if [ $HAS_CLAUDE = 1 ]; then
  bp="{\"model\":\"$CMAIN\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}"
  T=60
  out=$(body_code -X POST "$BASE/v1/messages$MSG_Q" -H "Authorization: Bearer $KEY" -H "$AV" -H "$CT" \
        "${CH[@]}" -d "$bp")
  c=$(printf '%s' "$out" | tail -n1)
  # 只认「非 200 + 明确提到 1m/长上下文」，避免把 5xx 里偶然出现的字样当成开关要求
  if [ "$c" != 200 ] && printf '%s' "$out" | grep -qiE '1m 上下文|context-1m|1m context|长上下文'; then
    BETA_REQ="$BETA_CC,$BETA_1M"
    BETA_1M_REQ=yes
    load_ch
    c2=$(code_of -X POST "$BASE/v1/messages$MSG_Q" -H "Authorization: Bearer $KEY" -H "$AV" -H "$CT" \
         "${CH[@]}" -d "$bp")
    if [ "$c2" = 200 ]; then
      warn "该站强制 1M 上下文开关，已追加 anthropic-beta: $BETA_1M"
    else
      warn "该站要求 1M 上下文（不带 → $c），但追加后仍 $c2"
      info "→ 两条路都不通：不带该开关 400、带上 $c2。属站点侧问题，非请求缺头"
    fi
  else
    info "无额外 anthropic-beta 要求（按 CC 基线 9 个开关即可）"
  fi
else
  info "无 claude 模型，跳过 anthropic-beta 探测"
fi

# ─── 1. L1 端点：/v1/models ───────────────────────────────
sect "1. L1 探活端点 /v1/models"
T=30
c=$(code_of -H "Authorization: Bearer $KEY" "${CH[@]}" "$BASE/v1/models")
case "$c" in
  200)     pass "200 → 可作 L1 端点（l1_path=/v1/models）"; R_MODELS="200" ;;
  404|405) info "$c → 不提供；L1 降级为 TCP/TLS（l1_path 留空）"; R_MODELS="$c" ;;
  401|403) fail "$c → 鉴权被拒。若下面 x-api-key 能通说明该站只认 x-api-key"; R_MODELS="$c" ;;
  000)     fail "网络不可达 / 超时"; R_MODELS="neterr" ;;
  *)       warn "$c"; R_MODELS="$c" ;;
esac

# ─── 2. 鉴权头风格 ────────────────────────────────────────
# 在该站**实际拥有**的协议上探，不能一律用 /v1/messages —— 纯 gpt 站没有它
sect "2. 鉴权头风格"
T=90

# try_auth <path> <payload>：打印明细，结果写入全局 R_AUTH / R_AUTHNOTE
# 两种头都不通时要分清「key 被拒」和「key 没问题但站坏了」——
# 前者要换 key，后者等站恢复。判据是真 key 的状态码 + 假 key 对照。
try_auth() {
  local path="$1" payload="$2" xk br bogus
  xk=$(code_of -X POST "$BASE$path" -H "x-api-key: $KEY" -H "$AV" -H "$CT" "${CH[@]}" -d "$payload")
  br=$(code_of -X POST "$BASE$path" -H "Authorization: Bearer $KEY" -H "$AV" -H "$CT" "${CH[@]}" -d "$payload")
  [ "$xk" = 200 ] && pass "x-api-key → 200" || fail "x-api-key → $xk"
  [ "$br" = 200 ] && pass "Bearer → 200"    || fail "Bearer → $br"
  if   [ "$xk" = 200 ] && [ "$br" = 200 ]; then R_AUTH=both;      R_AUTHNOTE=""
  elif [ "$xk" = 200 ];                    then R_AUTH=x-api-key; R_AUTHNOTE=""
  elif [ "$br" = 200 ];                    then R_AUTH=bearer;    R_AUTHNOTE=""
  else
    R_AUTH=none
    case "$xk/$br" in
      40[13]/*|*/40[13])
        R_AUTHNOTE="鉴权被拒(key 无效/分组停用)"
        info "真 key 返回 401/403 → key 本身被拒，需换 key" ;;
      *)
        # 未被 401/403 拒 → key 已通过鉴权，失败来自站点自身。用假 key 反证
        bogus=$(code_of -X POST "$BASE$path" -H "Authorization: Bearer $BOGUS_KEY" -H "$AV" -H "$CT" "${CH[@]}" -d "$payload")
        case "$bogus" in
          40[13]) R_AUTHNOTE="key 有效，站点故障(HTTP $br)"
                  warn "假 key → $bogus，真 key → $br：**key 是好的，站点自身故障**" ;;
          *)      R_AUTHNOTE="站点故障(HTTP $br)"
                  warn "真假 key 同为 $br → 站点连鉴权都没走到，整站故障" ;;
        esac ;;
    esac
  fi
}

if [ $HAS_CLAUDE = 1 ]; then
  info "探测端点：/v1/messages$MSG_Q（模型 $CMAIN）"
  try_auth "/v1/messages$MSG_Q" \
    "{\"model\":\"$CMAIN\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}"
else
  info "无 claude 模型，改在 /v1/chat/completions 上探（模型 $GMAIN）"
  try_auth /v1/chat/completions \
    "{\"model\":\"$GMAIN\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}"
  if [ "$R_AUTH" = none ]; then
    info "改在 /v1/responses 上重探"
    try_auth /v1/responses \
      "{\"model\":\"$GMAIN\",\"max_output_tokens\":16,\"input\":\"1+1=?\"}"
  fi
fi

case "$R_AUTH" in
  both)       AUTH=(-H "x-api-key: $KEY");            info "两种都通 → auth_style 可用 auto" ;;
  x-api-key)  AUTH=(-H "x-api-key: $KEY") ;;
  bearer)     AUTH=(-H "Authorization: Bearer $KEY") ;;
  none)       AUTH=(-H "x-api-key: $KEY")
              warn "两种鉴权都不通（${R_AUTHNOTE:-原因不明}）。后续检查结果不可信" ;;
esac

# ─── 3. 模型名（是否需要映射）─────────────────────────────
# 只测 tsv 里为该站填的模型名，不测别站的名字、不加硬编码候选。
sect "3. 模型名原名可用性（200 = 无需映射，body 零改动）"
R_MODELMAP=""
T=90

# check_model <协议> <模型名>
# 鉴权头按协议分别定：同一个站的 anthropic 与 openai 端点鉴权风格可能不同
# （实测有站的 /v1/messages 认 x-api-key，但 openai 端点只认 Bearer），
# 用统一的 $AUTH 会把「协议鉴权风格不同」误报成「模型不可用」。
check_model() {
  local proto="$1" m="$2" path out c ep
  local -a a
  if [ "$proto" = anthropic ]; then
    a=("${AUTH[@]}")
    out=$(body_code -X POST "$BASE/v1/messages$MSG_Q" "${a[@]}" -H "$AV" -H "$CT" "${CH[@]}" \
          -d "{\"model\":\"$m\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}")
    c=$(printf '%s' "$out" | tail -n1)
    ep=""
  else
    a=(-H "Authorization: Bearer $KEY")
    out=$(body_code -X POST "$BASE/v1/chat/completions" "${a[@]}" -H "$CT" "${CH[@]}" \
          -d "{\"model\":\"$m\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}")
    c=$(printf '%s' "$out" | tail -n1)
    ep=""
    # Bearer 被拒 → 换 x-api-key 重试（与 §6/§7 同一套退路）
    if [ "$c" = 401 ] || [ "$c" = 403 ]; then
      out=$(body_code -X POST "$BASE/v1/chat/completions" -H "x-api-key: $KEY" -H "$CT" "${CH[@]}" \
            -d "{\"model\":\"$m\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}")
      c=$(printf '%s' "$out" | tail -n1)
    fi
    # chat 说「本 API 不支持该模型」→ 该模型可能只挂在 Responses 上，换端点再测
    if [ "$c" != 200 ] && printf '%s' "$out" | grep -qiE '不支持所选模型|not supported'; then
      out=$(body_code -X POST "$BASE/v1/responses" "${a[@]}" -H "$CT" "${CH[@]}" \
            -d "{\"model\":\"$m\",\"max_output_tokens\":16,\"input\":\"1+1=?\"}")
      c=$(printf '%s' "$out" | tail -n1)
      ep="(仅 responses)"
    fi
  fi
  if [ "$c" = 200 ]; then
    pass "$m → 200 $ep"; R_MODELMAP="${R_MODELMAP}${m}=ok${ep:+@resp};"
  elif printf '%s' "$out" | grep -qiE 'model.{0,20}(not.{0,5}found|not.{0,5}exist|invalid|unsupported|no such)|不支持所选模型|模型不存在'; then
    # 区分「模型不存在」和「站挂了」—— 这决定 §4.3 的失败分类
    fail "$m → $c 该站无此模型名（需配映射或改 tsv）"; R_MODELMAP="${R_MODELMAP}${m}=nomodel;"
  else
    fail "$m → $c $ep"; R_MODELMAP="${R_MODELMAP}${m}=${c};"
  fi
}

if [ $HAS_CLAUDE = 1 ]; then
  for m in "${CMODELS[@]}"; do check_model anthropic "$m"; done
else
  info "跳过 claude 系列（该站无此类模型）"
fi
if [ $HAS_GPT = 1 ]; then
  for m in "${GMODELS[@]}"; do check_model openai "$m"; done
else
  info "跳过 gpt 系列（该站无此类模型）"
fi

# ─── 4. 流式 + 假活检测 + 首 Token 延迟 ───────────────────
sect "4. 流式（真活 / 假活 / 首 Token 延迟）"
if [ $HAS_CLAUDE = 1 ]; then
  SPATH="/v1/messages$MSG_Q"
  SBODY="{\"model\":\"$CMAIN\",\"max_tokens\":1,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}"
  SPAT='content_block_delta'
  SMODEL="$CMAIN"
else
  SPATH=/v1/chat/completions
  SBODY="{\"model\":\"$GMAIN\",\"max_tokens\":1,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}"
  SPAT='"delta"[[:space:]]*:|output_text.delta'
  SMODEL="$GMAIN"
fi
info "探测端点：$SPATH（模型 $SMODEL）"
DUMP=$(mktemp)
r=$(stream_probe "$DUMP" "$BASE$SPATH" "$SBODY" "$SPAT" 120 "${AUTH[@]}" -H "$AV" "${CH[@]}")
V=${r%%|*}; MS=${r##*|}
case "$V" in
  ok)         pass "收到有效 delta（真活），耗时 ${MS}ms"; R_STREAM="ok/${MS}ms" ;;
  nostream)   warn "站可用但未按 SSE 返回（忽略了 stream:true），耗时 ${MS}ms"
              info "→ 该站探活只能测总时长，测不到首 Token；真实流式体验也会退化"
              R_STREAM="nostream/${MS}ms" ;;
  fake_empty) fail "200 但无有效 delta → 假活"; R_STREAM="fake_empty" ;;
  fake_error) fail "流内 error："; sed -n '1,4p' "$DUMP" | sed 's/^/      /'; R_STREAM="fake_error" ;;
  timeout)    fail "120s 内无首 Token"; R_STREAM="timeout" ;;
  *)          fail "$V"; sed -n '1,3p' "$DUMP" | sed 's/^/      /'; R_STREAM="$V" ;;
esac
rm -f "$DUMP" "$DUMP.hdr" "$DUMP.err"

# ─── 5. count_tokens ─────────────────────────────────────
sect "5. /v1/messages/count_tokens（Claude Code 每轮都调）"
T=60
if [ $HAS_CLAUDE = 0 ]; then
  info "跳过（Anthropic 专属端点，该站无 claude 模型）"; R_COUNT="n/a"
else
  b="{\"model\":\"$CMAIN\",\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}"
  out=$(body_code -X POST "$BASE/v1/messages/count_tokens" "${AUTH[@]}" -H "$AV" -H "$CT" "${CH[@]}" -d "$b")
  if printf '%s' "$out" | grep -q 'input_tokens'; then
    pass "支持"; R_COUNT="ok"
  else
    c=$(printf '%s' "$out" | tail -n1)
    if [ "$R_AUTH" = none ]; then
      fail "→ $c（站点整体不可用，此项结论无效）"
    else
      fail "→ $c 不支持（网关需本地兜底实现）"
    fi
    R_COUNT="$c"
  fi
fi

# ─── 6. ★ /v1/responses ──────────────────────────────────
sect "6. ★ /v1/responses（决定 gpt 侧能否纯透传）"
if [ $HAS_GPT = 0 ]; then
  info "跳过（该站无 gpt 模型，此协议对它无意义）"; R_RESP="n/a"
else
  b="{\"model\":\"$GMAIN\",\"max_output_tokens\":16,\"input\":\"1+1=?\"}"
  out=$(body_code -X POST "$BASE/v1/responses" -H "Authorization: Bearer $KEY" -H "$CT" "${CH[@]}" -d "$b")
  c=$(printf '%s' "$out" | tail -n1)
  # Bearer 被拒时用 x-api-key 重试一次，避免把「鉴权风格不同」误判成「不支持该端点」
  if [ "$c" = 401 ] || [ "$c" = 403 ]; then
    out=$(body_code -X POST "$BASE/v1/responses" -H "x-api-key: $KEY" -H "$CT" "${CH[@]}" -d "$b")
    c=$(printf '%s' "$out" | tail -n1)
    [ "$c" = 200 ] && info "该端点需 x-api-key（非 Bearer）"
  fi
  if [ "$c" = 200 ]; then
    pass "支持 → gpt 侧纯透传，无需协议转换"; R_RESP="ok"
  else
    fail "→ $c（模型 $GMAIN）"; printf '%s' "$out" | head -c 240 | sed 's/^/      /'; echo
    R_RESP="$c"
  fi
fi

# ─── 7. /v1/chat/completions ─────────────────────────────
sect "7. /v1/chat/completions"
if [ $HAS_GPT = 0 ]; then
  info "跳过（该站无 gpt 模型）"; R_CHAT="n/a"
else
  b="{\"model\":\"$GMAIN\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}]}"
  c=$(code_of -X POST "$BASE/v1/chat/completions" -H "Authorization: Bearer $KEY" -H "$CT" "${CH[@]}" -d "$b")
  if [ "$c" = 401 ] || [ "$c" = 403 ]; then
    c=$(code_of -X POST "$BASE/v1/chat/completions" -H "x-api-key: $KEY" -H "$CT" "${CH[@]}" -d "$b")
    [ "$c" = 200 ] && info "该端点需 x-api-key（非 Bearer）"
  fi
  [ "$c" = 200 ] && { pass "支持"; R_CHAT="ok"; } || { fail "→ $c（模型 $GMAIN）"; R_CHAT="$c"; }
fi

# ─── 8. 长思考首 Token 延迟（校验 20min 超时是否必要）────
sect "8. 长思考首 Token 延迟（校准 §4.2 的 20 分钟）"
case "${R_STREAM%%/*}" in
  ok|nostream) ;;
  *) info "跳过（基础流式已失败）"; R_THINK="skip" ;;
esac
if [ "${R_THINK:-}" != skip ]; then
  QJSON=$(printf '%s' "$THINK_Q" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))' 2>/dev/null \
        || printf '%s' "$THINK_Q" | python -c 'import json,sys;print(json.dumps(sys.stdin.read()))' 2>/dev/null \
        || printf '"%s"' "$THINK_Q")
  if [ $HAS_CLAUDE = 1 ]; then
    TPATH="/v1/messages$MSG_Q"
    TBODY="{\"model\":\"$CMAIN\",\"max_tokens\":64,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":$QJSON}]}"
    TPAT='content_block_delta|thinking_delta'
  else
    TPATH=/v1/chat/completions
    TBODY="{\"model\":\"$GMAIN\",\"max_tokens\":64,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":$QJSON}]}"
    TPAT='"delta"[[:space:]]*:|output_text.delta'
  fi
  DUMP2=$(mktemp)
  r=$(stream_probe "$DUMP2" "$BASE$TPATH" "$TBODY" "$TPAT" 1200 "${AUTH[@]}" -H "$AV" "${CH[@]}")
  V=${r%%|*}; MS2=${r##*|}
  case "$V" in
    ok)       pass "首 Token ${MS2}ms（约 $((MS2/1000))s）"; R_THINK="${MS2}ms" ;;
    nostream) warn "非 SSE，${MS2}ms 是**总时长**而非首 Token（约 $((MS2/1000))s）"
              R_THINK="总时长${MS2}ms" ;;
    timeout)  fail "20 分钟内无响应 → 该站不可用于长任务"; R_THINK="timeout" ;;
    *)        fail "$V"; R_THINK="$V" ;;
  esac
  rm -f "$DUMP2" "$DUMP2.hdr" "$DUMP2.err"
fi

# ─── 汇总 ────────────────────────────────────────────────
sect "小结：$NAME"
KIND="claude+gpt"
[ $HAS_GPT = 0 ]    && KIND="仅 claude"
[ $HAS_CLAUDE = 0 ] && KIND="仅 gpt"
QUIRK=""
[ "$UA_REQ" = yes ]     && QUIRK="需claude-cli UA"
[ "$BETA_1M_REQ" = yes ] && QUIRK="${QUIRK:+$QUIRK + }需beta:1M"
QUIRK="${QUIRK:-—}"
printf '  站点类型=%s  特殊要求=%s\n' "$KIND" "$QUIRK"
printf '  models=%s  auth=%s  stream=%s  count_tokens=%s\n' \
  "$R_MODELS" "$R_AUTH" "$R_STREAM" "$R_COUNT"
printf '  responses=%s  chat=%s  长思考首token=%s\n' "$R_RESP" "$R_CHAT" "$R_THINK"
printf '  模型名: %s\n' "$R_MODELMAP"

if [ -n "${TSV_OUT:-}" ]; then
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$NAME" "$BASE" "$R_MODELS" "$R_AUTH" "$R_STREAM" "$R_COUNT" \
    "$R_RESP" "$R_CHAT" "$R_THINK" "$R_MODELMAP" "$KIND" "$QUIRK" >> "$TSV_OUT"
fi
