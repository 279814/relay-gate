#!/usr/bin/env bash
# M0 批量探测 + 生成能力矩阵。
#
# 用法：
#   bash scripts/probe-all.sh scripts/upstreams.tsv
#
# 输入格式（Tab 分隔，# 开头为注释，空行忽略）：
#   名称	base_url	api_key	claude模型列表	gpt模型列表	你的已知状态
#
# 一个物理中转站一行。模型列表用英文逗号分隔，填 "-" 表示该站无此类模型。
#
# 输出：docs/02-上游能力矩阵.md

set -uo pipefail

IN="${1:?需要输入文件，见 scripts/upstreams.example.tsv}"
[ -f "$IN" ] || { echo "找不到 $IN"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../docs/02-上游能力矩阵.md"
TSV="$(mktemp)"
export TSV_OUT="$TSV"

mkdir -p "$(dirname "$OUT")"

declare -a NOTES

n=0
# tr -d '\r'：容忍 Windows 编辑器保存的 CRLF，否则最后一列会带上 \r
while IFS=$'\t' read -r name base key cmodel gmodel note || [ -n "${name:-}" ]; do
  case "${name:-}" in ''|'#'*) continue ;; esac
  [ -z "${base:-}" ] && continue
  n=$((n+1))
  NOTES[$n]="${note:-}"
  # 空列按 "-" 处理（该站无此类模型），不回落到默认模型名
  bash "$HERE/probe-upstream.sh" "$base" "$key" "${cmodel:--}" "${gmodel:--}" "$name"
done < <(tr -d '\r' < "$IN")

# ── 生成矩阵 ──────────────────────────────────────────────
{
  echo "# 上游能力矩阵"
  echo
  echo "生成时间：$(date '+%Y-%m-%d %H:%M:%S')　　探测站点数：$n"
  echo
  echo '`n/a` = 该站没有这类模型，未探测（不计入任何统计）。'
  echo
  echo "## 结果"
  echo
  echo '| 站点 | 类型 | 特殊要求 | /v1/models | 鉴权 | 流式 | count_tokens | **/v1/responses** | chat/completions | 长思考首token |'
  echo '|---|---|---|---|---|---|---|---|---|---|'
  while IFS=$'\t' read -r name base models auth stream count resp chat think modelmap kind quirk; do
    printf '| %s | %s | %s | %s | %s | %s | %s | **%s** | %s | %s |\n' \
      "$name" "$kind" "${quirk:-—}" "$models" "$auth" "$stream" "$count" "$resp" "$chat" "$think"
  done < "$TSV"
  echo
  echo "## 模型名原名可用性"
  echo
  echo '探测的模型名 = 你在 `upstreams.tsv` 里为该站填写的名字，逐个实测。'
  echo
  echo '| 站点 | 明细（ok = 无需映射；nomodel = 该站无此名，需改 tsv 或配映射） |'
  echo '|---|---|'
  while IFS=$'\t' read -r name base models auth stream count resp chat think modelmap kind quirk; do
    printf '| %s | `%s` |\n' "$name" "${modelmap:-—}"
  done < "$TSV"
  echo
  echo "## 结论"
  echo
  # 统计口径：剔除整站不可用（auth=none），gpt 协议只看有 gpt 模型的站
  alive_n=$(awk -F'\t' '$4!="none"' "$TSV" | wc -l | tr -d ' ')
  gpt_n=$(awk -F'\t' '$4!="none" && $7!="n/a"' "$TSV" | wc -l | tr -d ' ')
  ok_resp=$(awk -F'\t' '$4!="none" && $7=="ok"' "$TSV" | wc -l | tr -d ' ')
  ok_chat=$(awk -F'\t' '$4!="none" && $8=="ok"' "$TSV" | wc -l | tr -d ' ')
  echo "### gpt 侧协议"
  echo
  echo "统计范围：鉴权通过 **且有 gpt 模型** 的 $gpt_n 个站。"
  echo
  if [ "$gpt_n" = 0 ]; then
    echo "→ **没有任何站提供可用的 gpt 模型**。gpt 侧的 \`/v1/responses\` 与 \`/v1/chat/completions\`"
    echo "  两个端点仍按设计实现（代码量很小，都是同一套透传逻辑），但暂时没有 Route 可绑。"
    echo "  等你接入支持 gpt 的站后重跑本脚本即可。"
  else
    echo "- 支持 \`/v1/responses\`：$ok_resp / $gpt_n"
    echo "- 支持 \`/v1/chat/completions\`：$ok_chat / $gpt_n"
    echo
    if [ "$ok_resp" = "$gpt_n" ]; then
      echo "→ **全部支持 Responses**。ccswitch 侧用 OpenAI Responses API，网关纯透传 \`/v1/responses\`。"
    elif [ "$ok_resp" = 0 ]; then
      echo "→ **无站支持 Responses**。ccswitch 侧改用 OpenAI Chat Completions，网关纯透传 \`/v1/chat/completions\`。"
    elif [ "$ok_chat" = "$gpt_n" ]; then
      echo "→ **部分支持 Responses，但 Chat Completions 全站支持**。"
      echo "  建议 ccswitch 侧统一用 Chat Completions —— 全站可用，且网关仍是纯透传，无需协议转换。"
      echo "  （若坚持用 Responses，则不支持的站只能从 gpt 类 ModelName 的 Route 里排除。）"
    else
      echo "→ **两个端点都只部分支持**。按站分别配置：支持 Responses 的绑到 \`openai-responses\` 的"
      echo "  ModelName，只支持 Chat 的绑到 \`openai-chat\` 的 ModelName。ccswitch 侧需要为两类"
      echo "  gpt 模型分别配协议。"
    fi
  fi
  echo
  echo "### count_tokens"
  ct_n=$(awk -F'\t' '$4!="none" && $6!="n/a"' "$TSV" | wc -l | tr -d ' ')
  ok_ct=$(awk -F'\t' '$4!="none" && $6=="ok"' "$TSV" | wc -l | tr -d ' ')
  echo
  if [ "$ct_n" = 0 ]; then
    echo "- 无可用 claude 站，未探测。"
  else
    echo "- 支持的站：$ok_ct / $ct_n（分母 = 鉴权通过且有 claude 模型的站）"
    if [ "$ok_ct" != "$ct_n" ]; then
      echo "- → 有站不支持，网关需本地兜底实现（返回估算值），否则 Claude Code 会报错。"
    else
      echo "- → 全部支持，网关直接透传即可。"
    fi
  fi
  echo
  echo "### 客户端指纹要求（影响网关出站头处理）"
  echo
  ua_sites=$(awk -F'\t' '$12 ~ /claude-cli/ {printf "%s ", $1}' "$TSV")
  beta_sites=$(awk -F'\t' '$12 ~ /beta:1M/ {printf "%s ", $1}' "$TSV")
  if [ -n "$ua_sites" ]; then
    echo "- **需 \`user-agent: claude-cli/*\`**：$ua_sites"
    echo "  → 这些站按 UA 白名单拦截，非 Claude Code 的 UA 一律 401。网关必须原样转发入站 UA"
    echo "    （§3.3.3 已列为保留头），且**探活请求也要带**，否则探活会把活站判死。"
  else
    echo "- 无站按 UA 拦截。"
  fi
  if [ -n "$beta_sites" ]; then
    echo "- **需 \`anthropic-beta: context-1m-2025-08-07\`**：$beta_sites"
    echo "  → 不带该头直接 400。网关必须原样转发入站 \`anthropic-beta\`（§3.3.3 已列为保留头），"
    echo "    探活请求需自带该头。"
  else
    echo "- 无站强制 anthropic-beta。"
  fi
  echo
  echo "### 超时校准"
  echo
  echo '长思考首 Token 实测值见上表。若普遍在 60s 内，§4.2 的 20 分钟是充裕的安全余量；'
  echo '若出现分钟级或 timeout，说明 20 分钟确有必要。'
  echo
  echo "## 待你审核"
  echo
  echo '有些站你已知不可用，请对照下表确认脚本结论与你的经验是否一致。'
  echo '标 ⚠ 的是**不一致**项：你觉得能用但脚本判失败（可能是脚本没测对），'
  echo '或你觉得挂了但脚本判可用（可能是最近恢复了）。这些需要单独排查。'
  echo
  echo '| 站点 | 你的已知状态 | 脚本结论 | 一致? |'
  echo '|---|---|---|---|'
  i=0
  while IFS=$'\t' read -r name base models auth stream count resp chat think modelmap kind quirk; do
    i=$((i+1))
    note="${NOTES[$i]:-—}"
    # 判定优先级：鉴权失败 > 流式失败 > 可用
    if [ "$auth" = none ]; then
      verdict="**整站不可用（鉴权/连接失败）**"; usable=0
    else
      case "$stream" in
        ok/*)       verdict="可用"; usable=1 ;;
        nostream/*) verdict="可用（但不支持 SSE 流式）"; usable=1 ;;
        *)          verdict="**流式失败: $stream**"; usable=0 ;;
      esac
    fi
    # 与你的备注比对。"不稳"含"稳"，故先判否定词
    case "$note" in
      *不稳*|*不确定*)     flag="—" ;;
      *好用*|*可用*|*稳*)  [ "$usable" = 1 ] && flag="✓" || flag="⚠" ;;
      *挂*|*不可用*|*废*)  [ "$usable" = 0 ] && flag="✓" || flag="⚠" ;;
      *)                   flag="—" ;;
    esac
    printf '| %s | %s | %s | %s |\n' "$name" "$note" "$verdict" "$flag"
  done < "$TSV"
} > "$OUT"

rm -f "$TSV"
echo
echo "矩阵已生成：$OUT"
