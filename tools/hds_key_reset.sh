#!/usr/bin/env bash
# hds_key_reset.sh — 重置容器 SSH 私钥并对平台限流做退避重试。
#
# 背景（2026-09-22 run#2777 / job 106576908613 根因）：
#   华为云 open-api 返回 "Too many requests. Please try again later."（短时间多次调用
#   list/start/start-tunnel 后限流），ssh-key-reset 拿不到私钥；旧写法
#     echo yes | tools/hds_session.sh devenv ssh-key-reset ... > /tmp/reset.log 2>&1 || true
#   把该错误整个吞掉，既不重试也不留标记，一路走到后续步骤的 chmod 才炸——日志里
#   没有一行病因，且把本应按「跳过、不告警」收尾的轮次升级成真失败 + 失败告警邮件。
#
# 本脚本的判据与退出码约定：
#   * 成功判据 = 私钥文件 ~/.devenv/.ssh/IdentityFile/<实例ID> 真实存在（不看 CLI 文本）。
#   * 0  = 私钥已就绪，调用方照常继续（chmod 由本脚本完成）。
#   * 10 = 重试耗尽且末次错误为平台限流（Too many requests）：平台侧瞬时故障，
#          调用方按既有「跳过语义」收尾（NOCOMPUTE_SKIP=1），不告警。
#   * 1  = 其他真实失败（未识别的输出、非限流类 reset 失败）：不掩盖，照常失败。
#
# 用法: bash tools/hds_key_reset.sh <instance-id>
#
# 可覆盖的环境变量（测试用）：
#   HDS_KEY_RESET_ATTEMPTS  总尝试次数（默认 4）
#   HDS_KEY_RESET_BACKOFF   每次失败后的退避秒数（默认 20）
#   HDS_KEY_RESET_WAIT      单次调用后等待私钥落盘的秒数（默认 10）
#   HDS_KEY_RESET_DEADLINE  本脚本总耗时硬上限秒数（默认 300）——重试与退避的累加值
#                           不得挤占 [2] 步骤与 30min job 预算；触顶则按已归类的末次
#                           错误收场（限流→10 跳过，其他→1 真失败）
#   HDS_KEY_RESET_LOG       命令输出落盘路径（默认 /tmp/reset.log）
#   HDS_SESSION_CMD         会话执行器（默认与本脚本同目录的 hds_session.sh）
set -u

INSTANCE="${1:-}"
if [ -z "$INSTANCE" ]; then
  echo "[keyreset][ERR] 缺少实例 ID；用法: bash tools/hds_key_reset.sh <instance-id>"
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SESSION_CMD="${HDS_SESSION_CMD:-$SCRIPT_DIR/hds_session.sh}"
ATTEMPTS="${HDS_KEY_RESET_ATTEMPTS:-4}"
BACKOFF="${HDS_KEY_RESET_BACKOFF:-20}"
WAIT="${HDS_KEY_RESET_WAIT:-10}"
DEADLINE="${HDS_KEY_RESET_DEADLINE:-300}"
LOG="${HDS_KEY_RESET_LOG:-/tmp/reset.log}"
KEYFILE="$HOME/.devenv/.ssh/IdentityFile/$INSTANCE"

T0=$(date +%s)
deadline_reached() { [ $(( $(date +%s) - T0 )) -ge "$DEADLINE" ]; }

# 最坏耗时上界（默认值下）：hds_session.sh 自带 `timeout 100`，故单次调用 ≤100s；
# 加 WAIT 10s 与退避 20s，两次尝试合计 ≤240s，触顶 DEADLINE 300s 前必然收敛 ——
# [2] 步骤没有自己的 timeout-minutes（job 上限 30min），重试绝不允许把它顶穿。

mkdir -p "$(dirname "$KEYFILE")" 2>/dev/null || true

attempt=1
last_class=none
stop_reason=""
saw_ratelimit=""
while [ "$attempt" -le "$ATTEMPTS" ]; do
  # 截止只约束「重试」，绝不取消第一次尝试：否则运维把上限设小就会把平台限流
  # 误判成真失败（本用例 test_deadline_caps_total_time 就是这么抓出来的）。
  if [ "$attempt" -gt 1 ] && deadline_reached; then
    stop_reason="超时（总耗时已达 ${DEADLINE}s 上限）"
    echo "[keyreset][warn] ${stop_reason}，停止重试（避免挤占 [2] 步骤与 job 预算）"
    break
  fi
  echo "[keyreset] 第 ${attempt}/${ATTEMPTS} 次 ssh-key-reset（实例=${INSTANCE}）"
  rc=0
  echo yes | "$SESSION_CMD" devenv ssh-key-reset --instance-id="$INSTANCE" > "$LOG" 2>&1 || rc=$?
  echo "[keyreset] 调用返回码=${rc}；输出尾 5 行："
  tail -5 "$LOG" 2>/dev/null | sed 's/^/    /' || true

  # 私钥是否已落盘（CLI 在该场景下即使失败也可能退出 0，故只能以文件为准）
  waited=0
  while [ "$waited" -lt "$WAIT" ]; do
    [ -f "$KEYFILE" ] && break
    sleep 1
    waited=$((waited + 1))
  done

  if [ -s "$KEYFILE" ]; then
    chmod 600 "$KEYFILE" 2>/dev/null || true
    echo "[keyreset][ok] 私钥已就绪: $KEYFILE"
    exit 0
  fi
  if [ -f "$KEYFILE" ]; then
    echo "[keyreset][warn] 私钥文件存在但为空（疑似半写），按失败处理: $KEYFILE"
  fi

  # 失败归类：限流优先（真实日志里限流信息嵌在 "reset private key failed: ..." 之后）
  if grep -qi 'too many requests' "$LOG" 2>/dev/null; then
    last_class=ratelimit
    saw_ratelimit=1
    echo "[keyreset][warn] 平台限流（Too many requests），私钥未生成"
  elif [ "$rc" -eq 124 ]; then
    # CLI 被 hds_session.sh 的 `timeout 100` 打断：平台侧卡死，同属瞬时故障
    last_class=timeout
    echo "[keyreset][warn] 调用超时（rc=124，平台侧无响应），私钥未生成"
  elif grep -qi 'reset private key failed' "$LOG" 2>/dev/null; then
    last_class=resetfail
    echo "[keyreset][warn] 私钥重置调用失败（非限流类错误），私钥未生成"
  else
    last_class=unknown
    echo "[keyreset][warn] 未识别的输出（返回码=${rc}），私钥未生成"
  fi

  attempt=$((attempt + 1))
  if [ "$attempt" -le "$ATTEMPTS" ] && ! deadline_reached; then
    echo "[keyreset] ${BACKOFF}s 退避后重试"
    sleep "$BACKOFF"
  fi
done

case "$last_class" in
  ratelimit|timeout)
    echo "[keyreset][ERR] 重试 ${ATTEMPTS} 次仍不可得（末次类型=${last_class}${saw_ratelimit:+，本轮出现过限流}）${stop_reason:+，$stop_reason}，私钥未生成: $KEYFILE（平台瞬时故障，调用方按跳过处理）"
    exit 10
    ;;
  *)
    echo "[keyreset][ERR] 重试 ${ATTEMPTS} 次后私钥仍未生成${stop_reason:+（$stop_reason）}: $KEYFILE（末次错误类型=${last_class}${saw_ratelimit:+，本轮出现过限流}，按真失败处理）"
    exit 1
    ;;
esac
