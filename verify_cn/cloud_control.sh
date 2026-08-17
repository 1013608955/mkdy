#!/usr/bin/env bash
# cloud_control.sh —— 由 GitHub Actions 调用，控制华为云开发者空间容器做「开机 → 验证 → 关机」。
#
# 设计要点：
#   * VERIFY_MAX_AGE_MIN=0（默认）→ 每次 GitHub 定时触发都拉起容器验证；
#     设为正整数（如 180）→ 仅当 verified.json 超过该分钟数未更新才开机（省核时，PC 关机备份模式）。
#     注意：一次完整生命周期（开机 1–3 分 + 验证 ~15–30 分 + 关机 1–3 分）约 20–35 分钟，
#     大于 15 分钟触发间隔，故「每次触发都验证」实际近乎连续运行（≈48 核时/天，省核时有限）。
#   * 开机后经隧道 + ssh-key-reset 拿私钥，SSH 进容器主动跑 run_local.py（可选注入 GITHUB_PAT 推送），
#     不依赖容器内 run_loop.sh 是否自启。
#   * 脚本退出（含出错）时一定尝试关机，避免容器泄漏常开烧核时。
#
# 前置：仓库内已放置 Linux AMD 版 hdspace（verify_cn/bin/hdspace）；容器已用 cloud_init.sh 初始化过
#       （/workspace/mkdy 仓库 + mihomo 已落持久盘）。
#
# 环境变量（由 GitHub Secrets / Variables 注入）：
#   HW_INSTANCE_ID  实例 ID，如 DevEnvC_W4yNKt（必填）
#   HW_AK / HW_SK   华为云访问密钥（必填）
#   HW_GITHUB_PAT   细粒度 PAT（Contents:write），容器内推送用（可选：不填则依赖容器控制台 GITHUB_PAT 环境变量）
#   HW_SSH_USER     SSH 登录用户名，默认 developer（可选，通常无需填）
#   HW_REGION       区域，默认 cn-north-4（可选，实例在其它区域才需填）
#   VERIFY_MAX_AGE_MIN  新鲜度阈值（分钟），默认 0=每次触发都验证（可选，建议用 repo variable 设置）
#   FORCE           任意非空值则忽略新鲜度强制跑一次（可选）
#   HDSPACE_BIN     hdspace 二进制路径（可选，默认 $GITHUB_WORKSPACE/verify_cn/bin/hdspace）
set -uo pipefail

HD="${HDSPACE_BIN:-${GITHUB_WORKSPACE:-$(cd "$(dirname "$0")/.." && pwd)}/verify_cn/bin/hdspace}"
INSTANCE_ID="${HW_INSTANCE_ID:?缺少 HW_INSTANCE_ID}"
AK="${HW_AK:?缺少 HW_AK}"
SK="${HW_SK:?缺少 HW_SK}"
PAT="${HW_GITHUB_PAT:-}"   # 可选：空则依赖容器内控制台 GITHUB_PAT
SSH_USER="${HW_SSH_USER:-developer}"
REGION="${HW_REGION:-cn-north-4}"
MAX_AGE_MIN="${VERIFY_MAX_AGE_MIN:-0}"
FORCE="${FORCE:-}"

log(){ echo "==> $*"; }

if [ ! -x "$HD" ]; then
  echo "[ERROR] 未找到可执行 hdspace：$HD" >&2
  echo "        请在本机把华为云开发者空间控制台下载的 Linux AMD 版 hdspace" >&2
  echo "        放到 verify_cn/bin/hdspace 并提交到仓库。" >&2
  exit 1
fi
chmod +x "$HD"

log "配置 hdspace (AK/SK)…"
# 兼容：仍写几处候选配置文件（部分版本走文件）
for d in ~/.huawei_devspace ~/.config/hdspace ~/.hdspace; do
  mkdir -p "$d"
  cat > "$d/config.yaml" <<EOF
access_key: $AK
secret_key: $SK
region: $REGION
EOF
done
# 额外导出常见 SDK 环境变量（部分实现会读这些）
export HUAWEI_CLOUD_ACCESS_KEY_ID="$AK" HUAWEI_CLOUD_SECRET_ACCESS_KEY="$SK" \
       HUAWEI_ACCESS_KEY="$AK" HUAWEI_SECRET_KEY="$SK" AK="$AK" SK="$SK"

# ---------- headless CI 凭据存储（keyring）----------
# hdspace 把 AK/SK 存进系统凭据存储（Linux = D-Bus secret-service，
# 由 gnome-keyring-daemon 提供）。headless 无桌面需手动起 dbus + keyring。
ensure_pkg(){
  local p="$1"
  command -v "$p" >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then
    local SUDO=""
    if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then SUDO=sudo; fi
    echo "[keyring] 安装 $p …"
    $SUDO apt-get update -qq 2>&1 | tail -2
    $SUDO apt-get install -y -qq "$p" 2>&1 | tail -5
  else
    echo "[WARN] 无 apt-get，无法安装 $p（keyring 可能不可用）"
  fi
}
ensure_pkg dbus
ensure_pkg gnome-keyring
ensure_pkg libsecret-tools   # 提供 secret-tool，用于诊断/初始化 secret-service
ensure_pkg expect            # 提供伪终端(pty) 喂 hdspace config（其 SK 读取需 tty）
ensure_pkg libglib2.0-bin   # 提供 gdbus，用于把 default 别名指向已解锁的 login keyring

# 若还没有 D-Bus session，用 dbus-run-session 重跑整个脚本（最可靠：后续所有
# hdspace 命令共享同一 session 的 keyring）；否则手动 dbus-launch。
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
  if command -v dbus-run-session >/dev/null 2>&1; then
    echo "[keyring] 无 D-Bus session，用 dbus-run-session 重跑本脚本…"
    exec dbus-run-session -- bash "$0" "$@"
  elif command -v dbus-launch >/dev/null 2>&1; then
    echo "[keyring] 启动 D-Bus session (dbus-launch)…"
    eval "$(dbus-launch --sh-syntax)"
  fi
fi
echo "[debug] DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-<空>}"

# 启动 keyring daemon 并提供 secrets 服务（headless 下用固定口令解锁/创建 login keyring）。
# 关键：hdspace 用 99designs/keyring 的 secret-service 后端，存储时要求 default(=login)
#       collection 已存在且已解锁；否则触发 GUI 解锁提示(SystemPrompter)→ headless 无显示→失败。
#       secret-tool 走 session 兜底不弹窗，不能证明 default collection 已就绪，故需显式创建。
# 注意：必须 --daemonize（否则 daemon 在 stdin 关闭后退出，secret-service 随之消失）。
KEYRING_PW="mkdy-ci-keyring"
if command -v gnome-keyring-daemon >/dev/null 2>&1; then
  echo "[keyring] 启动 gnome-keyring-daemon --daemonize --unlock（headless 固定口令，保持常驻）…"
  printf '%s' "$KEYRING_PW" | gnome-keyring-daemon --daemonize --unlock --components=secrets,ssh,pkcs11 >/tmp/keyring.env 2>&1
  sleep 6
  [ -s /tmp/keyring.env ] && eval "$(cat /tmp/keyring.env)" 2>/dev/null || true
  echo "[debug] gnome-keyring-daemon 进程:"; pgrep -a gnome-keyring-daemon 2>/dev/null | head -3 || echo "  (无进程在运行)"
  # 显式创建/解锁 login collection（secret-tool 直接写到 login，避免走 session 兜底）
  if command -v secret-tool >/dev/null 2>&1; then
    echo "[debug] secret-tool 写 --collection=login（创建/解锁 login keyring）…"
    echo -n "ci-test-value" | secret-tool store --label=mkdy-ci-test --collection=login mkdy_ci_test myvalue 2>&1 | head -3
    echo -n "secret-tool 读回: "; secret-tool lookup mkdy_ci_test myvalue 2>&1 | head -3
  fi
  # 确保 default 别名指向已解锁的 login collection（让 99designs/keyring 的 default 解析正确）
  if command -v gdbus >/dev/null 2>&1; then
    echo "[debug] gdbus：创建 default collection 并别名指向 login、解锁…"
    # 若 login 已由 --unlock 建立，这一步可能报“已存在”，忽略；否则创建并别名 default
    gdbus call --session --dest org.freedesktop.secret --object-path /org/freedesktop/secrets --method org.freedesktop.Secret.Service.CreateCollection "{'org.freedesktop.Secret.Collection.Label': <'Login'>}" default 2>&1 | head -3 || true
    gdbus call --session --dest org.freedesktop.secret --object-path /org/freedesktop/secrets/collection/login --method org.freedesktop.Secret.Collection.Unlock 2>&1 | head -2 || true
    gdbus call --session --dest org.freedesktop.secret --object-path /org/freedesktop/secrets --method org.freedesktop.Secret.Service.SetAlias default /org/freedesktop/secrets/collection/login 2>&1 | head -2 || true
    echo "[debug] secret-service items:"; gdbus call --session --dest org.freedesktop.secret --object-path /org/freedesktop/secrets --method org.freedesktop.Secret.Service.SearchItems '{}' 2>&1 | head -2 || true
  else
    echo "[WARN] 无 gdbus（libglib2.0-bin），跳过 default 别名修复"
  fi
else
  echo "[WARN] 未找到 gnome-keyring-daemon，keyring 后端不可用，hdspace 可能读不到凭据"
fi

# hdspace config 以交互方式读取 AK/SK（SK 需二次确认，不回显）。
# headless 下需用伪终端(pty) 喂入。先打印 --help 探测非交互参数，
# 再用 script 提供 pty 尝试写入，并完整捕获输出用于诊断。
echo "[keyring] hdspace config 诊断 + 写入…"
echo "--- hdspace config --help (探测非交互参数) ---"
"$HD" config --help 2>&1 | head -25
echo "--- 用 script 提供 pty 喂入 AK/SK/SK确认 ---"
printf '%s\n%s\n%s\n' "$AK" "$SK" "$SK" | script -qec "$HD config" /dev/null >/tmp/hdspace_cfg.log 2>&1
echo "script_exit=$?"
sed -n '1,30p' /tmp/hdspace_cfg.log 2>/dev/null

# 用只读的 devenv list 先验证凭据是否生效（失败则早退，不烧核时）
if ! "$HD" devenv list >/dev/null 2>&1; then
  echo "[ERROR] hdspace 凭据未生效（devenv list 失败），疑似 keyring / AK-SK 问题。"
  echo "  DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-<空>}"
  "$HD" devenv list 2>&1 | head -10
  exit 1
fi
log "hdspace 凭据 OK（devenv list 通过）"

# 调试开关：仅验证 keyring 可用即退出，不真开机（省核时）。CI 调试用，平时不设。
if [ -n "${CI_DEBUG_KEYRING:-}" ]; then
  echo "[debug][CI_DEBUG_KEYRING] KEYRING_OK — 凭据后端可用，主动退出（不烧核时）。"
  exit 0
fi

state_of(){
  "$HD" devenv list 2>/dev/null | grep "$INSTANCE_ID" | grep -oE "Running|Ready|Stopping|Starting|Error" | head -1
}

# 验证新鲜度：verified.json 的最近一次提交时间
REPO_ROOT="${GITHUB_WORKSPACE:-$(cd "$(dirname "$0")/.." && pwd)}"
VF="$REPO_ROOT/verify_cn/verified.json"
if [ -f "$VF" ]; then
  LAST_EPOCH=$(git -C "$REPO_ROOT" log -1 --format=%ct -- "$VF" 2>/dev/null || echo 0)
else
  LAST_EPOCH=0
fi
NOW_EPOCH=$(date +%s)
AGE_MIN=$(( (NOW_EPOCH - ${LAST_EPOCH:-0}) / 60 ))
log "verified.json 距上次推送 ${AGE_MIN} 分钟（阈值 ${MAX_AGE_MIN}）"

STATE="$(state_of)"
log "容器当前状态: ${STATE:-未知}"

# 决策：新鲜且无需强制 → 处理泄漏后退出
if [ -z "$FORCE" ] && [ "$MAX_AGE_MIN" -gt 0 ] && [ "$AGE_MIN" -lt "$MAX_AGE_MIN" ]; then
  if [ "$STATE" = "Running" ]; then
    log "验证尚新但容器在运行（疑似上轮未关机），执行关机以防泄漏核时。"
    "$HD" devenv close --instance-id="$INSTANCE_ID" >/dev/null 2>&1 || "$HD" devenv stop --instance-id="$INSTANCE_ID" >/dev/null 2>&1 || true
    sleep 60
  else
    log "验证仍新鲜（${AGE_MIN}m < ${MAX_AGE_MIN}m）且容器已关机，本次跳过（省核时）。"
  fi
  exit 0
fi
[ -n "$FORCE" ] && log "FORCE 模式：忽略新鲜度，强制执行一次验证。" \
                 || log "验证已陈旧，需要拉起云容器重新验证。"

# 确保开机
if [ "$STATE" != "Running" ]; then
  log "启动容器…"
  "$HD" devenv start --instance-id="$INSTANCE_ID"
  for i in $(seq 1 30); do
    [ "$(state_of)" = "Running" ] && break
    sleep 10
  done
  if [ "$(state_of)" != "Running" ]; then
    echo "[ERROR] 容器未能进入 Running 状态" >&2; exit 1
  fi
fi
log "容器已运行，建立 SSH 隧道（22 → 10022）…"
"$HD" devenv start-tunnel --instance-id="$INSTANCE_ID" --local-port=10022 --remote-port=22 >/tmp/tunnel.log 2>&1 &
TUN_PID=$!
# 退出（含失败）一律关隧道 + 关机
trap 'kill $TUN_PID 2>/dev/null; "$HD" devenv close --instance-id="$INSTANCE_ID" >/dev/null 2>&1 || "$HD" devenv stop --instance-id="$INSTANCE_ID" >/dev/null 2>&1 || true' EXIT
sleep 8

log "重置 SSH 密钥（每次开机后 authorized_keys 会被清空）…"
"$HD" devenv ssh-key-reset --instance-id="$INSTANCE_ID" >/dev/null 2>&1 || true
sleep 3

KEY=""
for tries in $(seq 1 10); do
  KEY=$(ls -1 ~/.devenv/.ssh/IdentityFile/"$INSTANCE_ID" 2>/dev/null \
     || ls -1 ~/.devenv/.ssh/IdentityFile/* 2>/dev/null | head -1)
  [ -n "$KEY" ] && break
  sleep 3
done
if [ -z "$KEY" ]; then
  echo "[ERROR] 未找到 SSH 私钥（ssh-key-reset 后应在 ~/.devenv/.ssh/IdentityFile/）" >&2
  exit 1
fi
chmod 600 "$KEY"
log "使用私钥: $KEY"

# 推送令牌：优先用 HW_GITHUB_PAT；未提供则依赖容器内控制台 GITHUB_PAT 环境变量（不写死到 URL）
if [ -n "$PAT" ]; then
  PUSH_URL="https://${PAT}@github.com/1013608955/mkdy.git"
  PUSH_SETUP="git remote set-url --push origin \"$PUSH_URL\" &&"
else
  PUSH_SETUP=""
fi
REMOTE_CMD="cd /workspace/mkdy && \
 git config --global user.email verify@mkdy.local && \
 git config --global user.name mkdy-verify-cloud && \
 git config --global http.version HTTP/1.1 && \
 ${PUSH_SETUP} \
 git pull --ff-only origin main 2>&1 | tail -2 ; \
 echo \"[debug] 容器内 GITHUB_PAT 可见: \${GITHUB_PAT:+是}\${GITHUB_PAT:-否}\" ; \
 python3 -m pip install --quiet pyyaml 2>/dev/null || true ; \
 python3 verify_cn/run_local.py"

log "SSH 进容器执行验证（推送令牌优先用 HW_GITHUB_PAT，否则依赖容器控制台 GITHUB_PAT）…"
ssh -i "$KEY" -p 10022 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 \
    "$SSH_USER@127.0.0.1" "$REMOTE_CMD"
RC=$?
log "验证命令返回码: $RC"
exit $RC
