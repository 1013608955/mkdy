#!/usr/bin/env bash
# cloud_init.sh —— 在华为云开发环境(容器版, 2vCPU)里一键落地节点验证。
#
# 前置（二选一，提供仓库推送凭证；不提供则只本地验证不推送）：
#   A. 环境变量：  export GITHUB_PAT=ghp_xxx     # 你的 fine-grained PAT（仓库 Contents:write）
#   B. 文件：      在仓库内建 verify_cn/.env 写一行  GITHUB_PAT=ghp_xxx
#                 （定时任务会自动 source 它，无需常驻 export）
#
# 用法（二选一）：
#   A. 已克隆本仓库：  bash verify_cn/cloud_init.sh
#   B. 空环境直通：    bash <(curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/1013608955/mkdy/main/verify_cn/cloud_init.sh)
#
# 设计：每小时 :05 自动跑 run_local.py 并推送 -> GitHub verify-tag 自动打标 s-verified.yaml。
# 容器常开即等价于「PC 关机也不中断」。想最省核时见末尾说明。
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/1013608955/mkdy.git}"
# 注意：容器重启会重置系统盘 /root，只有数据盘 /workspace（EVS）持久，
# 故仓库必须落在 /workspace，否则重启后部署全丢。
REPO_DIR="${REPO_DIR:-/workspace/mkdy}"
GITHUB_PAT="${GITHUB_PAT:-}"
MIHOMO_VER="${MIHOMO_VER:-latest}"

log(){ echo "==> $*"; }

# 安装函数：自动识别 Debian(apt) / EulerOS&RHEL(dnf,yum)
install_pkg(){
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y "$@" 2>/dev/null || true
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y "$@" 2>/dev/null || true
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y "$@" 2>/dev/null || true
  fi
}
log "[1/6] 安装系统依赖 (git/curl/python3/pip/unzip/ca-certificates)"
install_pkg git curl python3 python3-pip unzip ca-certificates cronie

log "[2/6] 配置 git 身份与推送凭证"
git config --global user.email "verify@mkdy.local"
git config --global user.name  "mkdy-verify-cloud"
git config --global pull.ff only
if [ -n "$GITHUB_PAT" ]; then
  # 仅把 push URL 改写为带 PAT 的 github 直连；fetch 仍走 ghproxy 镜像（国内快、稳）。
  # 华为云容器直连 GitHub 的 git smart-HTTP 传输会 stall，故 fetch 必须走镜像。
  git config --global credential.helper store 2>/dev/null || true
fi

log "[3/6] 克隆 / 更新仓库 -> $REPO_DIR"
# 部分环境 git over HTTP/2 会报 "curl 16 Error in the HTTP2 framing layer"，强制 HTTP/1.1
git config --global http.version HTTP/1.1
git config --global http.postBuffer 524288000
if [ -d "$REPO_DIR/.git" ]; then
  git -C "$REPO_DIR" pull --ff-only origin main || true
else
  for i in 1 2 3; do
    git clone --depth 1 "$REPO_URL" "$REPO_DIR" && break
    echo "    clone 失败，重试 ($i)..."; sleep 3; rm -rf "$REPO_DIR"
  done
  if [ ! -d "$REPO_DIR/.git" ]; then
    echo "[ERROR] 仓库克隆失败，请检查网络或手动克隆到 $REPO_DIR" >&2; exit 1
  fi
fi
if [ -n "$GITHUB_PAT" ]; then
  git -C "$REPO_DIR" remote set-url --push origin "https://${GITHUB_PAT}@github.com/1013608955/mkdy.git"
fi

log "[4/6] 下载 Linux mihomo 二进制（按架构自动选 amd64 / arm64）"
MIHOMO_DIR="$REPO_DIR/verify_cn"
if [ ! -x "$MIHOMO_DIR/mihomo" ]; then
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)        MIHOMO_ARCH=amd64 ;;
    aarch64|arm64) MIHOMO_ARCH=arm64 ;;
    *)             echo "[WARN] 未识别架构 $ARCH，默认 amd64" >&2; MIHOMO_ARCH=amd64 ;;
  esac
  echo "    检测到架构: $ARCH -> mihomo-linux-$MIHOMO_ARCH"
  ASSET_URL=$(curl -fsSL --http1.1 "https://api.github.com/repos/MetaCubeX/mihomo/releases/$MIHOMO_VER" \
                | grep -oE "https://[^\"]+mihomo-linux-${MIHOMO_ARCH}[^\"]+\\.gz" | head -1 || true)
  if [ -z "$ASSET_URL" ]; then
    ASSET_URL=$(curl -fsSL --http1.1 "https://ghproxy.net/https://api.github.com/repos/MetaCubeX/mihomo/releases/$MIHOMO_VER" \
                  | grep -oE "https://[^\"]+mihomo-linux-${MIHOMO_ARCH}[^\"]+\\.gz" | head -1 || true)
  fi
  if [ -z "$ASSET_URL" ]; then
    echo "[WARN] 无法定位 mihomo-linux-$MIHOMO_ARCH 资产，请手动放置 $MIHOMO_DIR/mihomo" >&2
  else
    echo "    mihomo asset: $ASSET_URL"
    curl -fsSL --http1.1 "$ASSET_URL" -o /tmp/mihomo.gz
    gunzip -f /tmp/mihomo.gz
    mv /tmp/mihomo "$MIHOMO_DIR/mihomo"
    chmod +x "$MIHOMO_DIR/mihomo"
  fi
else
  echo "    mihomo 已存在，跳过下载"
fi

log "[5/6] 安装 Python 依赖"
# 注意：EulerOS 的 pip 由 rpm 管理，`pip install --upgrade pip` 会报
# "Cannot uninstall pip ... installed by rpm"。故跳过自带 pip 升级，只装业务依赖。
python3 -m pip install --quiet pyyaml 2>/dev/null \
  || python3 -m pip install --quiet --user pyyaml 2>/dev/null \
  || true

# 定时任务命令：先 source .env 的 GITHUB_PAT（用户填了即自动推送）。
# 注意 run_local.py 本身不读 GITHUB_PAT，推送认证靠 origin remote URL 带 PAT，
# 故这里在跑之前把 remote URL 改写为带 PAT 的地址（仅当 .env 提供了 PAT 才改）。
RUN_CMD="cd $REPO_DIR && set -a; [ -f verify_cn/.env ] && . ./verify_cn/.env; set +a; [ -n \"\$GITHUB_PAT\" ] && git remote set-url --push origin https://\${GITHUB_PAT}@github.com/1013608955/mkdy.git; python3 verify_cn/run_local.py >> verify_cn/logs/run.log 2>&1"

log "[6/6] 安装定时任务（每小时 :05）"
if [ -d /run/systemd/system ]; then
  mkdir -p ~/.config/systemd/user
  sed "s|@REPO_DIR@|$REPO_DIR|g" "$REPO_DIR/verify_cn/mkdy-verify.service" > ~/.config/systemd/user/mkdy-verify.service
  sed "s|@REPO_DIR@|$REPO_DIR|g" "$REPO_DIR/verify_cn/mkdy-verify.timer"   > ~/.config/systemd/user/mkdy-verify.timer
  systemctl --user daemon-reload
  systemctl --user enable --now mkdy-verify.timer
  echo "    systemd timer 已启用（每小时 :05）"
else
  # 容器一般无 systemd；cron 在容器里也常不可用，故主用 nohup 后台循环
  # （容器常开即等价于定时任务，且不受 crond 是否存活影响）。先 sleep 1h 再跑，
  # 避免与下方「首次立即跑一次」并发。
  cat > "$REPO_DIR/verify_cn/run_loop.sh" <<'LOOP'
#!/usr/bin/env bash
# 每小时循环：优先用控制台注入的 process env GITHUB_PAT，未注入则 fallback 仓库内 .env。
# 仓库位于持久盘 /workspace（系统盘 /root 重启即丢），故路径硬编码。
while true; do
  sleep 3600
  cd /workspace/mkdy
  if [ -z "$GITHUB_PAT" ] && [ -f verify_cn/.env ]; then
    set -a; . ./verify_cn/.env; set +a
  fi
  if [ -n "$GITHUB_PAT" ]; then
    git remote set-url --push origin "https://${GITHUB_PAT}@github.com/1013608955/mkdy.git"
  fi
  python3 verify_cn/run_local.py >> verify_cn/logs/run.log 2>&1
done
LOOP
  chmod +x "$REPO_DIR/verify_cn/run_loop.sh"
  nohup "$REPO_DIR/verify_cn/run_loop.sh" >/dev/null 2>&1 &
  disown 2>/dev/null || true
  echo "    run_loop.sh 已在后台启动（首次 1h 后跑，之后每小时）"
  # 若系统有可用 cron，也顺手写一份（不影响上面的循环）
  if command -v crontab >/dev/null 2>&1; then
    ( crontab -l 2>/dev/null | grep -v 'run_local.py'; echo "5 * * * * $RUN_CMD" ) | crontab - 2>/dev/null \
      && echo "    （另：cron 也已写入）" || true
  fi
fi

log "首次立即跑一次（有 PAT 则直接推送，否则仅本地验证）"
if [ -n "$GITHUB_PAT" ]; then
  ( cd "$REPO_DIR" && python3 verify_cn/run_local.py )
else
  ( cd "$REPO_DIR" && python3 verify_cn/run_local.py --no-push )
fi

echo
log "完成。后续每小时 :05 自动验证并推送；GitHub verify-tag 自动打标 s-verified.yaml。"
log "查看日志： tail -f $REPO_DIR/verify_cn/logs/run.log"
echo
echo "【省核时进阶】若仅想跑几分钟/小时、其余时间关机："
echo "  1) 给 cron/timer 的 run_local.py 加 --shutdown-after（跑完即关机）；"
echo "  2) 用华为云「定时启停」或外部触发器每小时开机一次。"
echo "   （默认常开 2vCPU 约 1440 核时/月，8000 核时可撑 ~5.5 个月，足够省心。）"
