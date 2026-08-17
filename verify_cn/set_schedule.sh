#!/usr/bin/env bash
# set_schedule.sh —— 在【已初始化、且保持常开】的华为云开发环境容器里，
# 把节点验证间隔从旧的「每小时」改为「每 15 分钟」并立即生效（幂等、可重跑）。
#
# 背景：原 cloud_init.sh 把验证铺成每小时一次（systemd timer 或 run_loop.sh 后台循环）。
# 现改为 15 分钟一次，且整个验证在容器内自跑、自推 verified.json，
# 不再依赖 GitHub Actions 启停容器 / hdspace / keyring。
#
# 用法（在容器内执行一次，之后无需再管）：
#   cd /workspace/mkdy && git pull --ff-only origin main
#   bash verify_cn/set_schedule.sh
#
# 前置：容器需保持常开；GITHUB_PAT 已在控制台注入或写在 verify_cn/.env
#       （run_local.py 推送靠 git remote 里的 PAT，详见 cloud_init.sh）。
set -uo pipefail
REPO_DIR="${REPO_DIR:-/workspace/mkdy}"
LOG_DIR="$REPO_DIR/verify_cn/logs"
log(){ echo "==> $*"; }

mkdir -p "$LOG_DIR"

log "将节点验证间隔改为每 15 分钟一次（容器需保持常开）"

# ---- 1) 先清掉旧机制，避免重复/叠加触发 ----
pkill -f "verify_cn/run_loop.sh" 2>/dev/null || true
pkill -f "verify_cn/run_local.py" 2>/dev/null || true
sleep 1
if command -v crontab >/dev/null 2>&1; then
  crontab -l 2>/dev/null | grep -v 'run_local.py' | crontab - 2>/dev/null || true
fi
if [ -d /run/systemd/system ]; then
  systemctl --user disable --now mkdy-verify.timer 2>/dev/null || true
fi

# ---- 2) 选单一机制：有 systemd 用 timer，否则用 run_loop.sh 后台循环 ----
if [ -d /run/systemd/system ]; then
  mkdir -p ~/.config/systemd/user
  sed "s|@REPO_DIR@|$REPO_DIR|g" "$REPO_DIR/verify_cn/mkdy-verify.service" > ~/.config/systemd/user/mkdy-verify.service
  sed "s|@REPO_DIR@|$REPO_DIR|g" "$REPO_DIR/verify_cn/mkdy-verify.timer"   > ~/.config/systemd/user/mkdy-verify.timer
  systemctl --user daemon-reload
  systemctl --user enable --now mkdy-verify.timer
  log "systemd timer 已启用（每 15 分钟）"
  # 用户级 timer 需 linger 才能在容器重启后自动恢复；能设则设
  if command -v loginctl >/dev/null 2>&1; then
    loginctl enable-linger "$(id -un)" 2>/dev/null \
      && log "已 enable-linger，容器重启后 timer 仍会自动恢复" \
      || log "（可选）enable-linger 失败可忽略：手动重启容器后重跑本脚本即可"
  fi
else
  cat > "$REPO_DIR/verify_cn/run_loop.sh" <<'LOOP'
#!/usr/bin/env bash
# 每 15 分钟循环：优先用控制台注入的 process env GITHUB_PAT，未注入则 fallback 仓库内 .env。
# 仓库位于持久盘 /workspace（系统盘 /root 重启即丢），故路径硬编码。
while true; do
  sleep 900
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
  log "run_loop.sh 后台循环已启动（首次 15 分钟后跑，之后每 15 分钟）"
fi

log "完成。后续每 15 分钟自动验证并推送 verified.json；GitHub verify-tag 自动打标 s-verified.yaml。"
log "查看日志： tail -f $LOG_DIR/run.log"
