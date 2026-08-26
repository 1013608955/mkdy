#!/usr/bin/env bash
# boot_job.sh — 容器侧开机引导：装依赖 → 拉代码 → 跑一轮验证并推送。
# 由 CI 经 SSH(tunnel) 调用；幂等，系统盘重置后也能自举。
set -u
cd /workspace/mkdy || exit 9

# 1) Python 依赖装到持久盘（系统盘重置也不丢，冷启动秒过）
export PYTHONPATH="/workspace/pylibs${PYTHONPATH:+:$PYTHONPATH}"
if ! python3 -c "import yaml, requests" 2>/dev/null; then
  pip3 install --quiet --target /workspace/pylibs pyyaml requests \
    -i https://pypi.tuna.tsinghua.edu.cn/simple
fi

# 2) git 身份与配置（系统盘重置丢失）
git config --global user.email "ci@mkdy.local"
git config --global user.name "mkdy-ci"
git config --global http.version HTTP/1.1

# 2.5) 清理持久盘残留的 ghproxy 镜像重写（2026-08-26 该镜像证书到期，任何
# insteadOf 残留都会让 pull/fetch/push 全灭）。幂等：没有就什么都不做。
git config --global --unset-all url.https://ghproxy.net/https://github.com/.insteadOf 2>/dev/null || true
git config --unset-all  url.https://ghproxy.net/https://github.com/.insteadOf 2>/dev/null || true
# 若 origin 的 fetch url 被改成镜像地址，改回官方（push url 带 PAT 不动）
ORIGIN_URL=$(git remote get-url origin 2>/dev/null || true)
case "$ORIGIN_URL" in
  *ghproxy*) git remote set-url origin https://github.com/1013608955/mkdy.git ;;
esac

# 3) 拉最新代码——直连 github.com，不走 ghproxy 镜像。
#    2026-08-26 教训：ghproxy.net 证书到期（notAfter Aug 26 13:58 UTC）导致
#    pull 失败 → 本地 main 落后 → push non-fast-forward 连拒 3 次 →
#    verified.json 更新断链数小时。git 协议直连 GitHub 从容器一直可用，
#    当初走镜像只是防 raw 文件超时的习惯，git 操作不需要它。
git pull --ff-only origin main \
  || echo "[WARN] git pull 失败，沿用本地代码继续"

# 4) 迁移保护：杀掉常驻循环（按需模式下由 CI 决定何时再验）
pkill -f run_loop.sh 2>/dev/null || true

# 5) 跑一轮验证并推送（PAT 在持久盘 verify_cn/.env）
set -a
[ -f verify_cn/.env ] && . ./verify_cn/.env
set +a
python3 verify_cn/run_local.py
RC=$?
echo "[boot_job] done rc=$RC"
exit $RC
