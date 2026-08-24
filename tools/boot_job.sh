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

# 3) 拉最新代码（走镜像，失败仅告警）
git -c url."https://ghproxy.net/https://github.com/".insteadOf="https://github.com/" \
    pull --ff-only origin main \
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
