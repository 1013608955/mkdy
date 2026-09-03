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
#    坑（run #863 根因）：run_loop.sh 会 fork 出 `python3 verify_cn/run_local.py`
#    子进程，而 pkill -f run_loop.sh 只匹配到 shell 脚本本身、匹配不到该 python
#    子进程（其 cmdline 不含 "run_loop.sh"）→ 残留实例与下面第 5 步新起的
#    run_local.py 并发跑，各起一份 mihomo、各做全量两轮探测，在 2vCPU 上互抢
#    CPU/网络，两边都变慢 → 本轮撑爆 CI 的 600s 预算；且孤儿实例会自己 push
#    verified.json（写的是 verify_cn/logs/run.log，不在 ci_boot.log 里，极具迷惑性）。
#    故必须连 python 子进程一起杀，并等它真正退出（释放 mihomo 端口与临时目录）。
pkill -f run_loop.sh 2>/dev/null || true
pkill -f 'run_local\.py' 2>/dev/null || true
for i in $(seq 1 15); do
  pgrep -f 'run_local\.py' >/dev/null 2>&1 || break
  sleep 1
done
pgrep -f 'run_local\.py' >/dev/null 2>&1 \
  && echo "[WARN] 仍有残留 run_local.py 未退出，继续（可能与本轮争抢资源）" \
  || echo "[ok] 已清理常驻循环及残留验证进程"

# 5) 跑一轮验证并推送（PAT 在持久盘 verify_cn/.env）
set -a
[ -f verify_cn/.env ] && . ./verify_cn/.env
set +a
# -u 关键：Python 的 stdout 重定向到文件时是块缓冲（8KB），不显式 flush 就会出现
# 「十分钟一行日志都没有」的假死象——既看不出进度，也分不清到底是「慢」还是「真卡死」
# （run #863 排查时最大的障碍）。加 -u 后
# `[round1] 25/562 累计 ok=N 用时 Xs` 这类进度会实时落盘到 ci_boot.log，
# CI 侧轮询 tail -3 一眼就能判断是在推进还是卡住。
python3 -u verify_cn/run_local.py
RC=$?
echo "[boot_job] done rc=$RC"
exit $RC
