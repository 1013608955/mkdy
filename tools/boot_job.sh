#!/usr/bin/env bash
# boot_job.sh — 容器侧开机引导：装依赖 → 拉代码 → 跑一轮验证并推送。
# 由 CI 经 SSH(tunnel) 调用；幂等，系统盘重置后也能自举。
#
# PERSIST_ROOT（2026-10-16 新增）：持久盘挂载点。默认 /workspace（旧容器），
# AI 开发者空间·持久化版的 EVS 挂在 /root，故由 CI 用环境变量传入。
# 用 ${PERSIST_ROOT:-/workspace} 而非硬编码，是为了旧容器行为完全不变（零风险）。
set -u
PERSIST_ROOT="${PERSIST_ROOT:-/workspace}"
cd "$PERSIST_ROOT/mkdy" || exit 9

# 1) Python 依赖装到持久盘（系统盘重置也不丢，冷启动秒过）
export PYTHONPATH="$PERSIST_ROOT/pylibs${PYTHONPATH:+:$PYTHONPATH}"
if ! python3 -c "import yaml, requests" 2>/dev/null; then
  pip3 install --quiet --target "$PERSIST_ROOT/pylibs" pyyaml requests \
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
#    2026-09-11 #1658：pull 偶发失败会让本地基线落后，第一推必然 non-FF
#    被拒。加 90s 上限（stall 不空等）+ 1 次重试；再失败交给 run_local 的
#    push 重试（non-FF 会自动 fetch+merge）自愈。

# 3.0) 先清脏工作区（2026-10-16，verify-newcontainer 实测暴露）
#    现象：新容器 clone 后基线停在此刻，之后 main 上陆续有新提交
#    （本仓库自己的代码提交 + update-subs.yml 每小时提交 s-clash.* /
#    source_health.json），而工作区里这些生成物处于「已修改未提交」状态。
#    此时 push 必被 non-FF 拒绝，随后 _push_results 的
#    `merge -X ours FETCH_HEAD` 也必然失败：
#      error: Your local changes to the following files would be overwritten
#             by merge: s-clash.yaml / s-verified.yaml / source_health.json ...
#    根因是「脏工作区 + 陈旧基线」的组合；旧容器每轮 pull+commit 故从无此问题。
#
#    为什么可以放心丢弃：工作区里的改动**全部是生成物**
#    （s-clash.* / s-verified.* / source_health.json 由 update-subs.yml 在
#    GitHub 侧产出，本地改动无意义；verified.json 在第 3 步之后才写）。
#    唯一需要小心的是别丢 verified.json —— 故用 `git stash` 而非 `checkout --`，
#    若真有未跟踪的本地改动会留在 stash 里而非被静默销毁。
#    先 fetch 再 reset --hard origin/main，可顺带把陈旧基线一次拉齐。
echo "[3.0] 清理脏工作区并对齐基线"
git fetch origin main --quiet 2>/dev/null || true
git stash push --quiet -u -m "boot_job 预清理 $(date -Is)" 2>/dev/null || true
git reset --hard origin/main 2>&1 | tail -1 || true
git stash list 2>/dev/null | head -3 || true

PULLED=""
for i in 1 2; do
  if timeout 90 git pull --ff-only origin main; then PULLED=1; break; fi
  echo "[WARN] git pull 第 $i 次失败（或 90s 超时），20s 后重试"
  sleep 20
done
[ -n "$PULLED" ] || echo "[WARN] git pull 两次均失败，沿用本地代码继续（push 阶段会自动合并远端）"

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
