# 容器版（华为云开发环境）部署指南

把「本机节点验证」搬到华为云开发环境容器版，实现 **PC 关机也不中断** 的每小时验证。
云环境位于中国区，天然是「国内出口」，可做翻墙探测；且是完整 Linux，mihomo + pip + git 随便用
（与之前走不通的 FunctionGraph 受限运行时不是一回事）。

## 为什么是容器版
- 容器版 2 vCPU 4GiB 最省，且是完整 Linux，CLI/API 易自动化、启动快、用完易关机。
- 开发桌面带 GUI，对无界面任务纯属浪费且易忘了关；虚拟机官方已标注「即将下线」。
- 核时 = 分配 vCPU × 开机小时，**同 vCPU 下三者费率一致**，所以选容器只是最不容易被你忘记关。

## 一键落地（只需你做 1 步）
1. 在华为云开发者空间 → 云开发环境 → 创建 **容器版**，规格选 **2 vCPU 4GiB**，区域选中国区（如华南-广州）。
2. 进入容器终端，先准备好 GitHub fine-grained PAT（仓库 `Contents:write`），然后粘贴：

```bash
export GITHUB_PAT=你的PAT
bash <(curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/1013608955/mkdy/main/verify_cn/cloud_init.sh)
```

脚本会：装依赖 → 配 git → 克隆仓库 → 下载 Linux mihomo → 装 pyyaml → 装每小时 :05 定时任务 → 首次立即跑一次。

> 若已手动克隆过仓库，直接进入仓库目录跑 `bash verify_cn/cloud_init.sh` 即可。

## 验证链路
- 每小时 :05：容器里 `run_local.py` 起 mihomo、真链探测全部节点、写 `verified.json`、推送到 main。
- 推送触发 GitHub `update-subs.yml` → `merge_subs.py` 读 verified.json 一步产出 `s-verified.yaml`（方案A，免打标漂移）。
- 容器常开 = PC 关机也不中断。

## 核时消耗
- 2 vCPU 常开 24/7 ≈ 1440 核时/月；8000 核时可撑约 5.5 个月，足够省心（默认推荐）。
- 想更省：给定时任务的 `run_local.py` 加 `--shutdown-after`（跑完即关机），并用华为云「定时启停」或外部触发器每小时开机一次。

## 文件说明
- `cloud_init.sh`        —— 容器内一键引导（幂等，可重复跑）。
- `mkdy-verify.service` / `mkdy-verify.timer` —— systemd 单元（容器有 systemd 时用）。
- `run_local.py`         —— 验证主程序；新增 `--shutdown-after`（可选，省核时）。
- `LOCAL_VERIFY.md`      —— 本机（Windows）部署说明。
