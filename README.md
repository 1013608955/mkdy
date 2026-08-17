# mkdy — 自动代理节点聚合 + 单 Clash 订阅 + 中国出口真实链路验证

GitHub Actions 每小时自动运行：从多个公开订阅源拉取节点 → 合并去重 → 产出**单一**
Clash 订阅 `s-clash.yaml`；另有**本机 Windows 定时任务**与**华为云开发环境容器
（中国网络出口）**两套 `verify_cn` 探针，实测「该节点能否从中国网络出口连通」，
产出已验证子集 `s-verified.yaml`。

## 架构（方案 B：单合并工作流，纯 Python，无 SubConverter / 无 Docker）

每小时由 `.github/workflows/update-subs.yml`（`cron: 0 */1 * * *`，支持手动触发）执行：

1. `fetch_tuijian.py` —— 抓取 tuijianvpn 推荐订阅链接，存档到
   `latest_tuijian.txt` / `history_tuijian.txt`（仅作链接存档，不参与节点合并）。
2. `update_nodes.py` —— 从多个公开源（含上轮提交的 `s2.txt`）拉取节点，做 GitHub(US)
   侧 TCP 连通粗筛 + 代理握手探测（仅作评分信号，**不硬过滤**），≥65 分写入 `s1.txt`。
3. `fetch.py` —— 爬取米贝77 / Datiya 等网站，产出 `s2.txt`（整文件 base64 节点）
   与 `s2-clash-1.yaml` / `s2-clash-2.yaml`（已是 Clash YAML）。
4. `merge_subs.py` —— 把以上源（文件缺失自动跳过）解析为 Clash proxies、按
   `(type, server, port, 密钥, cipher)` 去重、排序，套用 `clash_template.yaml`
   规则模版，写出含 `proxy-groups` / `rules` / `dns` 的**完整** `s-clash.yaml`。

> 中间文件 `s.txt` / `s1.txt` / `s2.txt` / `s2-clash-*.yaml` 均为**运行期临时产物，
> 不入库**；仓库最终只保留两个订阅产物：`s-clash.yaml`（全量，喂给 verify_cn）与
> `s-verified.yaml`（打标，由 verify-tag.yml 产出）。
> 注：`s.txt` 为旧版主订阅，现已不产出，合并时被静默跳过。

## 客户端订阅地址

- **全量节点**（Clash YAML，v2rayN / Clash / NekoBox 等直接订阅）：
  `https://raw.githubusercontent.com/1013608955/mkdy/main/s-clash.yaml`
- **已验证可用**（仅含中国出口链路实测通过的节点，已套用规则模版）：
  `https://raw.githubusercontent.com/1013608955/mkdy/main/s-verified.yaml`

> 说明：旧版 base64 单文件订阅（`s.txt` / `s1.txt` / `s2.txt`）已移除。v2rayN 等客户端
> 原生支持 Clash YAML，无需再转 base64 导入。

## 中国出口真实链路验证（verify_cn）

`verify_cn/` 部署两套验证入口，均位于**中国网络出口**，与 GitHub CI（境外）形成互补，
补上「该节点能否从中国绕过 GFW」这一环：

- **本机 Windows 定时任务（主）**：每小时 :05 跑 `run_local.py`，用本机 mihomo 真链探测；
  PC 关机时由云端容器兜底。
- **华为云开发环境容器（第二出口，常开）**：容器保持常开，`run_local.py` 每 15 分钟
  自跑并自推 `verified.json`，**PC 关机也不中断**。

两套入口跑的是同一套 `run_local.py`，流程一致：

1. 读取 `s-clash.yaml` 的 `proxies`；
2. 起一个独立 mihomo 进程（随机端口，不碰用户 Clash Verge 的配置 / 端口），以每个节点
   为出口实测能否从中国网络连通目标——主目标 `google/generate_204`，失败节点用兜底目标
   `cloudflare/cdn-cgi/trace` 复测一轮，防止 google 单点被误杀；
3. 逐节点结果（含诊断 `detail`）写入 `verify_cn/verified.json`；
4. 推送触发 GitHub `verify-tag.yml` → `tag_verified.py`：读 `verified.json` +
   `s-clash.yaml` + `clash_template.yaml`，筛出验证通过（ok=true）的节点，套用「短期」
   规则模版（`proxy-groups` / `rules` / `dns`），输出**仅含验证通过节点**的完整
   `s-verified.yaml`（无需手动挑 ✅）。

> 不走「云函数 + xray 手工翻译协议」的旧路线：xray 不支持 hysteria2 / anytls / tuic，
> 且 `streamSettings` 映射是历史 bug 温床；mihomo 直接吃 `s-clash.yaml` 原文，与客户端
> 延迟测试同源。验证细节见 `verify_cn/README.md`。

### 本机定时任务（主，每小时 :05）

- `verify_cn/setup_schedule.ps1` 注册 Windows 任务计划 `mkdy-verify-local`，
  每小时 :05 跑 `run_local.bat`（**隐藏窗口运行，无黑色 cmd 弹窗**），结果写
  `verify_cn/logs/run.log`。
- 重注册（改配置后）：`powershell -ExecutionPolicy Bypass -File verify_cn\setup_schedule.ps1`
- 删除：`schtasks /delete /tn mkdy-verify-local /f`
- 部署说明见 `verify_cn/LOCAL_VERIFY.md`。

### 华为云容器（第二出口，常开自跑，每 15 分钟）

- 实例 `DevEnvC_W4yNKt`（华为云开发环境 → 容器版，2vCPU 4GiB，中国网络出口）。
- `cloud_init.sh` 一次性引导（装依赖 / 克隆仓库 / 下 Linux mihomo / 铺定时任务），
  `set_schedule.sh` 把间隔切到 15 分钟（幂等，可重跑）。
- **容器常开 = PC 关机也不中断**；验证完全在容器内自跑并自推 `verified.json`，
  不依赖 GitHub Actions 启停 / hdspace / keyring。
- 核时 ≈ 2vCPU × 24h ≈ 1440 核时/月，8000 核时可撑约 5.5 个月，足够省心。
- 前置（不进仓库）：控制台注入 `GITHUB_PAT`（fine-grained PAT，仓库 `Contents:write`），
  或写在仓库内 `verify_cn/.env`（定时任务会自动 source）。
- 部署细节见 `verify_cn/cloud_README.md`。

## ⚠️ 验证边界（重要）

- **GitHub CI（境外）** 只能做「GitHub 侧 TCP 连通 + 代理握手」粗筛，无法判断节点能否
  从中国绕过 GFW；CI 只给「境外可达」节点小幅加分，**绝不据此淘汰节点**。
- **真正的可用性裁判**仍是你的客户端 **url-test**（建议
  `url_test=https://cp.cloudflare.com/generate_204`）。
- **verify_cn（中国网络）** 补上了「能否从中国出口」这一环，但其结果也只是「当前可达」
  的快照，节点随时可能失效，请以客户端实测为准。

## 手动本地运行

```bash
pip install requests pyyaml beautifulsoup4
python fetch_tuijian.py   # -> latest_tuijian.txt / history_tuijian.txt
python update_nodes.py    # -> s1.txt
python fetch.py           # -> s2.txt + s2-clash-1.yaml + s2-clash-2.yaml
python merge_subs.py      # -> s-clash.yaml
```

> 必须先跑前三个抓取脚本生成中间文件，再跑 `merge_subs.py`；否则只会合并已存在/历史文件。

## 安全说明

- 拉取订阅源默认开启 TLS 证书校验（`verify=True`），仅证书异常时降级并告警。
- IP 类型细分（`住宅 / 机房`）依赖 `ipinfo.io`，**默认关闭**（不发起网络请求）；
  如需启用，在 CI / 环境变量配置 `IPINFO_TOKEN`（有 quota 上限，避免限流）。
- 所有写仓库操作经 `secrets.PAT_TOKEN` + `permissions: contents: write`，
  且 `update-subs.yml` 与 `verify-tag.yml` 共用 `concurrency.group: mkdy-subs`，
  避免并发推送导致 non-fast-forward 拒绝。
- 云端容器 / 本机定时任务的推送均使用 `GITHUB_PAT`（控制台环境变量或本机任务环境 /
  仓库内 `.env`），**不写入仓库、不提交**。
