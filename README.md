# mkdy — 自动代理节点聚合 + 单 Clash 订阅 + 中国出口真实链路验证

GitHub Actions 全自动运行：从多个公开订阅源拉取节点 → 合并去重 → 产出**单一**
Clash 订阅 `s-clash.yaml`；再由**华为云开发环境容器**（中国网络出口）做真实链路
验证，产出已验证子集 `s-verified.yaml` / `s-verified.txt`。全流程无人值守，
容器按需开关机（省核时模式）。

## 架构总览

```
┌─ 每小时 update-subs.yml ────────────────────────────────┐
│ update_nodes.py   公开URI源拉取+评分粗筛 -> s1.txt       │
│ fetch.py          爬米贝77/Datiya     -> s2-clash-1/2    │
│ fetch_extra.py    直连YAML订阅源      -> s2-clash-3..6   │
│ merge_subs.py     合并去重+套规则模版                    │
│                   -> s-clash.yaml / s-clash.txt          │
│                   + 读 verified.json 并入已验证节点       │
│                   -> s-verified.yaml / s-verified.txt    │
└──────────────────────────────────────────────────────────┘
           │ s-clash.yaml（含上轮✅节点）
           ▼
┌─ 每小时 hds-cycle.yml（华为云容器按需唤醒）────────────────┐
│ 唤醒容器(Ready->Running ~1min)                            │
│ → ssh-key-reset 密钥自举 → 隧道                           │
│ → boot_job：装依赖→拉代码→run_local.py 真链验证→推送       │
│ → stop 关机                                               │
└──────────────────────────────────────────────────────────┘
```

## 订阅产物（4 个）

| 文件 | 内容 | 用途 |
|---|---|---|
| `s-clash.yaml` | 全量节点 + proxy-groups/rules/dns 完整配置 | Clash / Verge 直接订阅 |
| `s-clash.txt` | 全量节点的分享链接（URI 列表） | v2rayN 等 |
| `s-verified.yaml` | **仅中国出口实测通过**的节点，完整配置 | 推荐日常使用 |
| `s-verified.txt` | 已验证节点的 URI 列表 | v2rayN 等 |

客户端订阅地址：

```
https://raw.githubusercontent.com/1013608955/mkdy/main/s-verified.yaml
https://raw.githubusercontent.com/1013608955/mkdy/main/s-clash.yaml
```

## 节点来源与源健康机制

三类来源（见 `config.yaml` 与各脚本内定义）：

1. **URI 订阅源**（`update_nodes.py`，约 8 个）：GitHub 侧 TCP 粗筛 + 握手探测评分
   （仅作信号不硬过滤），≥65 分进入合并。
2. **网页爬取**（`fetch.py`）：米贝77 / Datiya 分享站文章页抓订阅链接。
3. **直连 Clash YAML 源**（`fetch_extra.py`，4 个）：下载即用，质量最高。

**源健康机制**（`source_health.json`，随 CI 产物提交跨轮持久）：
某源连续失败 ≥5 次自动禁赛（不再浪费请求）；每 24 小时自动探活一次，
成功即清零回归——临时挂掉的源一天内自愈，无需人工干预。

## 中国出口真链验证（方案 A：无打标、无漂移）

验证在**华为云容器** `DevEnvC_W4yNKt`（ARM 2vCPU 4GiB，中国出口）内完成：

1. `hds-cycle.yml` 每小时整点唤醒容器（Ready→Running 约 1 分钟）；
2. `ssh-key-reset` 密钥自举后开隧道，执行 `tools/boot_job.sh`：
   装 Python 依赖 → git pull 最新代码 → 跑 `verify_cn/run_local.py`；
3. `run_local.py` 流程：
   - 读取 `s-clash.yaml` 全部 proxies；
   - **二分隔离坏节点**（以 `mihomo -t` 为预言机精准定位导致加载失败的节点并移除，
     不依赖猜测字段规则）；reality short-id 连写 hex 自动补冒号；
   - 起独立 mihomo 实测每节点能否从中国出口连通（google/generate_204 主目标，
     cloudflare/cdn-cgi/trace 兜底复测）；
   - 结果（含完整 proxy 配置与诊断 detail）写入 `verify_cn/verified.json` 并推送。
4. 推送触发 `update-subs.yml` → `merge_subs.py` 直接读取 `verified.json` 里
   的完整 proxy 配置产出 `s-verified.*`——**验证器存什么就出什么，无 name 匹配、
   无打标环节，从根上消除漂移**。

### 省核时（按需开关机）

- 旧模式容器常开 = 1440 核时/月；现模式每小时唤醒一次 ≈ **120-150 核时/月**
  （单周期 Running 约 6.5 分钟），8000 核时余额从撑 5.5 个月变为 **4 年以上**。
- 需要 ≤15 分钟新鲜度：把 `hds-cycle.yml` 的 cron 改为 `'*/15 * * * *'`
  （核时消耗约增至 3 倍）。`concurrency` 守卫保证周期绝不重叠。
- 手动触发：Actions 页 → hds-cycle → Run workflow（status=只查状态 /
  wake=仅开机 / wake_verify=完整周期）。

## ⚠️ 验证边界

- GitHub CI（境外）只做 TCP 连通 + 握手粗筛，**绝不据此淘汰节点**。
- 真正可用性裁判仍是客户端 url-test。verify_cn 结果只是「当前可达」快照。
- 数据中心 IP 出口会被部分节点服务端封禁，验证通过率天然偏低属正常现象。

## 本地手动运行

```bash
pip install -r requirements.txt
python update_nodes.py    # -> s1.txt
python fetch.py           # -> s2.txt + s2-clash-1/2.yaml
python fetch_extra.py     # -> s2-clash-3..6.yaml（可 --threshold 调禁赛阈值）
python merge_subs.py      # -> s-clash.yaml + s-verified.yaml（读已有 verified.json）
```

> 本机 Windows 定时任务路线（run_local.bat / setup_schedule.ps1）已弃用：
> 本机无 mihomo 二进制，验证统一走华为云容器。

## 安全说明

- 所有写仓库操作经 `secrets.PAT_TOKEN` / 容器侧 `GITHUB_PAT`
  （fine-grained，仅 Contents:write），不写入仓库、不提交。
- 凭据存华为云容器 `verify_cn/.env`（已在 .gitignore，权限 600）。
- CI 侧 hdspace 凭据走仓库 Secrets（`HDS_AK` / `HDS_SK`）；
  SSH 私钥由 `ssh-key-reset` 每次开机自动重建，无需托管。
- `update-subs.yml` 与 `hds-cycle.yml` 各自配置 concurrency，
  防并发推送冲突；生成产物合并冲突以本轮重算为准（`-X ours`）。

## 回滚锚点

`tag stable-20260824` @ `4b4ccdc` —— 功能完备稳定态快照，
异常时 `git reset --hard stable-20260824` 回滚（勿 force-push main）。
