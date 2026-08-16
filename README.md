# mkdy — 自动代理节点聚合 + 单 Clash 订阅 + 中国出口真实链路验证

GitHub Actions 每小时自动运行：从多个公开订阅源拉取节点 → 合并去重 → 产出**单一**
Clash 订阅 `s-clash.yaml`；另有部署在阿里云函数计算（FC）的 `verify_cn` 探针，
实测「该节点能否从中国网络出口连通」，产出已验证子集 `s-verified.yaml`。

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

`verify_cn/` 部署在阿里云函数计算（中国网络），与 GitHub CI（境外）形成互补：

- 读取 `s-clash.yaml` 的 `proxies`（通过环境变量 `NODE_SOURCE_URL` 指定，默认即该文件）；
- 借助内置 xray，以每个节点为出口 SOCKS 代理，实测能否从中国网络连通目标；
- 把逐节点结果（含诊断 `detail`）写入 `verify_cn/verified.json`（经 GitHub Contents API 回写仓库）；
- `verify-tag.yml` 触发 `tag_verified.py`：读 `verified.json` + `s-clash.yaml` + `clash_template.yaml`
  → 筛出验证通过（ok=true）的节点，套用「短期」规则模版（`proxy-groups` / `rules` / `dns`），
  输出**仅含验证通过节点**的完整 `s-verified.yaml`（无需手动挑 ✅）。

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
