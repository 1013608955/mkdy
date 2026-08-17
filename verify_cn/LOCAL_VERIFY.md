# 本机节点验证（run_local.py）

在**本机**（中国大陆出口）跑节点真链验证，替代此前的阿里云 FC / 华为云 FunctionGraph 方案。

## 为什么改在本机跑

云函数路线卡在两处硬伤：

1. **网络**：函数在国内出口拉 `raw.githubusercontent.com` 极不稳定（反复 ReadTimeout），
   要靠镜像兜底；且部署链路长（打包 → 上传 → 点部署 → 填环境变量），出错定位困难。
2. **依赖**：PySocks 在 FunctionGraph 的依赖包挂载路径上反复 `Missing dependencies for
   SOCKS support`，`requests.adapters` 在 import 期就固化了 SOCKSProxyManager 桩函数。

本机天然满足「从国内探测节点能否翻墙」，而且：

- 已有 git 凭证，直接 push，**不需要 fine-grained PAT**；
- 已有 mihomo 二进制（Clash Verge Rev 自带）；
- 没有冷启动、没有 600s 函数超时限制。

## 为什么用 mihomo 而不是 xray

| | xray | mihomo |
|---|---|---|
| hysteria2 / anytls / tuic | ❌ 不支持（`unknown config id: hysteria2`，启动即失败） | ✅ 支持 |
| 配置来源 | 需把 Clash 节点手工翻译成 xray outbound（reality/ws/grpc 字段逐个映射） | ✅ 直接吃 `s-clash.yaml` 的 `proxies` 原文 |
| 进程模型 | 每个节点起一个子进程 | 单进程 + delay API 并发测全部节点 |
| 与客户端一致性 | 自己实现的探测逻辑 | 就是 Clash 客户端「延迟测试」的同一套实现 |

实测差异明显：xray 路线在 198 个节点里验出 21 个可用；mihomo 路线在 318 个节点里
验出 30 个，其中包含 xray **完全无法验证**的 anytls / hysteria2 节点。

> 那层手工协议翻译（`verify_proxy_core.py` 的 `build_xray_config`）也是历史 bug 温床
> ——`streamSettings` 曾被 flatten 到 outbound 顶层，导致所有 TLS 节点静默失效。

## 依赖

- **mihomo 二进制**：`verify_cn/mihomo.exe`（不入库）
  从 Clash Verge 安装目录复制即可：
  ```bash
  cp "/d/Program Files/Clash Verge/verge-mihomo.exe" verify_cn/mihomo.exe
  ```
- **Python + pyyaml**：`C:/Users/Admin/.workbuddy/binaries/python/envs/default/Scripts/python.exe`
  ```bash
  # 注意：pyyaml 在 tuna 镜像取不到 cp313 轮子，要指定官方源
  .../Scripts/pip.exe install pyyaml -i https://pypi.org/simple
  ```

## 用法

```bash
cd verify_cn
PY="C:/Users/Admin/.workbuddy/binaries/python/envs/default/Scripts/python.exe"

"$PY" run_local.py --limit 20 --no-push   # 小规模试跑
"$PY" run_local.py                        # 全量 + 自动 commit/push
"$PY" run_local.py -c 20 -t 10 --no-pull  # 20 并发、10s 超时、跳过 pull
```

参数：`--limit N` 只测前 N 个 / `-c` 并发（默认 16）/ `-t` 超时秒（默认 8）/
`--no-pull` 跳过 git pull / `--no-push` 不提交 / `--no-fallback` 跳过兜底目标复测。

全量 318 节点、20 并发、10s 超时，约 **3 分钟**跑完。

## 流程与衔接

```
git pull ──> 读 s-clash.yaml 的 proxies
             │
             ├─> 生成临时 mihomo 配置（仅 external-controller，mode=direct）
             ├─> 起独立 mihomo 进程（随机端口，不碰 Clash Verge）
             ├─> round1：并发调 /proxies/{name}/delay 测 google/generate_204
             ├─> round2：round1 失败的节点用 cloudflare/cdn-cgi/trace 复测（防 google 单点误杀）
             └─> 写 verify_cn/verified.json
                 │
                 └─> git commit + push
                     └─> 触发 GitHub 端 verify-tag.yml（监听 verify_cn/verified.json）
                         └─> tag_verified.py 给已验证节点加 ✅ → s-verified.yaml
```

## 定时执行

用 Windows 任务计划程序每小时跑一次，见 `setup_schedule.ps1`。
日志落在 `verify_cn/logs/`（不入库）。

```powershell
# 查看任务
schtasks /query /tn mkdy-verify-local /v /fo list
# 立即跑一次
schtasks /run /tn mkdy-verify-local
# 删除
schtasks /delete /tn mkdy-verify-local /f
```

## 注意事项

- **TUN 模式会污染结果**：若 Clash Verge 开了 TUN，探测进程的出站流量会被劫持，
  结果不可信。检查方式：`Get-NetAdapter | ? Status -eq 'Up'`，出现 Mihomo/wintun
  虚拟网卡即为开启。当前环境只有物理网卡，干净。
- **重名节点**：mihomo 遇到 duplicate name 会 fatal 拒绝加载。runner 会丢弃重复项
  （而不是重命名 —— `verified.json` 的 name 必须与 `s-clash.yaml` 精确一致，
  否则 `tag_verified.py` 匹配不上）。根因已在 `merge_subs.py` / `fetch.py` 修复。
- **失败原因分布**：`timeout` 占多数属正常 —— 免费订阅里大量节点本就是死的；
  trojan 节点尤其明显（137 个里仅 1 个可用，多数是 Cloudflare 在 trojan 握手失败后
  回落成普通 HTTPS，返回 HTTP/2 帧或 503）。
