# mkdy — 自动代理节点聚合 + Clash 订阅生成

每天由 GitHub Actions 自动运行：从多个公开订阅源拉取节点 → 去重/粗筛 → 生成 `s1.txt`
（Base64 订阅），再经 [SubConverter](https://github.com/tindy2013/subconverter) 转换为
`s1-clash.yaml` / `s-clash.yaml` / `s2-clash.yaml` 等 Clash 配置。

## ⚠️ 验证边界（重要）

**GitHub CI 运行在境外网络，无法验证「该节点能否从中国绕过 GFW」。**

- CI 只做 **GitHub(US) 侧的连通性粗筛 + 代理握手探测**（`update_nodes.py`）：
  - TCP 连通性（各协议独立超时）；
  - `probe_proxy_handshake`：对 Trojan / VLESS(Reality) / TLS 类做真实 TLS 握手探测，
    作为「境外可达」的**小幅加分信号**，**绝不据此过滤/淘汰节点**（任何异常、超时、
    中国 IP 都降级为「不加分」，不会误杀）。
- **真正的可用性（能否在中国大陆正常使用、能否绕过封锁）必须在客户端验证**：
  CI 已通过 SubConverter 注入 `url_test=https://cp.cloudflare.com/generate_204`，
  请在你自己的 Clash / v2rayN 等客户端开启 **url-test / 延迟测试** 来最终筛选。

简言之：本仓库产出的是「候选节点池」，不是「已验证可用」的保证。客户端 url-test 才是
最终裁判。

## 安全说明

- 拉取订阅源默认开启 TLS 证书校验（`verify=True`），仅当证书异常时才降级为不校验并告警。
- IP 类型细分（`住宅 / 机房`）依赖 `ipinfo.io`，**默认关闭**（不发起网络请求）。
  如需启用，在 CI / 环境变量中配置 `IPINFO_TOKEN`（有 quota 上限，避免限流拖慢任务）。
- 删除说明：`update_clash.py` 为早期本地生成脚本，已无人调用且字段过期，已移除；
  所有 Clash 配置统一由 CI 中的 SubConverter 步骤生成。

## 主要配置

见 `update_nodes.py` 顶部 `CONFIG`：

- `sources`：订阅源列表（含权重）；
- `detection.dns.servers`：DNS 解析优先使用的服务器（UDP 查询，失败回退系统解析器）；
- `detection.score_threshold`：基础评分阈值，运行时按全体分布动态微调（见 `adjust_score_threshold`）。
