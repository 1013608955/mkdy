# mkdy 中国出口验证探针（verify_cn）

在中国大陆网络出口（阿里云函数计算 FC / **华为云函数工作流 FunctionGraph**）上对代理节点做**真实链路验证**，
产出 `已验证可用` 结论，回写仓库 `verify_cn/verified.json`。

> 华为云部署指南见 [`HUAWEI_DEPLOY.md`](./HUAWEI_DEPLOY.md)（华南-广州 cn-south-1，从零手动部署约 2 分钟）。
> 阿里云 FC 部署见 `s.yaml`（Serverless Devs）。

## 原理

- **socks5**：直接用 `pysocks` 把 `requests` 的流量经节点 socks5 代理拉目标 → 真链测试。
- **ss / vmess / vless / trojan / hysteria2**：函数内临时拉起 `xray` 二进制，
  开一个本地 SOCKS 入站（`127.0.0.1:<随机端口>`），把该节点作为出站，
  再用 `requests` 经 `socks5h://127.0.0.1:<端口>` 拉目标 URL。
  - `socks5h` 的 `h` 表示 DNS 也走代理，避免本地 DNS 泄露/失败。
- 无 `xray` 二进制时，非 socks5 协议返回 `xray_not_configured`，**绝不假阳性**。

> 说明：本探针验证的是“从该云函数所在中国位置/运营商能翻墙”，
> 不等于所有用户都能用（不同省份/ISP 的 GFW 行为不同）。客户端 `url_test` 仍是最终仲裁。

## 文件

- `verify_proxy_core.py`：平台无关核心（`parse_clash_yaml` / `verify_through_proxy` / `build_xray_config`）。
- `index.py`：FC 入口 `handler(event, context)`，拉节点 → 并发验证 → 写回 `verified.json`。
- `s.yaml`：阿里云 Serverless Devs 部署描述（含定时触发器）。
- `HUAWEI_DEPLOY.md`：华为云 FunctionGraph 控制台手动部署指南（华南-广州 cn-south-1）。
- `requirements.txt`：Python 依赖。
- `verified.json`：函数运行后**由其自身经 GitHub Contents API 直写**回仓库的结果（运行时生成，需配置 fine-grained PAT；非 GitHub Actions 代写）。

## 部署步骤（阿里云 FC）

1. **准备 xray 二进制**（完整协议覆盖必需）：
   - 下载 `xray-linux-64.zip`（与 FC 运行时同架构：x86_64 / amd64）。
   - 解压出 `xray` 可执行文件，放到本目录（`verify_cn/xray`），确保有执行权限
     （`chmod +x xray`）。部署时它会随 `codeUri: ./` 一起打包进函数。
   - 函数内 xray 路径由代码自动探测：华为云 `RUNTIME_CODE_ROOT=/opt/function/code` → `/opt/function/code/xray`；阿里云 FC → `/code/xray`；本地 → 脚本同目录。**无需手动配置**，通过 `XRAY_BIN` 环境变量可覆盖。
   - 若 FC 基础镜像缺个别动态库，换用 `xray-linux-64-v8` 或自行 `ldd` 排查。

2. **申请最小权限 Token**：
   - 在 GitHub 建 **fine-grained PAT**，**仅**授权 `1013608955/mkdy` 仓库的
     `Contents: write`（不要给整个账号的 repo 权限）。
   - 该 token 只用于回写 `verified.json`，不碰其他仓库。

3. **部署**：
   - 安装 Serverless Devs CLI（`npm i -g @serverless-devs/s` 或官方安装包）。
   - 登录阿里云（`s config add` / `s login`），确保 `access: default` 指向你的阿里云账号。
   - 在本目录执行 `s deploy`，按提示确认。
   - 在 FC 控制台把 `GITHUB_TOKEN` 环境变量设为上面的 fine-grained PAT
     （或在 `s.yaml` 里用 `{{env.GITHUB_TOKEN}}` 由本地环境变量注入，勿硬编码进文件）。

4. **定时触发**：
   - `s.yaml` 已带 `timer` 触发器，默认每小时（UTC）跑一次。
   - 如需北京时间整点：在 FC 控制台把触发器时区改为 `Asia/Shanghai`，cron 保持 `0 0 * * * *`。

## 成本（按之前估算）

每小时 1 次、每轮 ~100 节点、并发 8、256MB：月调用 ~744 次（免费 100 万）、
算力 ~5,580 GB-s（免费 40 万）、出网 < 200MB（免费 20GB/月）。
**三种资源都只占免费额度个位数百分比，不会超额。**

## 已知边界 / 待扩展

- 流控仅覆盖 **tcp / ws(+tls)**；`grpc` / `reality` / `shadowtls` / 复杂 `plugin`
  尚未映射，遇到会退化为 `xray_listen_timeout` 或握手失败，按需补 `_stream_settings`。
- 节点数很大时单次运行可能逼近 FC 600s 上限：调大 `CONCURRENCY` 或减少每轮节点数
  （例如函数只抽取部分节点、或拆多轮）。
- `hysteria2` 依赖 xray 对应版本支持。
