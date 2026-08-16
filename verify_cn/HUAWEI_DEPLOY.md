# 华为云 FunctionGraph 部署指南（verify_cn）

本探针核心逻辑（xray + SOCKS5 真链探测 + 回写 GitHub）**平台无关**，
已从阿里云 FC 迁移到华为云函数工作流（FunctionGraph），区域：**华南-广州 cn-south-1**。

入口签名 `def handler(event, context)` 与华为云 Python 事件函数完全一致，
代码**无需改动**，唯一差异是函数代码目录：华为云为 `/opt/function/code`，
阿里云为 `/code`。`index.py` 已自动探测 `RUNTIME_CODE_ROOT`，因此 `XRAY_BIN` 默认路径
在华为云即 `/opt/function/code/xray`，**无需手动配置**。

---

## 一、前置条件

1. 华为云账号，已实名（函数工作流在 `cn-south-1` 华南-广州）。
2. 本机已生成 `verify_cn/deploy.zip`（部署包，14.4MB，含 xray + 依赖 + 代码）。
   - 路径：`C:/Users/Admin/.openclaw/workspace/mkdy/verify_cn/deploy.zip`
   - 若需重建：`python verify_cn/build_package.py`（需先有 `verify_cn/xray` 与 `verify_cn/_wheels/`）。
3. GitHub **fine-grained PAT**（仅授权 `1013608955/mkdy` 仓库的 `Contents: write`），
   用于函数回写 `verify_cn/verified.json`。

---

## 二、创建函数

1. 登录华为云控制台 → **函数工作流 FunctionGraph** → 切换区域到 **华南-广州**。
2. **函数列表 → 创建函数 → 从零开始创建**。
3. 配置：
   - 函数类型：**事件函数**
   - 函数名称：`mkdy-verify-cn`（自定义）
   - 运行时：**Python 3.10**
   - 内存：**512 MB**（并发验证 200+ 节点、拉起 xray 需要，128MB 易 OOM）
   - 执行超时：**600 秒**（最坏情况 200 节点 / 并发 8 × 8s 超时 ≈ 200s，留足余量）
   - 企业项目：默认
4. 点击**创建函数**。

---

## 三、上传部署包

1. 进入函数详情 → **代码** 标签页。
2. 点击 **上传** → **本地 ZIP**，选择本机 `verify_cn/deploy.zip`。
3. 上传后确认代码根目录出现：`index.py`、`verify_proxy_core.py`、`xray`、
   `requests/`、`yaml/`、`socks.py` 等。
4. 点击**部署**（Deploy）。

> 华为云会把 zip 解压到 `/opt/function/code`，并自动把该目录加入 Python `sys.path`，
> 因此 `import verify_proxy_core` / `import requests` 都能找到。

---

## 四、配置环境变量

在 **配置 → 环境变量** 中添加：

| 变量名 | 值 | 是否必填 | 说明 |
|---|---|---|---|
| `GITHUB_TOKEN` | 你的 fine-grained PAT | **必填** | 仅 `Contents:write`（本仓库），用于回写 `verified.json` |
| `GITHUB_OWNER` | `1013608955` | 可选 | 代码默认值即此，可不填 |
| `GITHUB_REPO` | `mkdy` | 可选 | 代码默认值即此，可不填 |
| `XRAY_BIN` | 不填 | 可选 | 代码自动探测 `/opt/function/code/xray`，无需设置；如需覆盖再填 |
| `NODE_SOURCE_URL` | 见下 | 可选但**建议填** | 节点源地址 |
| `TIMEOUT` | `8` | 可选 | 单节点验证超时（秒），默认 8 |
| `CONCURRENCY` | `8` | 可选 | 并发验证线程数，默认 8 |

**关于 `NODE_SOURCE_URL`**：默认值是
`https://raw.githubusercontent.com/1013608955/mkdy/main/s-clash.yaml`。
华为云在中国大陆，`raw.githubusercontent.com` 可能被 GFW 不稳定限速/阻断——
但 `index.py` 的 `_fetch_node_source()` 已内置镜像兜底链
（原 URL → `ghproxy.net` → `raw.gitmirror.com` → `raw.kkgithub.com` → `jsdelivr`），
任一可达即用之。**为求稳，建议直接把 `NODE_SOURCE_URL` 设为镜像地址**，例如：

```
https://ghproxy.net/https://raw.githubusercontent.com/1013608955/mkdy/main/s-clash.yaml
```

配置完点击**保存**。

---

## 五、配置定时触发器（每小时）

1. 进入函数详情 → **配置 → 触发器** → **创建触发器**。
2. 触发器类型：**定时触发器（Timer）**。
3. 触发器名称：`hourly-verify`（自定义）。
4. 触发规则：选 **Cron 表达式**，填入：

   ```
   0 0 * * * *
   ```

   （含义：秒=0 分=0 时=每小时间=每日 月=每月 周=每星期 → 每小时整点触发。
   华为云非欧洲站点默认**北京时间**，无需额外设时区。）
   或选 **固定频率** 填 `1` 小时。
5. 是否启用：**是**（定时触发器创建后不支持改启用状态，请直接启用）。
6. 调用方式：同步/异步均可（建议异步，避免长耗时同步网关超时）。
7. 点击**确定**。

---

## 六、测试运行

1. 进入 **代码** 标签页 → 点击 **测试**（或「函数测试」）。
2. 测试事件：选「空白模板」，内容留空 `{}` 即可（定时器传入也是空事件）。
3. 点击**测试**，等待执行（200 节点约 1–3 分钟）。
4. 查看**执行结果**与**日志**：应看到类似
   `[verify] 节点源拉取成功：...`、`[verify] N/M ok; ...` 的输出；
   若失败，函数会返回带 `traceback` 的 JSON，便于定位真因。

---

## 七、验证是否生效

- 函数成功运行后，会经 GitHub Contents API 更新 `verify_cn/verified.json`
  （`generated_at` 字段为本次运行时间）。
- 在仓库看 `verify_cn/verified.json` 的 `generated_at` 是否刷新，
  以及 `ok` 字段是否有 >0 的节点（取决于免费节点在该华为云出口是否可达）。
- 若 `ok=0` 且日志显示节点侧超时/失败居多：这是**免费公共节点在华为云机房 IP 大多被封**
  的真实表现（与之前阿里云 0/211 同理），并非部署失败。可考虑换更活的订阅源。

---

## 八、与阿里云 FC 的差异速查

| 项 | 阿里云 FC | 华为云 FunctionGraph |
|---|---|---|
| 代码目录 | `/code` | `/opt/function/code`（由 `RUNTIME_CODE_ROOT` 暴露） |
| 入口 | `handler(event, context)` | 同左（完全一致） |
| 部署包 | 标准 zip，`s deploy` 或控制台上传 | 标准 zip，控制台上传 |
| 定时触发 | `s.yaml` timer / 控制台 | 定时触发器，`@every 1h` 或 `0 0 * * * *` |
| 二进制执行 | 支持（/code/xray） | 支持（/opt/function/code/xray，subprocess 可执行） |
| 出口 | 阿里云 cn-hangzhou 机房 IP | 华为云 cn-south-1 机房 IP |

---

## 九、计费提醒（重要）

迁移到华为云**不等于免费**：

- 函数**调用次数**与**算力（GB-秒）**在每小时 1 次、每次几百节点的量级下，
  基本落在华为云 FunctionGraph 免费额度内。
- **公网出流量**（函数拉节点源 + 真链测试产生的外网流量）两家云都**按量计费**。
  如果你在阿里云主要被收的是出流量计费，华为云同样会收这部分——
  区别仅是两家单价/免费额度不同，请到华为云官网核实当前 FunctionGraph 计费细则。
- 本探针意义是「从中国出口真测翻墙可用性」，与「本机（住宅 IP/已翻墙）客户端能通」
  不可直接比较；ok 数在不同 vantage（阿里/华为/你家）会有差异，属正常。

---

## 十、回滚 / 双跑注意

- 旧阿里云 FC 函数请你在**华为云跑通确认无误后**再于阿里云控制台删除，
  避免中途两云都计费或验证中断。
- `verify_cn/` 目录下的 `s.yaml` 仍是阿里云 Serverless Devs 描述，华为云用不到，
  保留无害（不影响华为部署）。
