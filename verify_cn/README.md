# mkdy 中国出口验证探针（verify_cn）

在中国大陆网络出口对聚合后的代理节点做**真实链路验证**，产出「已验证可用」结论，
回写仓库 `verify_cn/verified.json`（含完整 proxy dict）；GitHub 端 `update-subs.yml` 监听该文件、由 `merge_subs.py` 一步产出
仅含可用节点的 `s-verified.yaml`。

> 本机部署见 [`LOCAL_VERIFY.md`](./LOCAL_VERIFY.md)；
> 华为云容器部署见 [`cloud_README.md`](./cloud_README.md)。

## 原理

不走「云函数 + xray 手工翻译协议」的老路（xray 不支持 hysteria2 / anytls / tuic，且
`streamSettings` 映射是历史 bug 温床），而是直接复用 **mihomo**（Clash 内核）：

- 读取仓库根 `s-clash.yaml` 的 `proxies`（即最终喂给客户端的那份完整配置）；
- 起一个**独立**的 mihomo 进程（随机端口，不碰用户 Clash Verge 的配置 / 端口）；
- 并发调用每个节点的 `GET /proxies/{name}/delay?url=<目标>` 真链测试：
  - 主目标 `https://www.google.com/generate_204`；
  - 主目标失败的节点用兜底目标 `https://www.cloudflare.com/cdn-cgi/trace` 复测一轮，
    防止 google 单点被个别节点 / CDN 误杀；
- 逐节点结果（含诊断 `detail`）写入 `verify_cn/verified.json`；
- 若开启推送，`git commit + push` 后自动触发 GitHub `update-subs.yml` →
  `merge_subs.py` 读取 verified.json 的完整 proxy，直接产出带 ✅ 标记的 `s-verified.yaml`（方案A，免打标漂移）。

> 验证的是「从该出口位置能翻墙」，不等于所有用户都能用（不同省份 / ISP 的 GFW 行为不同）。
> 客户端 `url_test` 仍是最终仲裁。

## 两种运行方式

两者跑的是**同一套** `run_local.py`，区别仅在部署位置与触发方式：

### 1. 本机（主，Windows 定时任务，每小时 :05）

- `setup_schedule.ps1` 注册 Windows 任务计划 `mkdy-verify-local`，每小时 :05 跑
  `run_local.bat`（隐藏窗口、无黑框），结果写 `verify_cn/logs/run.log`。
- 重注册：`powershell -ExecutionPolicy Bypass -File verify_cn\setup_schedule.ps1`
- 删除：`schtasks /delete /tn mkdy-verify-local /f`
- 详见 [`LOCAL_VERIFY.md`](./LOCAL_VERIFY.md)。

### 2. 华为云开发环境容器（第二出口，常开自跑，每 15 分钟）

- `cloud_init.sh` 一次性引导：装依赖 → 配 git → 克隆仓库 → 下 Linux mihomo →
  装 pyyaml → 铺每 15 分钟定时任务（systemd timer 优先，否则 `run_loop.sh` 后台循环）→
  首次立即跑一次。
- 已初始化、保持常开的容器可用 `set_schedule.sh` 把间隔切到 15 分钟（幂等，可重跑）。
- **容器常开 = PC 关机也不中断**；验证完全在容器内自跑并自推 `verified.json`，
  不依赖 GitHub Actions 启停 / hdspace / keyring。
- 详见 [`cloud_README.md`](./cloud_README.md)。

## 文件清单

| 文件 | 作用 |
|---|---|
| `run_local.py` | 验证主程序（mihomo 真链探测，本机 / 容器通用） |
| `run_local.bat` | Windows 启动器（隐藏窗口调 `run_local.py`） |
| `setup_schedule.ps1` | 本机 Windows 任务计划注册（每小时 :05） |
| `cloud_init.sh` | 容器一键引导（幂等，可重复跑） |
| `set_schedule.sh` | 容器内把验证间隔切到每 15 分钟（幂等） |
| `mkdy-verify.service` / `mkdy-verify.timer` | systemd 单元模板（容器有 systemd 时用） |
| `merge_subs.py` | 读 `verified.json`（含完整 proxy）→ 一步产出 `s-verified.yaml`（方案A，已替代 tag_verified.py） |
| `requirements.txt` | Python 依赖（`pyyaml`） |
| `verified.json` | 运行产物（运行时生成，已入库以便 `update-subs.yml` 监听；含完整 proxy dict） |
| `LOCAL_VERIFY.md` | 本机（Windows）部署说明 |
| `cloud_README.md` | 容器部署说明 |

> 二进制 `mihomo` / `mihomo.exe` 与运行日志 `logs/` 由 `.gitignore` 排除，不入库；
> 前者从 Clash Verge 安装目录或 mihomo 官方发布复制，后者本地生成。

## 验证边界（重要）

- GitHub CI（境外）只做「GitHub 侧 TCP 连通 + 代理握手」粗筛，无法判断能否从中国绕过 GFW，
  **绝不据此淘汰节点**。
- 本探针补上「能否从中国出口」这一环，但其结果只是「当前可达」快照，节点随时可能失效，
  请以客户端 `url_test` 实测为准。
- 失败原因里 `timeout` 占多数属正常——免费订阅中大量节点本就是死的；
  trojan 节点尤其明显（握手失败后常回落成普通 HTTPS，返回 HTTP/2 帧或 503）。
