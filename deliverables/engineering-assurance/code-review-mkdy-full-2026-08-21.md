# mkdy 项目全面代码审查报告

**日期**：2026-08-21
**工作流**：工作流 1 — 全面代码审查（SOP）
**参与成员**：Cody（代码审查师）、Archi（系统架构师）、Tessa（测试专家）
**主理人**：甄宇航（Engineering Director，工程保障团队）

---

## 📌 TL;DR（执行摘要）

- 整体结论：主线数据流清晰自洽（采集→评分→抓取→合并→验证→打标），基础健壮性较好（普遍带超时/降级），但**存在 1 个架构级时序缺陷与若干安全/资源释放纰漏**，建议在继续扩展前优先收敛。
- 严重度分布：🔴严重 6 项 / 🟠高 6 项 / 🟡中 8 项 / 🟢低 6 项（跨三成员去重合并后）
- 阻塞 / 非阻塞：无硬性阻塞；🔴 项均为"应修但未上线即崩"的隐患，建议本迭代内闭环
- 已在本迭代修复并上线的项（P0/P1，不在本报告新问题清单内）：config.yaml 嵌套合并、fetch 协议补全、merge txt 路径对齐、weight 防御取值

---

## 🎯 核心结论卡片

| 项目 | 内容 |
|------|------|
| 整体评级 | 🟡 有条件通过（主线可用，需收敛 🔴 项） |
| 阻塞项数量 | 0（无上线即崩的硬阻塞） |
| 关键行动项 | 6 条 🔴 + 6 条 🟠 |
| 建议下一步 | 优先修复「跨工作流时序缺陷」「TLS 不校验」「子进程泄漏」「CI 零测试」 |

---

## 🔍 审查发现（按严重度排序，跨成员去重合并）

| # | 严重度 | 类别 | 文件:行 | 问题描述 | 建议修复 | 来源 |
|---|--------|------|---------|---------|---------|------|
| 1 | 🔴严重 | 架构/时序 | update-subs.yml / verify-tag.yml | 两工作流独立调度（:00 / :15），merge 并入 s-verified.yaml 但 verify-tag 晚跑 → 新验证节点最多延迟 ~1h 才进全量；CI/FC 双验证器还可能互相覆盖 | 方案(a) merge 不再并入 verified，下放客户端聚合；(b) 合并为单工作流内存读最新；(c) verify-tag 改 `on: push paths:[s-clash.yaml]` 由 update-subs 拉起 | Archi |
| 2 | 🔴严重 | 架构/耦合 | merge_subs.py:157 (VERIFIED_SOURCE) | merge 硬读 s-verified.yaml，与另一独立工作流产物强耦合；验证侧故障静默改变全量订阅 | 剥离为独立 `apply_verified.py` 后处理，或 merge 用 `--verified` 参数显式传入、默认跳过 | Archi |
| 3 | 🔴严重 | 安全/TLS | update_nodes.py:472-474 | `probe_proxy_handshake` 设 `check_hostname=False; verify_mode=CERT_NONE` 关闭证书校验，MITM 可伪造可达节点骗取加分 | 默认校验，仅显式 `allow_insecure` 配置时降级并告警 | Cody |
| 4 | 🔴严重 | 资源释放 | verify_cn/run_local.py:272-314 | mihomo 子进程仅在 try 内 terminate；若后续 wait_api 抛未捕获异常，finally 不执行 → 进程+临时目录泄漏；`proc.wait` 超时后 kill 未再次 wait → 僵尸残留 | Popen 放 try 之前；kill 后补 `proc.wait(timeout=5)`；`start_new_session=True` + `os.killpg` 整组回收 | Cody |
| 5 | 🔴严重 | 测试/CI | update-subs.yml / verify-tag.yml | 两核心工作流完全不跑测试，回归靠人工/线上异常发现 | 在 update-subs.yml 加 `python -m pytest tests/ -q`（外部依赖全 mock）；详见下方 Tessa CI 改造片段 | Tessa |
| 6 | 🔴严重 | 测试/可测性 | fetch_tuijian.py（整文件） | import 即 `requests.get` 并 exit，无法在 CI 不联网时 import/测；推荐链接提取逻辑失效无声 | 重构为 `main()` + 可测函数 `extract_link(soup_text)`，用 requests_mock 打桩 | Tessa |
| 7 | 🟠高 | 全局状态 | update_nodes.py:354,579-583 | `_PROBE_COUNT` 模块级全局，跨多次调用不重置；`lru_cache`(dns_resolve/get_ip_type) 跨运行缓存旧 IP | `main()` 开头 `reset_state()` 清空；或局部计数+闭包替代模块全局 | Cody |
| 8 | 🟠高 | 异常处理 | fetch.py:102,162,213 | 多处裸 `except:` 静默吞所有异常（含 KeyboardInterrupt/SystemExit），掩盖真实错误 | 改 `except (ValueError, ...)` 明确类型或 `except Exception` 并记日志 | Cody |
| 9 | 🟠高 | 资源/并发 | run_local.py:272 | Popen 无 timeout/start_new_session；CI 强杀时 mihomo 孤儿进程残留占端口 | `start_new_session=True`，超时场景 `os.killpg` 整组回收 | Cody |
| 10 | 🟠高 | 架构/配置 | update_nodes.py (_overlay_config_file) | CONFIG 内联 + config.yaml overlay 双轨，语义不清；正则 private_ip 无法 yaml 序列化被强制塞回；cn_ranges.txt import 即全量载入（冷启动成本） | 可配置项全迁 config.yaml，内联只留常量+默认值；cn_ranges 改 lru_cache 惰性加载 | Archi |
| 11 | 🟠高 | 架构/耦合 | tag_verified.py / run_local.py | 验证侧"精确 name 匹配"脆弱：run_local 遇重名直接丢弃（非重命名），merge 最后才 make_names_unique 改名 → 打标匹配不上漂移丢节点 | 上游保证 name 唯一；tag 匹配加 (type,server,port) 二级键兜底 | Archi |
| 12 | 🟠高 | 测试/覆盖 | verify_cn/run_local.py, tag_verified.py | 验证核心（build_mihomo_config/_norm_err/load_ok/分组注入）零测试，回归不可见 | 对 build_mihomo_config/_norm_err/load_ok 做纯函数单测 | Tessa |
| 13 | 🟠高 | 测试/依赖 | fetch.py / requirements.txt | bs4 缺失危及 import（连带 test_merge_subs 内 `import fetch` 失败）；requirements.txt 未含 beautifulsoup4 | 补 beautifulsoup4 入 requirements.txt；download_nodes 文本→节点逻辑单测化 | Tessa |
| 14 | 🟡中 | 配置/魔法串 | 多模块 | 状态标签/文件名/协议名散落硬编码（"prescreen_fail:*"/"cn_skip"/s1/s2/s-clash 等），跨模块拼写漂移无校验 | 抽 constants.py 集中 SCHEMES/SOURCE_FILES/VERIFY_STATUS 枚举；下游 import `_PARSERS.keys()` | Archi |
| 15 | 🟡中 | 边界/竞态 | update_nodes.py:308-346 | dns_resolve 守护线程 join(timeout) 后解析仍可能写入被丢弃且线程空转；lru_cache 缓存失败结果 False,[] 长期不重试 | 失败结果设短 TTL 或不缓存；解析线程显式 join 回收 | Cody |
| 16 | 🟡中 | 资源释放 | merge_subs.py:186 / fetch.py:248 | 多处 `open().read()` 未用 with，依赖 GC 释放句柄，CI 高频下释放不及时 | 统一改 `with open(...)` | Cody |
| 17 | 🟡中 | 架构/边界 | fetch_tuijian/fetch/update_nodes | 三套抓取逻辑重叠（请求→BS→正则抽链→下载→解析），update_nodes 单文件 998 行既采集又评分又报告 | 抽 fetcher.py（通用 get_html/extract_links/download_nodes）+ nodeio.py；update_nodes 拆 collect/score/report | Archi |
| 18 | 🟡中 | 可扩展 | fetch.py / run_local.py | 源站扩展靠 TARGET_SITES + `if site_name` 分支特例；验证出口硬编码 mihomo + HTTP 目标，换验证器需改核心 | fetch 改站点适配器注册表；run_local 验证后端抽象为 Verifier 接口，目标外置配置 | Archi |
| 19 | 🟡中 | 测试/隔离 | tests/ + update_nodes import | import 触发全局 CONFIG/CN_RANGES/SESSION 加载，污染测试隔离；缺 config.yaml/cn_ranges.txt 时行为漂移 | tmp_path 注入最小 config + 迷你 cn_ranges；setUp/tearDown 快照还原 CONFIG/_PROBE_COUNT | Tessa |
| 20 | 🟡中 | 测试/全局态 | update_nodes (_PROBE_COUNT/lru_cache) | 多次测试运行间状态泄漏（_PROBE_COUNT 封顶污染、lru_cache 跨用例缓存） | fixture 中 cache_clear() + 重置计数器 | Tessa |

（🟢低 6 项略：name_util 空 server 同名校正、workflow 空 merge commit、cleanup-old-runs curl PAT 明文、b64_safe_decode 失败原样返回、score_rules 表达力/速度档位、Python 版本不一致 3.10/3.12——详见各成员原始产出）

---

## 🏗️ 架构影响评估

主线数据流**单向无环、连贯自洽**，资源释放（mihomo 三级回收 + rmtree）与核心降级（GitHub 侧探测只加分不硬过滤）设计合理。

**最大架构风险（🔴1/🔴2）**：两个独立工作流通过文件系统（`s-verified.yaml`）互相依赖，本质是"用文件做跨工作流通信"的反模式，产生差一轮时序缺陷与隐式耦合。优先采用 **方案(c)**（verify-tag 改 `on: push paths:[s-clash.yaml]`）或 **方案(b)**（合并工作流），改动最小、收益实。

**配置双轨（🟠10）** 与 **验证脆弱匹配（🟠11）** 是次优先架构债，建议随下次配置重构一并处理。

**协议扩展设计（🟡18 部分）已较优**（`_PARSERS` 注册表 + `struct_to_uri` 反向转换），应保留并推广到源站/验证出口。

---

## 🧪 测试覆盖评估

**已覆盖**：node_parse 往返保真（ssr/tuic/hy2）、is_cn_ip、_resolve_connect、_deep_merge、merge_subs 去重/verified 优先/txt 路径、fetch.download_nodes 协议覆盖——共 25 项 unittest，本次 P0/P1 修复均带回归。

**零测试核心模块**：`fetch_tuijian.py`（整文件）、`verify_cn/run_local.py`、`verify_cn/tag_verified.py`、`fetch.py` 网络分支。

**零测试核心函数**：`update_nodes.calculate_node_score` / `process_single_node_final` / `probe_proxy_handshake` / `test_node_final` / `parse_node` / `fetch_source_data`。

**CI 改造建议（Tessa 提供，可直接落地 update-subs.yml）**：

```yaml
      - name: 安装依赖（含测试依赖）
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt   # 需补 beautifulsoup4

      - name: 运行单元测试（pytest 兼容 unittest 风格）
        run: python -m pytest tests/ -q --tb=short
        env:
          IPINFO_TOKEN: ""
          GITHUB_TOKEN: ""

      - name: 抓取 tuijianvpn 推荐订阅链接 -> latest_tuijian.txt
        continue-on-error: true
        run: python fetch_tuijian.py
```

要点：Python 统一 3.12；外部依赖在用例内用 `requests_mock`/`unittest.mock` 打桩，CI 不触发真实网络（契合沙箱约束）；`requirements.txt` 补 `beautifulsoup4` 否则 `import fetch` ImportError。

---

## ✅ 行动清单（按优先级排序）

| # | 行动 | 负责角色 | 紧急度 | 预期完成 |
|---|------|---------|--------|---------|
| 1 | 消除跨工作流时序缺陷：verify-tag 改 `on: push paths:[s-clash.yaml]` 或合并工作流，实现零延迟同步 | Archi + SRE | P0 | 下迭代 |
| 2 | `probe_proxy_handshake` 默认校验 TLS，仅 `allow_insecure` 时降级并告警 | Cody | P0 | 下迭代 |
| 3 | run_local mihomo 进程：Popen 前置 + kill 后 wait + start_new_session + os.killpg 整组回收 | Cody | P0 | 下迭代 |
| 4 | update-subs.yml 接入 pytest 步骤（外部依赖全 mock），拦截回归 | Tessa | P0 | 下迭代 |
| 5 | fetch_tuijian.py 重构为可测函数 + requests_mock 打桩，消除 import 即 exit | Tessa | P1 | 下迭代 |
| 6 | update_nodes 全局状态（_PROBE_COUNT/lru_cache）在 main 开头 reset_state 清空 | Cody | P1 | 下迭代 |
| 7 | fetch.py 裸 except 改为明确异常类型 + 日志 | Cody | P1 | 下迭代 |
| 8 | 验证侧 name 匹配加 (type,server,port) 二级键兜底，消除重名漂移丢节点 | Archi | P1 | 下迭代 |
| 9 | CONFIG 双轨收敛：可配置项全迁 config.yaml，cn_ranges 改惰性加载 | Archi | P2 | 规划中 |
| 10 | 抽 constants.py（SCHEMES/SOURCE_FILES/VERIFY_STATUS 枚举）+ fetcher.py/nodeio.py 消除重复抓取 | Archi | P2 | 规划中 |

---

## ⚠️ 待完善 / 已知局限

- 本次审查基于 2026-08-21 代码快照（HEAD `a185118`，含已上线的 P0/P1 修复）；若后续有提交，需重审。
- 审查未运行动态模糊/渗透测试，仅静态审查 + 局部单测覆盖；mihomo 真链验证路径未实测（依赖外部二进制）。
- 三位成员子代理首次调用因环境超时返回空，重试后成功；本报告基于重试后的有效产出汇编。
- `cn_ranges.txt` 由 `tools/gen_cn_ranges.py` 离线生成（APNIC 权威 10830 条 CIDR），审查假定其随仓库分发。

---

## 📚 数据来源 & 成员产出索引

- Cody（代码审查师）原始产出：安全/性能/正确性/可维护性审查，12 条发现（含 #3/#4/#7/#8/#9/#15/#16/#20 等）
- Archi（架构师）原始产出：架构与数据流评估，10 条发现（含 #1/#2/#10/#11/#14/#17/#18 等）
- Tessa（测试专家）原始产出：测试策略与 CI 集成评估，10 条发现 + CI 改造 YAML 片段（含 #5/#6/#12/#13/#19 等）

---

> 本报告由工程保障团队 AI 协作生成，关键决策请由人类工程负责人复核。
