"""守住 GitHub Actions 的 run 块长度硬限制。

## 2026-11-09 事故复盘

`hds-cycle.yml` 的 `[2]` 步骤 `run: |` 块因长期追加中文注释，UTF-8 字节数
累积到 **25041**，超过 GitHub 的 **21000** 上限，导致：

    gh workflow run → HTTP 422
    failed to parse workflow: (Line: 290, Col: 14):
      Exceeded max expression length 21000

即 **`workflow_dispatch` 完全不可用** —— 而华为云 FunctionGraph 每 15 分钟的
主力触发正是调它。故障表现极具迷惑性：日志里没有任何异常，只有 `cron`
和 `push` 触发的轮次在跑，看上去"一切正常"，实际链路已停滞 3.4 天。

## 关键事实

- 限制统计的是 **UTF-8 字节**，不是字符数
- **中文注释每字 3 字节**，本仓库注释极多，极易踩线
- 限制的作用域是**单个 `run:` 块**，不是整个文件
- `run:` 键之外的 YAML 注释**不计入**

## 本测试的作用

在推送前 / CI 里拦住超限，避免再次出现"静默失效"。
"""

from pathlib import Path

import pytest

WORKFLOW = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "hds-cycle.yml"
)

HARD_LIMIT = 21000   # GitHub 硬限制，超了 workflow_dispatch 直接不可用
WARN_LIMIT = 18000   # 软告警线，留 3000 字节余量给后续维护


def _load_steps():
    yaml = pytest.importorskip("yaml")
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return wf["jobs"]["cycle"]["steps"]


def test_run_blocks_under_github_expression_limit():
    """每个 run: 块的 UTF-8 字节数必须 < 21000。"""
    steps = _load_steps()
    over, near = [], []
    for s in steps:
        run = s.get("run") or ""
        if not run:
            continue
        n = len(run.encode("utf-8"))
        name = s.get("name") or "?"
        if n > HARD_LIMIT:
            over.append((name, n))
        elif n > WARN_LIMIT:
            near.append((name, n))

    assert not over, (
        "以下 run: 块超过 GitHub 21000 字节限制，"
        "会导致 workflow_dispatch 返回 HTTP 422 完全不可用：\n"
        + "\n".join(f"  {name}: {n} 字节（超限 {n - HARD_LIMIT}）" for name, n in over)
        + "\n\n修复：把长注释移到 run: 键之外的 YAML 注释区（不计入限制）。"
    )

    if near:
        print(
            "\n[注意] 以下 run: 块已接近 21000 上限，"
            "下次追加中文注释前请先瘦身：\n"
            + "\n".join(f"  {name}: {n} 字节（余量 {HARD_LIMIT - n}）" for name, n in near)
        )


def test_workflow_expressions_are_balanced():
    """${{ 与 }} 必须配对，否则 GitHub 会把后续内容全部当成一个超长表达式。"""
    text = WORKFLOW.read_text(encoding="utf-8")
    opens, closes = text.count("${{"), text.count("}}")
    assert opens == closes, (
        f"表达式定界符不配对：${{{{ 出现 {opens} 次，}}}} 出现 {closes} 次。"
        f"未闭合会把后面全部内容算作一个表达式，直接触发 21000 上限。"
    )
    for i, line in enumerate(text.splitlines(), 1):
        if line.count("${{") != line.count("}}"):
            pytest.fail(f"第 {i} 行表达式跨行未闭合：{line.strip()[:120]}")


def test_workflow_dispatch_triggerable_by_size():
    """兜底断言：最大的 run 块要给 GitHub 留出插值后的余量。

    插值会把 ${{ }} 替换成实际值，通常远短于表达式原文，但若某个 run 块
    本身就贴着上限，插值后仍可能越界。这里用 18000 作为工程上的安全线。
    """
    steps = _load_steps()
    biggest = max(
        ((s.get("name") or "?", len((s.get("run") or "").encode("utf-8")))
         for s in steps if s.get("run")),
        key=lambda x: x[1],
        default=("无", 0),
    )
    name, size = biggest
    assert size < WARN_LIMIT, (
        f"最大的 run 块是 {name}（{size} 字节），已超过工程安全线 "
        f"{WARN_LIMIT}。建议拆分步骤或把脚本移到 .github/scripts/ 下。"
    )
