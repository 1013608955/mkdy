"""source_health.py — 订阅源健康状态共享模块（update_nodes.py 与 fetch_extra.py 共用）。

状态持久于仓库根 source_health.json，CI 每轮随产物提交、跨轮生效：
- 某源连续失败 ≥ threshold 次 → 「禁赛」，不再每轮请求；
- 禁赛源每 probe_hours 小时自动试探一次（冷却探活自愈），成功即清零回归。

记录格式（按 url 索引）：
    {"consecutive_failures": int, "last_ok": str, "last_fail": str, "last_probe": str, "nodes": int}

2026-09-08 审查 Q-1：原 update_nodes / fetch_extra 各持一份同构实现，
策略调整需改两处，抽成本模块统一语义。
"""
import calendar
import json
import os
import time
from typing import Dict, Tuple

DEFAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "source_health.json")


def load(path: str = DEFAULT_FILE) -> Dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 — 状态文件缺失/损坏都从空开始，不阻断抓取
        return {}


def save(health: Dict, path: str = DEFAULT_FILE) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(health, f, ensure_ascii=False, indent=1, sort_keys=True)
    except OSError as e:
        print(f"[warn] 源健康状态写入失败: {str(e)[:60]}")


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def ts(s: str) -> float:
    """UTC 时间串 -> epoch 秒；解析失败返回 0（视为冷却已满，允许探活）。"""
    try:
        return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:  # noqa: BLE001
        return 0.0


def judge(health: Dict, url: str, threshold: int, probe_hours: float) -> Tuple[str, int]:
    """判定本 URL 本轮的动作。
    返回 (action, consecutive_failures)，action ∈ {"active", "probe", "skip"}：
      active — 正常拉取；
      probe  — 禁赛冷却期满，本轮试探性重试（已把 last_probe 戳写进 health，随 save 落盘）；
      skip   — 禁赛中且冷却未满，本轮跳过请求。
    """
    n = int((health.get(url) or {}).get("consecutive_failures", 0))
    if n < threshold:
        return "active", n
    last_probe = str((health.get(url) or {}).get("last_probe") or "")
    if (time.time() - ts(last_probe)) >= probe_hours * 3600:
        health.setdefault(url, {})["last_probe"] = now()
        return "probe", n
    return "skip", n


def record_success(health: Dict, url: str, nodes: int) -> bool:
    """拉取成功：清零计数、记 last_ok/节点数、清探活戳。返回此前是否处于禁赛（供日志）。"""
    rec = health.get(url) or {}
    was_benched = bool(rec.get("consecutive_failures"))
    health[url] = {"consecutive_failures": 0, "last_ok": now(), "nodes": nodes}
    health[url].pop("last_probe", None)
    return was_benched


def record_failure(health: Dict, url: str, threshold: int, probing: bool) -> int:
    """拉取失败：普通失败计数 +1；探活失败保持禁赛（计数不超阈值）并刷新冷却。
    返回更新后的连续失败次数（供日志）。"""
    rec = health.get(url) or {}
    if probing:
        rec["consecutive_failures"] = max(int(rec.get("consecutive_failures", 0)), threshold)
        rec["last_probe"] = now()
    else:
        rec["consecutive_failures"] = int(rec.get("consecutive_failures", 0)) + 1
    rec["last_fail"] = now()
    health[url] = rec
    return int(rec["consecutive_failures"])
