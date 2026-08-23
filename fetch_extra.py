#!/usr/bin/env python3
"""fetch_extra.py — 拉取「直连 Clash YAML」型订阅（非文章抓取站、非 URI 列表）。

特性：
- 每个源下载后校验能解析出 proxies 并做 name 唯一化（防 mihomo duplicate fatal）。
- 连续失败自动跳过 + 冷却探活自愈：某源连续失败 ≥ THRESHOLD 次（跨 CI 轮次
  持久，状态存仓库根 source_health.json 并随产物一起提交）则进入禁赛、不再
  每轮请求；但每 PROBE_INTERVAL 小时自动试探一次，成功即清零回归、失败刷新
  冷却继续禁赛——临时挂掉的源无需人工干预即可自愈。阈值/间隔可用参数调整。
"""
import argparse
import json
import os
import time

import requests
import yaml

from name_util import make_proxy_names_unique

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
}
TIMEOUT = 25
HERE = os.path.dirname(os.path.abspath(__file__))
HEALTH_FILE = os.path.join(HERE, "source_health.json")

# 直连 Clash YAML 订阅清单：(订阅URL, 产物文件名)
# 产物文件名须已登记进 merge_subs.YAML_SOURCES。
EXTRA_SUBS = [
    ("https://8.88888888.indevs.in/sub/rvebQ1qJ", "s2-clash-3.yaml"),
    ("https://8.88888888.indevs.in/sub/6p8FyJ7M", "s2-clash-4.yaml"),
    ("https://8.88888888.indevs.in/sub/XqN5mHbL", "s2-clash-5.yaml"),
    ("https://8.88888888.indevs.in/sub/QAyCEpmj", "s2-clash-6.yaml"),
]


def _load_health():
    try:
        with open(HEALTH_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_health(health):
    try:
        with open(HEALTH_FILE, "w", encoding="utf-8") as f:
            json.dump(health, f, ensure_ascii=False, indent=1, sort_keys=True)
    except OSError as e:
        print(f"[warn] 健康状态写入失败: {str(e)[:60]}")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ts(s):
    """UTC 时间串 -> epoch 秒；解析失败返回 0（视为冷却已满，允许探活）。"""
    try:
        import calendar
        return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:  # noqa: BLE001
        return 0


def fetch_one(url, out_file):
    """下载并校验单个 YAML 订阅，成功返回节点数。任何异常向上抛。"""
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    resp.raise_for_status()
    doc = yaml.safe_load(resp.text) or {}
    proxies = doc.get("proxies") or []
    if not isinstance(proxies, list) or not proxies:
        raise ValueError("响应中无 proxies 或为空")
    make_proxy_names_unique(proxies)
    doc["proxies"] = proxies
    with open(out_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False,
                       default_flow_style=False)
    return len(proxies)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=5,
                    help="连续失败多少次后跳过该源（默认5，约5小时）")
    ap.add_argument("--probe-interval-hours", type=float, default=24,
                    help="禁赛源的冷却探活间隔（默认24小时试一次）")
    args = ap.parse_args()

    health = _load_health()
    ok_cnt = 0
    for url, out_file in EXTRA_SUBS:
        rec = health.get(url) or {}
        n_fail = int(rec.get("consecutive_failures", 0))
        benched = n_fail >= args.threshold
        if benched:
            # 冷却探活：禁赛源每 probe_interval 小时自动试探一次，成功即回归
            last_probe = str(rec.get("last_probe") or "")
            due = (time.time() - _ts(last_probe)) >= args.probe_interval_hours * 3600
            if not due:
                print(f"[bench] {url} 禁赛中（连续失败 {n_fail} 次），"
                      f"{args.probe_interval_hours:.0f}h 冷却后自动探活")
                continue
            print(f"[probe] {url} 冷却期满，本轮试探性重试...")
        try:
            cnt = fetch_one(url, out_file)
            if n_fail:
                tag = "探活成功，恢复可用" if benched else "恢复可用"
                print(f"[recover] {url} {tag}（此前连续失败 {n_fail} 次）")
            health[url] = {"consecutive_failures": 0,
                           "last_ok": _now(), "nodes": cnt}
            health[url].pop("last_probe", None)
            ok_cnt += 1
            print(f"[ok] {out_file} <- {cnt} 节点")
        except Exception as e:  # noqa: BLE001
            if benched:
                # 探活失败：保持禁赛（计数不涨），刷新冷却计时
                rec["consecutive_failures"] = max(n_fail, args.threshold)
                rec["last_probe"] = _now()
                rec["last_fail"] = _now()
                health[url] = rec
                print(f"[probe-fail] {url}: {str(e)[:80]}，继续禁赛，"
                      f"{args.probe_interval_hours:.0f}h 后再探")
            else:
                rec["consecutive_failures"] = n_fail + 1
                rec["last_fail"] = _now()
                health[url] = rec
                print(f"[fail] {url}: {str(e)[:80]} "
                      f"(连续失败 {rec['consecutive_failures']}/{args.threshold})")

    _save_health(health)
    print(f"[done] 本轮成功 {ok_cnt}/{len(EXTRA_SUBS)} 个直连 YAML 源")


if __name__ == "__main__":
    main()
