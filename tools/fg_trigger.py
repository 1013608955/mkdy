#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FunctionGraph 定时触发器：每 15 分钟调 GitHub API 触发 hds-cycle。

- 纯 Python stdlib（urllib），华为云 Python 3.10 事件函数，入口 handler。
- 环境变量：GITHUB_PAT（fine-grained，仅需 mkdy 仓库 Actions: Write）。
- 超时 10s + 失败重试 2 次（间隔 3s）；全部失败仅打印日志（该轮丢弃，
  下轮照常；每小时 schedule 兜底仍在）。
"""

import json
import os
import time
import urllib.error
import urllib.request

API = ("https://api.github.com/repos/1013608955/mkdy/actions/"
       "workflows/hds-cycle.yml/dispatches")


def _dispatch_once(token: str) -> int:
    """单次尝试，返回 HTTP 状态码（2xx 视为成功）。"""
    body = json.dumps({
        "ref": "main",
        "inputs": {"action": "wake_verify"},
    }).encode()
    req = urllib.request.Request(
        API, data=body, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "mkdy-fg-trigger",
        })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        # GitHub 对 dispatch 成功返回 204 No Content；其他状态码视为失败
        return e.code
    except Exception as e:  # noqa: BLE001 — 网络/DNS/超时统一按重试处理
        print(f"[warn] request error: {e}")
        return 0


def handler(event, context):  # FunctionGraph 入口
    token = os.environ.get("GITHUB_PAT", "")
    if not token:
        print("[FATAL] 未配置环境变量 GITHUB_PAT")
        return {"statusCode": 500, "body": "missing GITHUB_PAT"}

    last = 0
    for attempt in range(1, 4):
        last = _dispatch_once(token)
        if 200 <= last < 300:
            print(f"[ok] attempt{attempt}: HTTP {last}，hds-cycle 已触发")
            return {"statusCode": 200, "body": "dispatched"}
        print(f"[retry] attempt{attempt}: HTTP {last}")
        time.sleep(3)

    print(f"[ERROR] 3 次均失败（最后 HTTP {last}）；本轮放弃，等待下一周期。"
          f"（GitHub 每小时 schedule 兜底不受影响）")
    return {"statusCode": 502, "body": f"dispatch failed: {last}"}
