"""index.py — 阿里云 FC 入口（也可用于腾讯云 SCF，只需改 handler 签名）。

流程：
1. 从 NODE_SOURCE_URL 拉取节点列表（默认读仓库里的 s-clash.yaml 原始文件）。
2. 在中国出口并发跑 verify_through_proxy（需自备 xray 二进制）。
3. 生成 verified.json 并写回仓库（用最小权限 fine-grained PAT）。
"""
import os
import time
import json
import base64
import concurrent.futures

import requests

from verify_proxy_core import parse_clash_yaml, verify_through_proxy

OWNER = os.environ.get("GITHUB_OWNER", "1013608955")
REPO = os.environ.get("GITHUB_REPO", "mkdy")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
NODE_URL = os.environ.get(
    "NODE_SOURCE_URL",
    f"https://raw.githubusercontent.com/{OWNER}/{REPO}/main/s-clash.yaml",
)
TARGET = os.environ.get("TARGET_URL", "https://www.google.com/generate_204")
XRAY = os.environ.get("XRAY_BIN", "/code/xray")
CONCURRENCY = int(os.environ.get("CONCURRENCY", "8"))
TIMEOUT = int(os.environ.get("TIMEOUT", "8"))
API = "https://api.github.com"


def _ensure_xray_executable():
    """FC 上传的二进制在 Linux 上可能丢失可执行位，运行时补上；Windows 忽略。"""
    try:
        if os.path.exists(XRAY):
            os.chmod(XRAY, 0o755)
    except OSError:
        pass


def _verify_one(node):
    ok, lat, det = verify_through_proxy(node, TARGET, TIMEOUT, XRAY)
    return {"name": node.get("name"), "proto": node.get("proto"),
            "ok": ok, "latency": round(lat, 3), "detail": det}


def commit_verified_json(owner, repo, token, verified):
    """把 verified.json PUT 回仓库（GitHub Contents API）。"""
    path = "verify_cn/verified.json"
    url = f"{API}/repos/{owner}/{repo}/contents/{path}"
    headers = {"Authorization": f"token {token}",
               "Accept": "application/vnd.github+json"}
    sha = None
    try:
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            sha = r.json().get("sha")
    except requests.RequestException:
        pass
    content = base64.b64encode(
        json.dumps(verified, ensure_ascii=False).encode("utf-8")).decode("ascii")
    body = {"message": f"verify: {verified['ok']}/{verified['count']} nodes ok",
            "content": content}
    if sha:
        body["sha"] = sha
    r = requests.put(url, headers=headers, json=body, timeout=20)
    return r.status_code


def handler(event, context):
    _ensure_xray_executable()
    r = requests.get(NODE_URL, timeout=30)
    r.raise_for_status()
    txt = r.text
    # 最小 sanity：确认返回内容确为节点订阅，避免把 GitHub 的 HTML 错误页
    # （404/502 等）静默当成节点源、产出空 verified.json 还报“成功”。
    _looks_like_nodes = ("proxies:" in txt) or any(
        s in txt for s in ("vmess://", "vless://", "trojan://", "ss://", "hysteria")
    )
    if not _looks_like_nodes:
        raise RuntimeError(
            f"[verify] NODE_SOURCE_URL 返回内容不像节点订阅 "
            f"(HTTP {r.status_code}, len={len(txt)}); 中止以免静默空验"
        )
    nodes = parse_clash_yaml(txt)
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        results = list(ex.map(_verify_one, nodes))
    verified = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": TARGET,
        "count": len(results),
        "ok": sum(1 for r in results if r["ok"]),
        "nodes": results,
    }
    if TOKEN:
        code = commit_verified_json(OWNER, REPO, TOKEN, verified)
        print(f"[verify] committed verified.json -> HTTP {code}")
    # 控制台日志可自诊断：打印失败原因分布
    from collections import Counter
    dc = Counter(r["detail"] for r in results)
    print(f"[verify] {verified['ok']}/{len(results)} ok; "
          f"target={TARGET}; details=" + "; ".join(f"{k}×{v}" for k, v in dc.most_common()))
    return {"nodes": len(results), "ok": verified["ok"]}
