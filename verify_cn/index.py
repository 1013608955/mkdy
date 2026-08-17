# ⚠️ DEPRECATED — 本文件（阿里云/腾讯云 FC 函数路线）已被 verify_cn/run_local.py（mihomo 真链探测）取代，仅留作历史参考，请勿在新流程中使用。
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
import urllib.request
import urllib.error
import traceback

from verify_proxy_core import parse_clash_yaml, verify_through_proxy

OWNER = os.environ.get("GITHUB_OWNER", "1013608955")
REPO = os.environ.get("GITHUB_REPO", "mkdy")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
NODE_URL = os.environ.get(
    "NODE_SOURCE_URL",
    f"https://raw.githubusercontent.com/{OWNER}/{REPO}/main/s-clash.yaml",
)
TARGET = os.environ.get("TARGET_URL", "https://www.google.com/generate_204")
# 兜底目标：google 单点可能被节点侧/特定 CDN 拦，任一能通即算节点可用，
# 更贴近“客户端能上网”的判定（避免 google 单点误杀可用节点）。
FALLBACK_TARGETS = [
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.ipify.org?format=json",
]
XRAY = os.environ.get("XRAY_BIN", "/code/xray")
CONCURRENCY = int(os.environ.get("CONCURRENCY", "8"))
# 默认 8s（按用户要求改回；FC 函数超时 600s 余量充足）。
# 注：15s 仍可由 env TIMEOUT 覆盖；多目标兜底+阿里DNS已保留以降误杀。
TIMEOUT = int(os.environ.get("TIMEOUT", "8"))
API = "https://api.github.com"
HEADERS = {"User-Agent": "Mozilla/5.0 (verify-cn)"}
# 节点源拉取超时（独立于节点验证 TIMEOUT）：raw.githubusercontent.com 在中国大陆
# 常被墙/极慢，命中后会等到超时再切镜像；20s 是“可达则快、不可达不过久等”的折中。
NODE_FETCH_TIMEOUT = int(os.environ.get("NODE_FETCH_TIMEOUT", "20"))


def _ensure_xray_executable():
    """FC 上传的二进制在 Linux 上可能丢失可执行位，运行时补上；Windows 忽略。"""
    try:
        if os.path.exists(XRAY):
            os.chmod(XRAY, 0o755)
    except OSError:
        pass


def _verify_one(node):
    """对单节点依次尝试 主目标 + 兜底目标，任一通即算 ok。
    返回里 detail 标注命中哪个目标（便于事后审计误杀）。"""
    targets = [TARGET] + FALLBACK_TARGETS
    primary_err = None
    for i, t in enumerate(targets):
        ok, lat, det = verify_through_proxy(node, t, TIMEOUT, XRAY)
        if i == 0:
            primary_err = det
        if ok:
            return {"name": node.get("name"), "proto": node.get("proto"),
                    "ok": True, "latency": round(lat, 3),
                    "detail": f"ok via {t} ({det})"}
    # 全部目标失败：保留主目标(google)的错误做头条，便于区分“彻底死”vs“仅 google 不通”
    return {"name": node.get("name"), "proto": node.get("proto"),
            "ok": False, "latency": 0.0,
            "detail": f"all_targets_fail(primary={primary_err})"}


def _http_get(url, timeout=20, headers=None):
    """标准库 HTTP GET。"""
    hdrs = dict(HEADERS)
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read().decode("utf-8", errors="replace")


def _http_put(url, data, headers=None):
    """标准库 HTTP PUT。"""
    hdrs = dict(HEADERS)
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method="PUT")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.getcode()


def commit_verified_json(owner, repo, token, verified):
    """把 verified.json PUT 回仓库（GitHub Contents API）。"""
    path = "verify_cn/verified.json"
    url = f"{API}/repos/{owner}/{repo}/contents/{path}"
    headers = {"Authorization": f"token {token}",
               "Accept": "application/vnd.github+json"}
    sha = None
    try:
        code, txt = _http_get(url, headers=headers)
        if code == 200:
            sha = json.loads(txt).get("sha")
    except (urllib.error.HTTPError, urllib.error.URLError):
        pass
    content = base64.b64encode(
        json.dumps(verified, ensure_ascii=False).encode("utf-8")).decode("ascii")
    body = {"message": f"verify: {verified['ok']}/{verified['count']} nodes ok",
            "content": content}
    if sha:
        body["sha"] = sha
    data = json.dumps(body).encode("utf-8")
    return _http_put(url, data, headers={"Content-Type": "application/json", **headers})


def _fetch_node_source():
    """拉取节点源，带镜像兜底。FC 在中国大陆，直连 raw.githubusercontent.com
    常被墙/超时（GFW 对 raw.github 不稳定），故依次尝试 原URL + ghproxy /
    gitmirror / jsDelivr 镜像，返回首个可用的 YAML 文本；每个候选都做
    “是否像节点订阅”的 sanity 校验，避免把镜像的错误页当成节点源。"""
    candidates = [NODE_URL]
    if "raw.githubusercontent.com" in NODE_URL:
        candidates += [
            f"https://ghproxy.net/{NODE_URL}",
            NODE_URL.replace("raw.githubusercontent.com", "raw.gitmirror.com"),
            NODE_URL.replace("raw.githubusercontent.com", "raw.kkgithub.com"),
            f"https://cdn.jsdelivr.net/gh/{OWNER}/{REPO}@main/s-clash.yaml",
        ]
    last_err = None
    for url in candidates:
        try:
            code, txt = _http_get(url, timeout=NODE_FETCH_TIMEOUT)
            if code >= 400:
                last_err = f"HTTP {code} @ {url}"
                continue
            _ok = ("proxies:" in txt) or any(
                s in txt for s in ("vmess://", "vless://", "trojan://", "ss://", "hysteria"))
            if not _ok:
                print(f"[verify] ⚠️ {url} 返回内容不像节点订阅，跳过")
                continue
            print(f"[verify] 节点源拉取成功：{url} ({len(txt)} bytes)")
            return txt
        except Exception as e:
            last_err = f"{type(e).__name__}: {e} @ {url}"
            print(f"[verify] 节点源拉取失败 {url}: {e}")
    raise RuntimeError(
        f"[verify] 所有节点源候选均失败（末错：{last_err}）；"
        f"raw.githubusercontent.com 在中国大陆常被墙，可在 FC 环境变量 "
        f"NODE_SOURCE_URL 直接改为镜像地址（如 https://ghproxy.net/...）"
    )


def handler(event, context):
    # 整体包一层 try/except：FC 默认对未捕获异常只显示“返回结果为空”，
    # 无法定位真因。改为返回带 traceback 的 JSON，便于下次直接看到失败点。
    try:
        _ensure_xray_executable()
        txt = _fetch_node_source()
        nodes = parse_clash_yaml(txt)
        if not nodes:
            return {"error": "解析节点源得到 0 个节点（节点源为空或格式异常）",
                    "ok": 0, "count": 0}
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
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[verify][ERROR]\n{tb}")
        return {"error": str(e), "traceback": tb, "ok": 0, "count": 0}
