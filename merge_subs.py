#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""merge_subs.py — 把多个订阅源合并、去重成一个干净的 Clash 订阅 (s-clash.yaml)。

设计目标（方案 B：单合并工作流 + 保留自动更新）：
- 不再依赖 SubConverter / Docker，纯 Python（stdlib + pyyaml）完成转换，CI 更快更稳。
- 订阅源：
    * s.txt / s1.txt / s2.txt         —— 整文件 base64 编码的 vmess/vless/trojan/ss 等 URI 订阅
    * s2-clash-1.yaml / s2-clash-2.yaml —— fetch.py 直接产出的 Clash YAML（米贝77 / Datiya）
- 去重键：(type, server.lower(), port, 主密钥uuid/password, cipher)
- 输出：仅含 `proxies:` 列表的干净 Clash 订阅，兼容 v2rayN（Clash 类型）与 verify_cn。

用法：
    python merge_subs.py [--out s-clash.yaml]
依赖：
    pip install pyyaml
"""
import argparse
import base64
import json
import os
import re
import sys

import yaml
from urllib.parse import parse_qs, unquote

SCHEMES = (
    "vmess://", "vless://", "trojan://", "ss://", "ssr://",
    "hysteria2://", "hysteria://", "tuic://",
)

TXT_SOURCES = ["s.txt", "s1.txt", "s2.txt"]
YAML_SOURCES = ["s2-clash-1.yaml", "s2-clash-2.yaml"]


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #
def b64decode(s):
    """容错 base64 解码（自动补 =），失败返回 None。"""
    s = (s or "").strip()
    if not s:
        return None
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
    except Exception:
        return None


def decode_sub(text):
    """把订阅文本（整文件 base64 / 逐行 base64 / 明文 URI）还原成 URI 列表。"""
    text = (text or "").strip()
    uris = []

    # 1) 整文件 base64（s.txt/s1.txt/s2.txt 的实际形态）
    flat = text.replace("\n", "").replace("\r", "")
    whole = b64decode(flat)
    if whole and any(s in whole for s in SCHEMES):
        uris += [u for u in whole.splitlines() if u.strip()]

    # 2) 逐行：明文 URI 或 逐行 base64
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(SCHEMES):
            uris.append(line)
        else:
            d = b64decode(line)
            if d and d.startswith(SCHEMES):
                uris.append(d)

    # 去重（保持顺序）
    seen, out = set(), []
    for u in uris:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _split_uri(uri):
    """vmess://xxx 之外的 URI：返回 (scheme, body, qget, fragment)。"""
    m = re.match(r"^([a-zA-Z0-9]+)://(.+)$", uri)
    scheme = m.group(1)
    rest = m.group(2)
    frag = ""
    if "#" in rest:
        rest, frag = rest.rsplit("#", 1)
        frag = unquote(frag)
    if "?" in rest:
        body, q = rest.split("?", 1)
        qd = parse_qs(q)
    else:
        body, qd = rest, {}
    qget = lambda k: (qd.get(k, [""])[0] or "")  # noqa: E731
    return scheme, body, qget, frag


# --------------------------------------------------------------------------- #
# 各协议 URI -> Clash proxy dict
# --------------------------------------------------------------------------- #
def parse_vmess(uri):
    b = uri[len("vmess://"):]
    d = b64decode(b)
    if not d:
        return None
    try:
        j = json.loads(d)
    except Exception:
        return None
    node = {
        "name": (j.get("ps") or f"vmess_{j.get('add')}:{j.get('port') or 0}").strip(),
        "type": "vmess",
        "server": j.get("add"),
        "port": int(j.get("port") or 0),
        "uuid": j.get("id"),
        "alterId": int(str(j.get("aid", 0) or 0)),
        "cipher": j.get("scy") or "auto",
        "tls": (str(j.get("tls") or "").lower() == "tls"),
        "network": j.get("net") or "tcp",
    }
    if node["network"] == "ws":
        node["ws-opts"] = {
            "path": j.get("path") or "/",
            "headers": {"Host": j.get("host") or j.get("sni") or node["server"]},
        }
    if j.get("sni"):
        node["servername"] = j["sni"]
    return node


def parse_vless(uri):
    scheme, body, qget, frag = _split_uri(uri)
    if "@" not in body:
        return None
    user, hostport = body.split("@", 1)
    hp = hostport.rsplit(":", 1)
    server, port = hp[0], int(hp[1]) if len(hp) > 1 else 443
    security = qget("security") or "none"
    net = qget("type") or "tcp"
    node = {
        "name": (frag or f"vless_{server}:{port}").strip(),
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": user,
        "flow": qget("flow") or "",
        "tls": security in ("tls", "reality"),
        "network": net,
    }
    sni = qget("sni")
    if sni:
        node["sni"] = sni
        node["servername"] = sni
    if qget("allowInsecure") == "1" or qget("skip-cert-verify") == "true":
        node["skip-cert-verify"] = True
    if net == "ws":
        node["ws-opts"] = {
            "path": qget("path") or "/",
            "headers": {"Host": qget("host") or sni or server},
        }
    if security == "reality":
        node["reality-opts"] = {
            "public-key": qget("pbk"),
            "short-id": qget("sid") or "",
            "spider-x": qget("spx") or "",
        }
        if qget("fp"):
            node["client-fingerprint"] = qget("fp")
    return node


def parse_trojan(uri):
    scheme, body, qget, frag = _split_uri(uri)
    if "@" not in body:
        return None
    user, hostport = body.split("@", 1)
    hp = hostport.rsplit(":", 1)
    server, port = hp[0], int(hp[1]) if len(hp) > 1 else 443
    node = {
        "name": (frag or f"trojan_{server}:{port}").strip(),
        "type": "trojan",
        "server": server,
        "port": port,
        "password": unquote(user),
        "tls": True,
        "network": qget("type") or "tcp",
    }
    sni = qget("sni")
    if sni:
        node["sni"] = sni
    if qget("allowInsecure") == "1" or qget("skip-cert-verify") == "true":
        node["skip-cert-verify"] = True
    if node["network"] == "ws":
        node["ws-opts"] = {
            "path": qget("path") or "/",
            "headers": {"Host": qget("host") or sni or server},
        }
    return node


def parse_ss(uri):
    rest = uri[len("ss://"):]
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        frag = unquote(frag).strip()
    plugin = ""
    if "?plugin=" in rest:
        rest, plugin = rest.split("?plugin=", 1)
        plugin = unquote(plugin)
    if "@" in rest:
        userinfo, hostport = rest.split("@", 1)
        dec = b64decode(userinfo)
        if dec and ":" in dec and "@" not in dec:
            method, password = dec.split(":", 1)
        elif ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            return None
        hp = hostport.rsplit(":", 1)
        server, port = hp[0], int(hp[1]) if len(hp) > 1 else 0
    else:
        dec = b64decode(rest)
        if not dec or "@" not in dec:
            return None
        up, hostport = dec.rsplit("@", 1)
        method, password = up.split(":", 1)
        hp = hostport.rsplit(":", 1)
        server, port = hp[0], int(hp[1]) if len(hp) > 1 else 0
    node = {
        "name": frag or f"ss_{server}:{port}",
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
    }
    if plugin:
        node["plugin"] = plugin
    return node


def parse_ssr(uri):
    b = uri[len("ssr://"):]
    d = b64decode(b)
    if not d or "@" not in d:
        return None
    try:
        head, params = d.split("/", 1)
    except ValueError:
        head, params = d, ""
    try:
        user, hostport = head.split("@", 1)
        method, password = user.split(":", 1)
        hp = hostport.rsplit(":", 1)
        server, port = hp[0], int(hp[1])
    except Exception:
        return None
    node = {
        "name": f"ssr_{server}:{port}",
        "type": "ssr",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
        "protocol": "origin",
        "obfs": "plain",
    }
    return node


def parse_hy2(uri):
    scheme, body, qget, frag = _split_uri(uri)
    user, hostport = (body.split("@", 1) if "@" in body else ("", body))
    hp = hostport.rsplit(":", 1)
    server, port = hp[0], int(hp[1]) if len(hp) > 1 else 0
    node = {
        "name": (frag or f"hysteria2_{server}:{port}").strip(),
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": unquote(user) or qget("auth"),
    }
    sni = qget("sni")
    if sni:
        node["sni"] = sni
    if qget("insecure") == "1":
        node["skip-cert-verify"] = True
    return node


def parse_tuic(uri):
    scheme, body, qget, frag = _split_uri(uri)
    user, hostport = (body.split("@", 1) if "@" in body else ("", body))
    hp = hostport.rsplit(":", 1)
    server, port = hp[0], int(hp[1]) if len(hp) > 1 else 0
    node = {
        "name": (frag or f"tuic_{server}:{port}").strip(),
        "type": "tuic",
        "server": server,
        "port": port,
        "password": unquote(user),
        "uuid": qget("uuid"),
    }
    return node


PARSERS = {
    "vmess://": parse_vmess,
    "vless://": parse_vless,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "ssr://": parse_ssr,
    "hysteria2://": parse_hy2,
    "hysteria://": parse_hy2,
    "tuic://": parse_tuic,
}


def parse_uri(uri):
    uri = (uri or "").strip()
    for scheme, parser in PARSERS.items():
        if uri.startswith(scheme):
            try:
                return parser(uri)
            except Exception:
                return None
    return None


# --------------------------------------------------------------------------- #
# 合并 / 去重 / 写出
# --------------------------------------------------------------------------- #
def load_clash_yaml(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data.get("proxies", []) or []
    except FileNotFoundError:
        return []


def dedup_key(p):
    t = (p.get("type") or "").lower()
    server = (str(p.get("server") or "")).lower()
    port = int(p.get("port") or 0)
    secret = p.get("uuid") or p.get("password") or ""
    cipher = p.get("cipher") or ""
    return (t, server, port, secret, cipher)


def clean_node(p):
    """去掉空值与明显非字段键，保证产物干净。"""
    out = {}
    for k, v in p.items():
        if v is None or v == "":
            continue
        out[k] = v
    return out


def make_names_unique(nodes):
    """兜底确保 name 唯一：同名重复追加 _2/_3/...，并把空名回填为可读默认。

    触发场景：某些订阅源 URI 不带 #fragment，导致多个不同节点被解析为同一默认名
    （如 "ss"），下游 Clash/Clash Verge 校验会因 duplicate name 拒绝加载。
    """
    counts = {}
    for n in nodes:
        name = (n.get("name") or "").strip()
        if not name:
            name = f"{n.get('type', 'node')}_{n.get('server', '')}:{n.get('port', 0)}"
            n["name"] = name
        if name in counts:
            counts[name] += 1
            n["name"] = f"{name}_{counts[name]}"
        else:
            counts[name] = 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="s-clash.yaml")
    ap.add_argument("--base", default=os.getcwd())
    args = ap.parse_args()

    base = args.base
    nodes = []

    # 1) 订阅文本（base64）
    for fn in TXT_SOURCES:
        p = os.path.join(base, fn)
        if not os.path.exists(p):
            print(f"[merge] 跳过缺失源: {fn}")
            continue
        text = open(p, encoding="utf-8", errors="replace").read()
        for uri in decode_sub(text):
            nd = parse_uri(uri)
            if nd and nd.get("server"):
                nodes.append(nd)

    # 2) 直接产出的 Clash YAML
    for fn in YAML_SOURCES:
        p = os.path.join(base, fn)
        for nd in load_clash_yaml(p):
            if isinstance(nd, dict) and nd.get("server"):
                nodes.append(nd)

    # 3) 去重
    seen, merged = set(), []
    for n in nodes:
        k = dedup_key(n)
        if not k[1]:  # 无 server 作废
            continue
        if k in seen:
            continue
        seen.add(k)
        merged.append(clean_node(n))

    # 4) name 唯一化（兜底：处理默认名冲突，保证 Clash/Clash Verge 校验通过）
    make_names_unique(merged)

    # 5) 稳定排序（便于 diff）
    merged.sort(key=lambda n: (n.get("type", ""), n.get("server", ""), int(n.get("port") or 0)))

    # 6) 写出（仅 proxies 列表，兼容 v2rayN 与 verify_cn）
    # 注意：header 只放注释，proxies: 由下方 dump 产出，避免重复 key。
    header = (
        "# Auto-merged subscription (mkdy)\n"
        f"# sources: {', '.join(TXT_SOURCES)} + {', '.join(YAML_SOURCES)}\n"
        f"# raw={len(nodes)} unique={len(merged)}\n"
    )
    body = yaml.safe_dump(
        {"proxies": merged},
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    out_path = os.path.join(base, args.out)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header)
        # 重新缩进 proxies 下的序列项，确保兼容性
        lines = body.splitlines()
        final = []
        for i, ln in enumerate(lines):
            if i == 0 and ln == "proxies:":
                final.append(ln)
            elif ln.startswith("- "):
                final.append("  " + ln)
            else:
                # 续行（属于上一个列表项）保持 4 格缩进
                final.append("  " + ln if ln else ln)
        f.write("\n".join(final) + "\n")

    print(f"[merge] 原始 {len(nodes)} 条 -> 去重后 {len(merged)} 条 -> {args.out}")


if __name__ == "__main__":
    main()
