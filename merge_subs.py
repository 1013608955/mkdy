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
from name_util import make_proxy_names_unique as make_names_unique
from node_parse import parse_uri_to_struct  # H1: 统一解析器

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


# --------------------------------------------------------------------------- #
# 各协议 URI -> Clash proxy dict（H1：统一由 node_parse.parse_uri_to_struct 解析）
# --------------------------------------------------------------------------- #
def parse_uri(uri):
    """解析单个订阅 URI 为 Clash proxy dict；未知/失败返回 None。"""
    return parse_uri_to_struct(uri)
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


# make_names_unique 已抽到 name_util.py（见顶部 import 别名为 make_names_unique）。


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

    # 6) 写出（完整 Clash 配置：mode + dns + proxies + proxy-groups + rules）
    #    加载 clash_template.yaml 模版，把 __ALL_PROXIES__ 占位符替换为实际节点名，
    #    使 s-clash.yaml 成为可直接导入 Clash/Clash Verge 的完整配置（不再是裸 proxies 列表）。
    template_path = os.path.join(base, "clash_template.yaml")
    if not os.path.exists(template_path):
        print(f"[merge][WARN] 模版文件 {template_path} 不存在，退化为仅 proxies 输出", file=sys.stderr)
        body = yaml.safe_dump({"proxies": merged}, allow_unicode=True, sort_keys=False, default_flow_style=False)
        out_path = os.path.join(base, args.out)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(body)
        print(f"[merge] 原始 {len(nodes)} 条 -> 去重后 {len(merged)} 条 -> {args.out} (无模版)")
        return

    with open(template_path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    # 注入实际节点
    all_names = [p["name"] for p in merged]
    doc["proxies"] = merged

    # 把 proxy-groups 里的 __ALL_PROXIES__ 占位符展开为全部节点名
    for g in doc.get("proxy-groups", []) or []:
        plist = g.get("proxies")
        if isinstance(plist, list):
            new_list = []
            for item in plist:
                if item == "__ALL_PROXIES__":
                    new_list.extend(all_names)
                else:
                    new_list.append(item)
            g["proxies"] = new_list

    header = (
        "# Auto-merged subscription (mkdy) — full Clash config with rules\n"
        f"# sources: {', '.join(TXT_SOURCES)} + {', '.join(YAML_SOURCES)}\n"
        f"# raw={len(nodes)} unique={len(merged)} groups={len(doc.get('proxy-groups', []))} rules={len(doc.get('rules', []))}\n"
    )
    out_path = os.path.join(base, args.out)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False, default_flow_style=False, width=10000)

    print(f"[merge] 原始 {len(nodes)} 条 -> 去重后 {len(merged)} 条 -> {args.out} (含规则层)")


if __name__ == "__main__":
    main()
