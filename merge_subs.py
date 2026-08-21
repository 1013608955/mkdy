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
import logging

import yaml
from urllib.parse import parse_qs, unquote
from name_util import make_proxy_names_unique as make_names_unique
from node_parse import parse_uri_to_struct, struct_to_uri  # H1: 统一解析器 + 反向转换

# 统一日志：与 update_nodes.init_logger 风格一致（格式/级别），便于后续集中采集
def _init_logger():
    logger = logging.getLogger("merge_subs")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        handler = logging.StreamHandler()
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    return logger


LOG = _init_logger()

SCHEMES = (
    "vmess://", "vless://", "trojan://", "ss://", "ssr://",
    "hysteria2://", "hysteria://", "tuic://",
)

TXT_SOURCES = ["s.txt", "s1.txt", "s2.txt"]
YAML_SOURCES = ["s2-clash-1.yaml", "s2-clash-2.yaml"]
# 已验证节点快照（中国出口验证通过的节点），由 verify-tag.yml 每次 CI 刷新。
# 在生成 s-clash.yaml 前去重阶段优先并入，使产物与 s-verified.yaml 最新内容同步。
VERIFIED_SOURCE = "s-verified.yaml"


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


def write_txt(txt_out, merged):
    """写出 s-clash.txt（v2rayN 兼容订阅格式，每行一个 URI）。
    目录不存在时自动创建，与 --out 的 yaml 同源同前缀。"""
    os.makedirs(os.path.dirname(txt_out) or ".", exist_ok=True)
    lines = []
    for nd in merged:
        uri = struct_to_uri(nd)
        if uri:
            lines.append(uri)
    with open(txt_out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    LOG.info(f"[merge] 写出 {len(lines)} 条 URI -> {txt_out}")


# make_names_unique 已抽到 name_util.py（见顶部 import 别名为 make_names_unique）。


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="s-clash.yaml")
    ap.add_argument("--base", default=os.getcwd())
    args = ap.parse_args()

    base = args.base
    nodes = []

    # 0) 优先并入"已验证节点"快照（s-verified.yaml，每次 CI 由 verify-tag 刷新）
    #    放在最前：去重时优先保留 verified 的完整配置（含 tls/reality 等），
    #    后续相同节点（server/port/uuid 一致）会被跳过而不覆盖 => 不丢字段。
    #    与下游统一去重配合 => 最终 s-clash.yaml 既无重复、又与 s-verified 最新内容同步。
    vpath = os.path.join(base, VERIFIED_SOURCE)
    n_verified = 0
    for nd in load_clash_yaml(vpath):
        if isinstance(nd, dict) and nd.get("server"):
            nodes.append(nd)
            n_verified += 1
    if n_verified:
        LOG.info(f"[merge] 从 {VERIFIED_SOURCE} 并入 {n_verified} 条已验证节点（优先）")

    # 1) 订阅文本（base64）
    for fn in TXT_SOURCES:
        p = os.path.join(base, fn)
        if not os.path.exists(p):
            LOG.info(f"[merge] 跳过缺失源: {fn}")
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
    #    统一基于 --out 计算 yaml / txt 输出路径：同源目录、同名前缀，目录自动创建，
    #    避免此前 txt 固定落在 --base 根导致的语义不对称 / --out 带子目录时 FileNotFoundError。
    out_path = os.path.join(base, args.out)
    out_base = os.path.dirname(out_path) or base
    out_stem = os.path.splitext(os.path.basename(args.out))[0] or "s-clash"
    txt_out = os.path.join(out_base, out_stem + ".txt")
    os.makedirs(out_base, exist_ok=True)

    template_path = os.path.join(base, "clash_template.yaml")
    if not os.path.exists(template_path):
        LOG.warning(f"[merge][WARN] 模版文件 {template_path} 不存在，退化为仅 proxies 输出")
        body = yaml.safe_dump({"proxies": merged}, allow_unicode=True, sort_keys=False, default_flow_style=False)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(body)
        LOG.info(f"[merge] 原始 {len(nodes)} 条 -> 去重后 {len(merged)} 条 -> {args.out} (无模版)")
        write_txt(txt_out, merged)  # 无模版时仍产出 v2rayN 兼容 txt，保持两产物对称
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
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False, default_flow_style=False, width=10000)

    LOG.info(f"[merge] 原始 {len(nodes)} 条 -> 去重后 {len(merged)} 条 -> {args.out} (含规则层)")
    write_txt(txt_out, merged)


if __name__ == "__main__":
    main()
