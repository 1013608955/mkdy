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
# s2-clash-1/2: fetch.py（米贝77/Datiya 文章抓取）
# s2-clash-3..6: fetch_extra.py（直连 Clash YAML 订阅，含连续失败自动跳过）
YAML_SOURCES = ["s2-clash-1.yaml", "s2-clash-2.yaml",
                "s2-clash-3.yaml", "s2-clash-4.yaml",
                "s2-clash-5.yaml", "s2-clash-6.yaml"]
# 方案 A：已验证节点直接来自 verify_cn/verified.json（验证器已携带完整 proxy dict），
# 不再依赖 verify-tag.yml 用 'name' 去 s-clash.yaml 重新 join（那是漂移根因）。
# merge_subs 读取 ok 节点的完整 proxy，一步产出 s-verified.yaml，彻底去掉打标环节。
VERIFIED_SOURCE = "verify_cn/verified.json"
VERIFIED_OUT = "s-verified.yaml"
VERIFIED_MARK = "✅ "  # 与历史 s-verified.yaml 客户端消费方式保持一致


def load_verified_proxies(path, name_index=None):
    """读 verify_cn/verified.json，返回验证通过的完整 proxy dict 列表（已加 ✅ 前缀）。

    方案 A：验证器在 nodes[i]['proxy'] 里存了完整节点配置，这里直接取用，
    用 (type,server,port) 兜底去重，不再依赖节点名字符串匹配，根除漂移。

    过渡兼容（name_index）：旧版 verified.json 不含 proxy 字段时，
    回退用节点名去 name_index（全量节点）取完整配置，避免迁移期节点丢失；
    新版验证器一跑即转纯方案 A 路径，name_index 不再被用到。
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f) or {}
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    out = []
    seen = set()
    fallback_used = 0
    for nd in data.get("nodes", []) or []:
        if not nd.get("ok"):
            continue
        name = nd.get("name", "")
        proxy = nd.get("proxy")
        if not isinstance(proxy, dict) or not proxy.get("server"):
            # 旧格式降级：用 name 去全量节点里找完整配置
            if name_index and name in name_index:
                proxy = name_index[name]
                fallback_used += 1
            else:
                continue
        if not isinstance(proxy, dict) or not proxy.get("server"):
            continue
        k = (str(proxy.get("type", "")).lower(),
             str(proxy.get("server", "")).lower(),
             int(proxy.get("port") or 0))
        if k in seen:
            continue
        seen.add(k)
        p = dict(proxy)
        # 加 ✅ 前缀标记（若已存在则跳过，避免重复前缀累积）
        pname = p.get("name", "")
        if not pname.startswith(VERIFIED_MARK):
            p["name"] = VERIFIED_MARK + pname
        out.append(p)
    if fallback_used:
        LOG.warning(f"[merge][WARN] {fallback_used} 条节点走了旧格式降级匹配（name_index），"
                    f"配置可能来自上一轮产物而非本轮验证；容器跑出新版 run_local 后此路径自动退出")
    return out


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


def write_verified_txt(txt_out, verified_nodes):
    """写出 s-verified.txt（已验证节点的 v2rayN 兼容订阅）。
    P0-2：方案 A 删除打标环节后此产物一度缺失，而 CI 的 git add 仍引用它；
    这里与 s-clash.txt 对称地产出，保持两套产物完整。"""
    os.makedirs(os.path.dirname(txt_out) or ".", exist_ok=True)
    lines = []
    for nd in verified_nodes:
        uri = struct_to_uri(nd)
        if uri:
            lines.append(uri)
    with open(txt_out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    LOG.info(f"[merge] 写出 {len(lines)} 条已验证 URI -> {txt_out}")


def write_verified(out_base, base, verified_nodes):
    """方案 A：单独产出 s-verified.yaml（仅含中国出口验证通过的节点）。

    入参 verified_nodes 由 main 统一计算（含旧格式 name 降级），
    独立于全量 s-clash.yaml 的去重/排序，避免打标环节的 name 漂移。
    无模版时退化为裸 proxies 输出。
    """
    if not verified_nodes:
        LOG.info(f"[merge] 无已验证节点，跳过 {VERIFIED_OUT}")
        return
    out_path = os.path.join(out_base, VERIFIED_OUT)
    os.makedirs(out_base, exist_ok=True)
    template_path = os.path.join(base, "clash_template.yaml")
    if not os.path.exists(template_path):
        with open(out_path, "w", encoding="utf-8") as f:
            yaml.safe_dump({"proxies": verified_nodes}, allow_unicode=True,
                           sort_keys=False, default_flow_style=False)
        LOG.info(f"[merge] 写出 {len(verified_nodes)} 条已验证节点 -> {VERIFIED_OUT} (无模版)")
        write_verified_txt(os.path.splitext(out_path)[0] + ".txt", verified_nodes)
        return
    with open(template_path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    all_names = [p["name"] for p in verified_nodes]
    doc["proxies"] = verified_nodes
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
        "# Auto-merged verified subscription (mkdy) — 中国出口验证通过节点\n"
        f"# verified={len(verified_nodes)}\n"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False, default_flow_style=False, width=10000)
    LOG.info(f"[merge] 写出 {len(verified_nodes)} 条已验证节点 -> {VERIFIED_OUT} (含规则层)")
    write_verified_txt(os.path.splitext(out_path)[0] + ".txt", verified_nodes)


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

    # 3) 方案 A：从 verify_cn/verified.json 并入"中国出口验证通过"的完整节点。
    #    验证器已把完整 proxy dict 存进 json，这里直接取用（不再 name join），
    #    去重时优先保留 verified 的完整配置（含 tls/reality 等）。
    #    name_index 为全量节点的 name->proxy 映射，供旧版 verified.json（无 proxy 字段）
    #    降级回退用 name 匹配，避免迁移期节点丢失；新版验证器一跑即转纯方案 A。
    #    额外并入上一次合并产物 s-clash.yaml 的 proxies 作查找源（与旧 tag_verified 逻辑一致），
    #    保证本地/CI 无论源 txt 是否就绪都能降级匹配。
    name_index = {n.get("name"): n for n in nodes if n.get("name")}
    # P0-1：从上一轮产物 s-clash.yaml 构建 name_index 时剥掉 "✅ " 前缀——
    # 旧版 verified.json 存的是裸名，若不剥前缀则永远匹配不上；同时给降级匹配
    # 打上来源标记（仅作过渡兼容，新版验证器一跑即退出此路径）。
    for nd in load_clash_yaml(os.path.join(base, "s-clash.yaml")):
        if isinstance(nd, dict) and nd.get("name"):
            nm = nd["name"]
            bare = nm[len(VERIFIED_MARK):] if nm.startswith(VERIFIED_MARK) else nm
            if bare not in name_index:
                p = dict(nd)
                if bare != nm:
                    p["name"] = bare  # 降级产物不带前缀，✅ 由 write_verified 统一加
                name_index[bare] = p
    vpath = os.path.join(base, VERIFIED_SOURCE)
    verified_nodes = load_verified_proxies(vpath, name_index)
    n_verified = len(verified_nodes)
    if n_verified:
        LOG.info(f"[merge] 从 {VERIFIED_SOURCE} 并入 {n_verified} 条已验证节点（优先，方案A）")
        nodes = verified_nodes + nodes  # verified 在前：去重时优先保留其完整配置

    # 4) 去重
    seen, merged = set(), []
    for n in nodes:
        k = dedup_key(n)
        if not k[1]:  # 无 server 作废
            continue
        if k in seen:
            continue
        seen.add(k)
        merged.append(clean_node(n))

    # 5) name 唯一化（兜底：处理默认名冲突，保证 Clash/Clash Verge 校验通过）
    make_names_unique(merged)

    # 6) 稳定排序（便于 diff）
    merged.sort(key=lambda n: (n.get("type", ""), n.get("server", ""), int(n.get("port") or 0)))

    # 7) 写出（完整 Clash 配置：mode + dns + proxies + proxy-groups + rules）
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
        write_verified(out_base, base, verified_nodes)  # 方案 A：仍产出 s-verified.yaml
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

    # 方案 A：额外产出 s-verified.yaml（验证通过节点，独立完整配置，免打标漂移）
    write_verified(out_base, base, verified_nodes)


if __name__ == "__main__":
    main()
