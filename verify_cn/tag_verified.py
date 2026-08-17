"""tag_verified.py — 从 verified.json 筛出「中国出口(FC)验证通过」的节点，套用
clash_template.yaml 规则模版，生成**仅含已验证节点**的完整 Clash 配置 s-verified.yaml。

- 输入：verify_cn/verified.json（FC 探针产出，含每节点 ok 标记）
       + s-clash.yaml（CI 每小时经 merge_subs.py 生成的完整订阅，含全部节点定义）
       + clash_template.yaml（规则模版，proxy-groups 内用 __ALL_PROXIES__ 占位）
- 输出：s-verified.yaml —— 仅含验证通过节点 + 完整规则层
       （mode/dns/3 个代理分组/rules，分组引用经 __ALL_PROXIES__ 注入为这些节点）

设计要点：
- verified.json 是某次验证的快照，节点名可能随订阅轮换而漂移；
  精确匹配不到的 ok 节点（已不在最新 s-clash.yaml）跳过并告警，不凭空造节点。
- 直接套用模版而非在 s-clash.yaml 上改，保证字段结构/分组定义/规则顺序
  严格遵循 clash_template.yaml（与 s-clash.yaml 同源）。

环境变量（均可选）：
  GITHUB_WORKSPACE  仓库根目录，默认当前目录
  SRC_YAML          源订阅，默认 <workspace>/s-clash.yaml
  VERIFIED_JSON     验证结果，默认 <workspace>/verify_cn/verified.json
  TEMPLATE_YAML     规则模版，默认 <workspace>/clash_template.yaml
  OUT_YAML          输出文件，默认 <workspace>/s-verified.yaml
  OUT_TXT           v2rayN 订阅输出，默认 <workspace>/s-verified.txt
"""
import json
import os
import sys

import yaml

# 确保无论 tag_verified.py 被从哪个目录直接执行，都能 import 到仓库根的 node_parse.py
# （python verify_cn/tag_verified.py 会把 sys.path[0] 设为 verify_cn/，需要显式补仓库根）
REPO = os.environ.get("GITHUB_WORKSPACE", os.getcwd())
if REPO not in sys.path:
    sys.path.insert(0, REPO)
from node_parse import struct_to_uri

SRC = os.environ.get("SRC_YAML", os.path.join(REPO, "s-clash.yaml"))
VERIFIED = os.environ.get("VERIFIED_JSON", os.path.join(REPO, "verify_cn", "verified.json"))
TEMPLATE = os.environ.get("TEMPLATE_YAML", os.path.join(REPO, "clash_template.yaml"))
OUT = os.environ.get("OUT_YAML", os.path.join(REPO, "s-verified.yaml"))
OUT_TXT = os.environ.get("OUT_TXT", os.path.join(REPO, "s-verified.txt"))


def load_ok(path):
    """返回 verified.json 中 ok=True 的节点名集合。"""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    ok = set()
    for n in data.get("nodes", []) or []:
        if n.get("ok") and n.get("name"):
            ok.add(n["name"])
    return ok


def main():
    ok = load_ok(VERIFIED)
    if not ok:
        print("[WARN] verified.json 无 ok 节点，跳过生成。", file=sys.stderr)
        return
    if not os.path.exists(SRC):
        print(f"[WARN] 源订阅不存在: {SRC}，跳过。", file=sys.stderr)
        return
    if not os.path.exists(TEMPLATE):
        print(f"[WARN] 规则模版不存在: {TEMPLATE}，跳过。", file=sys.stderr)
        return

    with open(SRC, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    name2node = {p["name"]: p for p in doc.get("proxies", []) if isinstance(p, dict)}

    # 精确匹配验证通过节点；匹配不到的视为漂移/失效，跳过并告警
    selected = [name2node[n] for n in ok if n in name2node]
    missing = [n for n in ok if n not in name2node]
    if missing:
        print(f"[WARN] {len(missing)} 个验证通过节点不在最新 s-clash.yaml"
              f"（名称漂移/已失效），已跳过：{missing[:5]}")
    if not selected:
        print("[WARN] 无可用已验证节点，跳过生成。", file=sys.stderr)
        return

    # 套用规则模版
    with open(TEMPLATE, encoding="utf-8") as f:
        tpl = yaml.safe_load(f) or {}
    names = [p["name"] for p in selected]

    out = {}
    for k, v in tpl.items():
        if k == "proxy-groups":
            groups = []
            for g in (v or []):
                g = dict(g)
                plist = g.get("proxies", [])
                new = []
                for item in plist:
                    if item == "__ALL_PROXIES__":
                        new.extend(names)
                    else:
                        new.append(item)
                g["proxies"] = new
                groups.append(g)
            out[k] = groups
        else:
            out[k] = v  # mode / log-level / dns / rules 等原样保留（模版不含 proxies 键）
    # 模版本身不含 proxies（节点由生成时注入），此处显式写入验证通过节点
    out["proxies"] = selected

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# s-verified.yaml — 仅含中国出口(FC)验证通过的节点 + clash_template 规则模版\n")
        f.write(f"# 来源 verified.json: {len(ok)} 个 ok → 匹配 {len(selected)}"
                f"（漂移跳过 {len(missing)}）\n")
        yaml.safe_dump(out, f, allow_unicode=True, sort_keys=False, width=10000)

    print(f"[tag] 验证通过 {len(ok)} → 匹配 {len(selected)}"
          f"（漂移跳过 {len(missing)}）→ 输出 {OUT}")

    # 写出 s-verified.txt（v2rayN 兼容订阅格式，仅已打标节点）
    lines = []
    for nd in selected:
        uri = struct_to_uri(nd)
        if uri:
            lines.append(uri)
    with open(OUT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[tag] 输出 {len(lines)} 条已验证 URI -> {OUT_TXT}")


if __name__ == "__main__":
    main()
