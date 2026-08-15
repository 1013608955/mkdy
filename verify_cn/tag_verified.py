"""tag_verified.py — 读取 verify_cn/verified.json，在 Clash 订阅里给「已验证可用」节点打标。

- 输入：verify_cn/verified.json（中国出口 FC 探针产出）+ s-clash.yaml（CI 生成的订阅，
        节点名与 verified.json 一一对应）
- 输出：s-verified.yaml —— 原订阅全部节点，已验证通过的节点名加 ✅ 前缀；
        同时把 proxy-groups 里对这些节点的显式引用一并改名，保证分组不失效。
- 不直接改写 s-clash.yaml（它由 CI 每小时经 merge_subs.py 重生成，会被覆盖）。

环境变量（均可选）：
  SRC_YAML  源订阅，默认仓库根 s-clash.yaml
  OUT_YAML  输出文件，默认仓库根 s-verified.yaml
  TAG       前缀，默认 "✅ "
"""
import json
import os
import sys

import yaml

REPO = os.environ.get("GITHUB_WORKSPACE", os.getcwd())
VERIFIED = os.path.join(REPO, "verify_cn", "verified.json")
SRC = os.environ.get("SRC_YAML", os.path.join(REPO, "s-clash.yaml"))
OUT = os.environ.get("OUT_YAML", os.path.join(REPO, "s-verified.yaml"))
TAG = os.environ.get("TAG", "✅ ")


def load_ok(path):
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
    if not os.path.exists(SRC):
        print(f"[WARN] 源订阅不存在: {SRC}，跳过。", file=sys.stderr)
        return
    with open(SRC, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    proxies = doc.get("proxies", []) or []
    rename = {}
    for p in proxies:
        name = p.get("name")
        if name and name in ok and not name.startswith(TAG):
            rename[name] = f"{TAG}{name}"
            p["name"] = rename[name]
    # 同步 proxy-groups 里的显式引用，避免分组失效
    for g in doc.get("proxy-groups", []) or []:
        plist = g.get("proxies")
        if isinstance(plist, list):
            g["proxies"] = [rename.get(n, n) for n in plist]
    with open(OUT, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False)
    print(f"源节点 {len(proxies)}，已标记 {len(rename)}，输出 {OUT}")


if __name__ == "__main__":
    main()
