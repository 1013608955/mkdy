"""name_util.py — 共享工具：保证 Clash proxy 名称唯一。

下游 Clash / Clash Verge 遇到 duplicate name 会 fatal 拒绝加载整份订阅，
故合并去重后必须确保 name 唯一。

实现要点（曾踩过的坑）：必须用「已占用名字集合」而非计数器。
计数器写法会把第 3 个同名节点改成 `X_3`，而上游本来就可能有一个节点叫
`X_3`（很多机场用 _N 后缀命名），两者撞车后 mihomo 直接 fatal 拒绝加载
整份订阅。故这里对生成的候选名循环递增直到不冲突，且新名也登记进集合。
"""


def make_proxy_names_unique(proxies):
    """兜底确保 name 唯一：同名重复追加 _2/_3/...，并把空名回填为可读默认。

    返回原地修改后的列表。
    """
    used = set()
    for p in proxies:
        if not isinstance(p, dict):
            continue
        name = (p.get("name") or "").strip()
        if not name:
            name = f"{p.get('type', 'node')}_{p.get('server', '')}:{p.get('port', 0)}"
        if name in used:
            i = 2
            while f"{name}_{i}" in used:
                i += 1
            name = f"{name}_{i}"
        p["name"] = name
        used.add(name)
    return proxies
