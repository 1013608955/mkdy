#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 APNIC 权威 delegated 文件生成 cn_ranges.txt（离线 CN CIDR 列表）。

用法:
    python tools/gen_cn_ranges.py [delegated_file] [output_file]

默认输入:  tools/_apnic.txt  (APNIC delegated-apnic-latest)
默认输出:  cn_ranges.txt      (仓库根，供 update_nodes.is_cn_ip 离线成员判定)

delegated 行格式:  registry|CC|type|start|value|date|status
  - ipv4: value = 地址个数  -> 前缀 = 32 - floor(log2(value))
  - ipv6: value = 前缀长度  -> 直接用
仅取 status 为 allocated/assigned 的 CN 记录（跳过 reserved/available）。
"""
import ipaddress
import math
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def iter_cn_cidrs(delegated_path: str):
    with open(delegated_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 7:
                continue
            registry, cc, typ, start, value, _date, status = parts[:7]
            if registry != "apnic" or cc != "CN":
                continue
            if typ not in ("ipv4", "ipv6"):
                continue
            if status not in ("allocated", "assigned"):
                continue
            try:
                if typ == "ipv4":
                    count = int(value)
                    prefix = 32 - math.floor(math.log2(count))
                    net = ipaddress.ip_network(f"{start}/{prefix}", strict=False)
                else:
                    net = ipaddress.ip_network(f"{start}/{value}", strict=False)
            except (ValueError, ZeroDivisionError):
                continue
            yield net


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "tools", "_apnic.txt")
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(REPO, "cn_ranges.txt")
    if not os.path.exists(src):
        sys.exit(f"✗ 找不到源文件 {src}，请先下载 APNIC delegated-apnic-latest")
    cidrs = sorted({str(n) for n in iter_cn_cidrs(src)},
                   key=lambda s: (s.split(".")[0].zfill(3) if ":" not in s else "z" + s))
    with open(out, "w", encoding="utf-8") as f:
        f.write("# 中国（CN）IP 网段列表，由 tools/gen_cn_ranges.py 从 APNIC delegated-apnic-latest 生成\n")
        f.write("# 供 update_nodes.is_cn_ip 离线成员判定使用，请勿手工编辑\n")
        f.write("\n".join(cidrs))
        f.write("\n")
    print(f"✓ 生成 {out}：{len(cidrs)} 条 CN CIDR")


if __name__ == "__main__":
    main()
