"""build_package.py — 把 verify_cn 打成可直接上传阿里云 FC 的代码包。

产物：verify_cn/deploy.zip（不经临时目录，直接写 zip，避免 Windows 上删目录触发安全拦截）
解压到 /code 后的结构：
  index.py
  verify_proxy_core.py
  requirements.txt
  xray                       (Linux x86_64 二进制，强制 0o755)
  requests/  yaml/  socks.py  ...  (来自 _wheels 的 manylinux 轮子，合并到根)
"""
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
WHEELS = os.path.join(HERE, "_wheels")
OUT = os.path.join(HERE, "deploy.zip")
XRAY_SRC = os.path.join(HERE, "xray")
CODE_FILES = ["index.py", "verify_proxy_core.py", "requirements.txt"]


def _mode_from_zip(zinfo):
    m = (zinfo.external_attr >> 16) & 0xFFFF
    return m if m else 0o644


def add_bytes(zf, data, arcname, mode):
    zi = zipfile.ZipInfo(arcname)
    zi.external_attr = (mode & 0xFFFF) << 16
    zi.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(zi, data)


def add_file(zf, full, arcname, mode):
    with open(full, "rb") as f:
        add_bytes(zf, f.read(), arcname, mode)


def main():
    if os.path.exists(OUT):
        os.remove(OUT)
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        # 1) 合并所有 manylinux 轮子到 zip 根
        for fn in sorted(os.listdir(WHEELS)):
            if not fn.endswith(".whl"):
                continue
            print(f"[wheel] {fn}")
            with zipfile.ZipFile(os.path.join(WHEELS, fn)) as wz:
                for name in wz.namelist():
                    if name.endswith("/"):
                        continue
                    rel = name
                    if rel.startswith("platlib/") or rel.startswith("purelib/"):
                        rel = rel.split("/", 1)[1]
                    add_bytes(z, wz.read(name), rel, _mode_from_zip(wz.getinfo(name)))
        # 2) 代码文件
        for cf in CODE_FILES:
            src = os.path.join(HERE, cf)
            if os.path.exists(src):
                add_file(z, src, cf, 0o644)
                print(f"[code]  {cf}")
            else:
                print(f"[warn] missing {cf}")
        # 3) xray 二进制：强制 0o755
        if os.path.exists(XRAY_SRC):
            add_file(z, XRAY_SRC, "xray", 0o755)
            print("[xray]  xray -> 0o755")
        else:
            print("[ERROR] xray 二进制缺失！")
    size = os.path.getsize(OUT)
    print(f"[done]  {OUT}  ({size/1024/1024:.1f} MB)")

    # 自检
    with zipfile.ZipFile(OUT) as z:
        names = z.namelist()
        ext = (z.getinfo("xray").external_attr >> 16) & 0xFFFF
        print(f"[check] xray mode = {oct(ext)}  exec={'Y' if ext & 0o100 else 'N'}")
        for pkg in ["requests/__init__.py", "yaml/__init__.py",
                    "socks.py", "index.py", "verify_proxy_core.py"]:
            print(f"[check] {pkg}: {'OK' if pkg in names else 'MISSING'}")
        so = [x for x in names if x.endswith(".so")]
        print(f"[check] .so bundled: {len(so)}  e.g. {so[:3]}")


if __name__ == "__main__":
    main()
