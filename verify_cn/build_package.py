"""build_package.py — verify_cn 打成可直接上传 FunctionGraph 的代码包 + 依赖包。

FunctionGraph 部署分两部分（与阿里云 FC 不同）：
- 代码包（deploy.zip）：仅 index.py / verify_proxy_core.py / requirements.txt / xray
  → 传到“代码”入口。
- 依赖包（deploy_deps.zip）：requests / urllib3 / certifi / charset_normalizer /
  idna / PyYAML / PySocks（私有依赖包）→ 控制台“函数依赖包”添加并挂到函数上，
  其内容会自动加进 PYTHONPATH。

代码包不放 Python 库——扁平打到 /opt/function 下不会被运行时识别为 sys.path 目录，
导致 import 失败（Missing dependencies for SOCKS support 等）。
"""
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
WHEELS = os.path.join(HERE, "_wheels")
XRAY_SRC = os.path.join(HERE, "xray")
CODE_FILES = ["index.py", "verify_proxy_core.py", "requirements.txt"]
CODE_OUT = os.path.join(HERE, "deploy.zip")
DEPS_OUT = os.path.join(HERE, "deploy_deps.zip")


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


def _make_code_zip():
    if os.path.exists(CODE_OUT):
        os.remove(CODE_OUT)
    with zipfile.ZipFile(CODE_OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for cf in CODE_FILES:
            src = os.path.join(HERE, cf)
            if os.path.exists(src):
                add_file(z, src, cf, 0o644)
                print(f"[code]  {cf}")
            else:
                print(f"[warn] missing {cf}")
        if os.path.exists(XRAY_SRC):
            add_file(z, XRAY_SRC, "xray", 0o755)
            print("[xray]  xray -> 0o755")
        else:
            print("[ERROR] xray 二进制缺失！")
    size = os.path.getsize(CODE_OUT)
    print(f"[done]  {CODE_OUT}  ({size/1024/1024:.1f} MB)")
    with zipfile.ZipFile(CODE_OUT) as z:
        names = z.namelist()
        ext = (z.getinfo("xray").external_attr >> 16) & 0xFFFF
        print(f"[check] xray mode = {oct(ext)}  exec={'Y' if ext & 0o100 else 'N'}")
        for f in CODE_FILES + ["xray"]:
            print(f"[check] {f}: {'OK' if f in names else 'MISSING'}")


def _make_deps_zip():
    if os.path.exists(DEPS_OUT):
        os.remove(DEPS_OUT)
    with zipfile.ZipFile(DEPS_OUT, "w", zipfile.ZIP_DEFLATED) as z:
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
    size = os.path.getsize(DEPS_OUT)
    print(f"[done]  {DEPS_OUT}  ({size/1024/1024:.1f} MB)")
    with zipfile.ZipFile(DEPS_OUT) as z:
        names = z.namelist()
        for pkg in ["requests/__init__.py", "yaml/__init__.py", "socks.py",
                    "urllib3/__init__.py", "charset_normalizer/__init__.py"]:
            print(f"[check] {pkg}: {'OK' if pkg in names else 'MISSING'}")
        so = [x for x in names if x.endswith(".so")]
        print(f"[check] .so bundled: {len(so)}  e.g. {so[:3]}")


def main():
    _make_code_zip()
    print()
    _make_deps_zip()


if __name__ == "__main__":
    main()
