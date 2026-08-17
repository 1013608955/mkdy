"""build_package.py — verify_cn 打成可直接上传 FunctionGraph 的代码包 + 依赖包。

FunctionGraph 部署分两部分（与阿里云 FC 不同）：
- 代码包（deploy.zip）：index.py / verify_proxy_core.py / requirements.txt / xray
  + vlibs/socks.py（随代码发布的 PySocks，运行时由 index.py 用 importlib 强制
  加载进 sys.modules，规避 urllib3 的 import socks 被同名模块遮蔽）。
  → 传到“代码”入口。
- 依赖包（deploy_deps.zip）：requests / urllib3 / certifi / charset_normalizer /
  idna / PyYAML / PySocks（私有依赖包）→ 控制台“函数依赖包”添加并挂到函数上。
  内部 layout 必须【扁平】（华为官方文档 `pip install --root /tmp/x` →
  `cd .../site-packages` → `zip -rq *.zip *`，把 site-packages 内容直接打平到
  zip 根）。FunctionGraph 会把依赖包解压到「与项目代码同级」的目录并加进
  PYTHONPATH，故扁平根即可被 import；切勿加 python3.10/site-packages/ 前缀
  （会变成 site-packages/site-packages/... 而 import 不到）。
"""
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
WHEELS = os.path.join(HERE, "_wheels")
XRAY_SRC = os.path.join(HERE, "xray")
VLIBS_SRC = os.path.join(HERE, "vlibs")
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
        # 随代码发布的 PySocks：vlibs/socks.py（运行时由 index.py 强制加载）
        if os.path.isdir(VLIBS_SRC):
            for fn in sorted(os.listdir(VLIBS_SRC)):
                full = os.path.join(VLIBS_SRC, fn)
                if os.path.isfile(full):
                    add_file(z, full, f"vlibs/{fn}", 0o644)
                    print(f"[vlibs] vlibs/{fn}")
        else:
            print("[warn] vlibs/ 缺失（PySocks 强制加载所需）")
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
        for f in CODE_FILES + ["xray", "vlibs/socks.py"]:
            print(f"[check] {f}: {'OK' if f in names else 'MISSING'}")


# FunctionGraph 私有依赖包布局（【扁平】！）：
# 华为官方文档示例 `cd .../site-packages; zip -rq *.zip *` —— 把 site-packages
# 的内容直接打平到 zip 根（requests/、urllib3/、socks.py、yaml/...）。
# FunctionGraph 会把依赖包解压到「与项目代码同级」目录并加进 PYTHONPATH，
# 故扁平根即可被 import。切勿加 python3.10/site-packages/ 前缀。
DEPS_PREFIX = ""


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
                    # 扁平：直接打平到 zip 根（不加任何前缀）
                    arcname = rel if not DEPS_PREFIX else (DEPS_PREFIX + rel)
                    add_bytes(z, wz.read(name), arcname, _mode_from_zip(wz.getinfo(name)))
    size = os.path.getsize(DEPS_OUT)
    print(f"[done]  {DEPS_OUT}  ({size/1024/1024:.1f} MB)")
    with zipfile.ZipFile(DEPS_OUT) as z:
        names = z.namelist()
        for pkg in ["requests/__init__.py",
                    "yaml/__init__.py",
                    "socks.py",
                    "urllib3/__init__.py",
                    "charset_normalizer/__init__.py"]:
            print(f"[check] {pkg}: {'OK' if pkg in names else 'MISSING'}")
        so = [x for x in names if x.endswith(".so")]
        print(f"[check] .so bundled: {len(so)}  e.g. {so[:3]}")


def main():
    _make_code_zip()
    print()
    _make_deps_zip()


if __name__ == "__main__":
    main()
