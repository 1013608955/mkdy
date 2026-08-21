"""run_local.py — 在本机（中国大陆出口）跑节点真链验证，替代华为云 FunctionGraph。

本机天生满足「从国内探测节点能否翻墙」的需求，且有 git 凭证，无需 PAT / 云平台。

为什么用 mihomo 而不是 xray：
- 协议覆盖全：hysteria2 / anytls / tuic 等 xray 直接不支持（xray 会报
  `unknown config id: hysteria2` 启动失败，这些节点在云函数里从来没被真正验证过）。
- 零协议翻译：s-clash.yaml 本身就是 Clash 配置，proxies 原样喂给 mihomo 即可，
  不需要手工映射 reality/ws/grpc 字段（那层翻译是历史 bug 的温床）。
- 单进程：一个 mihomo 实例 + delay API 并发测全部节点，不用给每个节点起一个
  子进程，快一个数量级。
- 与客户端同源：delay API 就是 Clash 客户端「延迟测试」的同一套实现，
  结果和用户实际使用体验一致。

流程：
1. （可选）git pull --ff-only 同步最新 s-clash.yaml。
2. 读 s-clash.yaml 的 proxies → 生成临时 mihomo 配置（仅本地 external-controller）。
3. 起独立 mihomo 进程（不碰用户 Clash Verge 的端口/配置）。
4. 并发调 /proxies/{name}/delay 真链测试；主目标失败的节点用兜底目标复测一轮。
5. 写 verify_cn/verified.json。
6. （可选）git add/commit/push —— push 后自动触发 GitHub 端 verify-tag.yml
   （监听 verify_cn/verified.json）产出 s-verified.yaml。

用法：
  python run_local.py --limit 20 --no-push   # 小规模试跑
  python run_local.py                        # 全量 + 推送
  python run_local.py -c 24 -t 8 --no-pull   # 24 并发、8s 超时、不 pull
"""
import os
import sys
import json
import time
import shutil
import socket
import signal
import argparse
import tempfile
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import concurrent.futures
from collections import Counter

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC_YAML = os.path.join(REPO, "s-clash.yaml")
OUT_JSON = os.path.join(HERE, "verified.json")
LOG_DIR = os.path.join(HERE, "logs")

TARGET = "https://www.google.com/generate_204"
# 兜底目标：google 单点可能被特定节点/CDN 拦，任一能通即算可用，避免误杀。
FALLBACK_TARGET = "https://www.cloudflare.com/cdn-cgi/trace"

# 访问本地 API 必须绕开系统代理（否则 127.0.0.1 请求可能被代理吞掉）
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_NO_WINDOW = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)} \
    if sys.platform == "win32" else {}


def _find_mihomo():
    envp = os.environ.get("MIHOMO_BIN")
    if envp and os.path.exists(envp):
        return envp
    for name in ("mihomo.exe", "mihomo", "verge-mihomo.exe"):
        p = os.path.join(HERE, name)
        if os.path.exists(p):
            return p
    return None


def _maybe_shutdown(after):
    """可选：跑完即关机，省云开发环境核时。仅当 --shutdown-after 时触发。
    需配合「外部定时开机」才有意义（否则容器关掉后下轮不会自动起）。"""
    if not after:
        return
    print("[shutdown] --shutdown-after 已设，运行结束后关闭环境以节省核时…")
    for cmd in (["sudo", "shutdown", "-h", "now"],
                ["shutdown", "-h", "now"],
                ["systemctl", "poweroff"]):
        try:
            subprocess.run(cmd, check=False)
            return
        except Exception:  # noqa: BLE001
            continue


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _git_bin():
    """定时任务(schtasks)的环境 PATH 里往往没有 git，必须显式探测，
    否则 commit/push 会以 FileNotFoundError 静默失败。"""
    envp = os.environ.get("GIT_BIN")
    if envp and os.path.exists(envp):
        return envp
    found = shutil.which("git")
    if found:
        return found
    for p in (r"C:\Program Files\Git\cmd\git.exe",
              r"C:\Program Files\Git\bin\git.exe",
              os.path.expanduser(
                  r"~\.workbuddy\binaries\PortableGit\versions\1.2.0"
                  r"\mingw64\bin\git.exe")):
        if os.path.exists(p):
            return p
    return "git"


GIT = _git_bin()


def _git(args, check=True):
    r = subprocess.run([GIT, "-C", REPO] + args, capture_output=True, text=True)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} 失败：{out}")
    return r.returncode, out


def _norm_reality_shortid(proxies):
    """short-id 连写 hex（如 '7d6b6b7a606c21cf'）归一化为冒号格式（值不变）。
    这是已知的安全修复；其余字段不动（避免瞎改导致连不上）。"""
    import re
    for p in proxies:
        if p.get("type") != "vless":
            continue
        opts = p.get("reality-opts")
        if not isinstance(opts, dict):
            continue
        sid = opts.get("short-id")
        if isinstance(sid, str) and sid and ":" not in sid:
            s = sid.strip()
            if len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
                opts["short-id"] = ":".join(
                    s[i:i + 2] for i in range(0, len(s), 2))


def _mihomo_accepts(proxies, mihomo_bin, workdir):
    """用 mihomo -t 校验这批 proxies 能否被加载。返回 True/False。"""
    import tempfile, os, subprocess
    cfg = build_mihomo_config(proxies, _free_port(), _free_port())
    wd = tempfile.mkdtemp(prefix="mihomo_chk_", dir=workdir)
    cp = os.path.join(wd, "config.yaml")
    with open(cp, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    try:
        r = subprocess.run([mihomo_bin, "-t", "-d", wd, "-f", cp],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def _isolate_bad_proxies(proxies, mihomo_bin, workdir):
    """以 mihomo -t 为预言机，二分隔离出会导致整份配置 fatal 的坏节点并移除，
    使剩余节点能被 mihomo 正常加载。上游订阅常混入各种格式损坏节点（reality
    字段、未知类型等），任一坏节点会让 mihomo 启动 fatal、拖垮全部验证。
    返回 (clean, removed)：clean 为可加载的 proxies，removed 为被移除节点名。"""
    _norm_reality_shortid(proxies)
    removed = []

    def split_bad(group):
        # group 已知会让 mihomo fatal；二分定位其中的坏节点逐个移除。
        if len(group) <= 1:
            removed.append(group[0].get("name"))
            return
        mid = len(group) // 2
        left, right = group[:mid], group[mid:]
        if not _mihomo_accepts(left, mihomo_bin, workdir):
            split_bad(left)
        if not _mihomo_accepts(right, mihomo_bin, workdir):
            split_bad(right)

    if not _mihomo_accepts(proxies, mihomo_bin, workdir):
        split_bad(list(proxies))
    clean = [p for p in proxies if p.get("name") not in set(removed)]
    return clean, removed


def build_mihomo_config(proxies, ctrl_port, mixed_port):
    """最小可用配置：只要能加载节点 + 开 external-controller 即可。
    mode=direct + 单条 MATCH,DIRECT 规则 → 不需要 geoip/geosite 数据文件。"""
    return {
        "mixed-port": mixed_port,
        "external-controller": f"127.0.0.1:{ctrl_port}",
        "mode": "direct",
        "log-level": "warning",
        "unified-delay": True,       # 去掉握手偏差，延迟更接近真实
        "geo-auto-update": False,    # 不联网下载 geo 数据
        "dns": {                     # 节点 server 为域名时用国内 DNS 解析
            "enable": True,
            "ipv6": False,
            "nameserver": ["223.5.5.5", "119.29.29.29"],
        },
        "proxies": proxies,
        "rules": ["MATCH,DIRECT"],
    }


def wait_api(ctrl, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with _OPENER.open(f"http://{ctrl}/version", timeout=2) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            time.sleep(0.3)
    return None


def test_delay(ctrl, name, url, timeout_ms):
    """调 mihomo delay API：真的经该节点发一次请求。返回 (ok, latency_s, detail)。"""
    q = urllib.parse.urlencode({"timeout": timeout_ms, "url": url})
    api = (f"http://{ctrl}/proxies/"
           f"{urllib.parse.quote(name, safe='')}/delay?{q}")
    try:
        with _OPENER.open(api, timeout=timeout_ms / 1000.0 + 6) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
            ms = data.get("delay", 0)
            return True, round(ms / 1000.0, 3), f"delay {ms}ms"
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:200]
        try:
            msg = json.loads(body).get("message", body)
        except json.JSONDecodeError:
            msg = body
        return False, 0.0, (msg or f"HTTP {e.code}").strip()
    except Exception as e:  # noqa: BLE001
        return False, 0.0, f"{type(e).__name__}: {e}"


def _norm_err(detail):
    """把五花八门的错误信息归一成少数几类，便于统计诊断。"""
    d = (detail or "").lower()
    if "timeout" in d or "deadline" in d or "i/o timeout" in d:
        return "timeout"
    if "refused" in d:
        return "conn_refused"
    if "reset" in d:
        return "conn_reset"
    if "unreachable" in d or "no route" in d:
        return "unreachable"
    if "no such host" in d or "dns" in d or "lookup" in d:
        return "dns_fail"
    if "eof" in d:
        return "eof"
    if "certificate" in d or "tls" in d or "handshake" in d:
        return "tls_fail"
    if "not found" in d:
        return "proxy_not_found"
    return (detail or "unknown")[:60]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="只验证前 N 个节点(试跑)，0=全量")
    ap.add_argument("-c", "--concurrency", type=int, default=16)
    ap.add_argument("-t", "--timeout", type=int, default=8, help="单次测试超时(秒)")
    ap.add_argument("--no-pull", action="store_true")
    ap.add_argument("--no-push", action="store_true")
    ap.add_argument("--no-fallback", action="store_true", help="跳过兜底目标复测")
    ap.add_argument("--shutdown-after", action="store_true",
                    help="跑完即关机（云环境省核时；需配合外部定时开机才有意义）")
    ap.add_argument("--source", default=SRC_YAML)
    args = ap.parse_args()

    # 时间戳：定时任务把 stdout 追加进同一个日志文件，需要分隔每轮运行
    print(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} 开始验证 =====")
    mihomo = _find_mihomo()
    if not mihomo:
        print("[FATAL] 未找到 mihomo 二进制（verify_cn/mihomo.exe）。", file=sys.stderr)
        sys.exit(2)
    print(f"[init] mihomo={mihomo}  git={GIT}")

    if not args.no_pull:
        try:
            _, out = _git(["pull", "--ff-only", "origin", "main"])
            print(f"[git] pull: {out.splitlines()[-1] if out else 'ok'}")
        except RuntimeError as e:
            print(f"[git] pull 跳过（{e}）；继续用本地 s-clash.yaml。")

    if not os.path.exists(args.source):
        print(f"[FATAL] 节点源不存在：{args.source}", file=sys.stderr)
        sys.exit(2)
    with open(args.source, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    proxies = [p for p in (data.get("proxies") or []) if p.get("name")]
    # 重名兜底：mihomo 遇到 duplicate name 会 fatal 拒绝加载整份配置。
    # 这里丢弃重复项而非重命名——verified.json 的 name 必须与 s-clash.yaml
    # 精确一致，否则 tag_verified.py 匹配不上，打标会失效。
    seen, uniq, dropped = set(), [], []
    for p in proxies:
        if p["name"] in seen:
            dropped.append(p["name"])
            continue
        seen.add(p["name"])
        uniq.append(p)
    if dropped:
        print(f"[warn] 丢弃 {len(dropped)} 个重名节点（上游 s-clash.yaml 有 duplicate "
              f"name，会导致 Clash 客户端拒绝加载）：{dropped[:3]}")
    proxies = uniq
    # 坏节点隔离：以 mihomo -t 为预言机二分定位导致整份配置 fatal 的坏节点并移除，
    # 避免单个坏节点（reality 字段损坏、未知类型等）拖垮全部验证。被隔离节点不验证，
    # 靠客户端 url-test 兜底（本项目安全边界：真正可用性由客户端判定）。
    proxies, _skipped = _isolate_bad_proxies(proxies, mihomo, tempfile.gettempdir())
    if _skipped:
        print(f"[skip] 隔离 {len(_skipped)} 个 mihomo 无法加载的坏节点（不验证，"
              f"靠客户端兜底）：{_skipped[:3]}")
    if args.limit > 0:
        proxies = proxies[:args.limit]
    if not proxies:
        print("[FATAL] 解析到 0 个节点。", file=sys.stderr)
        sys.exit(2)
    names = [p["name"] for p in proxies]
    proto_of = {p["name"]: (p.get("type") or "?") for p in proxies}
    # 方案 A：保留完整 proxy dict 映射，供 verified.json 直接携带完整节点配置，
    # 免去下游 tag_verified 用 'name' 去 s-clash.yaml 重新 join（这正是漂移根因）。
    proxy_of = {p["name"]: p for p in proxies}
    print(f"[init] 待验证节点：{len(proxies)}  并发：{args.concurrency}  "
          f"超时：{args.timeout}s")

    ctrl_port, mixed_port = _free_port(), _free_port()
    ctrl = f"127.0.0.1:{ctrl_port}"
    workdir = tempfile.mkdtemp(prefix="mihomo_verify_")
    cfg_path = os.path.join(workdir, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(build_mihomo_config(proxies, ctrl_port, mixed_port),
                       f, allow_unicode=True, sort_keys=False)
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, "mihomo.log")

    t0 = time.time()
    results = {}

    # P0#3：Popen 前置到 try 外，异常路径也能进 finally 回收；
    # start_new_session=True 让 mihomo 独立进程组，便于整组 killpg 回收（含其 children）。
    proc = subprocess.Popen([mihomo, "-d", workdir, "-f", cfg_path],
                            stdout=open(log_path, "w", encoding="utf-8"),
                            stderr=subprocess.STDOUT,
                            start_new_session=True, **_NO_WINDOW)
    try:
        ver = wait_api(ctrl)
        if not ver:
            with open(log_path, encoding="utf-8", errors="replace") as f:
                tail = f.read()[-800:]
            print(f"[FATAL] mihomo API 未就绪，日志：\n{tail}", file=sys.stderr)
            sys.exit(3)
        print(f"[init] mihomo 就绪 {ver}  控制端口={ctrl_port}")

        def _run_round(target_names, url, label):
            done = 0
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=args.concurrency) as ex:
                futs = {ex.submit(test_delay, ctrl, n, url,
                                  args.timeout * 1000): n
                        for n in target_names}
                for fut in concurrent.futures.as_completed(futs):
                    n = futs[fut]
                    ok, lat, det = fut.result()
                    results[n] = {"name": n, "proto": proto_of.get(n, "?"),
                                  "ok": ok, "latency": lat,
                                  "proxy": proxy_of.get(n),  # 方案 A：完整节点配置，下游免 join
                                  "detail": (f"ok via {url} ({det})" if ok
                                             else det)}
                    done += 1
                    if done % 25 == 0 or done == len(target_names):
                        okc = sum(1 for v in results.values() if v["ok"])
                        print(f"[{label}] {done}/{len(target_names)}  "
                              f"累计 ok={okc}  用时 {time.time()-t0:.0f}s")

        _run_round(names, TARGET, "round1")
        failed = [n for n in names if not results[n]["ok"]]
        if failed and not args.no_fallback:
            print(f"[round2] {len(failed)} 个节点主目标失败，用兜底目标复测…")
            _run_round(failed, FALLBACK_TARGET, "round2")
    finally:
        # P0#3：优先 terminate，超时则整组强杀并等待回收，杜绝僵尸/孤儿进程残留占端口
        try:
            proc.terminate()
            proc.wait(timeout=8)
        except Exception:  # noqa: BLE001
            try:
                if proc.pid is not None:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:  # noqa: BLE001
                proc.kill()
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(workdir, ignore_errors=True)

    ordered = [results[n] for n in names]
    verified = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": TARGET,
        "count": len(ordered),
        "ok": sum(1 for r in ordered if r["ok"]),
        # 方案 A：每个 node 携带完整 proxy dict（含 tls/reality/server/port 等），
        # merge_subs.py 直接消费 ok 节点的 proxy 产出 s-verified.yaml，
        # 不再需要 tag_verified.py 用 'name' 去 s-clash.yaml 重新 join（消除漂移）。
        "nodes": ordered,
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(verified, f, ensure_ascii=False, indent=1)
    print(f"[done] {verified['ok']}/{verified['count']} 可用；"
          f"总用时 {time.time()-t0:.0f}s；已写 {OUT_JSON}")

    okc = Counter(r["proto"] for r in ordered if r["ok"])
    if okc:
        print("[stat] 可用节点协议：" +
              "; ".join(f"{k}×{v}" for k, v in okc.most_common()))
    errc = Counter(_norm_err(r["detail"]) for r in ordered if not r["ok"])
    if errc:
        print("[stat] 失败原因：" +
              "; ".join(f"{k}×{v}" for k, v in errc.most_common(6)))

    if args.no_push:
        print("[push] --no-push，跳过推送。")
        _maybe_shutdown(args.shutdown_after)
        return
    _git(["add", "verify_cn/verified.json"])
    code, out = _git(["commit", "-m",
                      f"verify(local): {verified['ok']}/{verified['count']} 节点可用"],
                     check=False)
    if "nothing to commit" in out:
        print("[push] verified.json 无变化，跳过提交。")
        return
    for attempt in range(3):
        code, out = _git(["push", "origin", "main"], check=False)
        if code == 0:
            print("[push] 推送成功；GitHub 端 verify-tag 将自动打标产出 s-verified.yaml。")
            _maybe_shutdown(args.shutdown_after)
            return
        print(f"[push] 第 {attempt+1} 次被拒，合并远端后重试…")
        _git(["fetch", "origin", "main"], check=False)
        # 用 FETCH_HEAD 而非 origin/main：本仓库 origin/main 跟踪引用偶发 stuck 在旧
        # commit（packed-refs/CRLF 老问题，git update-ref 也修不动）。FETCH_HEAD 由
        # 上面的 fetch 现写，永远是最新真实 tip，避免把陈旧引用合进历史。
        # -X ours：verify_cn/verified.json 每次整体重写，多验证器并发推送时必冲突，
        # 取"本地刚实测的最新结果"才正确（本机/云端双验证器场景）。
        mc, mo = _git(["merge", "--no-edit", "-X", "ours", "FETCH_HEAD"], check=False)
        if mc != 0:
            print(f"[push][ERROR] 合并 origin/main 失败（需人工处理）：{mo}",
                  file=sys.stderr)
            sys.exit(1)
    print("[push][ERROR] push 连续 3 次失败。", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
