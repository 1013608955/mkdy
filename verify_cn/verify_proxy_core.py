"""verify_proxy_core.py — 平台无关的代理节点真实链路验证核心。

设计目标：在中国大陆网络出口（如阿里云 FC）上，真正把流量“通过节点”发出去，
验证节点是否能翻墙/可用，而不仅仅是握手。

- socks5：直接用 pysocks 走链。
- ss / vmess / vless / trojan / hysteria2：临时拉起 xray（需自备二进制），
  开一个本地 SOCKS 入站，把节点作为出战，再用 requests 经本地 SOCKS 拉目标。
- 未配置 xray 时，这些协议返回 ("xray_not_configured", ...) 而非假阳性。

本文件不依赖任何云平台 SDK，可直接用于阿里云 FC / 腾讯云 SCF / 本地。
"""
import os
import json
import time
import socket
import subprocess

import requests
import yaml

DEFAULT_TARGET = "https://www.google.com/generate_204"
XRAY_BIN_ENV = "XRAY_BIN"


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _extract_ws(p, node):
    # 提取 clash 的 ws-opts（path / headers.Host）
    node["network"] = p.get("network", "tcp")
    opts = p.get("ws-opts") or {}
    if node["network"] == "ws":
        node["ws_path"] = opts.get("path") or "/"
        node["ws_host"] = (opts.get("headers") or {}).get("Host") or p.get("server")


def _stream_settings(node, tls_default=False):
    net = node.get("network", "tcp")
    tls = node.get("tls", tls_default)
    ss = {"network": net}
    if net == "ws":
        ss["wsSettings"] = {
            "path": node.get("ws_path", "/"),
            "headers": {"Host": node.get("ws_host", "")},
        }
    if tls:
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": node.get("sni") or node.get("server")}
    # grpc / reality / shadowtls 等高级流控此处未覆盖，按需扩展
    return ss


def build_xray_config(node, local_port):
    """把 clash 风格节点描述转换为 xray 配置（本地 SOCKS 入站 + 节点出战）。"""
    proto = (node.get("proto") or "").lower()
    inbound = {"listen": "127.0.0.1", "port": local_port, "protocol": "socks",
               "settings": {"udp": True}, "tag": "in-socks"}
    ob = None
    if proto == "vmess":
        vnext = {"address": node["server"], "port": int(node["port"]),
                 "users": [{"id": node["uuid"], "security": node.get("cipher", "auto"), "level": 0}]}
        ob = {"protocol": "vmess", "settings": {"vnext": [vnext]}}
        ob.update(_stream_settings(node))
    elif proto == "vless":
        vnext = {"address": node["server"], "port": int(node["port"]),
                 "users": [{"id": node["uuid"], "level": 0, "flow": node.get("flow", "")}]}
        ob = {"protocol": "vless", "settings": {"vnext": [vnext]}}
        ob.update(_stream_settings(node))
    elif proto == "trojan":
        ob = {"protocol": "trojan",
              "settings": {"servers": [{"address": node["server"], "port": int(node["port"]),
                                         "password": node["password"]}]}}
        ob.update(_stream_settings(node, tls_default=True))
    elif proto in ("ss", "shadowsocks"):
        ob = {"protocol": "shadowsocks",
              "settings": {"servers": [{"address": node["server"], "port": int(node["port"]),
                                        "method": node["method"], "password": node["password"]}]}}
    elif proto in ("hysteria", "hysteria2", "hy2"):
        ob = {"protocol": "hysteria2",
              "settings": {"servers": [{"address": node["server"], "port": int(node["port"]),
                                        "password": node.get("password") or node.get("auth")}]}}
        if node.get("sni"):
            ob["streamSettings"] = {"tlsSettings": {"serverName": node["sni"]}}
    else:
        return None
    return {"inbounds": [inbound],
            "outbounds": [ob, {"protocol": "freedom", "tag": "direct"}],
            "log": {"loglevel": "warning"}}


def run_xray_chain(xray_bin, node, target_url, timeout, local_port):
    cfg = build_xray_config(node, local_port)
    if cfg is None:
        return False, 0.0, "unsupported_proto"
    if not os.access(xray_bin, os.X_OK):
        try:
            os.chmod(xray_bin, 0o755)
        except OSError:
            pass
    cfg_path = f"/tmp/xray_{local_port}.json"
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen([xray_bin, "run", "-c", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not _wait_port(local_port, timeout=6):
            return False, 0.0, "xray_listen_timeout"
        proxies = {"http": f"socks5h://127.0.0.1:{local_port}",
                   "https": f"socks5h://127.0.0.1:{local_port}"}
        start = time.time()
        r = requests.get(target_url, proxies=proxies, timeout=timeout,
                         headers={"User-Agent": "Mozilla/5.0"})
        return r.status_code < 400, time.time() - start, f"http {r.status_code}"
    except Exception as e:  # noqa: BLE001
        return False, 0.0, f"{type(e).__name__}: {e}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            proc.kill()
        try:
            os.remove(cfg_path)
        except OSError:
            pass


def run_socks5_chain(node, target_url, timeout):
    auth = ""
    if node.get("username"):
        auth = f"{node['username']}:{node.get('password', '')}@"
    proxies = {"http": f"socks5h://{auth}{node['server']}:{node['port']}",
               "https": f"socks5h://{auth}{node['server']}:{node['port']}"}
    try:
        start = time.time()
        r = requests.get(target_url, proxies=proxies, timeout=timeout,
                         headers={"User-Agent": "Mozilla/5.0"})
        return r.status_code < 400, time.time() - start, f"http {r.status_code}"
    except Exception as e:  # noqa: BLE001
        return False, 0.0, f"{type(e).__name__}: {e}"


def verify_through_proxy(node, target_url=DEFAULT_TARGET, timeout=8,
                         xray_bin=None, local_port=None):
    """对单个节点做真实链路验证，返回 (ok, latency, detail)。

    平台无关：socks5 走 pysocks；其余协议需 xray 二进制（见 XRAY_BIN）。
    无 xray 时对非 socks5 协议返回 ("xray_not_configured", ...) 而非假阳性。
    """
    proto = (node.get("proto") or "").lower()
    if proto == "socks5":
        return run_socks5_chain(node, target_url, timeout)
    if proto in ("ss", "shadowsocks", "vmess", "vless", "trojan",
                 "hysteria", "hysteria2", "hy2"):
        xb = xray_bin or os.environ.get(XRAY_BIN_ENV)
        if not xb or not os.path.exists(xb):
            return False, 0.0, "xray_not_configured"
        lp = local_port or _free_port()
        return run_xray_chain(xb, node, target_url, timeout, lp)
    return False, 0.0, "unsupported_proto"


def parse_clash_yaml(text):
    """从 Clash YAML 文本解析出节点列表（仅取验证所需字段）。"""
    data = yaml.safe_load(text) or {}
    out = []
    for p in data.get("proxies", []) or []:
        t = (p.get("type") or "").lower()
        if not t:
            continue
        node = {"name": p.get("name"), "proto": t,
                "server": p.get("server"), "port": p.get("port")}
        if t == "vmess":
            node["uuid"] = p.get("uuid")
            node["cipher"] = p.get("cipher", "auto")
            _extract_ws(p, node)
            node["tls"] = bool(p.get("tls") or p.get("tls-enabled", False))
            node["sni"] = p.get("servername") or p.get("sni") or p.get("server")
        elif t == "vless":
            node["uuid"] = p.get("uuid")
            node["flow"] = p.get("flow", "")
            _extract_ws(p, node)
            node["tls"] = bool(p.get("tls", False))
            node["sni"] = p.get("servername") or p.get("sni") or p.get("server")
        elif t == "trojan":
            node["password"] = p.get("password")
            node["sni"] = p.get("sni") or p.get("server")
        elif t in ("ss", "shadowsocks"):
            node["method"] = p.get("method")
            node["password"] = p.get("password")
        elif t in ("hysteria", "hysteria2", "hy2"):
            node["password"] = p.get("password") or p.get("auth")
            node["sni"] = p.get("sni") or p.get("server")
        elif t == "socks5":
            node["username"] = p.get("username")
            node["password"] = p.get("password")
        out.append(node)
    return out
