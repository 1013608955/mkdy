# node_parse.py — 统一订阅 URI 解析器（H1 收敛点）
#
# 解决评审 H1：原先 update_nodes.py 与 merge_subs.py 各自维护一套 URI->dict 解析器，
# 字段语义不同且覆盖率不齐（前者缺 ssr/hy2/tuic），协议字段变更需同步两处极易漂移。
# 此处抽出单一 parse_uri_to_struct()，两模块共用，仅在输出阶段做格式转换：
#   - update_nodes.py：取所需字段做评分/探测
#   - merge_subs.py：映射成 Clash YAML
#
# 本模块为纯标准库实现，可被两模块直接 import（无第三方依赖）。
import base64
import json
import re
from urllib.parse import unquote, parse_qs

# Clash 风格 AEAD 加密套件（用于派生 ss / vmess 的 security 语义）
_AEAD_CIPHERS = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")


def b64decode(s: str) -> str:
    """宽松 base64 解码：自动补 padding，忽略非法字符与解码错误。"""
    try:
        s = (s or "").strip()
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return ""


def _split_uri(uri: str):
    """vmess:// 之外的 URI：返回 (scheme, body, qget, fragment)。"""
    m = re.match(r"^([a-zA-Z0-9]+)://(.+)$", uri)
    if not m:
        return None
    scheme = m.group(1)
    rest = m.group(2)
    frag = ""
    if "#" in rest:
        rest, frag = rest.rsplit("#", 1)
        frag = unquote(frag)
    if "?" in rest:
        body, q = rest.split("?", 1)
        qd = parse_qs(q)
    else:
        body, q = rest, {}
    qget = lambda k: (qd.get(k, [""])[0] or "")  # noqa: E731
    return scheme, body, qget, frag


# --------------------------------------------------------------------------- #
# 各协议 URI -> 规范结构（Clash 风格 + 额外字段供 update_nodes 用）
#   额外字段：security_scheme（评分用安全语义）、sni、peer、proto（评分用协议键）
# --------------------------------------------------------------------------- #
def _parse_vmess(uri: str):
    b = uri[len("vmess://"):]
    d = b64decode(b)
    if not d:
        return None
    try:
        j = json.loads(d)
    except Exception:
        return None
    node = {
        "name": (j.get("ps") or f"vmess_{j.get('add')}:{j.get('port') or 0}").strip(),
        "type": "vmess",
        "server": j.get("add"),
        "port": int(j.get("port") or 0),
        "uuid": j.get("id"),
        "alterId": int(str(j.get("aid", 0) or 0)),
        "cipher": j.get("scy") or "auto",
        "tls": (str(j.get("tls") or "").lower() == "tls"),
        "network": j.get("net") or "tcp",
    }
    if node["network"] == "ws":
        node["ws-opts"] = {
            "path": j.get("path") or "/",
            "headers": {"Host": j.get("host") or j.get("sni") or node["server"]},
        }
    if j.get("sni"):
        node["servername"] = j["sni"]
    scy = j.get("scy") or ""
    node["security_scheme"] = (
        "tls" if node["tls"]
        else ("aead" if scy in _AEAD_CIPHERS else "none")
    )
    node["sni"] = j.get("sni") or j.get("host") or node["server"]
    node["proto"] = "vmess"
    node["peer"] = node["sni"]
    return node


def _parse_vless(uri: str):
    scheme, body, qget, frag = _split_uri(uri)
    if not scheme or "@" not in body:
        return None
    user, hostport = body.split("@", 1)
    hp = hostport.rsplit(":", 1)
    server, port = hp[0], int(hp[1]) if len(hp) > 1 else 443
    security = qget("security") or "none"
    net = qget("type") or "tcp"
    node = {
        "name": (frag or f"vless_{server}:{port}").strip(),
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": user,
        "flow": qget("flow") or "",
        "tls": security in ("tls", "reality"),
        "network": net,
    }
    sni = qget("sni")
    if sni:
        node["sni"] = sni
        node["servername"] = sni
    if qget("allowInsecure") == "1" or qget("skip-cert-verify") == "true":
        node["skip-cert-verify"] = True
    if net == "ws":
        node["ws-opts"] = {
            "path": qget("path") or "/",
            "headers": {"Host": qget("host") or sni or server},
        }
    if security == "reality":
        node["reality-opts"] = {
            "public-key": qget("pbk"),
            "short-id": qget("sid") or "",
            "spider-x": qget("spx") or "",
            "fingerprint": qget("fp") or "",
        }
    node["security_scheme"] = security
    node["proto"] = "vless"
    node["peer"] = sni or server
    return node


def _parse_trojan(uri: str):
    scheme, body, qget, frag = _split_uri(uri)
    if not scheme or "@" not in body:
        return None
    user, hostport = body.split("@", 1)
    hp = hostport.rsplit(":", 1)
    server, port = hp[0], int(hp[1]) if len(hp) > 1 else 443
    node = {
        "name": (frag or f"trojan_{server}:{port}").strip(),
        "type": "trojan",
        "server": server,
        "port": port,
        "password": unquote(user),
        "tls": True,
        "network": qget("type") or "tcp",
    }
    sni = qget("sni")
    if sni:
        node["sni"] = sni
    if qget("allowInsecure") == "1" or qget("skip-cert-verify") == "true":
        node["skip-cert-verify"] = True
    if node["network"] == "ws":
        node["ws-opts"] = {
            "path": qget("path") or "/",
            "headers": {"Host": qget("host") or sni or server},
        }
    node["security_scheme"] = qget("security") or "tls"
    node["proto"] = "trojan"
    node["peer"] = sni or server
    return node


def _parse_ss(uri: str):
    rest = uri[len("ss://"):]
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        frag = unquote(frag).strip()
    plugin = ""
    if "?plugin=" in rest:
        rest, plugin = rest.split("?plugin=", 1)
        plugin = unquote(plugin)
    if "@" in rest:
        userinfo, hostport = rest.split("@", 1)
        dec = b64decode(userinfo)
        if dec and ":" in dec and "@" not in dec:
            method, password = dec.split(":", 1)
        elif ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            return None
        hp = hostport.rsplit(":", 1)
        server, port = hp[0], int(hp[1]) if len(hp) > 1 else 0
    else:
        dec = b64decode(rest)
        if not dec or "@" not in dec:
            return None
        up, hostport = dec.rsplit("@", 1)
        method, password = up.split(":", 1)
        hp = hostport.rsplit(":", 1)
        server, port = hp[0], int(hp[1]) if len(hp) > 1 else 0
    node = {
        "name": frag or f"ss_{server}:{port}",
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
    }
    if plugin:
        node["plugin"] = plugin
    node["security_scheme"] = "aead" if (method or "") in _AEAD_CIPHERS else "none"
    node["proto"] = "ss"
    node["peer"] = server
    return node


def _parse_ssr(uri: str):
    b = uri[len("ssr://"):]
    d = b64decode(b)
    if not d or "@" not in d:
        return None
    try:
        head, params = d.split("/", 1)
    except ValueError:
        head, params = d, ""
    try:
        user, hostport = head.split("@", 1)
        method, password = user.split(":", 1)
        hp = hostport.rsplit(":", 1)
        server, port = hp[0], int(hp[1])
    except Exception:
        return None
    node = {
        "name": f"ssr_{server}:{port}",
        "type": "ssr",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
        "protocol": "origin",
        "obfs": "plain",
    }
    node["security_scheme"] = None
    node["proto"] = "ssr"
    node["peer"] = server
    return node


def _parse_hysteria(uri: str):
    scheme, body, qget, frag = _split_uri(uri)
    if not scheme or "@" not in body:
        return None
    user, hostport = (body.split("@", 1) if "@" in body else ("", body))
    hp = hostport.rsplit(":", 1)
    server, port = hp[0], int(hp[1]) if len(hp) > 1 else 0
    node = {
        # 兼容 merge_subs 历史输出：hysteria:// 与 hysteria2:// 均输出 type=hysteria2
        "name": (frag or f"hysteria2_{server}:{port}").strip(),
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": unquote(user) or qget("auth"),
    }
    sni = qget("sni")
    if sni:
        node["sni"] = sni
    if qget("insecure") == "1":
        node["skip-cert-verify"] = True
    tls_on = qget("tls") != "0"  # 默认开启
    node["tls"] = tls_on
    node["security_scheme"] = "tls" if tls_on else "none"
    # update_nodes 评分用协议键：hysteria:// -> hysteria，hysteria2:// -> hysteria2
    node["proto"] = "hysteria" if scheme == "hysteria" else "hysteria2"
    node["peer"] = sni or server
    return node


def _parse_tuic(uri: str):
    scheme, body, qget, frag = _split_uri(uri)
    if not scheme or "@" not in body:
        return None
    user, hostport = (body.split("@", 1) if "@" in body else ("", body))
    hp = hostport.rsplit(":", 1)
    server, port = hp[0], int(hp[1]) if len(hp) > 1 else 0
    node = {
        "name": (frag or f"tuic_{server}:{port}").strip(),
        "type": "tuic",
        "server": server,
        "port": port,
        "password": unquote(user),
        "uuid": qget("uuid"),
    }
    node["security_scheme"] = None
    node["proto"] = "tuic"
    node["peer"] = server
    return node


_PARSERS = {
    "vmess://": _parse_vmess,
    "vless://": _parse_vless,
    "trojan://": _parse_trojan,
    "ss://": _parse_ss,
    "ssr://": _parse_ssr,
    "hysteria2://": _parse_hysteria,
    "hysteria://": _parse_hysteria,
    "tuic://": _parse_tuic,
}


def parse_uri_to_struct(uri):
    """统一解析入口：订阅 URI -> 规范结构 dict，未知/解析失败返回 None。"""
    uri = (uri or "").strip()
    for scheme, parser in _PARSERS.items():
        if uri.startswith(scheme):
            try:
                return parser(uri)
            except Exception:
                return None
    return None
