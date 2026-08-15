import requests
import re
import socket
import ssl
import threading
import base64
import binascii
import os
import time
import hashlib
import logging
import uuid
from urllib.parse import unquote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import lru_cache
import urllib3
from typing import Dict, List, Tuple, Optional, Union
import json
# ========== 配置与初始化 ==========
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# 核心配置（已应用所有优化）
CONFIG: Dict = {
    "sources": [
        {"url": "https://raw.githubusercontent.com/1013608955/mkdy/main/s2.txt", "weight": 10},
        {"url": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub", "weight": 7},
        {"url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt", "weight": 5},
        {"url": "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray", "weight": 6},
        {"url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt", "weight": 4},
        {"url": "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt", "weight": 8},
        {"url": "https://raw.githubusercontent.com/HakurouKen/free-node/main/public", "weight": 7},
        {"url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", "weight": 6}
    ],
    "request": {"timeout": 15, "retry": 3, "retry_delay": 3, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
    "github": {"token": os.getenv("GITHUB_TOKEN", ""), "interval": 0.5, "cache_ttl": 3600, "cache_expire_days": 7},
    "detection": {
        "tcp_timeout": {"vmess": 5, "vless": 5, "trojan": 5, "ss": 4, "hysteria": 6},
        "tcp_retry": 1, # 优化：从 3 → 2
        "thread_pool": 8,
        "dns": {"servers": ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"], "timeout": 4, "cache_size": 1000},
        "http_test": {
            "timeout": 10,
            "targets": [
                "http://www.google.com/generate_204",
                "https://api.github.com/",
                "http://httpbin.org/ip",
                "https://api.ipify.org?format=json"
            ],
            "fallback": "http://baidu.com"
        },
        "score_threshold": 40,
        "rt_thresholds": { # 优化：所有协议 max 统一提升到 9s
            "vmess": {"min": 0.02, "max": 12},
            "vless": {"min": 0.02, "max": 12},
            "trojan": {"min": 0.02, "max": 12},
            "ss": {"min": 0.02, "max": 12},
            "hysteria": {"min": 0.01, "max": 12}
        }
    },
    "filter": {
        "private_ip": re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|0\.0\.0\.0)"),
        "cn_ip_ranges": [
            re.compile(r"^1\.0\.16\."), re.compile(r"^1\.0\.64\."), re.compile(r"^101\."),
            re.compile(r"^103\."), re.compile(r"^112\."), re.compile(r"^113\."),  # 103.96/103.106 确为CN，原负向预查误将其当境外，已修正
            re.compile(r"^120\."), re.compile(r"^121\."), re.compile(r"^122\."), re.compile(r"^123\."),
            re.compile(r"^139\."), re.compile(r"^140\."), re.compile(r"^141\."), re.compile(r"^150\."),
            re.compile(r"^151\."), re.compile(r"^163\."),             re.compile(r"^171\."),
            re.compile(r"^173\."), re.compile(r"^174\."), re.compile(r"^180\."), re.compile(r"^181\."),  # 172.32+ 多非CN，原正则将整段误判为CN；172.16/12 已由 private_ip 覆盖
            re.compile(r"^182\."), re.compile(r"^183\."), re.compile(r"^184\."), re.compile(r"^190\."),
            re.compile(r"^202\."), re.compile(r"^203\."), re.compile(r"^210\."), re.compile(r"^211\."),
            re.compile(r"^220\."), re.compile(r"^221\."), re.compile(r"^222\."), re.compile(r"^223\.")
        ],
        "ports": range(1, 65535),
        "max_remark_bytes": 200,
        "DEFAULT_PORT": 443,
        "SS_DEFAULT_CIPHER": "aes-256-gcm",
        "SS_VALID_CIPHERS": ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb"],
        "score_rules": {
            "protocol": {"vless": 20, "trojan": 18, "vmess": 18, "hysteria": 15, "ss": 12, "other": 0},
            "security": {"reality": 10, "tls": 15, "aead": 10, "none": 5},
            "port": {443: 10, 8443: 8, 80: 7, 465: 7, 9443: 7, "other": 5},
            "response_speed": {
                "vmess": {"fast": 8, "normal": 4, "slow": 0},
                "vless": {"fast": 9, "normal": 4, "slow": 0},
                "trojan": {"fast": 8, "normal": 4, "slow": 0},
                "ss": {"fast": 7, "normal": 3, "slow": 0},
                "hysteria": {"fast": 10, "normal": 5, "slow": 1}
            },
            "dns_valid": 8,
            "http_valid": 8, # 优化：22 → 10
            "cn_ip": -5, # 优化：-40 → -10
            "response_time_abnormal": -20,
            "stability": 5,
            "ip_type": {"residential": 15, "dc": 10, "unknown": 5}
        }
    }
}
# 日志初始化
def init_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        handler = logging.StreamHandler()
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    return logger
LOG = init_logger()
# 全局会话
def init_session() -> requests.Session:
    sess = requests.Session()
    sess.trust_env = False
    headers = {"User-Agent": CONFIG["request"]["ua"], "Accept": "*/*"}
    if CONFIG["github"]["token"]:
        headers["Authorization"] = f"token {CONFIG['github']['token']}"
    adapter = requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=16, max_retries=2)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    return sess
SESSION = init_session()
# ========== 工具函数（优化后）==========
def validate_port(port: Union[str, int]) -> int:
    try:
        p = int(port)
        return p if 1 <= p <= 65535 else CONFIG["filter"]["DEFAULT_PORT"]
    except (ValueError, TypeError):
        return CONFIG["filter"]["DEFAULT_PORT"]
def log_msg(content: str, line: str = "", proto: str = "") -> str:
    line_part = f"（{line[:20]}...）" if line and "保留" not in content else ""
    proto_part = f"（{proto}）" if proto else ""
    return f"{content}{line_part}{proto_part}"
def b64_safe_decode(b64_str: str) -> str:
    try:
        b64_str = b64_str.rstrip('=')
        b64_str += '=' * (4 - len(b64_str) % 4) if len(b64_str) % 4 else ''
        b64_str = b64_str.replace('-', '+').replace('_', '/')
        return base64.b64decode(b64_str, validate=True).decode('utf-8', errors='ignore')
    except Exception:
        return b64_str
def clean_node_line(line: str) -> str:
    """统一清理：去除中文、特殊字符、错误提示"""
    if not line:
        return ""
    line = re.sub(r'[\u4e00-\u9fa5\u200b\u3000\s]+', '', line)
    line = line.replace('＠', '@')
    error_keywords = ["订阅内容解析错误", "解析失败", "无效节点", "缺失字段", "过期", "已失效"]
    for kw in error_keywords:
        line = line.replace(kw, "")
    return line.strip()
def decode_b64_sub(text: str) -> str:
    text = text.strip()
    if not text:
        return ""
    clean = re.sub(r'\s+', '', text)
    if len(clean) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=_-]+$', clean):
        try:
            decoded = b64_safe_decode(clean)
            if '\n' in decoded:
                LOG.info(log_msg(f"✅ Base64解码成功，约{decoded.count('\n')+1}节点"))
                return decoded
        except Exception:
            pass
    lines = [l.strip() for l in text.split('\n') if l.strip() and not l.startswith('#')]
    LOG.info(log_msg(f"✅ 明文处理，{len(lines)}节点"))
    return '\n'.join(lines)
def is_private_ip(ip: str) -> bool:
    return bool(ip and CONFIG["filter"]["private_ip"].match(ip))
def is_cn_ip(ip: str) -> bool:
    if not ip or is_private_ip(ip):
        return False
    for pat in CONFIG["filter"]["cn_ip_ranges"]:
        if pat.match(ip):
            return True
    return False
def is_ip(addr: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', addr))
def _udp_resolve_a(domain: str, server: str, timeout: float) -> List[str]:
    """最小依赖的 UDP DNS A 记录查询（仅 IPv4）。超时或任何解析异常都抛给调用方回退。"""
    import struct
    try:
        txid = os.urandom(2)
        header = txid + struct.pack(">HHHHHH", 0x0100, 1, 0, 0, 0)  # flags: RD=1
        qname = b""
        for label in domain.split("."):
            if not label:
                continue
            qname += bytes([len(label)]) + label.encode("ascii")
        qname += b"\x00"
        question = qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
        req = header + question
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(req, (server, 53))
            data, _ = s.recvfrom(4096)
        if len(data) < 12:
            return []
        off = 12
        while off < len(data) and data[off] != 0:
            off += 1 + data[off]
        off += 1 + 4  # 跳过结尾 0x00 与 QTYPE/QCLASS
        ancount = struct.unpack(">H", data[4:6])[0]
        ips: List[str] = []
        for _ in range(ancount):
            if off < len(data) and (data[off] & 0xC0) == 0xC0:
                off += 2  # 压缩指针
            else:
                while off < len(data) and data[off] != 0:
                    off += 1 + data[off]
                off += 1
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and off + rdlen <= len(data) and rdlen == 4:
                ips.append(".".join(str(b) for b in data[off:off + 4]))
            off += rdlen
        return ips
    except Exception:
        return []

@lru_cache(maxsize=CONFIG["detection"]["dns"]["cache_size"])
def dns_resolve(domain: str) -> Tuple[bool, List[str]]:
    """解析域名到公网IP。
    修复B6：① 不再全局修改 socket.setdefaulttimeout（ThreadPoolExecutor 下存在线程竞态），
    改用线程 join(timeout) 包裹系统解析器；② 若配置了 dns.servers，优先对每个服务器做
    UDP DNS 查询（无第三方依赖），全部失败再回退系统解析器，保证配置生效且永不阻断。"""
    if not domain or domain == "未知":
        return False, []
    servers = CONFIG["detection"]["dns"]["servers"]
    timeout = CONFIG["detection"]["dns"]["timeout"]
    # 优先：对配置的 DNS 服务器做轻量 UDP A 查询（best-effort）
    for srv in servers:
        try:
            ips = _udp_resolve_a(domain, srv, timeout)
            valid = [ip for ip in ips if not is_private_ip(ip) and not is_cn_ip(ip)]
            if valid:
                return True, valid
        except Exception:
            continue
    # 回退：系统解析器（线程超时，避免全局 setdefaulttimeout 竞态）
    result: Dict = {}
    def _run():
        try:
            result["val"] = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        except Exception as e:  # noqa: BLE001
            result["err"] = e
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    if "val" in result:
        try:
            ips = sorted({info[4][0] for info in result["val"]})
            valid = [ip for ip in ips if not is_private_ip(ip) and not is_cn_ip(ip)]
            if valid:
                return True, valid
        except Exception:
            pass
    return False, []
# 修复B10：ipinfo.io 免费额度低、并发易 429 且会拖慢 CI。
# 默认不调用（无 IPINFO_TOKEN 时直接返回 unknown，仅损失住宅/机房细分加分，不影响主筛选）；
# 配置 token 时串行化并在单次运行配额内查询，杜绝超时/限流拖垮 CI。
_IPINFO_LOCK = threading.Lock()
_IPINFO_QUOTA = {"used": 0, "cap": 100}

@lru_cache(maxsize=1000)
def get_ip_type(ip: str) -> str:
    if is_private_ip(ip) or is_cn_ip(ip):
        return "unknown"
    token = os.getenv("IPINFO_TOKEN", "")
    if not token:
        return "unknown"
    with _IPINFO_LOCK:
        if _IPINFO_QUOTA["used"] >= _IPINFO_QUOTA["cap"]:
            return "unknown"
        _IPINFO_QUOTA["used"] += 1
    try:
        resp = SESSION.get(f"https://ipinfo.io/{ip}/json?token={token}", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if "hostname" in data and "dc" in data.get("hostname", "").lower():
            return "dc"
        if "org" in data and any(k in data["org"].lower() for k in ["residential", "home", "isp"]):
            return "residential"
        return "unknown"
    except Exception:
        return "unknown"
def process_remark(remark: str, proto: str) -> str:
    if not remark:
        return f"{proto}节点"
    try:
        decoded = unquote(remark)
        decoded = re.sub(r'[^\x20-\x7E\u4e00-\u9fa5]', '', decoded)
        b = decoded.encode('utf-8')
        if len(b) <= CONFIG["filter"]["max_remark_bytes"]:
            return decoded
        trunc = b[:CONFIG["filter"]["max_remark_bytes"]].decode('utf-8', errors='ignore')
        return trunc + "..." if len(trunc.encode()) + 3 <= CONFIG["filter"]["max_remark_bytes"] else trunc
    except Exception:
        return f"{proto}节点"
# ========== 协议解析（保持原逻辑，略微精简）==========
def parse_vmess(line: str) -> Optional[Dict]:
    try:
        b64_part = re.match(r'vmess://([A-Za-z0-9+/=]+)', line).group(1)[:1024]
        decoded = b64_safe_decode(b64_part)
        cfg = json.loads(re.sub(r'[\x00-\x1f\x7f-\x9f]', '', re.search(r'\{.*\}', decoded, re.DOTALL).group(0)))
        required = ["add", "port", "id"]
        if any(k not in cfg for k in required):
            return None
        uuid.UUID(cfg["id"])
        cfg["ps"] = process_remark(cfg.get("ps", ""), "VMess")
        cfg["port"] = validate_port(cfg.get("port"))
        return {
            "address": cfg["add"],
            "port": cfg["port"],
            "id": cfg["id"],
            "security_type": "tls" if cfg.get("tls") == "tls" else ("aead" if cfg.get("scy") in ["aes-128-gcm", "chacha20-ietf-poly1305"] else "none"),
            "sni": cfg.get("sni") or cfg.get("host") or cfg["add"],
            "ps": cfg["ps"]
        }
    except Exception:
        return None
def parse_vless(line: str) -> Optional[Dict]:
    try:
        core, remark = re.split(r'#', line[8:], 1) if '#' in line[8:] else (line[8:], "VLESS节点")
        remark = process_remark(remark, "VLESS")
        uuid_str, rest = core.split('@', 1)
        uuid.UUID(uuid_str)
        addr_port, param_str = (rest.split('?', 1) + [""])[:2]
        address, port_str = addr_port.split(':', 1)
        params = dict(p.lower().split('=', 1) for p in param_str.split('&') if '=' in p)
        security = params.get('security', 'tls')
        return {
            "address": address,
            "port": validate_port(port_str),
            "security_type": security,
            "sni": params.get('sni', address),
            "remarks": remark
        }
    except Exception:
        return None
def parse_trojan(line: str) -> Optional[Dict]:
    try:
        core, remark = re.split(r'#', line[9:], 1) if '#' in line[9:] else (line[9:], "Trojan节点")
        remark = process_remark(remark, "Trojan")
        password, rest = core.split('@', 1)
        addr_port, param_str = (rest.split('?', 1) + [""])[:2]
        address, port_str = addr_port.rsplit(':', 1)
        params = dict(p.lower().split('=', 1) for p in param_str.split('&') if '=' in p)
        return {
            "address": address,
            "port": validate_port(port_str),
            "password": password,
            "security_type": params.get('security', 'tls'),
            "sni": params.get('sni', address),
            "label": remark
        }
    except Exception:
        return None
def parse_ss(line: str) -> Optional[Dict]:
    try:
        core, remark = re.split(r'#', line[5:], 1) if '#' in line[5:] else (line[5:], "SS节点")
        remark = process_remark(remark, "SS")
        if '@' in core:
            auth_b64, addr = core.split('@', 1)
            auth = b64_safe_decode(auth_b64)
        else:
            auth = b64_safe_decode(core)
            auth, addr = auth.split('@', 1)
        address, port_str = addr.rsplit(':', 1)
        method, password = (auth.split(':', 1) + [CONFIG["filter"]["SS_DEFAULT_CIPHER"]])[:2]
        if method not in CONFIG["filter"]["SS_VALID_CIPHERS"]:
            return None
        return {
            "address": address,
            "port": validate_port(port_str),
            "method": method,
            "password": password,
            "security_type": "aead" if method in ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"] else "none",
            "remark": remark
        }
    except Exception:
        return None
def parse_hysteria(line: str) -> Optional[Dict]:
    try:
        core, remark = re.split(r'#', line[11:], 1) if '#' in line[11:] else (line[11:], "Hysteria节点")
        remark = process_remark(remark, "Hysteria")
        addr_part, param_str = (core.split('?', 1) + [""])[:2]
        address, port_str = addr_part.rsplit(':', 1)
        params = dict(p.lower().split('=', 1) for p in param_str.split('&') if '=' in p)
        auth = params.get('auth') or params.get('auth_str', '')
        if not auth:
            return None
        return {
            "address": address,
            "port": validate_port(port_str),
            "password": auth,
            "security_type": "tls" if params.get('tls', '1') == '1' else "none",
            "peer": params.get('peer', address),
            "label": remark
        }
    except Exception:
        return None
# 统一解析入口
PROTO_PARSERS = {
    "vmess": parse_vmess,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "hysteria": parse_hysteria,
}
def parse_node(line: str) -> Tuple[Optional[Dict], str]:
    clean = clean_node_line(line)
    if not clean:
        return None, ""
    for proto, parser in PROTO_PARSERS.items():
        if clean.startswith(f"{proto}://"):
            cfg = parser(line) # parser 已处理 remark
            if cfg:
                return cfg, proto
            else:
                return None, "" # 解析失败也返回空 proto
    return None, "" # 未知协议
# ========== 检测函数（优化后）==========
def probe_proxy_handshake(ip: str, port: int, proto: str, sni: str = "") -> Tuple[bool, str, float]:
    """GitHub(US)侧代理端点可达性探测 —— 仅作【评分信号】，绝不硬过滤。

    背景（评审§5.1）：GitHub 运行于境外网络，无法验证'该节点能否从中国绕过 GFW'。
    真正的可用性应在【客户端 url-test】验证（CI 已通过 SubConverter 注入
    url_test=https://cp.cloudflare.com/generate_204）。本函数只探测'从 GitHub 网络能否
    与该代理端点建立握手'，用于给'境外可达'节点小幅加分。

    降级保护：任何异常 / 超时 / 中国 IP 一律回退（返回 False，但节点不淘汰），
    仅当握手确实成功时返回 (True, ...)，用于加分。绝不误杀。"""
    if not ip or is_private_ip(ip):
        return False, "private", 0.0
    try:
        addr = socket.gethostbyname(ip)
    except Exception:
        return False, "dns_fail", 0.0
    if is_cn_ip(addr):
        return False, "cn_skip", 0.0
    timeout = min((CONFIG["detection"]["tcp_timeout"].get(proto, 5) or 5) + 2, 8)
    try:
        if proto in ("trojan", "vless", "vmess"):
            # TLS 握手探测（Trojan/tls 类真实可达性；Reality 也走 TLS）
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            start = time.time()
            with socket.create_connection((addr, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni or addr) as _tls:
                    _tls.do_handshake()
            return True, "tls_ok", time.time() - start
        else:
            # ss / hysteria 等：TCP 连通性退化探测（无 TLS 语义）
            start = time.time()
            with socket.create_connection((addr, port), timeout=timeout) as _sock:
                pass
            return True, "tcp_ok", time.time() - start
    except Exception:
        return False, "prescreen_pass", 0.0
def test_node_final(ip: str, port: int, proto: str) -> Tuple[bool, float, bool, str, float]:
    port = validate_port(port)
    if not ip or is_private_ip(ip):
        return False, 0.0, False, "private_ip", 0.0
    try:
        ip_addr = socket.gethostbyname(ip)
        if is_cn_ip(ip_addr):
            return False, 0.0, False, "cn_ip", 0.0
        success = 0
        times = []
        for _ in range(CONFIG["detection"]["tcp_retry"]):
            try:
                start = time.time()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(CONFIG["detection"]["tcp_timeout"].get(proto, 5))
                    if s.connect_ex((ip_addr, port)) == 0:
                        success += 1
                        times.append(time.time() - start)
            except Exception:
                pass
            time.sleep(0.1)
        avg_rt = sum(times) / len(times) if times else 0.0
        stability = success / CONFIG["detection"]["tcp_retry"]
        thresh = CONFIG["detection"]["rt_thresholds"].get(proto, {"min": 0.02, "max": 9})
        if avg_rt < thresh["min"] or avg_rt > thresh["max"]:
            return False, avg_rt, False, "rt_abnormal", stability
        # 注：真实"能否从中国绕过GFW"的可用性应在【客户端 url-test】验证（CI 已通过 SubConverter 注入
        # url_test=cloudflare generate_204）；此处仅做 GitHub 侧 TCP 连通粗筛，不构成质量评分。
        # GitHub 侧代理握手探测已移到 process_single_node_final 中（probe_proxy_handshake），
        # 仅作评分信号（outside_ok），不在此处做硬过滤，避免误杀节点。
        return True, avg_rt, True, "ok", stability
    except Exception:
        return False, 0.0, False, "dns_fail", 0.0
# ========== 评分与节点处理（优化后）==========
def calculate_node_score(proto: str, security: str, port: int, dns_ok: bool, outside_ok: bool,
                        response_time: float, is_cn: bool, stability: float, ip_type: str) -> int:
    rules = CONFIG["filter"]["score_rules"]
    score = 0
    if is_cn:
        score += rules["cn_ip"]
    if response_time < CONFIG["detection"]["rt_thresholds"][proto]["min"] or response_time > CONFIG["detection"]["rt_thresholds"][proto]["max"]:
        score += rules["response_time_abnormal"]
    score = max(score, 0)
    score += rules["protocol"].get(proto, 0)
    score += rules["security"].get(security, 0)
    score += rules["port"].get(port, rules["port"]["other"])
    score += rules["dns_valid"] if dns_ok else 0
    score += rules["http_valid"] if outside_ok else 0 # 不通不扣分，只通了加分
    score = max(score, 0)
    speed = rules["response_speed"][proto]
    score += speed["fast"] if response_time < 1 else speed["normal"] if response_time < 3 else speed["slow"]
    score += int(rules["stability"] * stability)
    score += rules["ip_type"].get(ip_type, 0)
    return min(max(score, 0), 100)
def process_single_node_final(node: Union[str, Dict]) -> Tuple[Optional[str], Dict, int]:
    raw_line = node["line"] if isinstance(node, dict) else node
    cfg, proto = parse_node(raw_line)
    if not cfg:
        return None, {}, 0
    address = cfg["address"]
    port = cfg["port"]
    domain = cfg.get("sni") or cfg.get("peer") or address
    security_type = cfg.get("security_type", "none")
    if is_private_ip(address):
        return None, {}, 0
    is_cn = is_cn_ip(address)
    dns_ok = dns_resolve(domain)[0] if domain and not is_ip(address) else True
    ip_type = get_ip_type(address)
    ok, rt, _, reason, stability = test_node_final(address, port, proto)
    if not ok:
        return None, {}, 0
    # 修复B2：GitHub 侧代理握手探测，仅作评分信号（outside_ok），绝不据此过滤
    outside_ok, outside_detail, _ = probe_proxy_handshake(address, port, proto, domain)
    score = calculate_node_score(proto, security_type, port, dns_ok, outside_ok, rt, is_cn, stability, ip_type)
    # 修复B1：此处不再按单节点自身分数算阈值过滤（原逻辑等于失效）；统一在 process_nodes_final 基于全体分布算一次动态阈值
    node_info = {
        "line": raw_line, "proto": proto, "ip": address, "port": port, "domain": domain,
        "security_type": security_type, "score": score, "response_time": rt, "dns_ok": dns_ok,
        "outside_ok": outside_ok, "is_cn": is_cn, "stability": stability, "ip_type": ip_type,
        "source_url": node.get("source_url", "") if isinstance(node, dict) else ""
    }
    LOG.info(f"✅ 通过预筛（{score}分） {address}:{port} ({proto}) RT:{rt:.2f}s 稳定性:{stability:.0%} outside:{outside_detail}")
    return raw_line, node_info, score
# ========== 去重（优化后）==========
def dedup_nodes_final(nodes: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []
    source_unique_count = {} # 新增：统计每个来源去重后剩余数量
   
    nodes.sort(key=lambda x: x["weight"], reverse=True)
    for node in nodes:
        cfg, proto = parse_node(node["line"])
        if cfg and proto:
            key = (cfg["address"], cfg["port"], proto)
            if key not in seen:
                seen.add(key)
                unique.append(node)
                url = node.get("source_url", "未知来源")
                source_unique_count[url] = source_unique_count.get(url, 0) + 1
   
    LOG.info(f"🔍 去重完成：原始{len(nodes)}条 → 去重后{len(unique)}条")
   
    # 新增：输出各来源去重后节点数量统计
    LOG.info("\n📊 去重后各数据源节点数量统计")
    total_original = len(nodes)
    total_unique = len(unique)
   
    # 遍历所有出现过的来源
    for url in set(node.get("source_url", "未知来源") for node in nodes):
        orig_count = sum(1 for n in nodes if n.get("source_url") == url) # 该来源原始数量
        uniq_count = source_unique_count.get(url, 0)
        retain_rate = (uniq_count / orig_count * 100) if orig_count > 0 else 0.0
        # 缩短URL显示（只显示域名+路径前缀）
        if '://' in url:
            parts = url.split('://', 1)[1].split('/', 1)
            short_url = parts[0] + (('/' + parts[1][:20] + '...') if len(parts) > 1 and len(parts[1]) > 20 else '')
        else:
            short_url = url[:40] + '...' if len(url) > 40 else url
       
        LOG.info(f"来源: {short_url}")
        LOG.info(f" 原始节点: {orig_count} 条 → 去重后剩余: {uniq_count} 条 (去重保留率: {retain_rate:.2f}%)")
        LOG.info("") # 空行分隔
   
    # 总体去重统计
    overall_rate = (total_unique / total_original * 100) if total_original > 0 else 0.0
    LOG.info(f"总体总结: 所有来源原始总计 {total_original} 条 → 去重后总计 {total_unique} 条 (总体去重保留率: {overall_rate:.2f}%)")
   
    return unique
# ========== 数据源与主流程（保持精简）==========
# 下方保留原函数（仅微调日志格式）
def fetch_source_data(url: str, weight: int) -> Tuple[List[str], int]:
    cache_dir = ".cache"
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_path = os.path.join(cache_dir, cache_key)
  
    if os.path.exists(cache_path):
        try:
            cache_mtime = os.path.getmtime(cache_path)
            if time.time() - cache_mtime < CONFIG["github"]["cache_ttl"]:
                with open(cache_path, "r", encoding="utf-8") as f:
                    lines = json.load(f)
                LOG.info(f"✅ 缓存加载 {url}（权重{weight}），节点 {len(lines)} 条")
                return lines, weight
        except (json.JSONDecodeError, OSError) as e:
            LOG.warning(f"⚠️ 缓存读取失败 {url}: {str(e)[:50]}，删除无效缓存")
            os.remove(cache_path)
  
    time.sleep(CONFIG["github"]["interval"])
  
    for retry in range(CONFIG["request"]["retry"]):
        try:
            try:
                resp = SESSION.get(
                    url,
                    timeout=CONFIG["request"]["timeout"],
                    verify=True,  # 修复B5：默认校验证书，避免中间人攻击（MITM）
                    headers={"Connection": "close"}
                )
            except requests.exceptions.SSLError as ssl_err:
                LOG.warning(f"⚠️ 证书校验失败，降级为不校验（存在 MITM 风险）: {url} - {str(ssl_err)[:60]}")
                resp = SESSION.get(
                    url,
                    timeout=CONFIG["request"]["timeout"],
                    verify=False,
                    headers={"Connection": "close"}
                )
            resp.raise_for_status()
          
            raw_content = resp.text
            if len(raw_content) < 100 and '404' not in raw_content:
                raise ValueError(f"拉取内容过短（{len(raw_content)}字符），可能被截断")
          
            LOG.debug(f"📝 拉取 {url} 原始内容长度：{len(raw_content)} 字符")
          
            raw_lines_before_decode = raw_content.split('\n')
            filtered_before_decode = []
            comment_count_first = 0
            empty_line_count_first = 0
          
            for l in raw_lines_before_decode:
                stripped_line = l.strip()
                if not stripped_line:
                    empty_line_count_first += 1
                    continue
                if stripped_line.startswith('#'):
                    comment_count_first += 1
                    continue
                filtered_before_decode.append(l)
          
            content_after_first_filter = '\n'.join(filtered_before_decode)
            LOG.info(f"📝 第一次过滤（解码前）：{url} 移除注释行{comment_count_first}行 | 空行{empty_line_count_first}行 | 剩余{len(filtered_before_decode)}行")
          
            content = decode_b64_sub(content_after_first_filter)
          
            raw_lines_after_decode = content.split('\n')
            lines = []
            comment_count_second = 0
            empty_line_count_second = 0
          
            for l in raw_lines_after_decode:
                stripped_line = l.strip()
                if not stripped_line:
                    empty_line_count_second += 1
                    continue
                if stripped_line.startswith('#'):
                    comment_count_second += 1
                    continue
                lines.append(stripped_line)
          
            LOG.info(f"📝 第二次过滤（解码后）：{url} 移除注释行{comment_count_second}行 | 空行{empty_line_count_second}行 | 剩余{len(lines)}行")
            if lines:
                LOG.debug(f"📝 {url} 有效节点示例（前3行）：{lines[:3]}")
          
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(lines, f, ensure_ascii=False)
                LOG.debug(f"✅ 缓存写入 {cache_path} 成功")
            except OSError as e:
                LOG.warning(f"⚠️ 缓存写入失败 {url}: {str(e)[:50]}")
          
            LOG.info(f"✅ 拉取成功 {url}（权重{weight}），最终有效节点 {len(lines)} 条")
            return lines, weight
        except Exception as e:
            error_msg = str(e)[:80]
            if retry < CONFIG["request"]["retry"] - 1:
                LOG.warning(f"⚠️ 拉取失败 {url}（重试 {retry+1}/{CONFIG['request']['retry']}）: {error_msg}")
                time.sleep(CONFIG["request"]["retry_delay"])
            else:
                LOG.error(f"❌ 拉取最终失败 {url}: {error_msg}")
                return [], weight
    return [], weight
def clean_expired_cache() -> None:
    cache_dir = ".cache"
    if not os.path.exists(cache_dir):
        return
    expire_seconds = CONFIG["github"]["cache_expire_days"] * 86400
    deleted = 0
  
    for file_name in os.listdir(cache_dir):
        file_path = os.path.join(cache_dir, file_name)
        try:
            if os.path.isfile(file_path):
                file_age = time.time() - os.path.getmtime(file_path)
                if file_age > expire_seconds:
                    os.remove(file_path)
                    deleted += 1
                    LOG.debug(f"🗑️ 删除过期缓存：{file_path}（{file_age/3600:.1f}小时）")
        except OSError as e:
            LOG.warning(f"⚠️ 缓存删除失败 {file_name}: {str(e)[:50]}")
  
    if deleted:
        LOG.info(f"🗑️ 清理过期缓存 {deleted} 个")
    else:
        LOG.debug(f"🗑️ 无过期缓存需要清理")
def validate_sources() -> bool:
    invalid = []
    pattern = re.compile(r'^https?://', re.IGNORECASE)
  
    for idx, src in enumerate(CONFIG["sources"], 1):
        url = src.get("url", "")
        weight = src.get("weight", 0)
        if not pattern.match(url):
            invalid.append(f"第{idx}个源：URL格式错误 {url}")
        if not isinstance(weight, int) or weight < 1:
            invalid.append(f"第{idx}个源：权重无效 {url}（权重{weight}）")
  
    if invalid:
        LOG.error("❌ 配置校验失败：")
        for err in invalid:
            LOG.error(f" - {err}")
        return False
    return True
def count_proto(lines: List[Union[str, Dict]]) -> Dict[str, int]:
    count = {"vmess":0, "vless":0, "trojan":0, "ss":0, "hysteria":0, "other":0}
    for line in lines:
        line_str = line["line"] if isinstance(line, dict) else line
        clean_line = clean_node_line(line_str)
        if clean_line.startswith('vmess://'):
            count["vmess"] +=1
        elif clean_line.startswith('vless://'):
            count["vless"] +=1
        elif clean_line.startswith('trojan://'):
            count["trojan"] +=1
        elif clean_line.startswith('ss://'):
            count["ss"] +=1
        elif clean_line.startswith('hysteria://'):
            count["hysteria"] +=1
        else:
            count["other"] +=1
    return count
def adjust_score_threshold(valid_nodes_info: List[Dict]) -> int:
    base_threshold = CONFIG["detection"]["score_threshold"]
    if not valid_nodes_info:
        return base_threshold
  
    scores = [n["score"] for n in valid_nodes_info if "score" in n]
    if not scores:
        return base_threshold
  
    avg_score = sum(scores)/len(scores)
    dynamic_threshold = max(40, min(75, int(avg_score * 0.5)))
  
    if dynamic_threshold != base_threshold:
        LOG.info(f"📊 动态调整阈值：{base_threshold} → {dynamic_threshold}（平均得分{avg_score:.1f}）")
  
    return dynamic_threshold
def fetch_all_sources() -> Tuple[List[Dict], Dict[str, Dict]]:
    all_nodes = []
    source_records = {}
  
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_source_data, src["url"], src["weight"]): src["url"] for src in CONFIG["sources"]}
        for future in as_completed(futures):
            url = futures[future]
            try:
                lines, weight = future.result()
                proto_count = count_proto(lines)
                source_records[url] = {
                    "original": lines,
                    "original_count": len(lines),
                    "weight": weight,
                    "proto_count": proto_count,
                    "retained_count": 0,
                    "retained_lines": []
                }
                all_nodes.extend([{"line": l, "weight": weight, "source_url": url} for l in lines])
            except Exception as e:
                LOG.error(f"❌ 处理源{url}异常：{str(e)[:50]}")
                source_records[url] = {
                    "original": [],
                    "original_count":0,
                    "weight":0,
                    "proto_count":count_proto([]),
                    "retained_count":0
                }
  
    LOG.info(f"\n📥 所有数据源拉取完成：累计原始节点 {len(all_nodes)} 条")
    return all_nodes, source_records
def process_nodes_final(unique_nodes: List[Dict]) -> Tuple[List[str], List[Dict]]:
    scored = []   # (line, node_info, score) 全部通过TCP预筛的节点
    total = len(unique_nodes)
    LOG.info(f"\n🔍 开始处理 {total} 个去重后节点（GitHub侧连通性粗筛，非中国侧可用性）")
  
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool"]) as executor:
        futures = [executor.submit(process_single_node_final, node) for node in unique_nodes]
        for idx, future in enumerate(as_completed(futures)):
            if idx % 10 == 0:
                progress = (idx / total) * 100 if total > 0 else 0
                LOG.info(f"⏳ 最终处理进度：{idx}/{total} ({progress:.1f}%)")
            try:
                line, node_info, score = future.result()
            except Exception as e:
                LOG.warning(f"⚠️ 节点处理异常: {str(e)[:50]}")
                continue
            if line:
                scored.append((line, node_info, score))
  
    # 基于全体节点分数计算【一次】动态阈值（修复B1：原先每个节点用自身分数算阈值，等于失效）
    threshold = adjust_score_threshold([{"score": s} for _, _, s in scored])
    valid_lines = [line for line, _, score in scored if score >= threshold]
    valid_nodes_info = [info for _, info, score in scored if score >= threshold]
  
    valid_nodes_info.sort(key=lambda x: x["score"], reverse=True)
    valid_lines_sorted = [node["line"] for node in valid_nodes_info]
  
    LOG.info(f"✅ 节点预筛完成（GitHub侧连通性粗筛，真实可用性请在客户端 url-test 验证）：共{len(valid_lines_sorted)}条（阈值{threshold}分）")
    return valid_lines_sorted, valid_nodes_info
def generate_final_stats(all_nodes: List[Dict], unique_nodes: List[Dict], valid_lines: List[str],
                        valid_nodes_info: List[Dict], start_time: float, source_records: Dict) -> None:
    excellent = [n for n in valid_nodes_info if n["score"] >= 90]
    good = [n for n in valid_nodes_info if 80 <= n["score"] < 90]
    qualified = [n for n in valid_nodes_info if 65 <= n["score"] < 80]
    proto_count = count_proto(valid_lines)
  
    def save_nodes(lines: List[str], filename: str, desc: str):
        if not lines:
            LOG.info(f"📄 {desc}为空，跳过保存")
            return
        try:
            encoded = base64.b64encode('\n'.join(lines).encode('utf-8')).decode('utf-8')
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(encoded)
            LOG.info(f"📄 {desc}保存至 {filename}（{len(lines)} 条，Base64编码）")
        except OSError as e:
            LOG.error(f"❌ {desc}保存失败: {str(e)[:50]}")
  
    save_nodes(valid_lines, 's1.txt', "所有有效节点（≥65分）")
  
    total_cost = time.time() - start_time
    avg_response_time = sum([n["response_time"] for n in valid_nodes_info]) / len(valid_nodes_info) if valid_nodes_info else 0
    avg_stability = sum([n["stability"] for n in valid_nodes_info]) / len(valid_nodes_info) if valid_nodes_info else 0
    outside_ok_rate = len([n for n in valid_nodes_info if n["outside_ok"]]) / len(valid_nodes_info) * 100 if valid_nodes_info else 0
    cn_ip_rate = len([n for n in valid_nodes_info if n["is_cn"]]) / len(valid_nodes_info) * 100 if valid_nodes_info else 0
  
    LOG.info(f"\n🏆 最终筛选报告：")
    LOG.info(f" ├─ 原始节点：{len(all_nodes)} 条 → 去重后：{len(unique_nodes)} 条 → 有效节点：{len(valid_lines)} 条")
    LOG.info(f" ├─ 节点分级：优质（≥90分）{len(excellent)}条 | 良好（80-89分）{len(good)}条 | 合格（65-79分）{len(qualified)}条")
    LOG.info(f" ├─ 协议分布：VLESS({proto_count['vless']}) | Trojan({proto_count['trojan']}) | VMess({proto_count['vmess']}) | SS({proto_count['ss']}) | Hysteria({proto_count['hysteria']})")
    LOG.info(f" ├─ 性能指标：平均响应 {avg_response_time:.2f}s | 平均稳定性 {avg_stability:.1%} | 境外握手通过率 {outside_ok_rate:.1f}% | 国内IP占比 {cn_ip_rate:.1f}%")
    LOG.info(f" └─ 总耗时：{total_cost:.2f} 秒 | 输出文件：s1.txt")
    # 新增来源统计
    generate_source_stats(source_records, valid_nodes_info)
# ========== 新增：各来源节点等级统计 ==========
def generate_source_stats(source_records: Dict[str, Dict], valid_nodes_info: List[Dict]) -> None:
    LOG.info("\n🏅 各数据源节点等级统计报告")
   
    # 统计每个来源的等级分布
    source_stats: Dict[str, Dict] = {}
    for node in valid_nodes_info:
        url = node.get("source_url", "未知来源")
        score = node["score"]
        if score >= 90:
            level = "优质 (≥90分)"
        elif score >= 80:
            level = "良好 (80-89分)"
        elif score >= 65:
            level = "合格 (65-79分)"
        else:
            level = "低分 (<65分)" # 理论上不会出现，已过滤
       
        if url not in source_stats:
            original = source_records.get(url, {}).get("original_count", 0)
            source_stats[url] = {
                "original": original,
                "retained": 0,
                "优质": 0,
                "良好": 0,
                "合格": 0
            }
       
        source_stats[url]["retained"] += 1
        if level == "优质 (≥90分)":
            source_stats[url]["优质"] += 1
        elif level == "良好 (80-89分)":
            source_stats[url]["良好"] += 1
        elif level == "合格 (65-79分)":
            source_stats[url]["合格"] += 1
   
    # 输出每个来源
    total_original = 0
    total_retained = 0
    total_excellent = 0
    total_good = 0
    total_qualified = 0
   
    for url, stats in source_stats.items():
        original = stats["original"]
        retained = stats["retained"]
        retain_rate = (retained / original * 100) if original > 0 else 0.0
       
        total_original += original
        total_retained += retained
        total_excellent += stats["优质"]
        total_good += stats["良好"]
        total_qualified += stats["合格"]
       
        short_url = url.split('://')[1] if '://' in url else url # 缩短显示
        LOG.info(f"来源: {short_url}")
        LOG.info(f" 原始节点: {original} 条 → 保留: {retained} 条 (保留率: {retain_rate:.2f}%)")
        LOG.info(f" ├─ 优质 (≥90分): {stats['优质']} 条")
        LOG.info(f" ├─ 良好 (80-89分): {stats['良好']} 条")
        LOG.info(f" └─ 合格 (65-79分): {stats['合格']} 条")
        LOG.info("")
   
    # 总体保留率
    total_rate = (total_retained / total_original * 100) if total_original > 0 else 0.0
    LOG.info("总体总结：")
    LOG.info(f" 所有来源原始总节点: {total_original} 条 → 总保留: {total_retained} 条 (总体保留率: {total_rate:.2f}%)")
    LOG.info(f" ├─ 优质: {total_excellent} 条")
    LOG.info(f" ├─ 良好: {total_good} 条")
    LOG.info(f" └─ 合格: {total_qualified} 条")
def main() -> None:
    start_time = time.time()
    LOG.info(f"🚀 开始终极节点筛选（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）")
  
    if not validate_sources():
        LOG.error("❌ 配置校验失败，退出")
        return
  
    clean_expired_cache()
  
    all_nodes, source_records = fetch_all_sources()
  
    unique_nodes = dedup_nodes_final(all_nodes)
  
    valid_lines, valid_nodes_info = process_nodes_final(unique_nodes)
  
    generate_final_stats(all_nodes, unique_nodes, valid_lines, valid_nodes_info, start_time, source_records)
    try:
        SESSION.close()
        LOG.info("🔌 关闭请求会话")
    except Exception as e:
        LOG.warning(f"⚠️ 会话关闭异常: {str(e)[:50]}")
  
    LOG.info("\n✅ 终极筛选完成！有效节点已保存至 s1.txt")
if __name__ == "__main__":
    main()
