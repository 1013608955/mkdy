import requests
import re
import socket
import base64
import binascii
import os
import time
import hashlib
import logging
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import lru_cache
import urllib3
from typing import Dict, List, Tuple, Optional, Union
import json

# ========== 基础配置与初始化 ==========
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG: Dict = {
    "sources": [
        {"url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt", "weight": 5},
        {"url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt", "weight": 5},
        {"url": "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray", "weight": 4},
        {"url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt", "weight": 4},
        {"url": "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt", "weight": 3},
        {"url": "https://raw.githubusercontent.com/HakurouKen/free-node/main/public", "weight": 3},
        {"url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", "weight": 2}
    ],
    "request": {"timeout": 120, "retry": 2, "retry_delay": 2, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
    "github": {"token": os.getenv("GITHUB_TOKEN", ""), "interval": 0.5, "cache_ttl": 3600, "cache_expire_days": 7},
    "detection": {
        "tcp_timeout": {"vmess":4, "vless":4, "trojan":4, "ss":2, "hysteria":4},
        "tcp_retry": 1,
        "thread_pool": os.cpu_count() * 2 if os.cpu_count() else 8,
        "dns": {"servers": ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"], "timeout":5, "cache_size":1000}
    },
    "filter": {
        "private_ip": re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|0\.0\.0\.0)"),
        "ports": range(1, 65535),
        "max_remark_bytes": 200
    }
}

DNS_CACHE_MAXSIZE = CONFIG["detection"]["dns"]["cache_size"]

# ========== 日志优化：减少重复输出 ==========
def init_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)  # 调整为INFO级别，减少DEBUG冗余
    logger.propagate = False
    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        handler = logging.StreamHandler()
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    return logger

LOG = init_logger()

# 全局请求会话
def init_session() -> requests.Session:
    sess = requests.Session()
    headers = {"User-Agent": CONFIG["request"]["ua"], "Accept": "application/vnd.github.v3.raw+json"}
    if CONFIG["github"]["token"]:
        headers["Authorization"] = f"token {CONFIG['github']['token']}"
    sess.headers.update(headers)
    adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=3)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    return sess

SESSION = init_session()

# ========== 通用工具函数 ==========
def validate_port(port: Union[str, int]) -> int:
    try:
        p = int(port)
        return p if p in CONFIG["filter"]["ports"] else 443
    except (ValueError, TypeError):
        return 443

def log_msg(content: str, line: str = "", proto: str = "") -> str:
    if "保留节点" in content:
        line_part = ""
    else:
        line_part = f"（{line[:50]}...）" if line else ""
    proto_part = f"（{proto}）" if proto else ""
    return f"{content}{line_part}{proto_part}"

def is_base64(s: str) -> bool:
    if not s or len(s) < 4:
        return False
    try:
        s = s.rstrip('=')
        s += '=' * (4 - len(s) % 4) if len(s) % 4 != 0 else ''
        base64.b64decode(s)
        return True
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False

def decode_b64_sub(text: str) -> str:
    original_text = text.strip()
    clean_for_b64 = re.sub(r'\s+', ' ', original_text)
    if is_base64(clean_for_b64.replace(' ', '')):
        try:
            clean_b64 = clean_for_b64.replace(' ', '')
            clean_b64 = clean_b64.rstrip('=')
            clean_b64 += '=' * (4 - len(clean_b64) % 4) if len(clean_b64) % 4 != 0 else ''
            decoded = base64.b64decode(clean_b64).decode('utf-8', errors='ignore')
            decoded_line_count = len([l for l in decoded.split('\n') if l.strip()])
            LOG.info(log_msg(f"✅ Base64解码成功，解析出{decoded_line_count}个有效节点"))
            return decoded
        except Exception as e:
            LOG.info(log_msg(f"❌ Base64解码失败: {str(e)[:50]}"))
            return original_text
    else:
        cleaned_lines = [l.strip() for l in original_text.split('\n') if l.strip()]
        plain_line_count = len(cleaned_lines)
        LOG.info(log_msg(f"✅ 明文订阅处理完成，解析出{plain_line_count}个有效节点"))
        return '\n'.join(cleaned_lines)

# ========== 协议特征检测 ==========
def is_vmess_content(content: str) -> bool:
    try:
        content_clean = content.replace(' ', '').rstrip('=')
        content_clean += '=' * (4 - len(content_clean) % 4) if len(content_clean) % 4 != 0 else ''
        decoded = base64.b64decode(content_clean).decode('utf-8', errors='ignore')
        cfg = json.loads(decoded)
        vmess_keys = ["add", "port", "id", "net", "type", "host", "path", "tls"]
        return any(key in cfg for key in vmess_keys)
    except:
        return False

# ========== 核心拆分逻辑（修复VLESS被拆+减少日志） ==========
def split_multi_nodes(line: str) -> List[str]:
    if not line:
        return []
    
    final_nodes = []
    remaining_content = line
    vmess_count = 0
    vless_count = 0

    # ========== 步骤1：优先提取VLESS（完整提取后移除） ==========
    while True:
        vless_start = remaining_content.find("vless://")
        if vless_start == -1:
            break
        # 找到VLESS节点的结束位置（下一个协议前缀或行尾）
        next_proto_pos = min(
            remaining_content.find("vmess://", vless_start) if remaining_content.find("vmess://", vless_start) != -1 else len(remaining_content),
            remaining_content.find("trojan://", vless_start) if remaining_content.find("trojan://", vless_start) != -1 else len(remaining_content),
            remaining_content.find("ss://", vless_start) if remaining_content.find("ss://", vless_start) != -1 else len(remaining_content),
            remaining_content.find("hysteria://", vless_start) if remaining_content.find("hysteria://", vless_start) != -1 else len(remaining_content)
        )
        vless_node = remaining_content[vless_start:next_proto_pos].strip()
        final_nodes.append(vless_node)
        vless_count += 1
        # 从剩余内容中移除该VLESS节点（避免内部字符被误识别）
        remaining_content = remaining_content[:vless_start] + remaining_content[next_proto_pos:]
    if vless_count > 0:
        LOG.info(f"📌 提取{ vless_count }个VLESS节点")

    # ========== 步骤2：优先提取VMess（完整提取后移除） ==========
    while True:
        # 先匹配vmess://前缀
        vmess_start = remaining_content.find("vmess://")
        if vmess_start != -1:
            next_proto_pos = min(
                remaining_content.find("vless://", vmess_start) if remaining_content.find("vless://", vmess_start) != -1 else len(remaining_content),
                remaining_content.find("trojan://", vmess_start) if remaining_content.find("trojan://", vmess_start) != -1 else len(remaining_content),
                remaining_content.find("ss://", vmess_start) if remaining_content.find("ss://", vmess_start) != -1 else len(remaining_content),
                remaining_content.find("hysteria://", vmess_start) if remaining_content.find("hysteria://", vmess_start) != -1 else len(remaining_content)
            )
            vmess_node = remaining_content[vmess_start:next_proto_pos].strip()
            final_nodes.append(vmess_node)
            vmess_count += 1
            remaining_content = remaining_content[:vmess_start] + remaining_content[next_proto_pos:]
        else:
            # 再匹配内容特征（无前缀的VMess）
            found = False
            for i in range(len(remaining_content) - 80):
                fragment = remaining_content[i:i+500]
                if is_vmess_content(fragment):
                    next_proto_pos = min(
                        remaining_content.find("vless://", i) if remaining_content.find("vless://", i) != -1 else len(remaining_content),
                        remaining_content.find("trojan://", i) if remaining_content.find("trojan://", i) != -1 else len(remaining_content),
                        remaining_content.find("ss://", i) if remaining_content.find("ss://", i) != -1 else len(remaining_content),
                        remaining_content.find("hysteria://", i) if remaining_content.find("hysteria://", i) != -1 else len(remaining_content)
                    )
                    vmess_node = remaining_content[i:next_proto_pos].strip()
                    final_nodes.append(vmess_node)
                    vmess_count += 1
                    remaining_content = remaining_content[:i] + remaining_content[next_proto_pos:]
                    found = True
                    break
            if not found:
                break
    if vmess_count > 0:
        LOG.info(f"📌 提取{ vmess_count }个VMess节点")

    # ========== 步骤3：提取其他协议（仅在剩余内容中匹配） ==========
    proto_rules = {
        "trojan": {"prefix": "trojan://", "min_len": 50, "required": "@"},
        "hysteria": {"prefix": "hysteria://", "min_len": 50, "required": None},
        "ss": {"prefix": "ss://", "min_len": 40, "required": None}
    }
    other_count = 0
    for proto, rule in proto_rules.items():
        prefix = rule["prefix"]
        pos = remaining_content.find(prefix)
        while pos != -1:
            next_pos = min(
                remaining_content.find("vless://", pos+len(prefix)) if remaining_content.find("vless://", pos+len(prefix)) != -1 else len(remaining_content),
                remaining_content.find("trojan://", pos+len(prefix)) if remaining_content.find("trojan://", pos+len(prefix)) != -1 else len(remaining_content),
                remaining_content.find("ss://", pos+len(prefix)) if remaining_content.find("ss://", pos+len(prefix)) != -1 else len(remaining_content),
                remaining_content.find("hysteria://", pos+len(prefix)) if remaining_content.find("hysteria://", pos+len(prefix)) != -1 else len(remaining_content)
            )
            node_str = remaining_content[pos:next_pos].strip()
            if len(node_str) >= rule["min_len"] and (not rule["required"] or rule["required"] in node_str):
                final_nodes.append(node_str)
                other_count += 1
            pos = remaining_content.find(prefix, next_pos)
    if other_count > 0:
        LOG.info(f"📌 提取{ other_count }个其他协议节点（Trojan/SS等）")

    if not final_nodes:
        final_nodes = [line.strip()]
    return final_nodes

def clean_node_content(line: str) -> str:
    if not line:
        return ""
    line = re.sub(r'[\u4e00-\u9fa5\u3000-\u303f\uff00-\uffef]', '', line)
    error_keywords = ["订阅内容解析错误", "解析失败", "无效节点", "缺失字段"]
    for keyword in error_keywords:
        line = line.replace(keyword, "")
    return line.strip()

def is_private_ip(ip: str) -> bool:
    return bool(ip and CONFIG["filter"]["private_ip"].match(ip))

@lru_cache(maxsize=DNS_CACHE_MAXSIZE)
def dns_resolve(domain: str) -> bool:
    if not domain or domain == "未知":
        return False
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(CONFIG["detection"]["dns"]["timeout"])
    try:
        for dns in CONFIG["detection"]["dns"]["servers"]:
            try:
                socket.gethostbyname_ex(domain)
                return True
            except (socket.gaierror, socket.timeout):
                continue
        LOG.info(log_msg(f"⚠️ 域名{domain}解析失败"))
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)

def process_remark(remark: str, proto: str) -> str:
    if not remark:
        return f"{proto}节点"
    try:
        decoded = unquote(remark)
        decoded = re.sub(r'[^\x20-\x7E\u4e00-\u9fa5@]', '', decoded)
        b_remark = decoded.encode('utf-8')
        max_len = CONFIG["filter"]["max_remark_bytes"]
        if len(b_remark) <= max_len:
            return decoded
        trunc = decoded[:max_len-3] + "..."
        LOG.info(log_msg(f"⚠️ {proto}备注超限，截断为：{trunc}", remark))
        return trunc
    except Exception as e:
        LOG.info(log_msg(f"⚠️ {proto}备注处理失败：{str(e)[:30]}", remark))
        return f"{proto}节点"

def validate_fields(fields: Dict, required: List[str], proto: str, line: str) -> bool:
    missing = [f for f in required if f not in fields]
    if missing:
        LOG.info(log_msg(f"📝 过滤无效{proto}节点：缺失{','.join(missing)}", line))
        return False
    return True

def extract_ip_port(line: str) -> Tuple[Optional[str], str, int]:
    ip_match = re.search(r'@([\d\.a-zA-Z-]+):', line)
    ip = ip_match.group(1) if ip_match else None
    domain_match = re.search(r'sni=([^&]+)|host=([^&]+)', line, re.I)
    domain = next((g for g in domain_match.groups() if g), "") if domain_match else ""
    port_match = re.search(r':(\d+)', line)
    port = validate_port(port_match.group(1)) if port_match else 443
    return ip, domain, port

# ========== 协议解析函数 ==========
def parse_vmess(line: str) -> Optional[Dict]:
    try:
        if line.startswith("vmess://"):
            vmess_raw = line[8:].strip()
        else:
            vmess_raw = line.strip()
        base64_match = re.match(r'^[A-Za-z0-9+/=]+', vmess_raw)
        if not base64_match:
            raise ValueError("无有效Base64段")
        vmess_part = base64_match.group(0)[:1024]
        if not is_base64(vmess_part):
            raise ValueError("Base64格式错误")
        vmess_part = vmess_part.rstrip('=')
        vmess_part += '=' * (4 - len(vmess_part) % 4) if len(vmess_part) % 4 != 0 else ''
        decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
        json_match = re.search(r'\{.*\}', decoded, re.DOTALL)
        if not json_match:
            raise ValueError("无有效JSON")
        decoded = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_match.group(0))
        cfg = json.loads(decoded)
        if not validate_fields(cfg, ["add", "port", "id"], "VMess", line):
            return None
        cfg["ps"] = process_remark(cfg.get('ps', ''), "VMess")
        cfg["port"] = validate_port(cfg.get('port', 443))
        return {
            "address": cfg["add"],
            "port": cfg["port"],
            "id": cfg["id"],
            "alterId": cfg.get('aid', 0),
            "security": cfg.get('scy', 'auto'),
            "network": cfg.get('net', 'tcp'),
            "tls": cfg.get('tls', 'none'),
            "serverName": cfg.get('host', cfg["add"]) or cfg.get('sni', cfg["add"]),
            "ps": cfg["ps"]
        }
    except Exception as e:
        LOG.info(log_msg(f"❌ VMess解析失败: {str(e)}", line))
        return None

def parse_vless(line: str) -> Optional[Dict]:
    try:
        vless_core = line[8:].strip()
        vless_parts = vless_core.split('?', 1)
        base_part = vless_parts[0]
        if '@' not in base_part:
            raise ValueError("缺失@分隔符")
        uuid, addr_port = base_part.split('@', 1)
        if not uuid or not addr_port or ':' not in addr_port:
            raise ValueError("地址端口格式错误")
        address, port_str = addr_port.split(':', 1)
        port = validate_port(port_str)
        params = {}
        if len(vless_parts) > 1:
            for param in vless_parts[1].split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v
        cfg = {
            "uuid": uuid,
            "address": address,
            "port": port,
            "security": params.get('security', 'tls'),
            "sni": params.get('sni', address),
            "network": params.get('type', 'tcp'),
            "remarks": process_remark(params.get('remarks', ''), "VLESS")
        }
        if not validate_fields(cfg, ["uuid", "address", "port"], "VLESS", line):
            return None
        return cfg
    except Exception as e:
        LOG.info(log_msg(f"❌ VLESS解析失败: {str(e)}", line))
        return None

def parse_trojan(line: str) -> Optional[Dict]:
    try:
        trojan_core = line[8:].strip()
        trojan_parts = trojan_core.split('?', 1)
        base_part = trojan_parts[0]
        if '@' not in base_part:
            raise ValueError("缺失@分隔符")
        password, addr_port = base_part.split('@', 1)
        if not password or not addr_port or ':' not in addr_port:
            raise ValueError("地址端口格式错误")
        address, port_str = addr_port.split(':', 1)
        port = validate_port(port_str)
        params = {}
        if len(trojan_parts) > 1:
            for param in trojan_parts[1].split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v
        cfg = {
            "address": address,
            "port": port,
            "password": password,
            "sni": params.get('sni', address),
            "security": params.get('security', 'tls'),
            "label": process_remark(params.get('label', ''), "Trojan")
        }
        if not validate_fields(cfg, ["address", "port", "password"], "Trojan", line):
            return None
        return cfg
    except Exception as e:
        LOG.info(log_msg(f"❌ Trojan解析失败: {str(e)}", line))
        return None

def parse_ss(line: str) -> Optional[Dict]:
    try:
        # 严格过滤：若内容是VMess/VLESS则跳过
        if is_vmess_content(line) or line.startswith(("vmess://", "vless://")):
            LOG.warning(log_msg(f"⚠️ 跳过疑似VMess/VLESS的SS解析", line))
            return None
        ss_part = line[5:].strip()
        if is_base64(ss_part.replace(' ', '')):
            try:
                ss_part = ss_part.replace(' ', '').rstrip('=')
                ss_part += '=' * (4 - len(ss_part) % 4) if len(ss_part) % 4 != 0 else ''
                ss_part = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
            except:
                LOG.info(log_msg(f"⚠️ SS Base64解码失败，尝试明文解析", line))
        ss_parts = ss_part.split('#', 1)
        ss_core = ss_parts[0]
        if '@' not in ss_core:
            parts = ss_core.rsplit(':', 1)
            if len(parts) != 2:
                raise ValueError("无有效地址端口")
            auth_part, addr_port = parts
        else:
            auth_part, addr_port = ss_core.split('@', 1)
        if ':' not in addr_port:
            raise ValueError("地址端口格式错误")
        address, port_str = addr_port.split(':', 1)
        port = validate_port(port_str)
        if ':' not in auth_part:
            raise ValueError("无有效加密方式")
        method, password = auth_part.split(':', 1)
        cfg = {
            "address": address.strip(),
            "port": port,
            "remark": process_remark(ss_parts[1] if len(ss_parts) > 1 else '', "SS"),
            "method": method,
            "password": password
        }
        if not validate_fields(cfg, ["address", "port", "method", "password"], "SS", line):
            return None
        return cfg
    except Exception as e:
        LOG.info(log_msg(f"❌ SS解析失败: {str(e)}", line))
        return None

def parse_hysteria(line: str) -> Optional[Dict]:
    try:
        hysteria_core = line[10:].strip()
        hysteria_parts = hysteria_core.split('?', 1)
        base_part = hysteria_parts[0]
        if '@' not in base_part:
            parts = base_part.rsplit(':', 1)
            if len(parts) != 2:
                raise ValueError("无有效地址端口")
            auth_part, addr_port = parts
        else:
            auth_part, addr_port = base_part.split('@', 1)
        if ':' not in addr_port:
            raise ValueError("地址端口格式错误")
        address, port_str = addr_port.split(':', 1)
        port = validate_port(port_str)
        params = {}
        if len(hysteria_parts) > 1:
            for param in hysteria_parts[1].split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v
        cfg = {
            "address": address,
            "port": port,
            "password": auth_part,
            "obfs": params.get('obfs', ''),
            "auth": params.get('auth', ''),
            "alpn": params.get('alpn', ''),
            "label": process_remark(params.get('label', ''), "Hysteria")
        }
        if not validate_fields(cfg, ["address", "port", "password"], "Hysteria", line):
            return None
        return cfg
    except Exception as e:
        LOG.info(log_msg(f"❌ Hysteria解析失败: {str(e)}", line))
        return None

# ========== 节点处理逻辑 ==========
def test_node(ip: str, port: int, proto: str) -> bool:
    port = validate_port(port)
    if not ip or is_private_ip(ip):
        return False
    try:
        timeout = CONFIG["detection"]["tcp_timeout"].get(proto, 5)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                ip_addr = socket.gethostbyname(ip)
            except socket.gaierror:
                LOG.info(log_msg(f"⚠️ DNS解析失败: {ip}", proto=proto))
                return False
            if sock.connect_ex((ip_addr, port)) != 0:
                return False
        if proto in ["vmess", "vless", "trojan"]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(4)
                sock.connect((ip_addr, port))
                sock.send(b"\x00")
        elif proto == "hysteria":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.settimeout(4)
                udp_sock.sendto(b"\x00", (ip_addr, port))
        return True
    except Exception as e:
        LOG.info(log_msg(f"⚠️ 节点连接失败: {str(e)[:30]}", proto=proto))
        return False

def process_single_node_raw(raw_line: str, source_url: str = "") -> List[Tuple[Optional[str], str, Optional[str], int, str]]:
    results = []
    split_nodes = split_multi_nodes(raw_line)
    if len(split_nodes) > 1:
        LOG.info(log_msg(f"🔍 拆分出{len(split_nodes)}个节点", raw_line))
    for node_line in split_nodes:
        try:
            if not node_line:
                continue
            clean_line = clean_node_content(node_line)
            if not clean_line:
                continue
            ip, domain, port = None, "", 443
            cfg = None
            proto = ""
            # 优先识别VMess/VLESS
            if clean_line.startswith('vless://'):
                proto = "vless"
                cfg = parse_vless(clean_line)
            elif is_vmess_content(clean_line) or clean_line.startswith('vmess://'):
                proto = "vmess"
                cfg = parse_vmess(clean_line)
            elif clean_line.startswith('trojan://'):
                proto = "trojan"
                cfg = parse_trojan(clean_line)
            elif clean_line.startswith('ss://'):
                proto = "ss"
                cfg = parse_ss(clean_line)
            elif clean_line.startswith('hysteria://'):
                proto = "hysteria"
                cfg = parse_hysteria(clean_line)
            else:
                proto = "other"
                ip, domain, port = extract_ip_port(clean_line)
            if cfg and isinstance(cfg, dict):
                ip = cfg.get("address", ip)
                domain = cfg.get("serverName") or cfg.get("sni") or domain or cfg.get("label")
                port = cfg.get("port", port)
            if is_private_ip(ip):
                continue
            if ip and cfg and not test_node(ip, port, proto):
                continue
            if domain and not dns_resolve(domain):
                continue
            if not ip and not domain:
                continue
            LOG.info(f"✅ 保留节点: {ip or domain}:{port}（{proto}）")
            results.append((clean_line, domain, ip, port, source_url))
        except Exception as e:
            LOG.info(log_msg(f"❌ 节点处理失败: {str(e)}", node_line))
            continue
    return results

def process_single_node(node: Union[str, Dict]) -> List[Tuple[Optional[str], str, Optional[str], int, str]]:
    raw_line = node["line"] if isinstance(node, dict) else node
    source_url = node.get("source_url", "") if isinstance(node, dict) else ""
    return process_single_node_raw(raw_line, source_url)

def dedup_nodes(nodes: List[Dict]) -> List[Dict]:
    seen_raw = set()
    raw_unique = []
    for node in nodes:
        raw_line = node["line"]
        proto = "other"
        if raw_line.startswith('vless://'):
            proto = "vless"
        elif is_vmess_content(raw_line) or raw_line.startswith('vmess://'):
            proto = "vmess"
        elif raw_line.startswith('trojan://'):
            proto = "trojan"
        elif raw_line.startswith('ss://'):
            proto = "ss"
        elif raw_line.startswith('hysteria://'):
            proto = "hysteria"
        key_raw = f"{raw_line[:50]}:{proto}"
        if key_raw not in seen_raw:
            seen_raw.add(key_raw)
            raw_unique.append(node)
    seen_detail = set()
    final_unique = []
    for node in raw_unique:
        raw_line = node["line"]
        split_nodes = split_multi_nodes(raw_line)
        for split_node in split_nodes:
            detail_key = ""
            if split_node.startswith('vless://'):
                parts = split_node[8:].split('@', 1)
                detail_key = f"vless:{parts[0]}" if parts else split_node[:50]
            elif is_vmess_content(split_node) or split_node.startswith('vmess://'):
                vmess_part = split_node[8:] if split_node.startswith('vmess://') else split_node
                base64_match = re.match(r'^[A-Za-z0-9+/=]+', vmess_part)
                detail_key = f"vmess:{base64_match.group(0)[:20]}" if base64_match else split_node[:50]
            elif split_node.startswith('trojan://'):
                parts = split_node[8:].split('@', 1)
                detail_key = f"trojan:{parts[0]}" if parts else split_node[:50]
            elif split_node.startswith('ss://'):
                parts = split_node[5:].split('@', 1)
                detail_key = f"ss:{parts[0]}" if parts else split_node[:50]
            elif split_node.startswith('hysteria://'):
                parts = split_node[10:].split('@', 1)
                detail_key = f"hysteria:{parts[0]}" if parts else split_node[:50]
            else:
                detail_key = split_node[:50]
            if detail_key not in seen_detail:
                seen_detail.add(detail_key)
                final_unique.append(node)
                break
    LOG.info(f"📌 去重统计：原始{len(nodes)}条 → 去重后{len(final_unique)}条")
    return final_unique

# ========== 数据源与主逻辑 ==========
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
                LOG.info(f"✅ 缓存加载 {url}（{len(lines)}个节点）")
                return lines, weight
        except Exception as e:
            LOG.info(f"⚠️ 缓存读取失败: {str(e)[:50]}")
    try:
        resp = SESSION.get(url, timeout=CONFIG["request"]["timeout"], verify=False)
        resp.raise_for_status()
        content = decode_b64_sub(resp.text)
        raw_lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
        seen_raw = set()
        raw_unique = []
        for line in raw_lines:
            key = line[:50]
            if key not in seen_raw:
                seen_raw.add(key)
                raw_unique.append(line)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(raw_unique, f, ensure_ascii=False)
        LOG.info(f"✅ 拉取成功 {url}：原始{len(raw_lines)}条 → 去重后{len(raw_unique)}条")
        return raw_unique, weight
    except Exception as e:
        LOG.info(f"❌ 拉取失败 {url}: {str(e)[:80]}")
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
            if os.path.isfile(file_path) and time.time() - os.path.getmtime(file_path) > expire_seconds:
                os.remove(file_path)
                deleted += 1
        except Exception as e:
            LOG.info(f"⚠️ 缓存删除失败 {file_name}: {str(e)[:50]}")
    if deleted > 0:
        LOG.info(f"🗑️ 清理过期缓存 {deleted} 个")

def validate_sources() -> bool:
    invalid = []
    pattern = re.compile(r'^https?://')
    for idx, src in enumerate(CONFIG["sources"], 1):
        url = src.get("url", "")
        weight = src.get("weight", 0)
        if not pattern.match(url):
            invalid.append(f"第{idx}个源：URL格式错误 {url}")
        if not isinstance(weight, int) or weight < 1:
            invalid.append(f"第{idx}个源：权重无效 {url}")
    if invalid:
        LOG.info("❌ 配置校验失败：")
        for err in invalid:
            LOG.info(f"   - {err}")
        return False
    return True

def count_proto(lines: List[Union[str, Dict]]) -> Dict[str, int]:
    count = {"vmess":0, "vless":0, "trojan":0, "ss":0, "hysteria":0, "other":0}
    for line in lines:
        line_str = line["line"] if isinstance(line, dict) else line
        if line_str.startswith('vless://'):
            count["vless"] +=1
        elif is_vmess_content(line_str) or line_str.startswith('vmess://'):
            count["vmess"] +=1
        elif line_str.startswith('trojan://'):
            count["trojan"] +=1
        elif line_str.startswith('ss://'):
            count["ss"] +=1
        elif line_str.startswith('hysteria://'):
            count["hysteria"] +=1
        else:
            count["other"] +=1
    return count

def fetch_all_sources() -> Tuple[List[Dict], Dict[str, Dict]]:
    all_nodes = []
    source_records = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_source_data, src["url"], src["weight"]): src for src in CONFIG["sources"]}
        for future in as_completed(futures):
            src = futures[future]
            url = src["url"]
            try:
                lines, weight = future.result()
                proto_count = count_proto(lines)
                source_records[url] = {
                    "original": len(lines),
                    "proto": proto_count,
                    "retained": 0
                }
                all_nodes.extend([{"line": l, "source_url": url, "weight": weight} for l in lines])
            except Exception as e:
                LOG.info(f"❌ 处理源{url}异常：{str(e)[:50]}")
                source_records[url] = {"original":0, "proto":count_proto([]), "retained":0}
    return all_nodes, source_records

def process_nodes(unique_nodes: List[Dict], source_records: Dict[str, Dict]) -> Tuple[List[str], List[Dict]]:
    valid_lines = []
    valid_nodes = []
    seen_ips = set()
    seen_domains = set()
    total = len(unique_nodes)
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool"]) as executor:
        futures = {executor.submit(process_single_node, node): node for node in unique_nodes}
        for idx, future in enumerate(as_completed(futures)):
            if idx % 10 == 0:
                LOG.info(f"⏳ 处理进度：{idx}/{total}（{idx/total*100:.1f}%）")
            try:
                node_results = future.result()
                for line, domain, ip, port, source_url in node_results:
                    if not line:
                        continue
                    if (ip and ip in seen_ips) or (domain and domain in seen_domains):
                        continue
                    if ip:
                        seen_ips.add(ip)
                    if domain:
                        seen_domains.add(domain)
                    valid_lines.append(line)
                    valid_nodes.append({"line": line, "source_url": source_url})
                    # 更新源的保留数
                    if source_url in source_records:
                        source_records[source_url]["retained"] += 1
            except Exception as e:
                LOG.info(f"⚠️ 节点处理异常: {str(e)[:50]}")
                continue
    LOG.info(f"✅ 处理完成：共保留{len(valid_lines)}个有效节点")
    return valid_lines, valid_nodes

def generate_stats(all_nodes: List[Dict], unique_nodes: List[Dict], valid_lines: List[str], source_records: Dict[str, Dict], start_time: float) -> None:
    valid_proto = count_proto(valid_lines)
    LOG.info(f"\n📊 最终统计：")
    LOG.info(f"   - 原始节点：{len(all_nodes)} 条")
    LOG.info(f"   - 去重后：{len(unique_nodes)} 条")
    LOG.info(f"   - 有效节点：{len(valid_lines)} 条")
    LOG.info(f"   - 协议分布：VMess({valid_proto['vmess']}) | VLESS({valid_proto['vless']}) | Trojan({valid_proto['trojan']}) | SS({valid_proto['ss']}) | Hysteria({valid_proto['hysteria']})")
    LOG.info(f"\n📋 各源详情：")
    for url, record in source_records.items():
        proto = record["proto"]
        retained = record["retained"]
        original = record["original"]
        rate = f"{retained/original*100:.2f}%" if original > 0 else "0.00%"
        LOG.info(f"   - {url}：")
        LOG.info(f"     原始：{original} 条（VMess:{proto['vmess']} VLESS:{proto['vless']} Trojan:{proto['trojan']} SS:{proto['ss']}）")
        LOG.info(f"     保留：{retained} 条 | 保留率：{rate}")
    total_cost = time.time() - start_time
    LOG.info(f"\n⏱️  耗时：{total_cost:.2f} 秒")
    # 保存订阅文件
    try:
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(valid_lines))
        LOG.info(f"📄 订阅文件已保存至 s1.txt（{len(valid_lines)}个节点）")
    except Exception as e:
        LOG.error(f"❌ 订阅文件保存失败: {str(e)[:50]}")

def main() -> None:
    start_time = time.time()
    LOG.info(f"🚀 开始节点更新（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）")
    if not validate_sources():
        return
    clean_expired_cache()
    all_nodes, source_records = fetch_all_sources()
    if not all_nodes:
        LOG.info("❌ 无有效节点可处理")
        return
    unique_nodes = dedup_nodes(all_nodes)
    valid_lines, valid_nodes = process_nodes(unique_nodes, source_records)
    generate_stats(all_nodes, unique_nodes, valid_lines, source_records, start_time)
    LOG.info("✅ 节点更新任务完成！")

if __name__ == "__main__":
    main()
