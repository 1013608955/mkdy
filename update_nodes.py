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

# ========== 配置与初始化 ==========
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 核心配置（统一默认值，删除无意义常量别名）
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
        "thread_pool": 8,
        "dns": {"servers": ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"], "timeout":5, "cache_size":1000}
    },
    "filter": {
        "private_ip": re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|0\.0\.0\.0)"),
        "ports": range(1, 65535),
        "max_remark_bytes": 200,
        "DEFAULT_PORT": 443,  # 统一默认端口
        "SS_DEFAULT_CIPHER": "aes-256-gcm"  # 统一SS默认加密方式
    }
}

# 日志初始化
def init_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S")
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

# ========== 通用工具函数（复用重复逻辑） ==========
def validate_port(port: Union[str, int]) -> int:
    """校验并返回合法端口，默认443"""
    try:
        p = int(port)
        return p if p in CONFIG["filter"]["ports"] else CONFIG["filter"]["DEFAULT_PORT"]
    except (ValueError, TypeError):
        return CONFIG["filter"]["DEFAULT_PORT"]

def log_msg(content: str, line: str = "", proto: str = "") -> str:
    """日志格式化（保留所有图标输出）"""
    if "保留节点" in content:
        line_part = ""
    else:
        if "解析错误" in content or "过滤无效" in content or "空地址节点" in content:
            line_part = f"（{line}）" if line else ""
        else:
            safe_line = line[:20].encode('ascii', 'ignore').decode('ascii')
            line_part = f"（{safe_line}...）" if safe_line else ""
    proto_part = f"（{proto}）" if proto else ""
    return f"{content}{line_part}{proto_part}"

def b64_safe_decode(b64_str: str) -> str:
    """安全解码Base64（自动补全填充符，失败返回原字符串）"""
    try:
        b64_str = b64_str.rstrip('=')
        b64_str += '=' * (4 - len(b64_str) % 4) if len(b64_str) % 4 != 0 else ''
        return base64.b64decode(b64_str).decode('utf-8', errors='ignore')
    except Exception:
        return b64_str

def clean_special_chars(line: str) -> str:
    """通用字符清洗：移除不可见字符、全角@转半角"""
    if not line:
        return ""
    clean_line = re.sub(r'[\u200b\u3000\s]+', '', line)
    clean_line = clean_line.replace('＠', '@')
    return clean_line

def proto_preprocess(line: str, proto_prefix: str) -> Tuple[str, str]:
    """通用协议前置处理：清洗字符+拆分备注+提取核心内容"""
    clean_line = clean_special_chars(line)
    remark = f"{proto_prefix.upper()}节点"
    
    if '#' in clean_line:
        main_part, remark = clean_line.split('#', 1)
        remark = process_remark(remark, proto_prefix.upper())
    else:
        main_part = clean_line
    
    if not main_part.startswith(proto_prefix):
        raise ValueError(f"非{proto_prefix.upper()}节点格式")
    
    core_content = main_part[len(proto_prefix):].strip()
    if not core_content:
        raise ValueError(f"{proto_prefix.upper()}核心内容为空")
    
    return core_content, remark

def decode_b64_sub(text: str) -> str:
    """解码订阅内容"""
    original_text = text.strip()
    clean_for_b64 = re.sub(r'\s+', '', original_text)
    
    try:
        decoded = b64_safe_decode(clean_for_b64)
        decoded_line_count = len([l for l in decoded.split('\n') if l.strip()])
        LOG.info(log_msg(f"✅ Base64解码成功，解析出{decoded_line_count}个有效节点"))
        return decoded
    except Exception as e:
        LOG.info(log_msg(f"❌ Base64解码失败: {str(e)[:50]}"))
        cleaned_lines = [l.strip() for l in original_text.split('\n')]
        plain_line_count = len([l for l in cleaned_lines if l])
        LOG.info(log_msg(f"✅ 明文订阅处理完成，解析出{plain_line_count}个有效节点"))
        return '\n'.join(cleaned_lines)

def clean_node_content(line: str) -> str:
    """清洗节点内容"""
    if not line:
        return ""
    line = re.sub(r'[\u4e00-\u9fa5]', '', line)
    error_keywords = ["订阅内容解析错误", "解析失败", "无效节点", "缺失字段"]
    for keyword in error_keywords:
        line = line.replace(keyword, "")
    return line.strip()

def is_private_ip(ip: str) -> bool:
    """判断是否为私有IP"""
    return bool(ip and CONFIG["filter"]["private_ip"].match(ip))

@lru_cache(maxsize=CONFIG["detection"]["dns"]["cache_size"])
def dns_resolve(domain: str) -> bool:
    """DNS解析（增加重试）"""
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
        LOG.info(log_msg(f"⚠️ 域名{domain}解析失败（所有DNS服务器均失败）"))
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)

def process_remark(remark: str, proto: str) -> str:
    """处理节点备注（避免label too long崩溃）"""
    if not remark:
        return f"{proto}节点"
    try:
        decoded = unquote(remark)
        decoded = re.sub(r'[^\x20-\x7E\u4e00-\u9fa5]', '', decoded)
        b_remark = decoded.encode('utf-8')
        max_len = CONFIG["filter"]["max_remark_bytes"]
        
        if len(b_remark) <= max_len:
            return decoded
        
        # 安全截断
        trunc_len = max_len
        while trunc_len > 0:
            try:
                trunc = b_remark[:trunc_len].decode('utf-8')
                break
            except UnicodeDecodeError:
                trunc_len -= 1
        else:
            trunc = "截断失败"
        
        if len(trunc.encode('utf-8')) + 3 <= max_len:
            trunc += "..."
        LOG.info(log_msg(f"⚠️ {proto}备注超限，截断为：{trunc}", remark))
        return trunc
    except Exception as e:
        LOG.info(log_msg(f"⚠️ {proto}备注处理失败：{str(e)[:30]}", remark))
        return f"{proto}节点"

def validate_fields(fields: Dict, required: List[str], proto: str, line: str) -> bool:
    """字段校验：仅判断字段是否存在"""
    missing = [f for f in required if f not in fields]
    if missing:
        LOG.info(log_msg(f"📝 过滤无效{proto}节点：缺失{','.join(missing)}", line, proto))
        return False
    return True

def extract_ip_port(line: str) -> Tuple[Optional[str], str, int]:
    """提取IP/端口"""
    ip_match = re.search(r'@([\d\.a-zA-Z-]+):', line)
    ip = ip_match.group(1) if ip_match else None
    
    domain_match = re.search(r'sni=([^&]+)|host=([^&]+)', line, re.I)
    domain = next((g for g in domain_match.groups() if g), "") if domain_match else ""
    
    port_match = re.search(r':(\d+)', line)
    port = validate_port(port_match.group(1)) if port_match else CONFIG["filter"]["DEFAULT_PORT"]
    return ip, domain, port

# ========== 协议解析函数 ==========
def parse_vmess(line: str) -> Optional[Dict]:
    """解析VMess节点：精准提取Base64串，截断非Base64字符"""
    try:
        base64_match = re.match(r'^[A-Za-z0-9+/=]+', line[8:].strip())
        if not base64_match:
            raise ValueError("未提取到有效Base64字符段")
        
        vmess_part = base64_match.group(0)[:1024]
        decoded = b64_safe_decode(vmess_part)
        
        json_match = re.search(r'\{.*\}', decoded, re.DOTALL)
        if not json_match:
            raise ValueError("未提取到有效JSON配置")
        
        cfg = json.loads(re.sub(r'[\x00-\x1f\x7f-\x9f\u3000]', '', json_match.group(0)))
        if not validate_fields(cfg, ["add", "port", "id"], "VMess", line):
            return None
        
        # 默认值兜底
        cfg["ps"] = process_remark(cfg.get('ps', ''), "VMess")
        cfg["port"] = validate_port(cfg.get('port', CONFIG["filter"]["DEFAULT_PORT"]))
        cfg["aid"] = cfg.get('aid', 0)
        cfg["net"] = cfg.get('net', 'tcp')
        cfg["scy"] = cfg.get('scy', 'auto')
        cfg["tls"] = cfg.get('tls', 'none')
        cfg["host"] = cfg.get('host', cfg["add"])
        cfg["sni"] = cfg.get('sni', cfg["add"])

        return {
            "address": cfg["add"],
            "port": cfg["port"],
            "id": cfg["id"],
            "alterId": cfg["aid"],
            "security": cfg["scy"],
            "network": cfg["net"],
            "tls": cfg["tls"],
            "serverName": cfg["host"] or cfg["sni"],
            "ps": cfg["ps"]
        }
    except Exception as e:
        LOG.info(log_msg(f"❌ VMess解析错误: {str(e)}", line, "vmess"))
        return None

def parse_vless(line: str) -> Optional[Dict]:
    """解析VLESS节点"""
    try:
        core_content, remark = proto_preprocess(line, "vless://")
        vless_parts = core_content.split('?', 1)
        base_part = vless_parts[0]
        param_part = vless_parts[1] if len(vless_parts) > 1 else ''
        
        if '@' not in base_part:
            raise ValueError("缺失UUID@地址格式")
        
        uuid, addr_port = base_part.split('@', 1)
        if not uuid or not addr_port or ':' not in addr_port:
            raise ValueError("UUID/地址端口错误")
        
        address, port_str = addr_port.split(':', 1)
        port = validate_port(port_str)
        params = {}
        
        for p in param_part.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                k_lower = k.lower()
                if k_lower == "remarks":
                    v = process_remark(v, "VLESS")
                params[k_lower] = v
        
        cfg = {
            "uuid": uuid,
            "address": address,
            "port": port,
            "security": params.get('security', 'tls'),
            "sni": params.get('sni', address),
            "network": params.get('type', 'tcp'),
            "remarks": params.get('remarks', 'VLESS节点')
        }
        
        if not validate_fields(cfg, ["uuid", "address", "port"], "VLESS", line):
            return None
        return cfg
    except ValueError as e:
        LOG.info(log_msg(f"📝 过滤无效VLESS节点：{str(e)}", line, "vless"))
        return None
    except Exception as e:
        LOG.info(log_msg(f"❌ VLESS解析错误: {str(e)}", line, "vless"))
        return None

def parse_trojan(line: str) -> Optional[Dict]:
    """解析Trojan节点"""
    try:
        core_content, remark = proto_preprocess(line, "trojan://")
        trojan_parts = core_content.split('?', 1)
        trojan_part = trojan_parts[0]
        param_part = trojan_parts[1] if len(trojan_parts) > 1 else ''
        
        if '@' not in trojan_part:
            raise ValueError("缺失密码@地址格式")
        
        password, addr_port = trojan_part.split('@', 1)
        if not password or not addr_port or ':' not in addr_port:
            raise ValueError("密码/地址端口错误")
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        params = {}
        
        for p in param_part.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k.lower()] = v
        
        cfg = {
            "address": address,
            "port": port,
            "password": password,
            "sni": params.get('sni', address),
            "security": params.get('security', 'tls'),
            "label": remark
        }
        
        if not validate_fields(cfg, ["address", "port", "password"], "Trojan", line):
            return None
        return cfg
    except ValueError as e:
        LOG.info(log_msg(f"📝 过滤无效Trojan节点：{str(e)}", line, "trojan"))
        return None
    except Exception as e:
        LOG.info(log_msg(f"❌ Trojan解析错误: {str(e)}", line, "trojan"))
        return None

def parse_ss(line: str) -> Optional[Dict]:
    """解析SS节点：兼容标准/非主流格式"""
    try:
        ss_core, remark = proto_preprocess(line, "ss://")
        addr_port = ""
        decoded_auth = ""
        
        # 非主流格式（@在Base64外）
        if '@' in ss_core:
            base64_part, addr_port = ss_core.split('@', 1)
            decoded_auth = b64_safe_decode(base64_part)
        # 标准格式（@在Base64内）
        else:
            decoded_auth = b64_safe_decode(ss_core)
            if '@' not in decoded_auth:
                raise ValueError("标准格式但Base64内无@分隔符")
            decoded_auth, addr_port = decoded_auth.split('@', 1)
        
        # 校验地址端口
        if not addr_port or ':' not in addr_port:
            raise ValueError("地址端口格式错误（需为IP:端口/域名:端口）")
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        
        # 解析加密方式和密码
        if not decoded_auth:
            raise ValueError("加密方式/密码为空")
        
        if ':' not in decoded_auth:
            method = CONFIG["filter"]["SS_DEFAULT_CIPHER"]
            password = decoded_auth.strip()
        else:
            method, password = decoded_auth.split(':', 1)
            method = method.strip()
            password = password.strip()
            if not method or not password:
                raise ValueError("加密方式或密码为空")
        
        cfg = {
            "address": address.strip(),
            "port": port,
            "remark": remark,
            "method": method,
            "password": password
        }
        
        if not validate_fields(cfg, ["address", "port"], "SS", line):
            return None
        return cfg
    except ValueError as e:
        LOG.info(log_msg(f"📝 过滤无效SS节点：{str(e)}", line, "ss"))
        return None
    except Exception as e:
        LOG.info(log_msg(f"❌ SS解析错误: {str(e)}", line, "ss"))
        return None

def parse_hysteria(line: str) -> Optional[Dict]:
    """解析Hysteria节点"""
    try:
        core_content, remark = proto_preprocess(line, "hysteria://")
        hysteria_parts = core_content.split('?', 1)
        core_part = hysteria_parts[0]
        param_part = hysteria_parts[1] if len(hysteria_parts) > 1 else ''
        
        if '@' not in core_part:
            raise ValueError("缺失认证@地址格式")
        
        auth_part, addr_port = core_part.split('@', 1)
        if not auth_part or not addr_port or ':' not in addr_port:
            raise ValueError("认证/地址端口错误")
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        params = {}
        
        for p in param_part.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k.lower()] = v
        
        cfg = {
            "address": address,
            "port": port,
            "password": auth_part,
            "obfs": params.get('obfs', ''),
            "auth": params.get('auth', ''),
            "alpn": params.get('alpn', ''),
            "label": remark
        }
        
        if not validate_fields(cfg, ["address", "port", "password"], "Hysteria", line):
            return None
        return cfg
    except ValueError as e:
        LOG.info(log_msg(f"📝 过滤无效Hysteria节点：{str(e)}", line, "hysteria"))
        return None
    except Exception as e:
        LOG.info(log_msg(f"❌ Hysteria解析错误: {str(e)}", line, "hysteria"))
        return None

# ========== 节点处理逻辑 ==========
def test_node(ip: str, port: int, proto: str) -> bool:
    """检测节点可用性（精简socket逻辑）"""
    port = validate_port(port)
    if not ip or is_private_ip(ip):
        return False
    
    ip_addr = ""
    def _tcp_connect(timeout: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                return sock.connect_ex((ip_addr, port)) == 0
        except Exception:
            return False
    
    try:
        # DNS解析
        try:
            ip_addr = socket.gethostbyname(ip)
        except socket.gaierror:
            LOG.info(log_msg(f"⚠️ DNS解析失败: {ip}", proto=proto))
            return False
        
        # 基础TCP连接
        timeout = CONFIG["detection"]["tcp_timeout"].get(proto, 5)
        if not _tcp_connect(timeout):
            return False
        
        # 协议专属检测
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
        LOG.info(log_msg(f"⚠️ TCP检测失败: {str(e)[:30]}", proto=proto))
        return False

def process_single_node(node: Union[str, Dict]) -> Tuple[Optional[str], str, Optional[str], int, str]:
    """处理单个节点"""
    raw_line = node["line"] if isinstance(node, dict) else node
    source_url = node.get("source_url", "") if isinstance(node, dict) else ""
    
    try:
        if not raw_line:
            return None, "", None, CONFIG["filter"]["DEFAULT_PORT"], source_url
        
        clean_line = clean_node_content(raw_line)
        if not clean_line:
            LOG.info(log_msg(f"📝 过滤空节点", raw_line))
            return None, "", None, CONFIG["filter"]["DEFAULT_PORT"], source_url
        
        ip, domain, port = None, "", CONFIG["filter"]["DEFAULT_PORT"]
        cfg = None
        proto = ""
        
        # 协议路由
        if clean_line.startswith('vmess://'):
            proto, cfg = "vmess", parse_vmess(clean_line)
        elif clean_line.startswith('vless://'):
            proto, cfg = "vless", parse_vless(clean_line)
        elif clean_line.startswith('trojan://'):
            proto, cfg = "trojan", parse_trojan(clean_line)
        elif clean_line.startswith('ss://'):
            proto, cfg = "ss", parse_ss(clean_line)
        elif clean_line.startswith('hysteria://'):
            proto, cfg = "hysteria", parse_hysteria(clean_line)
        else:
            proto = "other"
            ip, domain, port = extract_ip_port(clean_line)
        
        # 提取节点信息
        if cfg and isinstance(cfg, dict):
            ip = cfg.get("address", ip)
            domain = cfg.get("serverName") or cfg.get("sni") or domain
            port = cfg.get("port", port)
        
        # 过滤逻辑
        if is_private_ip(ip):
            LOG.info(log_msg(f"📝 过滤私有IP：{ip}:{port}", clean_line, proto))
            return None, "", None, port, source_url
        
        if ip and cfg and not test_node(ip, port, proto):
            LOG.info(log_msg(f"📝 过滤不可用节点：{ip}:{port}", clean_line, proto))
            return None, "", None, port, source_url
        
        if domain and not dns_resolve(domain):
            LOG.info(log_msg(f"⚠️ 域名{domain}解析失败，但IP{ip}有效", clean_line, proto))
        
        if not ip and not domain:
            LOG.info(log_msg(f"📝 过滤空地址节点", clean_line, proto))
            return None, "", None, port, source_url
        
        LOG.info(f"✅ 保留节点: {ip or domain}:{port}（{proto}）")
        return clean_line, domain, ip, port, source_url
    except Exception as e:
        LOG.info(log_msg(f"❌ 节点处理错误: {str(e)}", raw_line, proto))
        return None, "", None, CONFIG["filter"]["DEFAULT_PORT"], source_url

def dedup_nodes(nodes: List[Dict]) -> List[Dict]:
    """节点去重（精简proto判断）"""
    seen = set()
    unique = []
    nodes.sort(key=lambda x: x["weight"], reverse=True)
    proto_list = ["vmess", "vless", "trojan", "ss", "hysteria"]
    
    for node in nodes:
        raw_line = node["line"]
        clean_line = clean_node_content(raw_line)
        ip = node.get("ip", "")
        port = node.get("port", CONFIG["filter"]["DEFAULT_PORT"])
        proto = "other"
        
        # 提前终止循环
        for p in proto_list:
            if clean_line.startswith(f"{p}://"):
                proto = p
                break
        
        key = f"{ip}:{port}:{proto}" if ip else f"{clean_line[:50]}:{proto}"
        if key not in seen:
            seen.add(key)
            unique.append({"line": raw_line, "source_url": node["source_url"]})
    return unique

# ========== 数据源与统计 ==========
def fetch_source_data(url: str, weight: int) -> Tuple[List[str], int]:
    """拉取订阅源数据"""
    cache_dir = ".cache"
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_path = os.path.join(cache_dir, cache_key)
    
    # 加载缓存
    if os.path.exists(cache_path):
        try:
            cache_mtime = os.path.getmtime(cache_path)
            if time.time() - cache_mtime < CONFIG["github"]["cache_ttl"]:
                with open(cache_path, "r", encoding="utf-8") as f:
                    lines = json.load(f)
                LOG.info(f"✅ 缓存加载 {url}（权重{weight}），节点 {len(lines)} 条")
                return lines, weight
        except (json.JSONDecodeError, OSError) as e:
            LOG.info(f"⚠️ 缓存读取失败 {url}: {str(e)[:50]}")
    
    time.sleep(CONFIG["github"]["interval"])
    
    # 拉取数据
    for retry in range(CONFIG["request"]["retry"]):
        try:
            resp = SESSION.get(url, timeout=CONFIG["request"]["timeout"], verify=False)
            resp.raise_for_status()
            content = decode_b64_sub(resp.text)
            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
            
            # 保存缓存
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(lines, f, ensure_ascii=False)
            except OSError as e:
                LOG.info(f"⚠️ 缓存写入失败 {url}: {str(e)[:50]}")
            
            LOG.info(f"✅ 拉取成功 {url}（权重{weight}），节点 {len(lines)} 条")
            return lines, weight
        except Exception as e:
            if retry < CONFIG["request"]["retry"] - 1:
                LOG.info(f"⚠️ 拉取失败 {url}（重试 {retry+1}）: {str(e)[:80]}")
                time.sleep(CONFIG["request"]["retry_delay"])
            else:
                LOG.info(f"❌ 拉取最终失败 {url}: {str(e)[:80]}")
                return [], weight
    return [], weight

def clean_expired_cache() -> None:
    """清理过期缓存"""
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
        except OSError as e:
            LOG.info(f"⚠️ 缓存删除失败 {file_name}: {str(e)[:50]}")
    
    if deleted:
        LOG.info(f"🗑️ 清理过期缓存 {deleted} 个")

def validate_sources() -> bool:
    """校验订阅源配置"""
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
        LOG.info("❌ 配置校验失败：")
        for err in invalid:
            LOG.info(f"   - {err}")
        return False
    return True

def count_proto(lines: List[Union[str, Dict]]) -> Dict[str, int]:
    """统计协议类型"""
    count = {"vmess":0, "vless":0, "trojan":0, "ss":0, "hysteria":0, "other":0}
    for line in lines:
        line_str = line["line"] if isinstance(line, dict) else line
        clean_line = clean_node_content(line_str)
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

def fetch_all_sources() -> Tuple[List[Dict], Dict[str, Dict]]:
    """拉取所有订阅源"""
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
                LOG.info(f"❌ 处理源{url}异常：{str(e)[:50]}")
                source_records[url] = {
                    "original": [],
                    "original_count":0,
                    "weight":0,
                    "proto_count":count_proto([]),
                    "retained_count":0
                }
    return all_nodes, source_records

def process_nodes(unique_nodes: List[Dict]) -> Tuple[List[str], List[Dict]]:
    """批量处理节点"""
    valid_lines = []
    valid_nodes = []
    seen_ips = set()
    seen_domains = set()
    total = len(unique_nodes)
    
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool"]) as executor:
        futures = [executor.submit(process_single_node, node) for node in unique_nodes]
        for idx, future in enumerate(as_completed(futures)):
            if idx % 10 == 0:
                progress = (idx / total) * 100 if total > 0 else 0
                LOG.info(f"⏳ 处理进度：{idx}/{total} ({progress:.1f}%)")
            try:
                line, domain, ip, port, source_url = future.result()
            except Exception as e:
                LOG.info(f"⚠️ 节点处理异常: {str(e)[:50]}")
                continue
            if not line:
                continue
            
            if domain in seen_domains or ip in seen_ips:
                continue
            if domain:
                seen_domains.add(domain)
            if ip:
                seen_ips.add(ip)
            
            valid_lines.append(line)
            valid_nodes.append({"line": line, "source_url": source_url})
    return valid_lines, valid_nodes

def generate_stats(all_nodes: List[Dict], unique_nodes: List[Dict], valid_lines: List[str], 
                   source_records: Dict, valid_nodes: List[Dict], start_time: float) -> None:
    """生成统计信息并保存结果"""
    # 更新保留记录
    for url in source_records:
        retained = [n for n in valid_nodes if n["source_url"] == url]
        source_records[url]["retained_count"] = len(retained)
        source_records[url]["retained_lines"] = retained
    
    # 排序（优先Reality/TLS节点）
    def sort_key(line: str) -> int:
        score = 0
        if "reality" in line.lower(): score += 100
        elif "tls" in line.lower(): score += 50
        if line.startswith('vless://'): score += 40
        elif line.startswith('trojan://'): score += 30
        elif line.startswith('vmess://'): score += 20
        elif line.startswith('hysteria://'): score += 10
        elif line.startswith('ss://'): score += 5
        return score
    
    valid_lines.sort(key=sort_key, reverse=True)
    LOG.info(f"✅ 最终有效节点：{len(valid_lines)} 条（Reality/TLS优先）")
    
    # 保存结果
    clean_valid_lines = [clean_node_content(line) for line in valid_lines if clean_node_content(line)]
    encoded = base64.b64encode('\n'.join(clean_valid_lines).encode('utf-8')).decode('utf-8') if clean_valid_lines else ""
    
    try:
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write(encoded)
        LOG.info(f"📄 订阅文件保存至 s1.txt（{len(clean_valid_lines)} 纯净节点）")
    except OSError as e:
        LOG.error(f"❌ 订阅文件保存失败: {str(e)[:50]}")
    
    # 输出统计
    LOG.info(f"\n📋 数据源统计：")
    for idx, src in enumerate(CONFIG["sources"], 1):
        url = src["url"]
        rec = source_records.get(url, {"original_count":0, "proto_count":count_proto([]), "retained_count":0})
        rate = f"{(rec['retained_count']/rec['original_count']*100):.2f}%" if rec['original_count']>0 else "0.00%"
        proto = rec["proto_count"]
        LOG.info(f"    {idx}. {url}")
        LOG.info(f"       - 📝 原始：{rec['original_count']} 条（VMess：{proto['vmess']} | VLESS：{proto['vless']} | Trojan：{proto['trojan']} | SS：{proto['ss']} | Hysteria：{proto['hysteria']}） | 保留：{rec['retained_count']} 条 | 保留率：{rate}")
    
    valid_proto = count_proto(clean_valid_lines)
    total_cost = time.time() - start_time
    total_original = len(all_nodes)
    retention_rate = f"{(len(clean_valid_lines)/total_original*100):.2f}%" if total_original>0 else "0.00%"
    
    LOG.info(f"\n📊 任务总结：")
    LOG.info(f"   - 原始节点：{total_original} 条 | 去重后：{len(unique_nodes)} 条 | 有效纯净节点：{len(clean_valid_lines)} 条")
    LOG.info(f"   - 协议分布：VMess({valid_proto['vmess']}) | VLESS({valid_proto['vless']}) | Trojan({valid_proto['trojan']}) | SS({valid_proto['ss']}) | Hysteria({valid_proto['hysteria']})")
    LOG.info(f"   - 整体保留率：{retention_rate}")
    LOG.info(f"   - 耗时：{total_cost:.2f} 秒")

def main() -> None:
    """主函数"""
    start_time = time.time()
    
    if not validate_sources():
        LOG.info("❌ 配置校验失败，退出")
        return
    
    clean_expired_cache()
    LOG.info(f"🚀 开始节点更新（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）")
    
    all_nodes, source_records = fetch_all_sources()
    LOG.info(f"\n📊 拉取完成，原始节点：{len(all_nodes)} 条")
    
    unique_nodes = dedup_nodes(all_nodes)
    LOG.info(f"🔍 去重后节点：{len(unique_nodes)} 条")
    
    valid_lines, valid_nodes = process_nodes(unique_nodes)
    generate_stats(all_nodes, unique_nodes, valid_lines, source_records, valid_nodes, start_time)
    
    # 关闭会话
    try:
        SESSION.close()
        LOG.info("🔌 关闭请求会话")
    except Exception as e:
        LOG.info(f"⚠️ 会话关闭异常: {str(e)[:50]}")
    
    LOG.info("✅ 节点更新任务完成！")

if __name__ == "__main__":
    main()
