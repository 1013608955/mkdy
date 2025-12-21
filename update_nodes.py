import requests
import re
import socket
import base64
import json
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

# ========== 基础配置与初始化 ==========
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 精简配置结构，合并冗余配置项
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
        "max_remark_bytes": 120
    }
}

# 定义常量（修复lru_cache动态参数隐患）
DNS_CACHE_MAXSIZE = CONFIG["detection"]["dns"]["cache_size"]

# 日志初始化（精简逻辑）
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

# 全局请求会话（精简初始化）
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

# ========== 通用工具函数（极致精简+修复隐患） ==========
def validate_port(port: Union[str, int]) -> int:
    """校验并返回合法端口，默认443"""
    try:
        p = int(port)
        return p if p in CONFIG["filter"]["ports"] else 443
    except (ValueError, TypeError):
        return 443

def log_msg(content: str, line: str = "", proto: str = "") -> str:
    """精简日志格式化"""
    line_part = f"（{line[:20]}...）" if line else ""
    proto_part = f"（{proto}）" if proto else ""
    return f"{content}{line_part}{proto_part}"

def is_base64(s: str) -> bool:
    """简化Base64校验"""
    if not s or len(s) < 4:
        return False
    try:
        s += '=' * (4 - len(s) % 4) if len(s) % 4 != 0 else ''
        base64.b64decode(s, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False

def decode_b64_sub(text: str) -> str:
    """修复核心：保留明文的换行符，仅清理Base64的空白字符，解决拉取数量与手动下载不一致问题"""
    original_text = text.strip()
    # 先尝试判断是否是Base64编码（Base64订阅通常无换行，或只有少量空白）
    clean_for_b64 = re.sub(r'\s+', '', original_text)
    if is_base64(clean_for_b64):
        try:
            # Base64解码：解码后恢复为多行节点
            clean_for_b64 += '=' * (4 - len(clean_for_b64) % 4) if len(clean_for_b64) % 4 != 0 else ''
            decoded = base64.b64decode(clean_for_b64).decode('utf-8', errors='ignore')
            # 新增日志：打印解码后的节点数，方便核对
            decoded_line_count = len([l for l in decoded.split('\n') if l.strip()])
            LOG.info(log_msg(f"✅ Base64解码成功，解析出{decoded_line_count}个有效节点"))
            return decoded
        except Exception as e:
            LOG.info(log_msg(f"❌ Base64解码失败: {str(e)[:50]}"))
            return original_text  # 解码失败则返回原始内容
    else:
        # 明文订阅：仅清理每行的首尾空白，保留换行符（核心修复点）
        cleaned_lines = [l.strip() for l in original_text.split('\n')]
        # 新增日志：打印明文订阅的节点数，方便核对
        plain_line_count = len([l for l in cleaned_lines if l])
        LOG.info(log_msg(f"✅ 明文订阅处理完成，解析出{plain_line_count}个有效节点"))
        return '\n'.join(cleaned_lines)

def is_private_ip(ip: str) -> bool:
    """简化私有IP判断（单正则匹配）"""
    return bool(ip and CONFIG["filter"]["private_ip"].match(ip))

@lru_cache(maxsize=DNS_CACHE_MAXSIZE)  # 使用常量修复动态参数隐患
def dns_resolve(domain: str) -> bool:
    """精简DNS解析（修复全局socket超时修改隐患）"""
    if not domain or domain == "未知":
        return False
    # 保存原有超时，执行后还原
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
        # 还原全局socket超时
        socket.setdefaulttimeout(original_timeout)

def process_remark(remark: str, proto: str) -> str:
    """精简备注处理逻辑"""
    if not remark:
        return f"{proto}节点"
    try:
        decoded = unquote(remark)
        b_remark = decoded.encode('utf-8')
        max_len = CONFIG["filter"]["max_remark_bytes"]
        if len(b_remark) <= max_len:
            return decoded
        
        # 精简截断逻辑
        for step in range(0, 6):
            try:
                trunc = b_remark[:max_len-step].decode('utf-8')
                break
            except UnicodeDecodeError:
                continue
        else:
            trunc = b_remark[:max_len-5].decode('utf-8', errors='ignore')
        
        # 精简省略号处理
        if len(trunc.encode('utf-8')) + 3 <= max_len:
            trunc += "..."
        LOG.info(log_msg(f"⚠️ {proto}备注超限，截断为{len(trunc.encode('utf-8'))}字节", remark))
        return trunc
    except Exception as e:
        LOG.info(log_msg(f"⚠️ {proto}备注处理失败：{str(e)[:30]}", remark))
        return f"{proto}节点"

def validate_fields(fields: Dict, required: List[str], proto: str, line: str) -> bool:
    """精简字段校验"""
    missing = [f for f in required if not fields.get(f)]
    if missing:
        LOG.info(log_msg(f"📝 过滤无效{proto}节点：缺失{','.join(missing)}", line))
        return False
    return True

def extract_ip_port(line: str) -> Tuple[Optional[str], str, int]:
    """精简IP/端口/域名提取"""
    ip_match = re.search(r'@([\d\.a-zA-Z-]+):', line)
    ip = ip_match.group(1) if ip_match else None
    
    domain_match = re.search(r'sni=([^&]+)|host=([^&]+)', line, re.I)
    domain = next((g for g in domain_match.groups() if g), "") if domain_match else ""
    
    port_match = re.search(r':(\d+)', line)
    port = validate_port(port_match.group(1)) if port_match else 443
    return ip, domain, port

# ========== 协议解析函数（统一精简+修复索引越界隐患） ==========
def parse_vmess(line: str) -> Optional[Dict]:
    """解析VMess（精简逻辑+修复截断隐患）"""
    try:
        # 限制长度但保留合理范围（修复硬编码500可能截断有效内容）
        vmess_part = re.sub(r'[@#]', '', line[8:])[:1024]
        vmess_part = re.sub(r'[^A-Za-z0-9+/=]', '', vmess_part)
        if not is_base64(vmess_part):
            raise ValueError("非Base64格式")
        
        vmess_part += '=' * (4 - len(vmess_part) % 4) if len(vmess_part) % 4 != 0 else ''
        decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
        json_match = re.search(r'\{.*\}', decoded, re.DOTALL)
        decoded = json_match.group(0) if json_match else decoded
        decoded = re.sub(r'[\x00-\x1f\x7f-\x9f\u3000]', '', decoded)
        cfg = json.loads(decoded)
        
        if not validate_fields(cfg, ["add", "port", "id", "aid"], "VMess", line):
            return None
        
        cfg["ps"] = process_remark(cfg.get('ps', ''), "VMess")
        cfg["port"] = validate_port(cfg.get('port', 443))
        return {
            "address": cfg.get('add'), "port": cfg["port"], "id": cfg.get('id'),
            "alterId": cfg.get('aid', 0), "security": cfg.get('scy', 'auto'),
            "network": cfg.get('net', 'tcp'), "tls": cfg.get('tls', ''),
            "serverName": cfg.get('host') or cfg.get('sni', ''), "ps": cfg["ps"]
        }
    except Exception as e:
        LOG.info(log_msg(f"❌ VMess解析错误: {str(e)[:50]}", line))
        return None

def parse_vless(line: str) -> Optional[Dict]:
    """解析VLESS（修复索引越界隐患）"""
    try:
        vless_core = line[8:]
        # 安全拆分参数（避免无?时索引越界）
        vless_parts = vless_core.split('?', 1)
        base_part = vless_parts[0]
        param_part = vless_parts[1] if len(vless_parts) > 1 else ''
        
        if '@' not in base_part:
            raise ValueError("缺失UUID@地址格式")
        
        uuid, addr_port = base_part.split('@', 1)
        if not uuid or not addr_port or ':' not in addr_port:
            raise ValueError("UUID/地址端口错误")
        
        address, port_str = addr_port.split(':', 1)
        port = validate_port(port_str)
        # 安全解析参数
        params = {}
        for p in param_part.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                k_lower = k.lower()
                if k_lower == "remarks":
                    v = process_remark(v, "VLESS")
                params[k_lower] = v
        
        cfg = {"uuid": uuid, "address": address, "port": port, "security": params.get('security', 'tls'),
               "sni": params.get('sni', ''), "network": params.get('type', 'tcp'), "remarks": params.get('remarks', 'VLESS节点')}
        
        if not validate_fields(cfg, ["uuid", "address", "port"], "VLESS", line):
            return None
        return cfg
    except ValueError as e:
        LOG.info(log_msg(f"📝 过滤无效VLESS节点：{str(e)}", line))
        return None
    except Exception as e:
        LOG.info(log_msg(f"❌ VLESS解析错误: {str(e)[:50]}", line))
        return None

def parse_trojan(line: str) -> Optional[Dict]:
    """解析Trojan（修复语法+索引越界隐患）"""
    try:
        # 安全处理备注
        trojan_parts = line.split('#', 1)
        label = process_remark(trojan_parts[1], "Trojan") if len(trojan_parts) > 1 else ""
        trojan_core = trojan_parts[0]
        
        # 安全拆分参数和核心部分
        trojan_core_parts = trojan_core[8:].split('?', 1)
        trojan_part = trojan_core_parts[0]
        param_part = trojan_core_parts[1] if len(trojan_core_parts) > 1 else ''
        
        if '@' not in trojan_part:
            raise ValueError("缺失密码@地址格式")
        
        password, addr_port = trojan_part.split('@', 1)
        if not password or not addr_port or ':' not in addr_port:
            raise ValueError("密码/地址端口错误")
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        # 安全解析参数
        params = {}
        for p in param_part.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k.lower()] = v
        
        cfg = {"address": address, "port": port, "password": password, "sni": params.get('sni', ''),
               "security": params.get('security', 'tls'), "label": label or "Trojan节点"}
        
        if not validate_fields(cfg, ["address", "port", "password"], "Trojan", line):
            return None
        return cfg
    except ValueError as e:
        LOG.info(log_msg(f"📝 过滤无效Trojan节点：{str(e)}", line))
        return None
    except Exception as e:
        LOG.info(log_msg(f"❌ Trojan解析错误: {str(e)[:50]}", line))
        return None

def parse_ss(line: str) -> Optional[Dict]:
    """解析SS（精简逻辑）"""
    try:
        ss_part = line[5:]
        if is_base64(ss_part):
            ss_part += '=' * (4 - len(ss_part) % 4) if len(ss_part) % 4 != 0 else ''
            ss_part = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
        
        # 安全处理备注
        ss_parts = ss_part.split('#', 1)
        remark = process_remark(ss_parts[1], "SS") if len(ss_parts) > 1 else ""
        ss_core = ss_parts[0]
        
        if '@' not in ss_core:
            raise ValueError("缺失@分隔符")
        
        auth_part, addr_port = ss_core.split('@', 1)
        if not auth_part or not addr_port or ':' not in addr_port:
            raise ValueError("认证/地址端口错误")
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        method = auth_part.split(':')[0] if ':' in auth_part else ""
        
        cfg = {"address": address.strip(), "port": port, "remark": remark or "SS节点", "method": method}
        if not validate_fields(cfg, ["address", "port"], "SS", line):
            return None
        return cfg
    except ValueError as e:
        LOG.info(log_msg(f"📝 过滤无效SS节点：{str(e)}", line))
        return None
    except Exception as e:
        LOG.info(log_msg(f"❌ SS解析错误: {str(e)[:50]}", line))
        return None

def parse_hysteria(line: str) -> Optional[Dict]:
    """解析Hysteria（修复索引越界隐患）"""
    try:
        # 安全处理备注
        hysteria_parts = line.split('#', 1)
        label = process_remark(hysteria_parts[1], "Hysteria") if len(hysteria_parts) > 1 else ""
        hysteria_core = hysteria_parts[0]
        
        # 安全拆分参数和核心部分
        hysteria_core_parts = hysteria_core[10:].split('?', 1)
        core_part = hysteria_core_parts[0]
        param_part = hysteria_core_parts[1] if len(hysteria_core_parts) > 1 else ''
        
        if '@' not in core_part:
            raise ValueError("缺失认证@地址格式")
        
        auth_part, addr_port = core_part.split('@', 1)
        if not auth_part or not addr_port or ':' not in addr_port:
            raise ValueError("认证/地址端口错误")
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        # 安全解析参数
        params = {}
        for p in param_part.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k.lower()] = v
        
        cfg = {"address": address, "port": port, "password": auth_part, "obfs": params.get('obfs', ''),
               "auth": params.get('auth', ''), "alpn": params.get('alpn', ''), "label": label or "Hysteria节点"}
        
        if not validate_fields(cfg, ["address", "port", "password"], "Hysteria", line):
            return None
        return cfg
    except ValueError as e:
        LOG.info(log_msg(f"📝 过滤无效Hysteria节点：{str(e)}", line))
        return None
    except Exception as e:
        LOG.info(log_msg(f"❌ Hysteria解析错误: {str(e)[:50]}", line))
        return None

# ========== 节点检测与处理（修复cfg为None的隐患） ==========
def test_node(ip: str, port: int, proto: str) -> bool:
    """精简节点可用性检测"""
    port = validate_port(port)
    if not ip or is_private_ip(ip):
        return False
    
    # TCP握手检测
    try:
        timeout = CONFIG["detection"]["tcp_timeout"].get(proto, 3)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return False
    except Exception as e:
        LOG.info(log_msg(f"⚠️ TCP检测失败: {str(e)[:30]}", proto_type=proto))
        return False
    
    # 简易协议验证
    try:
        if proto in ["vmess", "vless", "trojan"]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(4)
                sock.connect((ip, port))
                sock.send(b"\x00")
        elif proto == "hysteria":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.settimeout(4)
                udp_sock.sendto(b"\x00", (ip, port))
        return True
    except:
        return True  # 宽松验证，超时/重置均视为可用

def process_single_node(node: Union[str, Dict]) -> Tuple[Optional[str], str, Optional[str], int, str]:
    """精简单节点处理（修复cfg为None的隐患）"""
    line = node["line"] if isinstance(node, dict) else node
    source_url = node.get("source_url", "") if isinstance(node, dict) else ""
    
    try:
        if not line:
            return None, "", None, 443, source_url
        
        ip, domain, port = None, "", 443
        cfg = None
        proto = ""
        
        # 协议解析路由
        if line.startswith('vmess://'):
            proto, cfg = "vmess", parse_vmess(line)
        elif line.startswith('vless://'):
            proto, cfg = "vless", parse_vless(line)
        elif line.startswith('trojan://'):
            proto, cfg = "trojan", parse_trojan(line)
        elif line.startswith('ss://'):
            proto, cfg = "ss", parse_ss(line)
        elif line.startswith('hysteria://'):
            proto, cfg = "hysteria", parse_hysteria(line)
        else:
            proto = "other"
            ip, domain, port = extract_ip_port(line)
        
        # 解析结果提取（修复cfg为None的隐患）
        if cfg and isinstance(cfg, dict):
            ip = cfg.get("address", ip)
            domain = cfg.get("serverName") or cfg.get("sni") or domain
            port = cfg.get("port", port)
        
        # 过滤逻辑
        if is_private_ip(ip):
            LOG.info(log_msg(f"📝 过滤私有IP：{ip}:{port}", line, proto))
            return None, "", None, 443, source_url
        
        # 仅当ip和cfg都存在时才检测
        if ip and cfg:
            if not test_node(ip, port, proto):
                LOG.info(log_msg(f"📝 过滤不可用节点：{ip}:{port}", line, proto))
                return None, "", None, 443, source_url
        
        if domain and not dns_resolve(domain):
            LOG.info(log_msg(f"⚠️ 域名{domain}解析失败，但IP{ip}有效", line, proto))
        
        if not ip and not domain:
            LOG.info(log_msg(f"📝 过滤空地址节点", line, proto))
            return None, "", None, 443, source_url
        
        LOG.info(log_msg(f"✅ 保留节点: {ip or domain}:{port}", line, proto))
        return line, domain, ip, port, source_url
    except Exception as e:
        LOG.info(log_msg(f"❌ 节点处理错误: {str(e)[:50]}", line))
        return None, "", None, 443, source_url

def dedup_nodes(nodes: List[Dict]) -> List[Dict]:
    """精简去重逻辑（修复next()无默认值隐患）"""
    seen = set()
    unique = []
    nodes.sort(key=lambda x: x["weight"], reverse=True)
    
    for node in nodes:
        line = node["line"]
        ip = node.get("ip", "")
        port = node.get("port", 443)
        # 安全获取协议类型（添加默认值）
        proto_list = ["vmess", "vless", "trojan", "ss", "hysteria"]
        proto = "other"
        for p in proto_list:
            if line.startswith(f"{p}://"):
                proto = p
                break
        # 生成去重键
        key = f"{ip}:{port}:{proto}" if ip else f"{line[:50]}:{proto}"
        
        if key not in seen:
            seen.add(key)
            unique.append({"line": line, "source_url": node["source_url"]})
    return unique

# ========== 数据源处理（修复缓存读写异常处理隐患） ==========
def fetch_source_data(url: str, weight: int) -> Tuple[List[str], int]:
    """精简源数据拉取（增强缓存异常处理）"""
    # 缓存处理
    cache_dir = ".cache"
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_path = os.path.join(cache_dir, cache_key)
    
    # 读取缓存（增强异常处理）
    if os.path.exists(cache_path):
        try:
            cache_mtime = os.path.getmtime(cache_path)
            if time.time() - cache_mtime < CONFIG["github"]["cache_ttl"]:
                with open(cache_path, "r", encoding="utf-8") as f:
                    lines = json.load(f)
                LOG.info(f"✅ 缓存加载 {url}（权重{weight}），节点 {len(lines)} 条")
                return lines, weight
        except (json.JSONDecodeError, OSError, PermissionError) as e:
            LOG.info(f"⚠️ 缓存读取失败 {url}: {str(e)[:50]}，重新拉取")
    
    # 限流
    time.sleep(CONFIG["github"]["interval"])
    
    # 重试拉取
    for retry in range(CONFIG["request"]["retry"]):
        try:
            resp = SESSION.get(url, timeout=CONFIG["request"]["timeout"], verify=False)
            resp.raise_for_status()
            content = decode_b64_sub(resp.text)
            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
            
            # 写入缓存（增强异常处理）
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(lines, f, ensure_ascii=False)
            except (OSError, PermissionError) as e:
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
    """精简缓存清理（增强异常处理）"""
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
        except (OSError, PermissionError) as e:
            LOG.info(f"⚠️ 缓存文件删除失败 {file_name}: {str(e)[:50]}")
    if deleted:
        LOG.info(f"🗑️ 清理过期缓存 {deleted} 个")

def validate_sources() -> bool:
    """精简源配置校验"""
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
        LOG.info("❌ 源配置校验失败：")
        for err in invalid:
            LOG.info(f"   - {err}")
        return False
    return True

def count_proto(lines: List[Union[str, Dict]]) -> Dict[str, int]:
    """精简协议统计"""
    count = {"vmess":0, "vless":0, "trojan":0, "ss":0, "hysteria":0, "other":0}
    for line in lines:
        line_str = line["line"] if isinstance(line, dict) else line
        if line_str.startswith('vmess://'):
            count["vmess"] +=1
        elif line_str.startswith('vless://'):
            count["vless"] +=1
        elif line_str.startswith('trojan://'):
            count["trojan"] +=1
        elif line_str.startswith('ss://'):
            count["ss"] +=1
        elif line_str.startswith('hysteria://'):
            count["hysteria"] +=1
        else:
            count["other"] +=1
    return count

# ========== 主函数拆分（修复global变量隐患） ==========
def fetch_all_sources() -> Tuple[List[Dict], Dict[str, Dict]]:
    """拉取所有源数据"""
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
                    "original": lines, "original_count": len(lines), "weight": weight,
                    "proto_count": proto_count, "retained_count": 0, "retained_lines": []
                }
                all_nodes.extend([{"line": l, "weight": weight, "source_url": url} for l in lines])
            except Exception as e:
                LOG.info(f"❌ 处理源{url}异常：{str(e)[:50]}", exc_info=True)
                source_records[url] = {"original": [], "original_count":0, "weight":0, "proto_count":count_proto([]), "retained_count":0}
    return all_nodes, source_records

def process_nodes(unique_nodes: List[Dict]) -> Tuple[List[str], List[Dict]]:
    """处理去重后的节点"""
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
                LOG.info(f"⚠️ 节点处理异常: {str(e)[:50]}", exc_info=True)
                continue
            if not line:
                continue
            
            # 最终去重
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
    """生成统计信息"""
    # 更新源保留统计
    for url in source_records:
        retained = [n for n in valid_nodes if n["source_url"] == url]
        source_records[url]["retained_count"] = len(retained)
        source_records[url]["retained_lines"] = retained
    
    # 排序（Reality/TLS优先）
    def sort_key(line: str) -> int:
        score = 0
        if "reality" in line.lower(): 
            score += 100
        elif "tls" in line.lower(): 
            score += 50
        if line.startswith('vless://'): 
            score += 40
        elif line.startswith('trojan://'): 
            score += 30
        elif line.startswith('vmess://'): 
            score += 20
        elif line.startswith('hysteria://'): 
            score += 10
        elif line.startswith('ss://'): 
            score += 5
        return score
    
    valid_lines.sort(key=sort_key, reverse=True)
    LOG.info(f"✅ 最终有效节点：{len(valid_lines)} 条（Reality/TLS优先）")
    
    # 保存文件（修复空字符串编码隐患）
    if valid_lines:
        content = '\n'.join(valid_lines)
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    else:
        encoded = ""
    try:
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write(encoded)
        LOG.info(f"📄 订阅文件保存至 s1.txt（{len(valid_lines)} 节点）")
    except (OSError, PermissionError) as e:
        LOG.error(f"❌ 订阅文件保存失败: {str(e)[:50]}")
    
    # 输出详细统计
    LOG.info(f"\n📋 数据源统计：")
    for idx, src in enumerate(CONFIG["sources"], 1):
        url = src["url"]
        rec = source_records.get(url, {"original_count":0, "proto_count":count_proto([]), "retained_count":0})
        original_count = rec["original_count"]
        rate = f"{(rec['retained_count']/original_count*100):.2f}%" if original_count > 0 else "0.00%"
        proto = rec["proto_count"]
        LOG.info(f"    {idx}. {url}")
        stat_line = (f"       - 📝 原始：{original_count} 条（VMess：{proto['vmess']} | VLESS：{proto['vless']} | "
                     f"Trojan：{proto['trojan']} | SS：{proto['ss']} | Hysteria：{proto['hysteria']}） | "
                     f"保留：{rec['retained_count']} 条 | 保留率：{rate}")
        LOG.info(stat_line)
    
    # 总统计
    valid_proto = count_proto(valid_lines)
    total_cost = time.time() - start_time
    total_original = len(all_nodes)
    retention_rate = f"{(len(valid_lines)/total_original*100):.2f}%" if total_original > 0 else "0.00%"
    
    LOG.info(f"\n📊 任务总结：")
    LOG.info(f"   - 原始节点：{total_original} 条 | 去重后：{len(unique_nodes)} 条 | 有效节点：{len(valid_lines)} 条")
    LOG.info(f"   - 协议分布：VMess({valid_proto['vmess']}) | VLESS({valid_proto['vless']}) | Trojan({valid_proto['trojan']}) | SS({valid_proto['ss']}) | Hysteria({valid_proto['hysteria']})")
    LOG.info(f"   - 整体保留率：{retention_rate}")
    LOG.info(f"   - 耗时：{total_cost:.2f} 秒")

def main() -> None:
    """主函数（修复所有隐患，无global变量）"""
    start_time = time.time()
    
    # 前置检查
    if not validate_sources():
        LOG.info("❌ 配置校验失败，退出")
        return
    
    # 初始化
    clean_expired_cache()
    LOG.info(f"🚀 开始节点更新（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）")
    
    # 核心流程
    all_nodes, source_records = fetch_all_sources()
    LOG.info(f"\n📊 拉取完成，原始节点：{len(all_nodes)} 条")
    
    unique_nodes = dedup_nodes(all_nodes)
    LOG.info(f"🔍 去重后节点：{len(unique_nodes)} 条")
    
    valid_lines, valid_nodes = process_nodes(unique_nodes)
    generate_stats(all_nodes, unique_nodes, valid_lines, source_records, valid_nodes, start_time)
    
    # 资源释放
    try:
        SESSION.close()
        LOG.info("🔌 关闭请求会话，释放资源")
    except Exception as e:
        LOG.info(f"⚠️ 会话关闭异常: {str(e)[:50]}")
    
    LOG.info("✅ 节点更新任务完成！")

if __name__ == "__main__":
    main()
