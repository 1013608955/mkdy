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

# ========== 禁用urllib3的InsecureRequestWarning警告 ==========
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ====================== 日志初始化（保留图标，移除级别显示） ======================
def init_logger() -> logging.Logger:
    """初始化日志（保留图标输出，仅显示时间+消息）"""
    formatter = logging.Formatter(
        "%(asctime)s - %(message)s",  # 移除levelname，保留图标
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)  # 确保所有图标日志都能输出
    logger.addHandler(console_handler)
    logger.propagate = False
    return logger

LOG = init_logger()

# ====================== 核心配置（宽松验证+延长超时） ======================
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
    "request": {
        "timeout": 120,
        "retry_times": 2,  # 减少重试（SESSION已配置max_retries）
        "retry_delay": 2,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    "github": {
        "token": os.getenv("GITHUB_TOKEN", ""),
        "request_interval": 0.5,
        "cache_ttl": 3600,
        "cache_expire_days": 7  # 缓存过期天数
    },
    "detection": {
        "tcp_timeout": {
            "vmess/vless/trojan": 4,
            "ss": 2,
            "hysteria": 4
        },
        "tcp_retry": 1,
        "thread_pool_size": os.cpu_count() * 2 if os.cpu_count() else 8,  # 动态线程数
        "dns_servers": ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"],
        "dns_timeout": 5,
        "dns_cache_maxsize": 1000  # DNS缓存最大条数
    },
    "filter": {
        "private_ips": [
            re.compile(r"^192\.168\.\d+\.\d+$"),
            re.compile(r"^10\.\d+\.\d+\.\d+$"),
            re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$"),
            re.compile(r"^127\.\d+\.\d+\.\d+$"),
            re.compile(r"^0\.0\.0\.0$")
        ],
        "valid_ports": range(1, 65535),
        "max_remark_bytes": 120
    }
}

# ====================== 全局资源初始化 ======================
def init_request_session() -> requests.Session:
    """初始化请求会话（复用连接池）"""
    session = requests.Session()
    headers = {
        "User-Agent": CONFIG["request"]["user_agent"],
        "Accept": "application/vnd.github.v3.raw+json"
    }
    if CONFIG["github"]["token"]:
        headers["Authorization"] = f"token {CONFIG['github']['token']}"
    session.headers.update(headers)
    
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=10,
        pool_maxsize=20,
        max_retries=3  # SESSION层重试，避免双重重试
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

SESSION = init_request_session()

# ====================== 通用工具函数（核心封装） ======================
def validate_port(port: Union[str, int]) -> int:
    """通用端口校验（添加类型注解）"""
    try:
        port_int = int(port)
        return port_int if port_int in CONFIG["filter"]["valid_ports"] else 443
    except (ValueError, TypeError):
        return 443

def format_log_msg(content: str, line: str = "", proto_type: str = "") -> str:
    """通用日志内容格式化（精简重复拼接）"""
    line_part = f"（{line[:20]}...）" if line else ""
    proto_part = f"（{proto_type}）" if proto_type else ""
    return f"{content}{line_part}{proto_part}"

def clean_proto_str(s: str) -> str:
    """通用协议字符串清洗（替代重复的编码/过滤）"""
    if not s:
        return ""
    return s.encode('ascii', 'ignore').decode('ascii').strip()

def validate_proto_fields(fields: Dict, required: List[str], proto_type: str, line: str) -> bool:
    """通用必填字段校验（封装重复逻辑）"""
    missing = [f for f in required if f not in fields or not fields[f]]
    if missing:
        LOG.info(format_log_msg(f"📝 过滤无效{proto_type}节点：缺失必填字段 {','.join(missing)}", line))
        return False
    return True

def is_base64(s: str) -> bool:
    if not s or len(s) < 4:
        return False
    try:
        padding = 4 - len(s) % 4
        if padding != 4:
            s += '=' * padding
        base64.b64decode(s, validate=True)
        return True
    except (binascii.Error, ValueError, TypeError):
        return False

def decode_base64_sub(text: str) -> str:
    clean_text = re.sub(r'\s+', '', text.strip())
    if not clean_text:
        return text
    if is_base64(clean_text):
        try:
            padding = 4 - len(clean_text) % 4
            if padding != 4:
                clean_text += '=' * padding
            decoded = base64.b64decode(clean_text).decode('utf-8', errors='ignore')
            LOG.info(format_log_msg(f"✅ Base64解码成功，解析出明文内容（长度：{len(decoded)}）"))
            return decoded
        except (binascii.Error, ValueError) as e:
            LOG.info(format_log_msg(f"❌ Base64解码失败: {str(e)[:50]}"))
            return text
    else:
        return text

def is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    for pattern in CONFIG["filter"]["private_ips"]:
        if pattern.match(ip):
            return True
    return False

@lru_cache(maxsize=CONFIG["detection"]["dns_cache_maxsize"])
def test_domain_resolve(domain: str) -> bool:
    """DNS解析（改用lru_cache，提升性能）"""
    if not domain or domain == "未知":
        return False
    
    socket.setdefaulttimeout(CONFIG["detection"]["dns_timeout"])
    resolve_success = False
    for dns_server in CONFIG["detection"]["dns_servers"]:
        try:
            original_dns = socket.getaddrinfo
            def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
                return socket._socket.getaddrinfo(host, port, family, type, proto, flags)
            socket.getaddrinfo = custom_getaddrinfo
            socket.gethostbyname_ex(domain)
            resolve_success = True
            break
        except (socket.gaierror, socket.timeout):
            continue
        finally:
            socket.getaddrinfo = original_dns
    
    if not resolve_success:
        LOG.info(format_log_msg(f"⚠️ 域名{domain}解析失败（所有DNS源均失败）"))
    return resolve_success

def clean_vmess_json(decoded_str: str) -> str:
    """清理VMess JSON中的乱码"""
    try:
        json_match = re.search(r'\{.*\}', decoded_str, re.DOTALL)
        if json_match:
            clean_json = json_match.group(0)
            clean_json = re.sub(r'[\x00-\x1f\x7f-\x9f\u3000]', '', clean_json)
            return clean_json
        return decoded_str
    except Exception as e:
        LOG.info(format_log_msg(f"⚠️ VMess JSON清理失败: {str(e)[:50]}", decoded_str))
        return decoded_str

def count_protocol_nodes(lines: List[Union[str, Dict]]) -> Dict[str, int]:
    """统计节点列表中各协议的数量（精简初始化）"""
    proto_count = {k: 0 for k in ["vmess", "vless", "trojan", "ss", "hysteria", "other"]}
    for line in lines:
        line_str = line["line"] if isinstance(line, dict) else line
        if line_str.startswith('vmess://'):
            proto_count["vmess"] += 1
        elif line_str.startswith('vless://'):
            proto_count["vless"] += 1
        elif line_str.startswith('trojan://'):
            proto_count["trojan"] += 1
        elif line_str.startswith('ss://'):
            proto_count["ss"] += 1
        elif line_str.startswith('hysteria://'):
            proto_count["hysteria"] += 1
        else:
            proto_count["other"] += 1
    return proto_count

def process_remark(remark: str, proto_type: str) -> str:
    """通用备注处理：URL解码→截断→兜底"""
    if not remark:
        return f"{proto_type}节点"
    
    try:
        decoded_remark = unquote(remark)
        remark_bytes = decoded_remark.encode('utf-8')
        max_bytes = CONFIG["filter"]["max_remark_bytes"]
        
        if len(remark_bytes) <= max_bytes:
            return decoded_remark
        
        truncated_bytes = remark_bytes[:max_bytes]
        for back_step in range(0, 6):
            try:
                truncated_remark = truncated_bytes[:len(truncated_bytes)-back_step].decode('utf-8')
                break
            except UnicodeDecodeError:
                continue
        else:
            truncated_remark = remark_bytes[:max_bytes-5].decode('utf-8', errors='ignore')
        
        ellipsis = "..."
        if len(truncated_remark.encode('utf-8')) + len(ellipsis.encode('utf-8')) <= max_bytes:
            truncated_remark += ellipsis
        
        LOG.info(format_log_msg(f"⚠️ {proto_type}备注超限（原{len(remark_bytes)}字节），截断为{len(truncated_remark.encode('utf-8'))}字节", remark))
        return truncated_remark
    except Exception as e:
        LOG.info(format_log_msg(f"⚠️ {proto_type}备注处理失败：{str(e)[:30]}，使用默认备注", remark))
        return f"{proto_type}节点"

def extract_ip_port_from_line(line: str) -> Tuple[Optional[str], str, int]:
    """通用IP/端口提取"""
    ip = None
    port = 443
    domain = ""
    
    ip_match = re.search(r'@([\d\.a-zA-Z-]+):', line)
    if ip_match:
        ip = ip_match.group(1)
    
    domain_match = re.search(r'sni=([^&]+)|host=([^&]+)', line, re.IGNORECASE)
    if domain_match:
        domain = next((g for g in domain_match.groups() if g), "")
    
    port_match = re.search(r':(\d+)', line)
    if port_match:
        port = validate_port(port_match.group(1))
    
    return ip, domain, port

# ====================== 缓存清理函数 ======================
def clean_expired_cache() -> None:
    """清理过期缓存（保留最近N天）"""
    cache_dir = ".cache"
    if not os.path.exists(cache_dir):
        return
    now = time.time()
    expire_seconds = CONFIG["github"]["cache_expire_days"] * 86400
    deleted_count = 0
    
    for filename in os.listdir(cache_dir):
        filepath = os.path.join(cache_dir, filename)
        if os.path.getmtime(filepath) < now - expire_seconds:
            try:
                os.remove(filepath)
                deleted_count += 1
            except OSError as e:
                LOG.error(f"🗑️ 清理缓存失败 {filename}: {str(e)[:50]}")
    
    if deleted_count > 0:
        LOG.info(f"🗑️ 清理过期缓存 {deleted_count} 个文件")

# ====================== 配置校验函数 ======================
def validate_sources_config() -> bool:
    """校验数据源配置合法性"""
    valid_url_pattern = re.compile(r'^https?://', re.IGNORECASE)
    invalid_sources = []
    
    for idx, src in enumerate(CONFIG["sources"], 1):
        url = src.get("url", "")
        weight = src.get("weight", 0)
        
        if not valid_url_pattern.match(url):
            invalid_sources.append(f"第{idx}个源：URL格式错误 {url}")
        if not isinstance(weight, int) or weight < 1:
            invalid_sources.append(f"第{idx}个源：权重无效 {url}（权重{weight}）")
    
    if invalid_sources:
        LOG.info("❌ 数据源配置校验失败：")
        for err in invalid_sources:
            LOG.info(f"   - {err}")
        return False
    return True

# ====================== 协议解析函数（精简重复逻辑） ======================
def extract_vmess_config(vmess_line: str) -> Optional[Dict]:
    """解析VMess协议节点（复用通用函数）"""
    try:
        vmess_part = clean_proto_str(vmess_line[8:])
        vmess_part = re.split(r'[@#]', vmess_part)[0].strip()
        vmess_part = re.sub(r'[^A-Za-z0-9+/=]', '', vmess_part)
        
        if not is_base64(vmess_part):
            raise ValueError("非Base64格式")
        
        padding = 4 - len(vmess_part) % 4
        if padding != 4:
            vmess_part += '=' * padding
        
        decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
        decoded = clean_vmess_json(decoded)
        cfg = json.loads(decoded)
        
        # 复用通用字段校验
        if not validate_proto_fields(cfg, ["add", "port", "id", "aid"], "VMess", vmess_line):
            return None
        
        cfg["ps"] = process_remark(cfg.get('ps', ''), "VMess")
        cfg["port"] = validate_port(cfg.get('port', 443))
        
        return {
            "address": cfg.get('add'),
            "port": cfg["port"],
            "id": cfg.get('id', ''),
            "alterId": cfg.get('aid', 0),
            "security": cfg.get('scy', 'auto'),
            "network": cfg.get('net', 'tcp'),
            "tls": cfg.get('tls', ''),
            "serverName": cfg.get('host') or cfg.get('sni', ''),
            "ps": cfg["ps"]
        }
    except (json.JSONDecodeError, binascii.Error, ValueError) as e:
        LOG.info(format_log_msg(f"❌ VMess解析错误: {str(e)[:50]}", vmess_line))
        return None
    except Exception as e:
        LOG.info(format_log_msg(f"❌ VMess未知解析错误: {str(e)[:50]}", vmess_line), exc_info=True)
        return None

def extract_vless_config(vless_line: str) -> Optional[Dict]:
    """解析VLESS协议节点（复用通用函数）"""
    try:
        vless_part = clean_proto_str(vless_line[8:])
        base_part, param_part = (vless_part.split('?') + [''])[:2]
        uuid_addr_port = base_part.split('@')
        
        # 基础校验
        if len(uuid_addr_port) < 2:
            raise ValueError("缺失UUID/地址/端口")
        
        uuid = uuid_addr_port[0].strip()
        addr_port = uuid_addr_port[1].strip()
        if not uuid or not addr_port or ':' not in addr_port:
            raise ValueError("UUID/地址端口格式错误")
        
        address, port_str = addr_port.split(':')
        port = validate_port(port_str)
        if not address:
            raise ValueError("地址为空")
        
        # 解析参数
        params = {}
        for param in param_part.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                k_lower = k.lower()
                if k_lower == "remarks":
                    v = process_remark(v, "VLESS")
                params[k_lower] = v
        
        # 封装返回结果
        cfg = {
            "uuid": uuid,
            "address": address,
            "port": port,
            "security": params.get('security', 'tls'),
            "sni": params.get('sni') or params.get('SNI', ''),
            "network": params.get('type', 'tcp') or params.get('Type', 'tcp'),
            "remarks": params.get('remarks', 'VLESS节点')
        }
        
        # 复用通用字段校验
        if not validate_proto_fields(cfg, ["uuid", "address", "port"], "VLESS", vless_line):
            return None
        
        return cfg
    except ValueError as e:
        LOG.info(format_log_msg(f"📝 过滤无效VLESS节点：{str(e)}", vless_line))
        return None
    except Exception as e:
        LOG.info(format_log_msg(f"❌ VLESS未知解析错误: {str(e)[:50]}", vless_line), exc_info=True)
        return None

def extract_trojan_config(trojan_line: str) -> Optional[Dict]:
    """解析Trojan协议节点（复用通用函数）"""
    try:
        label = ""
        if '#' in trojan_line:
            trojan_part, label = trojan_line.split('#', 1)
            label = process_remark(label, "Trojan")
        else:
            trojan_part = trojan_line
        
        trojan_part = clean_proto_str(trojan_part[8:])
        password_addr = trojan_part.split('?')[0]
        
        # 基础校验
        if '@' not in password_addr:
            raise ValueError("缺失密码@地址格式")
        
        password, addr_port = password_addr.split('@')
        if not password or not addr_port or ':' not in addr_port:
            raise ValueError("密码/地址端口格式错误")
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        if not address:
            raise ValueError("地址为空")
        
        # 解析参数
        params = {}
        if '?' in trojan_part:
            param_str = trojan_part.split('?')[1]
            for param in param_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v
        
        # 封装返回结果
        cfg = {
            "address": address,
            "port": port,
            "password": password,
            "sni": params.get('sni') or params.get('SNI', ''),
            "security": params.get('security', 'tls'),
            "label": label
        }
        
        # 复用通用字段校验
        if not validate_proto_fields(cfg, ["address", "port", "password"], "Trojan", trojan_line):
            return None
        
        return cfg
    except ValueError as e:
        LOG.info(format_log_msg(f"📝 过滤无效Trojan节点：{str(e)}", trojan_line))
        return None
    except Exception as e:
        LOG.info(format_log_msg(f"❌ Trojan未知解析错误: {str(e)[:50]}", trojan_line), exc_info=True)
        return None

def extract_ss_config(ss_line: str) -> Optional[Dict]:
    """解析SS协议节点（复用通用函数）"""
    try:
        ss_part = clean_proto_str(ss_line[5:])
        
        # Base64解码
        if is_base64(ss_part):
            padding = 4 - len(ss_part) % 4
            if padding != 4:
                ss_part += '=' * padding
            ss_part = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
        
        # 基础校验
        if '@' not in ss_part:
            raise ValueError("缺失@分隔符（密码@地址格式）")
        
        # 处理备注
        remark = ""
        if '#' in ss_part:
            ss_part, remark = ss_part.split('#', 1)
            remark = process_remark(remark, "SS")
        
        # 提取地址端口
        auth_part, addr_port_part = ss_part.split('@', 1)
        if not auth_part or not addr_port_part or ':' not in addr_port_part:
            raise ValueError("认证信息/地址端口格式错误")
        
        address, port_str = addr_port_part.rsplit(':', 1)
        port = validate_port(port_str)
        if not address:
            raise ValueError("地址为空")
        
        # 封装返回结果
        cfg = {
            "address": address.strip(),
            "port": port,
            "remark": remark,
            "method": auth_part.split(':')[0] if ':' in auth_part else ""
        }
        
        # 复用通用字段校验
        if not validate_proto_fields(cfg, ["address", "port"], "SS", ss_line):
            return None
        
        return cfg
    except (binascii.Error, ValueError) as e:
        LOG.info(format_log_msg(f"📝 过滤无效SS节点：{str(e)}", ss_line))
        return None
    except Exception as e:
        LOG.info(format_log_msg(f"❌ SS未知解析错误: {str(e)[:50]}", ss_line), exc_info=True)
        return None

def extract_hysteria_config(hysteria_line: str) -> Optional[Dict]:
    """解析Hysteria协议节点（复用通用函数）"""
    try:
        # 处理备注
        label = ""
        if '#' in hysteria_line:
            hysteria_part, label = hysteria_line.split('#', 1)
            label = process_remark(label, "Hysteria")
        else:
            hysteria_part = hysteria_line
        
        hysteria_core = clean_proto_str(hysteria_part[10:])
        
        # 基础校验
        if '@' not in hysteria_core:
            raise ValueError("缺失@分隔符（认证@地址格式）")
        
        # 解析参数
        params = {}
        if '?' in hysteria_core:
            hysteria_core, param_str = hysteria_core.split('?', 1)
            for param in param_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v
        
        # 提取地址端口
        auth_part, addr_port = hysteria_core.split('@', 1)
        if not auth_part or not addr_port or ':' not in addr_port:
            raise ValueError("认证信息/地址端口格式错误")
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        if not address:
            raise ValueError("地址为空")
        
        # 封装返回结果
        cfg = {
            "address": address,
            "port": port,
            "password": auth_part,
            "obfs": params.get('obfs', ''),
            "auth": params.get('auth', ''),
            "alpn": params.get('alpn', ''),
            "label": label
        }
        
        # 复用通用字段校验
        if not validate_proto_fields(cfg, ["address", "port", "password"], "Hysteria", hysteria_line):
            return None
        
        return cfg
    except ValueError as e:
        LOG.info(format_log_msg(f"📝 过滤无效Hysteria节点：{str(e)}", hysteria_line))
        return None
    except Exception as e:
        LOG.info(format_log_msg(f"❌ Hysteria未知解析错误: {str(e)[:50]}", hysteria_line), exc_info=True)
        return None

# ====================== 节点检测函数 ======================
def test_node_availability(ip: str, port: int, proto_type: str, proto_cfg: Optional[Dict] = None) -> bool:
    """宽松版节点检测（精简重复逻辑）"""
    port = validate_port(port)
    if not ip or is_private_ip(ip):
        return False

    # 第一步：快速TCP握手检测
    tcp_available = False
    try:
        # 动态获取超时时间
        timeout_map = CONFIG["detection"]["tcp_timeout"]
        tcp_timeout = timeout_map.get(f"{proto_type}", 3)
        if proto_type in ["vmess", "vless", "trojan"]:
            tcp_timeout = timeout_map["vmess/vless/trojan"]
        elif proto_type == "ss":
            tcp_timeout = timeout_map["ss"]
        elif proto_type == "hysteria":
            tcp_timeout = timeout_map["hysteria"]
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(tcp_timeout)
            if sock.connect_ex((ip, port)) == 0:
                tcp_available = True
    except (socket.gaierror, OSError) as e:
        LOG.info(format_log_msg(f"⚠️ TCP检测失败: {str(e)[:30]}", proto_type=proto_type))
        return False

    if not tcp_available:
        return False

    # 第二步：宽松版协议验证
    try:
        if proto_type in ["vmess", "vless", "trojan"]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(4)
                sock.connect((ip, port))
                sock.send(b"\x00")
                return True
        elif proto_type == "ss":
            return bool(proto_cfg and proto_cfg.get("address") and proto_cfg.get("port"))
        elif proto_type == "hysteria":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                    udp_sock.settimeout(4)
                    udp_sock.sendto(b"\x00", (ip, port))
                return True
            except:
                return True
        return True
    except (ConnectionRefusedError, OSError):
        return False
    except (socket.timeout, ConnectionResetError):
        return True
    except Exception as e:
        LOG.info(format_log_msg(f"⚠️ 协议验证异常: {str(e)[:30]}", proto_type=proto_type))
        return True

# ====================== 节点处理函数 ======================
def deduplicate_nodes(nodes: List[Dict]) -> List[Dict]:
    """按 IP+端口+协议 去重（精简逻辑）"""
    seen = set()
    unique_nodes = []
    
    # 先按权重排序
    nodes.sort(key=lambda x: x["weight"], reverse=True)
    
    for node in nodes:
        line = node["line"]
        ip = node.get("ip", "")
        port = node.get("port", 443)
        proto = ""
        
        if line.startswith('vmess://'):
            proto = "vmess"
        elif line.startswith('vless://'):
            proto = "vless"
        elif line.startswith('trojan://'):
            proto = "trojan"
        elif line.startswith('ss://'):
            proto = "ss"
        elif line.startswith('hysteria://'):
            proto = "hysteria"
        
        # 去重键
        key = f"{ip}:{port}:{proto}" if ip else f"{line[:50]}:{proto}"
        
        if key not in seen:
            seen.add(key)
            unique_nodes.append({
                "line": line,
                "source_url": node["source_url"]
            })
    
    return unique_nodes

def process_node(node_item: Union[str, Dict]) -> Tuple[Optional[str], str, Optional[str], int, str]:
    """处理单个节点（精简重复判断）"""
    # 兼容输入格式
    if isinstance(node_item, dict):
        line = node_item["line"]
        source_url = node_item["source_url"]
    else:
        line = node_item
        source_url = ""
    
    try:
        if not line:
            return None, "", None, 443, source_url
        
        ip, domain, port, remark = None, "", 443, ""
        proto_cfg = None
        proto_type = ""
        
        # 按协议解析
        if line.startswith('vmess://'):
            proto_type = "vmess"
            proto_cfg = extract_vmess_config(line)
            if proto_cfg:
                ip, domain, port, remark = proto_cfg["address"], proto_cfg["serverName"], proto_cfg["port"], proto_cfg["ps"]
        elif line.startswith('vless://'):
            proto_type = "vless"
            proto_cfg = extract_vless_config(line)
            if proto_cfg:
                ip, domain, port, remark = proto_cfg["address"], proto_cfg["sni"], proto_cfg["port"], proto_cfg["remarks"]
        elif line.startswith('trojan://'):
            proto_type = "trojan"
            proto_cfg = extract_trojan_config(line)
            if proto_cfg:
                ip, domain, port, remark = proto_cfg["address"], proto_cfg["sni"], proto_cfg["port"], proto_cfg["label"]
        elif line.startswith('ss://'):
            proto_type = "ss"
            proto_cfg = extract_ss_config(line)
            if proto_cfg:
                ip, domain, port, remark = proto_cfg["address"], "", proto_cfg["port"], proto_cfg["remark"]
        elif line.startswith('hysteria://'):
            proto_type = "hysteria"
            proto_cfg = extract_hysteria_config(line)
            if proto_cfg:
                ip, domain, port, remark = proto_cfg["address"], "", proto_cfg["port"], proto_cfg["label"]
        else:
            ip, domain, port = extract_ip_port_from_line(line)
            if '#' in line:
                remark = process_remark(line.split('#')[1], "其他")
            proto_type = "other"
        
        # 过滤私有IP（仅一次判断）
        if is_private_ip(ip):
            LOG.info(format_log_msg(f"📝 过滤私有IP节点：{ip}:{port}", line, proto_type))
            return None, "", None, 443, source_url
        
        # 可用性检测（仅一次调用）
        availability_result = True
        if ip and proto_cfg:
            availability_result = test_node_availability(ip, port, proto_type, proto_cfg)
        
        if ip and proto_cfg and not availability_result:
            LOG.info(format_log_msg(f"📝 过滤不可用节点：{ip}:{port}（端口拒绝连接）", line, proto_type))
            return None, "", None, 443, source_url
        elif ip and proto_cfg and not availability_result:
            LOG.info(format_log_msg(f"⚠️ 协议验证异常，但保留：{ip}:{port}", line, proto_type))
        
        # DNS解析警告（不过滤）
        if domain and not test_domain_resolve(domain):
            LOG.info(format_log_msg(f"⚠️ 域名{domain}解析失败，但IP{ip}检测通过", line, proto_type))
        
        # 空地址过滤
        if not ip and not domain:
            LOG.info(format_log_msg(f"📝 过滤空地址节点", line, proto_type))
            return None, "", None, 443, source_url
        
        LOG.info(format_log_msg(f"✅ 保留节点: {ip or domain}:{port}", line, proto_type))
        return line, domain, ip, port, source_url
    except (ValueError, OSError) as e:
        LOG.info(format_log_msg(f"❌ 节点处理错误: {str(e)[:50]}", line))
        return None, "", None, 443, source_url
    except Exception as e:
        LOG.info(format_log_msg(f"❌ 节点处理异常: {str(e)[:50]}", line), exc_info=True)
        return None, "", None, 443, source_url

# ====================== 数据源拉取函数 ======================
def fetch_source(url: str, weight: int) -> Tuple[List[str], int]:
    """拉取订阅源数据（精简重试逻辑）"""
    cache_dir = ".cache"
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_path = os.path.join(cache_dir, cache_key)
    
    # 读取缓存
    if os.path.exists(cache_path):
        cache_mtime = os.path.getmtime(cache_path)
        if time.time() - cache_mtime < CONFIG["github"]["cache_ttl"]:
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    lines = json.load(f)
                LOG.info(f"✅ 从缓存加载 {url}（权重{weight}），有效节点 {len(lines)} 条")
                return lines, weight
            except json.JSONDecodeError as e:
                LOG.info(f"❌ 缓存文件损坏 {url}: {str(e)[:50]}")
    
    # 控制请求频率
    time.sleep(CONFIG["github"]["request_interval"])
    
    # 重试拉取（精简逻辑）
    for retry in range(CONFIG["request"]["retry_times"]):
        try:
            resp = SESSION.get(url, timeout=CONFIG["request"]["timeout"], verify=False)
            resp.raise_for_status()
            decoded_content = decode_base64_sub(resp.text)
            lines = [l.strip() for l in decoded_content.split('\n') if l.strip() and not l.startswith('#')]
            
            # 写入缓存
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(lines, f, ensure_ascii=False)
            
            LOG.info(f"✅ 拉取成功 {url}（权重{weight}），有效节点 {len(lines)} 条")
            return lines, weight
        except (requests.exceptions.RequestException, TimeoutError) as e:
            error_msg = str(e)[:80]
            if retry < CONFIG["request"]["retry_times"] - 1:
                LOG.info(f"⚠️ 拉取失败 {url}（重试 {retry+1}）: {error_msg}")
                time.sleep(CONFIG["request"]["retry_delay"])
            else:
                LOG.info(f"❌ 拉取最终失败 {url}: {error_msg}")
                return [], weight
        except Exception as e:
            LOG.info(f"❌ 拉取异常 {url}: {str(e)[:50]}", exc_info=True)
            return [], weight
    
    return [], weight

# ====================== 主函数 ======================
def main() -> None:
    """主流程（整合所有优化）"""
    start_time = time.time()
    all_nodes: List[Dict] = []
    source_records: Dict[str, Dict] = {}
    
    # 前置检查
    if not validate_sources_config():
        LOG.info("❌ 配置校验失败，退出程序")
        return
    
    # 清理过期缓存
    clean_expired_cache()
    
    LOG.info(f"🚀 开始节点更新任务（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）")
    
    # 1. 多线程拉取所有订阅源
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(fetch_source, src["url"], src["weight"]): src["url"] for src in CONFIG["sources"]}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                lines, weight = future.result()
                proto_count = count_protocol_nodes(lines)
                source_records[url] = {
                    "original_lines": lines,
                    "original_count": len(lines),
                    "weight": weight,
                    "protocol_count": proto_count,
                    "retained_count": 0,
                    "retained_lines": []
                }
                # 加入总列表
                for line in lines:
                    all_nodes.append({
                        "line": line,
                        "weight": weight,
                        "source_url": url
                    })
            except Exception as e:
                LOG.info(f"❌ 处理订阅源{url}异常：{str(e)[:50]}", exc_info=True)
                source_records[url] = {
                    "original_lines": [],
                    "original_count": 0,
                    "weight": 0,
                    "protocol_count": count_protocol_nodes([]),
                    "retained_count": 0,
                    "retained_lines": []
                }
    
    # 2. 去重
    LOG.info(f"\n📊 拉取完成，原始节点总数：{len(all_nodes)} 条")
    unique_nodes = deduplicate_nodes(all_nodes)
    LOG.info(f"🔍 去重后节点总数：{len(unique_nodes)} 条")
    
    # 3. 处理节点
    valid_lines: List[str] = []
    valid_nodes_with_source: List[Dict] = []
    seen_ips = set()
    seen_domains = set()
    total_nodes = len(unique_nodes)
    
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool_size"]) as executor:
        futures = [executor.submit(process_node, node) for node in unique_nodes]
        for idx, future in enumerate(as_completed(futures)):
            if idx % 10 == 0:
                progress = (idx / total_nodes) * 100
                LOG.info(f"⏳ 处理进度：{idx}/{total_nodes} ({progress:.1f}%)")
            try:
                line, domain, ip, port, source_url = future.result()
            except Exception as e:
                LOG.info(f"⚠️ 节点处理异常: {str(e)[:50]}", exc_info=True)
                continue
            if not line:
                continue
            
            # 最终去重
            if domain and domain in seen_domains:
                continue
            if ip and ip in seen_ips:
                continue
            
            seen_domains.add(domain)
            seen_ips.add(ip)
            valid_lines.append(line)
            valid_nodes_with_source.append({
                "line": line,
                "source_url": source_url
            })
    
    # 4. 统计保留节点
    for url in source_records.keys():
        retained_lines = [node for node in valid_nodes_with_source if node["source_url"] == url]
        source_records[url]["retained_count"] = len(retained_lines)
        source_records[url]["retained_lines"] = retained_lines
    
    # 5. 排序
    def sort_by_priority(line: str) -> int:
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
    
    valid_lines.sort(key=sort_by_priority, reverse=True)
    LOG.info(f"✅ 最终有效节点数：{len(valid_lines)} 条（Reality/TLS优先）")
    
    # 6. 保存文件
    if valid_lines:
        combined = '\n'.join(valid_lines)
        encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write(encoded)
        LOG.info(f"📄 订阅文件已保存至 s1.txt（Base64编码，{len(valid_lines)} 个节点）")
    else:
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write("")
        LOG.info(f"ℹ️  无有效节点，创建空 s1.txt")
    
    # 7. 输出数据源统计
    LOG.info(f"\n📋 各数据源详细统计：")
    for idx, src in enumerate(CONFIG["sources"], 1):
        url = src["url"]
        record = source_records.get(url, {
            "original_count": 0,
            "protocol_count": count_protocol_nodes([]),
            "retained_count": 0
        })
        original_count = record["original_count"]
        proto_count = record["protocol_count"]
        retained_count = record["retained_count"]
        
        retention_rate = "0.00%" if original_count == 0 else f"{(retained_count / original_count) * 100:.2f}%"
        
        LOG.info(f"    {idx}. {url}")
        stat_line = (f"       - 📝 原始节点数：{original_count} 条 "
                     f"（VMess：{proto_count['vmess']} | VLESS：{proto_count['vless']} | Trojan：{proto_count['trojan']} | "
                     f"SS：{proto_count['ss']} | Hysteria：{proto_count['hysteria']} | 其他：{proto_count['other']}） | "
                     f"保留节点数：{retained_count} 条 | 保留率：{retention_rate}")
        LOG.info(stat_line)
    
    # 8. 输出任务统计
    total_cost = time.time() - start_time
    valid_proto_count = count_protocol_nodes(valid_lines)
    LOG.info(f"\n📊 任务完成统计：")
    LOG.info(f"   - 原始节点总数：{len(all_nodes)} 条")
    LOG.info(f"   - 去重后节点数：{len(unique_nodes)} 条")
    LOG.info(f"   - 最终有效节点：{len(valid_lines)} 条")
    LOG.info(f"   - 协议分布：VMess({valid_proto_count['vmess']}) | VLESS({valid_proto_count['vless']}) | Trojan({valid_proto_count['trojan']}) | SS({valid_proto_count['ss']}) | Hysteria({valid_proto_count['hysteria']})")
    LOG.info(f"   - 整体保留率：{(len(valid_lines)/len(all_nodes)*100):.2f}%" if len(all_nodes) > 0 else "   - 整体保留率：0.00%")
    LOG.info(f"   - 耗时：{total_cost:.2f} 秒")
    LOG.info(f"✅ 节点更新任务完成！")
    
    # 释放资源
    SESSION.close()
    LOG.info("🔌 关闭请求会话，释放资源")

if __name__ == "__main__":
    main()
