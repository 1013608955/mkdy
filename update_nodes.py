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

# ========== 禁用urllib3的InsecureRequestWarning警告（适配GitHub Actions） ==========
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ====================== 日志初始化（适配GitHub Actions实时输出） ======================
def init_logger():
    """初始化日志（实时输出，适配GitHub Actions）"""
    formatter = logging.Formatter(
        "%(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    # 移除重复日志处理器
    logger.propagate = False
    return logger

LOG = init_logger()

# ====================== 核心配置（宽松验证+延长超时） ======================
CONFIG = {
    "sources": [
        # 格式：{"url": 订阅源地址, "weight": 权重（越高越优先）}
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
        "retry_times": 3,  # GitHub Actions环境减少重试次数，加快运行
        "retry_delay": 2,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    "github": {
        "token": os.getenv("GITHUB_TOKEN", ""),  # 适配GitHub Actions环境变量
        "request_interval": 0.5,  # 缩短间隔，适配1小时调度
        "cache_ttl": 3600
    },
    "detection": {
        "tcp_timeout": {
            "vmess/vless/trojan": 4,  # 延长至4秒，适配海外慢节点
            "ss": 2,
            "hysteria": 4
        },
        "tcp_retry": 1,
        "thread_pool_size": 8,  # 并发从5→8，加快检测
        "dns_servers": ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"],
        "dns_timeout": 5,
        "dns_cache_ttl": 300
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
def init_request_session():
    """初始化请求会话（复用连接池，适配GitHub Actions）"""
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
        max_retries=3
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

SESSION = init_request_session()
DNS_CACHE = {}

# ====================== 通用工具函数 ======================
def validate_port(port):
    """通用端口校验"""
    try:
        port_int = int(port)
        return port_int if port_int in CONFIG["filter"]["valid_ports"] else 443
    except (ValueError, TypeError):
        return 443

def process_remark(remark, proto_type):
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
        
        LOG.info(f"⚠️ {proto_type}备注超限（原{len(remark_bytes)}字节），截断为{len(truncated_remark.encode('utf-8'))}字节：{truncated_remark[:20]}...")
        return truncated_remark
    except Exception as e:
        LOG.info(f"⚠️ {proto_type}备注处理失败：{str(e)[:30]}，使用默认备注")
        return f"{proto_type}节点"

def extract_ip_port_from_line(line):
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

def log_parse_error(proto_type, line, e):
    """通用解析失败日志"""
    LOG.info(f"⚠️ {proto_type}解析失败（{line[:20]}...）: {str(e)[:50]}")

def deduplicate_nodes(nodes):
    """按 IP+端口+协议 去重，保留高权重源节点"""
    seen = set()
    unique_nodes = []
    
    # 先按权重排序（高权重在前）
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
        
        # 去重键：IP+端口+协议（空IP跳过去重）
        if ip:
            key = f"{ip}:{port}:{proto}"
        else:
            key = f"{line[:50]}:{proto}"  # 无IP时按行内容去重
        
        if key not in seen:
            seen.add(key)
            unique_nodes.append({
                "line": node["line"],
                "source_url": node["source_url"]  # 保留数据源URL，用于后续统计
            })
    
    return unique_nodes

# ====================== 宽松版增强型节点可用性检测（核心优化） ======================
def test_node_availability(ip, port, proto_type, proto_cfg=None):
    """
    宽松版节点检测：仅过滤“明确拒绝连接”的节点，减少误判
    核心：端口通+不明确拒绝 → 保留；仅端口拒绝连接 → 过滤
    """
    port = validate_port(port)
    if not ip or is_private_ip(ip):
        return False

    # 第一步：快速TCP握手检测
    tcp_available = False
    try:
        # 动态获取超时时间
        timeout_map = CONFIG["detection"]["tcp_timeout"]
        if proto_type in ["vmess", "vless", "trojan"]:
            tcp_timeout = timeout_map["vmess/vless/trojan"]
        elif proto_type == "ss":
            tcp_timeout = timeout_map["ss"]
        elif proto_type == "hysteria":
            tcp_timeout = timeout_map["hysteria"]
        else:
            tcp_timeout = 3
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(tcp_timeout)
            if sock.connect_ex((ip, port)) == 0:
                tcp_available = True
    except Exception:
        return False

    if not tcp_available:
        return False

    # 第二步：宽松版协议验证（仅过滤明确拒绝的节点）
    try:
        if proto_type in ["vmess", "vless", "trojan"]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(4)  # 延长超时至4秒
                sock.connect((ip, port))
                sock.send(b"\x00")  # 发送空包，不强制接收
                return True
        elif proto_type == "ss":
            # SS：配置完整即认为可用
            if proto_cfg and proto_cfg.get("address") and proto_cfg.get("port"):
                return True
        elif proto_type == "hysteria":
            # Hysteria：UDP检测宽松处理
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                    udp_sock.settimeout(4)
                    udp_sock.sendto(b"\x00", (ip, port))
                return True
            except:
                return True
        return True
    except (ConnectionRefusedError, OSError):
        # 仅“明确拒绝连接”才返回False（过滤）
        return False
    except (socket.timeout, ConnectionResetError):
        # 超时/连接重置 → 保留（反探测节点常见行为）
        return True
    except Exception:
        # 未知错误 → 保留
        return True

# ====================== 基础过滤工具函数 ======================
def is_base64(s):
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

def decode_base64_sub(text):
    clean_text = re.sub(r'\s+', '', text.strip())
    if not clean_text:
        return text
    if is_base64(clean_text):
        try:
            padding = 4 - len(clean_text) % 4
            if padding != 4:
                clean_text += '=' * padding
            decoded = base64.b64decode(clean_text).decode('utf-8', errors='ignore')
            LOG.info(f"✅ Base64解码成功，解析出明文内容（长度：{len(decoded)}）")
            return decoded
        except Exception as e:
            LOG.info(f"❌ Base64解码失败: {str(e)[:50]}")
            return text
    else:
        return text

def is_private_ip(ip):
    if not ip:
        return False
    for pattern in CONFIG["filter"]["private_ips"]:
        if pattern.match(ip):
            return True
    return False

def test_domain_resolve(domain):
    """DNS解析（带缓存）"""
    if not domain or domain == "未知":
        return False
    
    if domain in DNS_CACHE:
        cache_time, result = DNS_CACHE[domain]
        if time.time() - cache_time < CONFIG["detection"]["dns_cache_ttl"]:
            return result
    
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
    
    DNS_CACHE[domain] = (time.time(), resolve_success)
    if not resolve_success:
        LOG.info(f"⚠️ 域名{domain}解析失败（所有DNS源均失败），将尝试IP直连检测")
    return resolve_success

def clean_vmess_json(decoded_str):
    """清理VMess JSON中的乱码"""
    try:
        json_match = re.search(r'\{.*\}', decoded_str, re.DOTALL)
        if json_match:
            clean_json = json_match.group(0)
            clean_json = re.sub(r'[\x00-\x1f\x7f-\x9f\u3000]', '', clean_json)
            return clean_json
        return decoded_str
    except Exception as e:
        log_parse_error("VMess JSON", decoded_str[:20], e)
        return decoded_str

def count_protocol_nodes(lines):
    """统计节点列表中各协议的数量"""
    count = {
        "vmess": 0,
        "vless": 0,
        "trojan": 0,
        "ss": 0,
        "hysteria": 0,
        "other": 0
    }
    for line in lines:
        # 兼容带source_url的节点字典
        if isinstance(line, dict):
            line = line["line"]
        if line.startswith('vmess://'):
            count["vmess"] += 1
        elif line.startswith('vless://'):
            count["vless"] += 1
        elif line.startswith('trojan://'):
            count["trojan"] += 1
        elif line.startswith('ss://'):
            count["ss"] += 1
        elif line.startswith('hysteria://'):
            count["hysteria"] += 1
        else:
            count["other"] += 1
    return count

# ====================== 协议解析函数（必填字段校验） ======================
def extract_vmess_config(vmess_line):
    """解析VMess协议节点（校验必填字段）"""
    try:
        vmess_part = vmess_line[8:].strip()
        vmess_part = re.split(r'[@#]', vmess_part)[0].strip()
        vmess_part = vmess_part.encode('ascii', 'ignore').decode('ascii')
        vmess_part = re.sub(r'[^A-Za-z0-9+/=]', '', vmess_part)
        if not vmess_part:
            raise Exception("Base64串过滤后为空")
        
        padding = 4 - len(vmess_part) % 4
        if padding != 4:
            vmess_part += '=' * padding
        
        decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
        decoded = clean_vmess_json(decoded)
        cfg = json.loads(decoded)
        
        # 校验VMess必填字段
        required_fields = ["add", "port", "id", "aid"]
        missing_fields = [f for f in required_fields if f not in cfg or not cfg[f]]
        if missing_fields:
            raise Exception(f"缺失必填字段：{','.join(missing_fields)}")
        
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
    except Exception as e:
        if "缺失必填字段" in str(e):
            LOG.info(f"📝 过滤无效VMess节点：{vmess_line[:20]}...（{str(e)}）")
            return None
        log_parse_error("VMess", vmess_line, e)
        return None

def extract_vless_config(vless_line):
    """解析VLESS协议节点（校验必填字段）"""
    try:
        vless_part = vless_line[8:].strip()
        vless_part = vless_part.encode('ascii', 'ignore').decode('ascii')
        base_part, param_part = (vless_part.split('?') + [''])[:2]
        uuid_addr_port = base_part.split('@')
        
        # 校验VLESS必填字段
        if len(uuid_addr_port) < 2:
            raise Exception("缺失UUID/地址/端口")
        
        uuid = uuid_addr_port[0].strip()
        addr_port = uuid_addr_port[1].strip()
        if not uuid or not addr_port:
            raise Exception("UUID或地址端口为空")
        
        if ':' not in addr_port:
            raise Exception("地址端口格式错误")
        
        address, port_str = addr_port.split(':')
        port = validate_port(port_str)
        if not address:
            raise Exception("地址为空")
        
        # 解析参数+通用备注处理
        params = {}
        for param in param_part.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                if k.lower() == "remarks":
                    v = process_remark(v, "VLESS")
                params[k.lower()] = v
        
        return {
            "uuid": uuid,
            "address": address,
            "port": port,
            "security": params.get('security', 'tls'),
            "sni": params.get('sni') or params.get('SNI', ''),
            "network": params.get('type', 'tcp') or params.get('Type', 'tcp'),
            "remarks": params.get('remarks', 'VLESS节点')
        }
    except Exception as e:
        if any(msg in str(e) for msg in ["缺失UUID", "地址为空", "格式错误"]):
            LOG.info(f"📝 过滤无效VLESS节点：{vless_line[:20]}...（{str(e)}）")
            return None
        log_parse_error("VLESS", vless_line, e)
        return None

def extract_trojan_config(trojan_line):
    """解析Trojan协议节点（校验必填字段）"""
    try:
        label = ""
        if '#' in trojan_line:
            trojan_part, label = trojan_line.split('#', 1)
            label = process_remark(label, "Trojan")
        else:
            trojan_part = trojan_line
        
        trojan_part = trojan_part[8:].strip()
        trojan_part = trojan_part.encode('ascii', 'ignore').decode('ascii')
        password_addr = trojan_part.split('?')[0]
        
        # 校验Trojan必填字段
        if '@' not in password_addr:
            raise Exception("缺失密码@地址格式")
        
        password, addr_port = password_addr.split('@')
        if not password or not addr_port:
            raise Exception("密码或地址端口为空")
        
        if ':' not in addr_port:
            raise Exception("地址端口格式错误")
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        if not address:
            raise Exception("地址为空")
        
        # 解析参数
        params = {}
        if '?' in trojan_part:
            param_str = trojan_part.split('?')[1]
            for param in param_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v
        
        return {
            "address": address,
            "port": port,
            "password": password,
            "sni": params.get('sni') or params.get('SNI', ''),
            "security": params.get('security', 'tls'),
            "label": label
        }
    except Exception as e:
        if any(msg in str(e) for msg in ["缺失密码", "格式错误", "地址为空"]):
            LOG.info(f"📝 过滤无效Trojan节点：{trojan_line[:20]}...（{str(e)}）")
            return None
        log_parse_error("Trojan", trojan_line, e)
        return None

def extract_ss_config(ss_line):
    """解析SS协议节点（校验必填字段）"""
    try:
        ss_part = ss_line[5:].strip()
        
        # Base64解码
        if is_base64(ss_part):
            padding = 4 - len(ss_part) % 4
            if padding != 4:
                ss_part += '=' * padding
            try:
                ss_part = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
            except Exception as e:
                log_parse_error("SS Base64", ss_line, e)
        
        # 校验SS必填字段
        if '@' not in ss_part:
            raise Exception("缺失@分隔符（密码@地址格式）")
        
        # 通用备注处理
        remark = ""
        if '#' in ss_part:
            ss_part, remark = ss_part.split('#', 1)
            remark = process_remark(remark, "SS")
        
        # 提取地址和端口
        auth_part, addr_port_part = ss_part.split('@', 1)
        if not auth_part or not addr_port_part:
            raise Exception("SS认证信息或地址端口为空")
        
        if ':' not in addr_port_part:
            raise Exception("地址端口格式错误")
        
        address, port_str = addr_port_part.rsplit(':', 1)
        port = validate_port(port_str)
        if not address:
            raise Exception("地址为空")
        
        return {
            "address": address.strip(),
            "port": port,
            "remark": remark,
            "method": auth_part.split(':')[0] if ':' in auth_part else ""  # 加密方式
        }
    except Exception as e:
        if any(msg in str(e) for msg in ["缺失@分隔符", "格式错误", "地址为空"]):
            LOG.info(f"📝 过滤无效SS节点：{ss_line[:20]}...（{str(e)}）")
            return None
        log_parse_error("SS", ss_line, e)
        return None

def extract_hysteria_config(hysteria_line):
    """解析Hysteria协议节点（校验必填字段）"""
    try:
        # 通用备注处理
        label = ""
        if '#' in hysteria_line:
            hysteria_part, label = hysteria_line.split('#', 1)
            label = process_remark(label, "Hysteria")
        else:
            hysteria_part = hysteria_line
        
        hysteria_core = hysteria_part[10:].strip()
        hysteria_core = hysteria_core.encode('ascii', 'ignore').decode('ascii')
        
        # 校验Hysteria必填字段
        if '@' not in hysteria_core:
            raise Exception("缺失@分隔符（认证@地址格式）")
        
        # 解析参数
        params = {}
        if '?' in hysteria_core:
            hysteria_core, param_str = hysteria_core.split('?', 1)
            for param in param_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v
        
        # 提取地址和端口
        auth_part, addr_port = hysteria_core.split('@', 1)
        if not auth_part or not addr_port:
            raise Exception("认证信息或地址端口为空")
        
        if ':' not in addr_port:
            raise Exception("地址端口格式错误")
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        if not address:
            raise Exception("地址为空")
        
        return {
            "address": address,
            "port": port,
            "password": auth_part,
            "obfs": params.get('obfs', ''),
            "auth": params.get('auth', ''),
            "alpn": params.get('alpn', ''),
            "label": label
        }
    except Exception as e:
        if any(msg in str(e) for msg in ["缺失@分隔符", "格式错误", "地址为空"]):
            LOG.info(f"📝 过滤无效Hysteria节点：{hysteria_line[:20]}...（{str(e)}）")
            return None
        log_parse_error("Hysteria", hysteria_line, e)
        return None

# ====================== 节点处理与拉取函数 ======================
def fetch_source(url, weight):
    """拉取订阅源数据（带权重，适配GitHub Actions）"""
    cache_dir = ".cache"
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_path = os.path.join(cache_dir, cache_key)
    
    # 读取缓存
    if os.path.exists(cache_path):
        cache_mtime = os.path.getmtime(cache_path)
        if time.time() - cache_mtime < CONFIG["github"]["cache_ttl"]:
            with open(cache_path, "r", encoding="utf-8") as f:
                lines = json.load(f)
            LOG.info(f"✅ 从缓存加载 {url}（权重{weight}），有效节点 {len(lines)} 条")
            return lines, weight
    
    # 控制请求频率
    time.sleep(CONFIG["github"]["request_interval"])
    
    # 重试拉取
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
        except Exception as e:
            error_msg = str(e)[:80]
            if retry < CONFIG["request"]["retry_times"] - 1:
                LOG.info(f"⚠️ 拉取失败 {url}（重试 {retry+1}）: {error_msg}")
                time.sleep(CONFIG["request"]["retry_delay"])
            else:
                LOG.info(f"❌ 拉取最终失败 {url}: {error_msg}")
                return [], weight

def process_node(node_item):
    """处理单个节点（宽松验证+保留疑似可用节点）"""
    # 兼容带source_url的节点字典
    if isinstance(node_item, dict):
        line = node_item["line"]
        source_url = node_item["source_url"]
    else:
        line = node_item
        source_url = ""
    
    try:
        if not line:
            return None, "", "", 443, source_url
        
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
            # 其他协议：通用提取
            ip, domain, port = extract_ip_port_from_line(line)
            if '#' in line:
                remark = process_remark(line.split('#')[1], "其他")
            proto_type = "other"
        
        # 过滤私有IP
        if is_private_ip(ip):
            LOG.info(f"📝 过滤私有IP节点：{ip}:{port}（备注：{remark[:20]}...）")
            return None, "", "", 443, source_url
        
        # 宽松版可用性检测（仅过滤明确拒绝的节点）
        availability_result = True
        if ip and proto_cfg:
            availability_result = test_node_availability(ip, port, proto_type, proto_cfg)
        
        # 仅当“明确拒绝连接”时过滤，其余情况保留
        if ip and proto_cfg and availability_result is False:
            LOG.info(f"📝 过滤不可用节点：{ip}:{port}（{proto_type}端口拒绝连接）（备注：{remark[:20]}...）")
            return None, "", "", 443, source_url
        elif ip and proto_cfg and not availability_result:
            # 协议验证异常但端口通，保留并标记
            LOG.info(f"⚠️  节点协议验证异常，但保留：{ip}:{port}（{proto_type}）（备注：{remark[:20]}...）")
        
        # DNS解析失败警告（不过滤，仅提示）
        if domain and not test_domain_resolve(domain):
            LOG.info(f"⚠️ 域名{domain}解析失败，但IP{ip}检测通过（备注：{remark[:20]}...）")
        
        # 空地址过滤
        if not ip and not domain:
            LOG.info(f"📝 过滤空地址节点：{line[:20]}...（备注：{remark[:20]}...）")
            return None, "", "", 443, source_url
        
        LOG.info(f"✅ 保留节点: {'IP' if ip else '域名'} - {ip or domain}:{port}（{proto_type}）（备注：{remark[:20]}...）")
        return line, domain, ip, port, source_url
    except Exception as e:
        if "label too long" in str(e).lower():
            LOG.info(f"⚠️ 节点备注过长（{line[:20]}...）: {str(e)[:50]}")
        else:
            LOG.info(f"❌ 节点处理异常（{line[:20]}...）: {str(e)[:50]}")
        return None, "", "", 443, source_url

# ====================== 主函数（适配GitHub Actions） ======================
def main():
    """主流程：拉取→去重→检测→排序→保存"""
    start_time = time.time()
    all_nodes = []
    source_records = {}
    
    LOG.info(f"🚀 开始节点更新任务（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）")
    
    # 1. 多线程拉取所有订阅源（带权重）
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
                    "retained_count": 0,  # 初始化保留节点数
                    "retained_lines": []   # 初始化保留节点列表
                }
                # 加入总列表（带权重和数据源URL）
                for line in lines:
                    all_nodes.append({
                        "line": line,
                        "weight": weight,
                        "source_url": url
                    })
            except Exception as e:
                LOG.info(f"❌ 处理订阅源{url}异常：{str(e)[:50]}")
                # 异常源也记录，避免统计时KeyError
                source_records[url] = {
                    "original_lines": [],
                    "original_count": 0,
                    "weight": 0,
                    "protocol_count": count_protocol_nodes([]),
                    "retained_count": 0,
                    "retained_lines": []
                }
    
    # 2. 按权重去重
    LOG.info(f"\n📊 拉取完成，原始节点总数：{len(all_nodes)} 条")
    unique_nodes = deduplicate_nodes(all_nodes)
    LOG.info(f"🔍 去重后节点总数：{len(unique_nodes)} 条")
    
    # 3. 多线程处理节点（宽松验证）
    valid_lines = []
    valid_nodes_with_source = []  # 保留节点+数据源URL
    seen_ips = set()
    seen_domains = set()
    total_nodes = len(unique_nodes)
    
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool_size"]) as executor:
        futures = [executor.submit(process_node, node) for node in unique_nodes]
        for idx, future in enumerate(as_completed(futures)):
            if idx % 10 == 0:  # 每10个节点输出一次进度
                progress = (idx / total_nodes) * 100
                LOG.info(f"⏳ 处理进度：{idx}/{total_nodes} ({progress:.1f}%)")
            try:
                line, domain, ip, port, source_url = future.result()
            except Exception as e:
                LOG.info(f"⚠️ 节点处理异常: {str(e)[:50]}")
                continue
            if not line:
                continue
            
            # 最终去重（IP+域名）
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
    
    # 4. 统计各数据源的保留节点数
    for url in source_records.keys():
        retained_lines = [node for node in valid_nodes_with_source if node["source_url"] == url]
        source_records[url]["retained_count"] = len(retained_lines)
        source_records[url]["retained_lines"] = retained_lines
    
    # 5. 按优先级排序（Reality/TLS优先）
    def sort_by_priority(line):
        """排序规则：Reality > TLS > 其他，协议类型优先级：VLESS > Trojan > VMess > SS > Hysteria"""
        score = 0
        # Reality/TLS优先
        if "reality" in line.lower():
            score += 100
        elif "tls" in line.lower():
            score += 50
        # 协议优先级
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
    
    # 6. 保存为Base64编码的订阅文件
    if valid_lines:
        combined = '\n'.join(valid_lines)
        encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write(encoded)
        LOG.info(f"📄 订阅文件已保存至 s1.txt（Base64编码，{len(valid_lines)} 个节点）")
    else:
        # 无有效节点时创建空文件
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write("")
        LOG.info(f"ℹ️  无有效节点，创建空 s1.txt")
    
    # 7. 输出各数据源详细统计（含保留率）
    LOG.info(f"\n📋 各数据源详细统计：")
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        
        # 计算保留率（处理除零错误）
        if original_count == 0:
            retention_rate = "0.00%"
        else:
            retention_rate = f"{(retained_count / original_count) * 100:.2f}%"
        
        # 输出数据源序号和URL
        LOG.info(f"{current_time} -    {idx}. {url}")
        # 输出该源的节点统计（含保留率）
        stat_line = (f"{current_time} -       - 📝 原始节点数：{original_count} 条 "
                     f"（VMess：{proto_count['vmess']} | VLESS：{proto_count['vless']} | Trojan：{proto_count['trojan']} | "
                     f"SS：{proto_count['ss']} | Hysteria：{proto_count['hysteria']} | 其他：{proto_count['other']}） | "
                     f"保留节点数：{retained_count} 条 | 保留率：{retention_rate}")
        LOG.info(stat_line)
    
    # 8. 输出任务完成统计
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

if __name__ == "__main__":
    main()
