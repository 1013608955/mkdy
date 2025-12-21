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
import subprocess
import platform
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====================== 日志初始化（自定义格式+图标） ======================
def init_logger():
    """初始化日志（自定义时间格式+图标替代级别）"""
    # 自定义时间格式
    formatter = logging.Formatter(
        "%(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"  # 时间格式改为指定样式
    )
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # 文件处理器
    file_handler = logging.FileHandler("crawl.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    
    # 配置logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

LOG = init_logger()

# ====================== 配置项（解耦+GitHub适配） ======================
CONFIG = {
    "sources": [
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
        "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
        "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
        "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
        "https://raw.githubusercontent.com/HakurouKen/free-node/main/public", 
        "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"    
    ],
    "request": {
        "timeout": 120,  # 延长超时时间，适配跨境访问
        "retry_times": 5,  # 增加重试次数
        "retry_delay": 3,  # 延长重试间隔
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    "github": {
        "token": os.getenv("GITHUB_TOKEN", ""),  # 从环境变量获取Token，避免硬编码
        "request_interval": 1,  # 源之间的请求间隔（秒），避免限流
        "cache_ttl": 3600  # 缓存有效期（1小时）
    },
    "detection": {
        "tcp_timeout": 3,
        "tcp_retry": 1,
        "thread_pool_size": 10,  # 降低线程数适配GitHub Actions
        "dns_servers": ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"],
        "dns_timeout": 5,
        "dns_cache_ttl": 300  # DNS缓存有效期（5分钟）
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
    },
    "quality": {
        "ping_count": 3,  # 延迟检测ping次数
        "max_delay": 500  # 最大可接受延迟（ms），超过则过滤
    }
}

# ====================== 全局资源初始化 ======================
# 1. 请求会话（连接池复用）
def init_request_session():
    """初始化请求会话（复用连接池，减少TCP握手开销）"""
    session = requests.Session()
    headers = {
        "User-Agent": CONFIG["request"]["user_agent"],
        "Accept": "application/vnd.github.v3.raw+json"
    }
    if CONFIG["github"]["token"]:
        headers["Authorization"] = f"token {CONFIG['github']['token']}"
    session.headers.update(headers)
    
    # 配置连接池和重试
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=10,
        pool_maxsize=20,
        max_retries=3
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

SESSION = init_request_session()

# 2. DNS缓存
DNS_CACHE = {}

# ====================== 基础工具函数 ======================
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
    
    # 读取DNS缓存
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
    
    # 写入DNS缓存
    DNS_CACHE[domain] = (time.time(), resolve_success)
    if not resolve_success:
        LOG.info(f"⚠️ 域名{domain}解析失败（所有DNS源均失败），将尝试IP直连检测")
    return resolve_success

def clean_vmess_json(decoded_str):
    """清理VMess JSON中的乱码/非JSON字符"""
    try:
        json_match = re.search(r'\{.*\}', decoded_str, re.DOTALL)
        if json_match:
            clean_json = json_match.group(0)
            clean_json = re.sub(r'[\x00-\x1f\x7f-\x9f\u3000]', '', clean_json)
            return clean_json
        return decoded_str
    except Exception as e:
        LOG.info(f"⚠️ 清理VMess JSON乱码失败：{str(e)[:50]}")
        return decoded_str

def truncate_remark(remark):
    """按UTF-8字节数截断备注，避免label too long（强化容错）"""
    if not remark:
        return ""
    
    try:
        remark_bytes = remark.encode('utf-8')
        max_bytes = CONFIG["filter"]["max_remark_bytes"]
        
        if len(remark_bytes) <= max_bytes:
            return remark
        
        truncated_bytes = remark_bytes[:max_bytes]
        # 循环回退确保解码成功
        truncated_remark = ""
        for back_step in range(0, 6):
            try:
                truncated_remark = truncated_bytes[:len(truncated_bytes)-back_step].decode('utf-8')
                break
            except UnicodeDecodeError:
                continue
        else:
            truncated_remark = remark_bytes[:max_bytes-5].decode('utf-8', errors='ignore')
        
        # 添加省略号
        ellipsis = "..."
        if len(truncated_remark.encode('utf-8')) + len(ellipsis.encode('utf-8')) <= max_bytes:
            truncated_remark += ellipsis
        
        LOG.info(f"⚠️ 备注字节数超限（原{len(remark_bytes)}字节），已截断为{len(truncated_remark.encode('utf-8'))}字节：{truncated_remark[:20]}...")
        return truncated_remark
    except Exception as e:
        LOG.info(f"⚠️ 备注截断失败：{str(e)[:30]}，使用默认备注")
        return "默认节点"

def test_tcp_connect(ip, port):
    """测试TCP连接是否可用"""
    if isinstance(port, str):
        try:
            port = int(port)
        except:
            return False
    if not ip or port not in CONFIG["filter"]["valid_ports"]:
        return False
    
    for retry_num in range(CONFIG["detection"]["tcp_retry"] + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(CONFIG["detection"]["tcp_timeout"])
                if sock.connect_ex((ip, port)) == 0:
                    return True
            if retry_num < CONFIG["detection"]["tcp_retry"]:
                time.sleep(0.5)
        except (socket.gaierror, socket.timeout, OSError):
            continue
    return False

def ping_delay(ip):
    """检测节点延迟（跨平台兼容）"""
    if not ip or is_private_ip(ip):
        return 9999  # 私有IP返回高延迟
    
    try:
        # 适配Windows/Linux/macOS的ping命令
        param = "-n" if platform.system().lower() == "windows" else "-c"
        count = CONFIG["quality"]["ping_count"]
        timeout = CONFIG["detection"]["tcp_timeout"]
        
        # 执行ping命令
        result = subprocess.run(
            ["ping", param, str(count), "-w", str(timeout * 1000), ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        
        # 解析延迟（适配不同系统输出）
        if result.returncode == 0:
            # 提取延迟数值
            delay_match = re.search(r'平均 = (\d+)ms|avg = (\d+\.?\d*) ms', result.stdout)
            if delay_match:
                delay = float(delay_match.group(1) or delay_match.group(2))
                return min(int(delay), 9999)
    except Exception as e:
        LOG.info(f"🐞 检测{ip}延迟失败：{str(e)[:30]}")
    
    return 9999

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

# ====================== 各协议解析函数 ======================
def extract_vmess_config(vmess_line):
    """解析VMess协议节点（修复：剥离@/#后缀）"""
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
        
        cfg["ps"] = truncate_remark(cfg.get('ps', ''))
        
        port = cfg.get('port', 443)
        if isinstance(port, str):
            port = port.strip()
        
        return {
            "address": cfg.get('add'),
            "port": port,
            "id": cfg.get('id', ''),
            "alterId": cfg.get('aid', 0),
            "security": cfg.get('scy', 'auto'),
            "network": cfg.get('net', 'tcp'),
            "tls": cfg.get('tls', ''),
            "serverName": cfg.get('host') or cfg.get('sni', ''),
            "ps": cfg["ps"]
        }
    except json.JSONDecodeError as e:
        LOG.info(f"⚠️ VMess JSON解析失败（{vmess_line[:20]}...）: {str(e)[:50]}")
        try:
            decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
            decoded = clean_vmess_json(decoded)
            ip_match = re.search(r'"add":"([\d\.a-zA-Z-]+)"', decoded)
            port_match = re.search(r'"port":"?(\d+)"?', decoded)
            host_match = re.search(r'"host":"([^"]+)"|\"sni\":\"([^"]+)"', decoded)
            
            port = "443"
            if port_match:
                port = port_match.group(1).strip()
            
            if ip_match and port_match:
                return {
                    "address": ip_match.group(1),
                    "port": port,
                    "id": "", 
                    "alterId": 0, 
                    "security": "auto",
                    "network": "tcp", 
                    "tls": "",
                    "serverName": host_match.group(1) if host_match else "",
                    "ps": ""
                }
            else:
                raise Exception("核心字段（IP/端口）提取失败")
        except:
            raise Exception(f"JSON解析失败且无法提取核心字段: {str(e)}")
    except Exception as e:
        LOG.info(f"⚠️ VMess解析失败（{vmess_line[:20]}...）: {str(e)[:50]}")
        return None

def extract_vless_config(vless_line):
    """解析VLESS协议节点"""
    try:
        vless_part = vless_line[8:].strip()
        vless_part = vless_part.encode('ascii', 'ignore').decode('ascii')
        base_part, param_part = (vless_part.split('?') + [''])[:2]
        uuid_addr_port = base_part.split('@')
        
        if len(uuid_addr_port) != 2:
            ip_match = re.search(r'@([\d\.a-zA-Z-]+)', base_part)
            port_match = re.search(r':(\d+)', base_part)
            uuid_match = re.search(r'^([0-9a-fA-F\-]+)', base_part)
            if not (ip_match and port_match):
                raise Exception("核心字段提取失败")
            uuid = uuid_match.group(1) if uuid_match else ""
            address = ip_match.group(1)
            port = int(port_match.group(1)) if port_match else 443
        else:
            uuid = uuid_addr_port[0].strip()
            addr_port = uuid_addr_port[1].strip()
            try:
                address, port = addr_port.split(':')
                port = int(port)
            except:
                address = addr_port
                port = 443
        
        params = {}
        for param in param_part.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                if k.lower() == "remarks":
                    v = truncate_remark(v)
                params[k.lower()] = v
        
        return {
            "uuid": uuid,
            "address": address,
            "port": port if port in CONFIG["filter"]["valid_ports"] else 443,
            "security": params.get('security', 'tls'),
            "sni": params.get('sni') or params.get('SNI'),
            "network": params.get('type', 'tcp') or params.get('Type'),
            "remarks": params.get('remarks', '')
        }
    except Exception as e:
        LOG.info(f"⚠️ VLESS解析失败（{vless_line[:20]}...）: {str(e)[:50]}")
        ip_port_match = re.search(r'@([\d\.a-zA-Z-]+):(\d+)', vless_line)
        if ip_port_match:
            return {
                "uuid": "",
                "address": ip_port_match.group(1),
                "port": int(ip_port_match.group(2)),
                "security": "tls",
                "sni": "",
                "network": "tcp",
                "remarks": ""
            }
        return None

def extract_trojan_config(trojan_line):
    """解析Trojan协议节点（强化容错）"""
    try:
        label = ""
        if '#' in trojan_line:
            trojan_part, label = trojan_line.split('#', 1)
            label = unquote(label)
            try:
                label = truncate_remark(label)
            except Exception as e:
                LOG.info(f"⚠️ Trojan备注截断失败：{str(e)[:30]}（{trojan_line[:20]}...）")
                label = "Trojan节点"
            if not label:
                LOG.info(f"⚠️ Trojan节点标签为空（{trojan_line[:20]}...）")
        else:
            trojan_part = trojan_line
        
        trojan_part = trojan_part[8:].strip()
        trojan_part = trojan_part.encode('ascii', 'ignore').decode('ascii')
        password_addr = trojan_part.split('?')[0]
        
        password = ""
        address = ""
        port = 443
        if '@' in password_addr:
            password, addr_port = password_addr.split('@')
            if ':' in addr_port:
                address, port_str = addr_port.rsplit(':', 1)
                port = int(port_str) if port_str.isdigit() else 443
            else:
                address = addr_port
        else:
            ip_port_match = re.search(r'@([\d\.a-zA-Z-]+):(\d+)', trojan_part)
            if ip_port_match:
                address = ip_port_match.group(1)
                port = int(ip_port_match.group(2))
        
        params = {}
        if '?' in trojan_part:
            param_str = trojan_part.split('?')[1]
            for param in param_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v
        
        return {
            "address": address,
            "port": port if port in CONFIG["filter"]["valid_ports"] else 443,
            "password": password,
            "sni": params.get('sni') or params.get('SNI'),
            "security": params.get('security', 'tls'),
            "label": label
        }
    except Exception as e:
        if any(keyword in str(e).lower() for keyword in ["label", "empty", "too long", "truncate"]):
            LOG.info(f"⚠️ Trojan节点标签异常（非核心，保留节点）：{str(e)[:50]}（{trojan_line[:20]}...）")
            ip_port_match = re.search(r'@([\d\.a-zA-Z-]+):(\d+)', trojan_line)
            if ip_port_match:
                return {
                    "address": ip_port_match.group(1),
                    "port": int(ip_port_match.group(2)),
                    "password": "",
                    "sni": "",
                    "security": "tls",
                    "label": "Trojan节点"
                }
        else:
            LOG.info(f"❌ Trojan核心字段解析失败（{trojan_line[:20]}...）: {str(e)[:50]}")
        return None

def extract_ss_config(ss_line):
    """解析SS（Shadowsocks）协议节点"""
    try:
        ss_part = ss_line[5:].strip()
        
        decoded_ss = ""
        if is_base64(ss_part):
            padding = 4 - len(ss_part) % 4
            if padding != 4:
                ss_part += '=' * padding
            try:
                decoded_ss = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
                ss_part = decoded_ss
            except Exception as e:
                LOG.info(f"⚠️ SS Base64解码失败（{ss_line[:20]}...）: {str(e)[:50]}")
        
        remark = ""
        if '#' in ss_part:
            ss_part, remark = ss_part.split('#', 1)
            remark = unquote(remark)
            remark = truncate_remark(remark)
        
        address = ""
        port = 443
        if '@' in ss_part:
            auth_part, addr_port_part = ss_part.split('@', 1)
            if ':' in addr_port_part:
                address, port_str = addr_port_part.rsplit(':', 1)
                port = int(port_str) if port_str.isdigit() else 443
            else:
                address = addr_port_part
            
            if not address or address.strip() == "":
                raise Exception("SS节点地址为空")
        
        return {
            "address": address.strip(),
            "port": port if port in CONFIG["filter"]["valid_ports"] else 443,
            "remark": remark
        }
    except Exception as e:
        LOG.info(f"⚠️ SS解析失败（{ss_line[:20]}...）: {str(e)[:50]}")
        return None

def extract_hysteria_config(hysteria_line):
    """解析Hysteria协议节点"""
    try:
        label = ""
        hysteria_part = hysteria_line
        if '#' in hysteria_line:
            hysteria_part, label = hysteria_line.split('#', 1)
            label = unquote(label)
            label = truncate_remark(label)
        
        hysteria_core = hysteria_part[10:].strip()
        hysteria_core = hysteria_core.encode('ascii', 'ignore').decode('ascii')
        
        params = {}
        if '?' in hysteria_core:
            hysteria_core, param_str = hysteria_core.split('?', 1)
            for param in param_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v
        
        address = ""
        port = 443
        password = ""
        
        if '@' in hysteria_core:
            password, addr_port = hysteria_core.split('@', 1)
            if ':' in addr_port:
                address, port_str = addr_port.rsplit(':', 1)
                port = int(port_str) if port_str.isdigit() else 443
            else:
                address = addr_port
        else:
            if ':' in hysteria_core:
                address, port_str = hysteria_core.rsplit(':', 1)
                port = int(port_str) if port_str.isdigit() else 443
            else:
                ip_port_match = re.search(r'([\d\.a-zA-Z\-]+):(\d+)', hysteria_core)
                if ip_port_match:
                    address = ip_port_match.group(1)
                    port = int(ip_port_match.group(2))
                else:
                    address = hysteria_core
        
        port = port if port in CONFIG["filter"]["valid_ports"] else 443
        
        return {
            "address": address,
            "port": port,
            "password": password,
            "obfs": params.get('obfs', ''),
            "auth": params.get('auth', ''),
            "alpn": params.get('alpn', ''),
            "label": label
        }
    except Exception as e:
        LOG.info(f"⚠️ Hysteria解析失败（{hysteria_line[:20]}...）: {str(e)[:50]}")
        return None

# ====================== 节点处理与拉取函数 ======================
def fetch_source(url, cache_dir=".cache"):
    """拉取订阅源数据（带缓存+GitHub限流防护）"""
    # 初始化缓存目录
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_path = os.path.join(cache_dir, cache_key)
    
    # 读取缓存（未过期则直接返回）
    if os.path.exists(cache_path):
        cache_mtime = os.path.getmtime(cache_path)
        if time.time() - cache_mtime < CONFIG["github"]["cache_ttl"]:
            with open(cache_path, "r", encoding="utf-8") as f:
                lines = json.load(f)
            LOG.info(f"✅ 从缓存加载 {url}，有效节点 {len(lines)} 条")
            return lines
    
    # 控制请求频率，避免GitHub限流
    time.sleep(CONFIG["github"]["request_interval"])
    
    # 拉取数据
    for retry in range(CONFIG["request"]["retry_times"]):
        try:
            resp = SESSION.get(url, timeout=CONFIG["request"]["timeout"], verify=False)
            resp.raise_for_status()
            decoded_content = decode_base64_sub(resp.text)
            lines = [l.strip() for l in decoded_content.split('\n') if l.strip() and not l.startswith('#')]
            proto_count = count_protocol_nodes(lines)
            LOG.info(f"✅ 拉取成功 {url}，有效节点 {len(lines)} 条（VMess：{proto_count['vmess']} | VLESS：{proto_count['vless']} | Trojan：{proto_count['trojan']} | SS：{proto_count['ss']} | Hysteria：{proto_count['hysteria']} | 其他：{proto_count['other']}）（重试：{retry}）")
            
            # 写入缓存
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(lines, f)
            return lines
        except Exception as e:
            error_msg = str(e)[:80]
            if retry < CONFIG["request"]["retry_times"] - 1:
                LOG.info(f"⚠️ 拉取失败 {url}（重试 {retry+1}）: {error_msg}")
                time.sleep(CONFIG["request"]["retry_delay"])
            else:
                LOG.info(f"❌ 拉取最终失败 {url}: {error_msg}")
                return []

def process_node(line):
    """处理单个节点，提取核心信息并过滤无效节点"""
    try:
        if not line:
            return None, "", "", 443, 9999  # 新增延迟字段
        ip, domain, port, remark, delay = None, "", 443, "", 9999
        
        # 按协议解析
        if line.startswith('vmess://'):
            cfg = extract_vmess_config(line)
            if cfg:
                ip = cfg["address"]
                domain = cfg["serverName"]
                port = cfg["port"]
                remark = cfg["ps"]
        elif line.startswith('vless://'):
            cfg = extract_vless_config(line)
            if cfg:
                ip = cfg["address"]
                domain = cfg["sni"]
                port = cfg["port"]
                remark = cfg["remarks"]
        elif line.startswith('trojan://'):
            cfg = extract_trojan_config(line)
            if cfg:
                ip = cfg["address"]
                domain = cfg["sni"]
                port = cfg["port"]
                remark = cfg["label"]
        elif line.startswith('ss://'):
            cfg = extract_ss_config(line)
            if cfg:
                ip = cfg["address"]
                domain = ""
                port = cfg["port"]
                remark = cfg["remark"]
        elif line.startswith('hysteria://'):
            cfg = extract_hysteria_config(line)
            if cfg:
                ip = cfg["address"]
                domain = ""
                port = cfg["port"]
                remark = cfg["label"]
        else:
            ip_match = re.search(r'@([\d\.]+):', line)
            if ip_match:
                ip = ip_match.group(1)
            domain_match = re.search(r'sni=([^&]+)|host=([^&]+)', line, re.IGNORECASE)
            if domain_match:
                domain = next((g for g in domain_match.groups() if g), "")
            port_match = re.search(r':(\d+)', line)
            if port_match:
                port = int(port_match.group(1)) if port_match.group(1) in CONFIG["filter"]["valid_ports"] else 443
            if '#' in line:
                remark = line.split('#')[1]
                remark = unquote(remark)
                remark = truncate_remark(remark)
        
        # 过滤私有IP
        if is_private_ip(ip):
            LOG.info(f"📝 过滤私有IP节点：{ip}:{port}（备注：{remark[:20]}...）")
            return None, "", "", 443, 9999
        
        # 测试TCP连接
        if ip and not test_tcp_connect(ip, port):
            LOG.info(f"📝 过滤TCP连接失败节点：{ip}:{port}（备注：{remark[:20]}...）")
            return None, "", "", 443, 9999
        
        # DNS解析提醒
        if domain and not test_domain_resolve(domain):
            LOG.info(f"⚠️ 域名{domain}解析失败，但IP{ip}连接正常（备注：{remark[:20]}...）")
        
        # 过滤空地址
        if not ip and not domain:
            LOG.info(f"📝 过滤空地址节点：{line[:20]}...（备注：{remark[:20]}...）")
            return None, "", "", 443, 9999
        
        # 检测节点延迟
        delay = ping_delay(ip)
        if delay > CONFIG["quality"]["max_delay"]:
            LOG.info(f"📝 过滤高延迟节点：{ip}:{port}（延迟：{delay}ms，备注：{remark[:20]}...）")
            return None, "", "", 443, 9999
        
        LOG.info(f"✅ 保留节点: {'IP' if ip else '域名'} - {ip or domain}:{port}（延迟：{delay}ms，备注：{remark[:20]}...）")
        return line, domain, ip, port, delay
    except Exception as e:
        LOG.info(f"❌ 节点处理异常（{line[:20]}...）: {str(e)[:50]}")
        return None, "", "", 443, 9999

# ====================== 主函数 ======================
def main():
    """主流程：拉取→处理→质量分级→保存"""
    start_time = time.time()
    source_records = {}
    all_lines_set = set()
    
    try:
        # 1. 多线程拉取订阅源
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(fetch_source, url): url for url in CONFIG["sources"]}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    lines = future.result()
                    proto_count = count_protocol_nodes(lines)
                    source_records[url] = {
                        "original": lines,
                        "original_count": len(lines),
                        "protocol_count": proto_count
                    }
                    all_lines_set.update(lines)
                except Exception as e:
                    LOG.info(f"❌ 处理订阅源{url}异常：{str(e)[:50]}")
        
        unique_lines = list(all_lines_set)
        LOG.info(f"\n📝 全局去重后总节点：{len(unique_lines)} 条")

        # 2. 按协议优先级排序
        reality_lines = [l for l in unique_lines if 'reality' in l.lower()]
        hysteria_lines = [l for l in unique_lines if l.startswith('hysteria://') and l not in reality_lines]
        tls_lines = [l for l in unique_lines if 'tls' in l.lower() and l not in reality_lines + hysteria_lines]
        ss_lines = [l for l in unique_lines if l.startswith('ss://') and l not in reality_lines + hysteria_lines + tls_lines]
        normal_lines = [l for l in unique_lines if l not in reality_lines + hysteria_lines + tls_lines + ss_lines]
        processing_order = reality_lines + hysteria_lines + tls_lines + ss_lines + normal_lines
        
        LOG.info(f"📝 优先级拆分 - Reality节点：{len(reality_lines)} 条 | Hysteria节点：{len(hysteria_lines)} 条 | TLS节点：{len(tls_lines)} 条 | SS节点：{len(ss_lines)} 条 | 普通节点：{len(normal_lines)} 条")

        # 3. 多线程处理节点
        valid_nodes = []  # 存储(延迟, 节点链接)
        seen_ips = set()
        seen_domains = set()
        total_nodes = len(processing_order)
        
        with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool_size"]) as executor:
            futures = [executor.submit(process_node, line) for line in processing_order]
            for idx, future in enumerate(as_completed(futures)):
                if idx % 100 == 0:
                    progress = (idx / total_nodes) * 100
                    LOG.info(f"\n📝 处理进度：{idx}/{total_nodes} ({progress:.1f}%)")
                try:
                    line, domain, ip, port, delay = future.result()
                except Exception as e:
                    LOG.info(f"⚠️ 节点处理异常: {str(e)[:50]}")
                    continue
                if not line:
                    continue
                
                # 去重
                if domain and domain in seen_domains:
                    continue
                if ip and ip in seen_ips:
                    continue
                
                seen_domains.add(domain)
                seen_ips.add(ip)
                valid_nodes.append((delay, line))
        
        # 4. 按延迟排序（升序）
        valid_nodes.sort(key=lambda x: x[0])
        valid_lines = [node[1] for node in valid_nodes]

        # 5. 保存结果
        combined = '\n'.join(valid_lines)
        encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write(encoded)

        # 6. 输出统计信息
        total_cost = time.time() - start_time
        valid_proto_count = count_protocol_nodes(valid_lines)
        LOG.info(f"\n🎉 最终处理完成：")
        LOG.info(f"   - 📝 原始总节点：{len(unique_lines)} 条")
        LOG.info(f"   - ✅ 过滤后可用节点：{len(valid_lines)} 条")
        LOG.info(f"   - 📊 有效节点协议分布：VMess：{valid_proto_count['vmess']} | VLESS：{valid_proto_count['vless']} | Trojan：{valid_proto_count['trojan']} | SS：{valid_proto_count['ss']} | Hysteria：{valid_proto_count['hysteria']} | 其他：{valid_proto_count['other']}")
        LOG.info(f"   - 🌐 独特IP：{len(seen_ips)} 个")
        LOG.info(f"   - 📛 独特域名：{len(seen_domains)} 个")
        LOG.info(f"   - 🔤 备注最大字节数：{CONFIG['filter']['max_remark_bytes']}（UTF-8）")
        LOG.info(f"   - ⏱️ 总耗时：{total_cost:.2f} 秒（{total_cost/60:.2f} 分钟）")
        LOG.info(f"   - 📄 节点已保存至：s1.txt（Base64编码格式）")

        # 7. 各数据源统计
        LOG.info("\n📋 各数据源详细统计：")
        for idx, (url, stats) in enumerate(source_records.items(), 1):
            original_count = stats['original_count']
            proto_count = stats['protocol_count']
            retained_count = len([line for line in stats['original'] if line in valid_lines])
            retention_rate = (retained_count / original_count * 100) if original_count > 0 else 0.0
            LOG.info(f"   {idx}. {url}")
            LOG.info(f"      - 📝 原始节点数：{original_count} 条（VMess：{proto_count['vmess']} | VLESS：{proto_count['vless']} | Trojan：{proto_count['trojan']} | SS：{proto_count['ss']} | Hysteria：{proto_count['hysteria']} | 其他：{proto_count['other']}）")
            LOG.info(f"      - ✅ 最终保留：{retained_count} 条 | 📈 保留率：{retention_rate:.2f}%")
    
    except KeyboardInterrupt:
        LOG.info("⚠️ 脚本被手动中断")
    except Exception as e:
        LOG.info(f"❌ 脚本运行异常：{str(e)}")
        # 记录错误日志
        with open("error.log", "w", encoding="utf-8") as f:
            f.write(f"Error: {str(e)}\nTime: {time.ctime()}")
        raise
    finally:
        # 释放资源
        SESSION.close()
        LOG.info(f"🔚 脚本结束，总耗时：{time.time()-start_time:.2f}秒")

if __name__ == "__main__":
    main()
