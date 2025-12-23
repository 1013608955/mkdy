import requests
import re
import socket
import base64
import binascii
import os
import time
import hashlib
import logging
import uuid
import struct
from urllib.parse import unquote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import lru_cache
import urllib3
from typing import Dict, List, Tuple, Optional, Union
import json

# ========== 配置与初始化 ==========
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 核心配置（优化评分规则、动态阈值）
CONFIG: Dict = {
    "sources": [
        {"url": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub", "weight": 5},
        {"url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt", "weight": 5},
        {"url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt", "weight": 5},
        {"url": "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray", "weight": 4},
        {"url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt", "weight": 4},
        {"url": "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt", "weight": 3},
        {"url": "https://raw.githubusercontent.com/HakurouKen/free-node/main/public", "weight": 3},
        {"url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", "weight": 2}
    ],
    "request": {"timeout": 15, "retry": 3, "retry_delay": 3, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
    "github": {"token": os.getenv("GITHUB_TOKEN", ""), "interval": 0.5, "cache_ttl": 3600, "cache_expire_days": 7},
    "detection": {
        "tcp_timeout": {"vmess":5, "vless":5, "trojan":5, "ss":4, "hysteria":6},
        "tcp_retry": 3,  # 增加检测次数用于计算稳定性
        "thread_pool": 8,
        "dns": {"servers": ["223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"], "timeout":4, "cache_size":1000},
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
        "score_threshold": 65,  # 基础阈值从75降至65
        "min_response_time": 0.1,
        "max_response_time": 5.0,
        # 分协议响应时间阈值（优化后）
        "rt_thresholds": {
            "vmess": {"min": 0.05, "max": 6},
            "vless": {"min": 0.05, "max": 6},
            "trojan": {"min": 0.05, "max": 6},
            "ss": {"min": 0.05, "max": 7},
            "hysteria": {"min": 0.01, "max": 4}
        }
    },
    "filter": {
        "private_ip": re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|0\.0\.0\.0)"),
        "cn_ip_ranges": [
            re.compile(r"^1\.0\.16\."), re.compile(r"^1\.0\.64\."), re.compile(r"^101\."),
            re.compile(r"^103\.(?!106|96)"), re.compile(r"^112\."), re.compile(r"^113\."),
            re.compile(r"^120\."), re.compile(r"^121\."), re.compile(r"^122\."), re.compile(r"^123\."),
            re.compile(r"^139\."), re.compile(r"^140\."), re.compile(r"^141\."), re.compile(r"^150\."),
            re.compile(r"^151\."), re.compile(r"^163\."), re.compile(r"^171\."),
            re.compile(r"^172\.(?!16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)"),
            re.compile(r"^173\."), re.compile(r"^174\."), re.compile(r"^180\."), re.compile(r"^181\."),
            re.compile(r"^182\."), re.compile(r"^183\."), re.compile(r"^184\."), re.compile(r"^190\."),
            re.compile(r"^202\."), re.compile(r"^203\."), re.compile(r"^210\."), re.compile(r"^211\."),
            re.compile(r"^220\."), re.compile(r"^221\."), re.compile(r"^222\."), re.compile(r"^223\.")
        ],
        "ports": range(1, 65535),
        "max_remark_bytes": 200,
        "DEFAULT_PORT": 443,
        "SS_DEFAULT_CIPHER": "aes-256-gcm",
        "SS_VALID_CIPHERS": ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb"],
        # 重构后的评分规则
        "score_rules": {
            "protocol": {"vless": 20, "trojan": 18, "vmess": 15, "hysteria": 15, "ss": 10, "other": 0},
            "security": {"reality": 25, "tls": 20, "aead": 15, "none": 0},
            "port": {443: 10, 8443: 8, 80: 7, 465: 7, 9443: 7, "other": 5},
            "response_speed": {
                "vmess": {"fast": 8, "normal": 4, "slow": 0},
                "vless": {"fast": 9, "normal": 4, "slow": 0},
                "trojan": {"fast": 8, "normal": 4, "slow": 0},
                "ss": {"fast": 7, "normal": 3, "slow": 0},
                "hysteria": {"fast": 10, "normal": 5, "slow": 1}
            },
            "dns_valid": 8,          # 提升DNS权重
            "http_valid": 22,        # 外网访问权重小幅提升
            "cn_ip": -40,            # 降低国内IP扣分
            "response_time_abnormal": -80, # 降低异常扣分
            "stability": 10,         # 新增稳定性权重
            "ip_type": {"residential": 15, "dc": 5, "unknown": 0} # 新增IP类型权重
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

# 全局请求会话
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

# ========== 核心工具函数 ==========
def validate_port(port: Union[str, int]) -> int:
    try:
        p = int(port)
        return p if p in CONFIG["filter"]["ports"] else CONFIG["filter"]["DEFAULT_PORT"]
    except (ValueError, TypeError):
        return CONFIG["filter"]["DEFAULT_PORT"]

def log_msg(content: str, line: str = "", proto: str = "") -> str:
    if "保留节点" in content:
        line_part = ""
    else:
        if "解析错误" in content or "过滤无效" in content or "空地址节点" in content:
            line_part = f"（{line}）" if line else ""
        else:
            safe_line = line[:20].encode('ascii', 'ignore').decode('ascii') if line else ""
            line_part = f"（{safe_line}...）" if safe_line else ""
    proto_part = f"（{proto}）" if proto else ""
    return f"{content}{line_part}{proto_part}"

def b64_safe_decode(b64_str: str) -> str:
    try:
        b64_str = b64_str.rstrip('=')
        b64_str += '=' * (4 - len(b64_str) % 4) if len(b64_str) % 4 != 0 else ''
        b64_str = b64_str.replace('-', '+').replace('_', '/')
        return base64.b64decode(b64_str, validate=True).decode('utf-8', errors='ignore')
    except (binascii.Error, ValueError, TypeError):
        return b64_str

def clean_special_chars(line: str) -> str:
    if not line:
        return ""
    clean_line = re.sub(r'[\u200b\u3000\s]+', '', line)
    clean_line = clean_line.replace('＠', '@')
    return clean_line

def proto_preprocess(line: str, proto_prefix: str) -> Tuple[str, str]:
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
    original_text = text.strip()
    if not original_text:
        return ""
    
    base64_pattern = re.compile(r'^[A-Za-z0-9+/=_-]+$')
    clean_for_b64 = re.sub(r'\s+', '', original_text)
    
    if len(clean_for_b64) % 4 == 0 and base64_pattern.match(clean_for_b64):
        try:
            decoded = b64_safe_decode(clean_for_b64)
            decoded_line_count = len([l for l in decoded.split('\n') if l.strip()])
            LOG.info(log_msg(f"✅ Base64解码成功，解析出{decoded_line_count}个有效节点"))
            return decoded
        except Exception as e:
            LOG.info(log_msg(f"❌ Base64解码失败: {str(e)[:50]}，使用明文处理"))
    
    cleaned_lines = [l.strip() for l in original_text.split('\n')]
    plain_line_count = len([l for l in cleaned_lines if l])
    LOG.info(log_msg(f"✅ 明文订阅处理完成，解析出{plain_line_count}个有效节点"))
    return '\n'.join(cleaned_lines)

def clean_node_content(line: str) -> str:
    if not line:
        return ""
    line = re.sub(r'[\u4e00-\u9fa5]', '', line)
    error_keywords = ["订阅内容解析错误", "解析失败", "无效节点", "缺失字段"]
    for keyword in error_keywords:
        line = line.replace(keyword, "")
    return line.strip()

def is_private_ip(ip: str) -> bool:
    return bool(ip and CONFIG["filter"]["private_ip"].match(ip))

def is_cn_ip(ip: str) -> bool:
    if not ip or is_private_ip(ip):
        return False
    for pattern in CONFIG["filter"]["cn_ip_ranges"]:
        if pattern.match(ip):
            return True
    return False

def is_ip(address: str) -> bool:
    """判断是否为纯IP地址（用于IP直连判断）"""
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', address))

@lru_cache(maxsize=CONFIG["detection"]["dns"]["cache_size"])
def dns_resolve(domain: str) -> Tuple[bool, List[str]]:
    if not domain or domain == "未知":
        return False, []
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(CONFIG["detection"]["dns"]["timeout"])
    ip_list = []
    try:
        for dns in CONFIG["detection"]["dns"]["servers"]:
            try:
                ip_list = socket.gethostbyname_ex(domain)[2]
                valid_ips = [ip for ip in ip_list if not is_private_ip(ip) and not is_cn_ip(ip)]
                if valid_ips:
                    return True, valid_ips
            except (socket.gaierror, socket.timeout):
                continue
        LOG.info(log_msg(f"⚠️ 域名{domain}解析失败/仅国内/私有IP", domain))
        return False, ip_list
    finally:
        socket.setdefaulttimeout(original_timeout)

@lru_cache(maxsize=1000)
def get_ip_type(ip: str) -> str:
    """识别IP类型：住宅IP/数据中心IP/未知"""
    if is_private_ip(ip) or is_cn_ip(ip):
        return "unknown"
    try:
        # 增加超时和缓存，避免API限流
        resp = SESSION.get(
            f"https://ipinfo.io/{ip}/json", 
            timeout=5,
            headers={"User-Agent": CONFIG["request"]["ua"]}
        )
        data = resp.json()
        if "hostname" in data and "dc" in data["hostname"].lower():
            return "dc"
        elif "org" in data and any(keyword in data["org"].lower() for keyword in ["residential", "home", "isp"]):
            return "residential"
        else:
            return "unknown"
    except Exception as e:
        LOG.debug(f"⚠️ IP类型识别失败 {ip}: {str(e)[:50]}")
        return "unknown"

def process_remark(remark: str, proto: str) -> str:
    if not remark:
        return f"{proto}节点"
    try:
        decoded = unquote(remark)
        decoded = re.sub(r'[^\x20-\x7E\u4e00-\u9fa5]', '', decoded)
        b_remark = decoded.encode('utf-8')
        max_len = CONFIG["filter"]["max_remark_bytes"]
        
        if len(b_remark) <= max_len:
            return decoded
        
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
    missing = [f for f in required if f not in fields]
    if missing:
        LOG.info(log_msg(f"📝 过滤无效{proto}节点：缺失{','.join(missing)}", line, proto))
        return False
    return True

def extract_ip_port(line: str) -> Tuple[Optional[str], str, int]:
    ip_match = re.search(r'@([\d\.a-zA-Z-]+):', line)
    ip = ip_match.group(1) if ip_match else None
    
    sni_match = re.search(r'sni=([^&]+)', line, re.I)
    domain = sni_match.group(1) if sni_match else ""
    if not domain:
        domain_match = re.search(r'host=([^&]+)', line, re.I)
        domain = next((g for g in domain_match.groups() if g), "") if domain_match else ""
    
    port_match = re.search(r':(\d+)', line)
    port = validate_port(port_match.group(1)) if port_match else CONFIG["filter"]["DEFAULT_PORT"]
    return ip, domain, port

def test_outside_access(ip: str, port: int, proto: str, cfg: Dict = None) -> Tuple[bool, str, float]:
    if proto not in ["vmess", "vless", "trojan", "ss"]:
        return False, "", 0.0
    
    target_list = CONFIG["detection"]["http_test"]["targets"]
    timeout = CONFIG["detection"]["http_test"]["timeout"]
    
    try:
        ip_addr = socket.gethostbyname(ip)
        if is_cn_ip(ip_addr):
            LOG.info(log_msg(f"📝 过滤国内IP节点：{ip_addr}:{port}", proto=proto))
            return False, "", 0.0
        
        for target in target_list:
            try:
                start_time = time.time()
                parsed = urlparse(target)
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    if sock.connect_ex((ip_addr, port)) != 0:
                        continue
                    
                    request = (
                        f"{parsed.scheme.upper()} {parsed.path or '/'}?{parsed.query} HTTP/1.1\r\n"
                        f"Host: {parsed.netloc}\r\n"
                        f"User-Agent: {CONFIG['request']['ua']}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    sock.send(request.encode('utf-8'))
                    response = sock.recv(4096)
                    elapsed = time.time() - start_time
                    
                    if len(response) > 0 and any(code in response.decode('utf-8', errors='ignore') for code in ["200", "204"]):
                        return True, target, elapsed
                
                LOG.info(log_msg(f"⚠️ 目标{target}响应无效：{ip_addr}:{port}", proto=proto))
            except socket.timeout:
                LOG.info(log_msg(f"⚠️ 目标{target}超时：{ip_addr}:{port}", proto=proto))
                continue
            except Exception as e:
                LOG.info(log_msg(f"⚠️ 目标{target}测试失败：{str(e)[:30]}", proto=proto))
                continue
        
        try:
            fallback = CONFIG["detection"]["http_test"]["fallback"]
            parsed_fb = urlparse(fallback)
            start_time = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout/2)
                if sock.connect_ex((ip_addr, port)) == 0:
                    request_fb = (
                        f"GET {parsed_fb.path or '/'} HTTP/1.1\r\n"
                        f"Host: {parsed_fb.netloc}\r\n"
                        f"User-Agent: {CONFIG['request']['ua']}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    sock.send(request_fb.encode('utf-8'))
                    response_fb = sock.recv(1024)
                    if len(response_fb) > 0:
                        LOG.info(log_msg(f"⚠️ 仅能访问国内站点：{ip_addr}:{port}", proto=proto))
        except Exception:
            pass
        
        return False, "", 0.0
    except Exception as e:
        LOG.info(log_msg(f"⚠️ 外网测试失败：{str(e)[:30]}", proto=proto))
        return False, "", 0.0

def calculate_node_score(
    proto: str, 
    security: str, 
    port: int, 
    dns_ok: bool, 
    outside_ok: bool, 
    response_time: float, 
    is_cn: bool,
    stability: float,
    ip_type: str
) -> int:
    """优化后的评分函数：分协议阈值、权重重构、新增维度"""
    score = 0
    rules = CONFIG["filter"]["score_rules"]
    rt_thresholds = CONFIG["detection"]["rt_thresholds"].get(proto, {"min":0.05, "max":6})
    
    # 1. 国内IP扣分（降低至-40，不直接置0）
    if is_cn:
        cn_score = rules["cn_ip"]
        score += cn_score
        score = max(score, 0)  # 保证不低于0
    
    # 2. 响应时间异常扣分（分协议阈值，不直接置0）
    if response_time < rt_thresholds["min"] or response_time > rt_thresholds["max"]:
        rt_score = rules["response_time_abnormal"]
        score += rt_score
        score = max(score, 0)
    
    # 3. 协议类型得分
    proto_score = rules["protocol"].get(proto, 0)
    score += proto_score
    
    # 4. 安全类型得分
    security_score = rules["security"].get(security, 0)
    score += security_score
    
    # 5. 端口得分
    port_score = rules["port"].get(port, rules["port"]["other"])
    score += port_score
    
    # 6. DNS有效性得分（IP直连也加分）
    dns_score = rules["dns_valid"] if (dns_ok or is_ip(ip_type)) else 0
    score += dns_score
    
    # 7. 外网访问得分（无外网扣分，不直接置0）
    outside_score = rules["http_valid"] if outside_ok else -rules["http_valid"]
    score += outside_score
    score = max(score, 0)
    
    # 8. 响应速度得分（分协议）
    speed_score = 0
    speed_rules = rules["response_speed"].get(proto, {"fast": 0, "normal": 0, "slow": 0})
    if response_time < 1.0:
        speed_score = speed_rules["fast"]
    elif response_time < 3.0:
        speed_score = speed_rules["normal"]
    else:
        speed_score = speed_rules["slow"]
    score += speed_score
    
    # 9. 稳定性得分（成功率*权重）
    stability_score = int(rules["stability"] * stability)
    score += stability_score
    
    # 10. IP类型得分
    ip_type_score = rules["ip_type"].get(ip_type, 0)
    score += ip_type_score
    
    # 总分限制在0-100
    final_score = min(max(score, 0), 100)
    
    # 输出评分明细日志
    LOG.info(
        f"📊 评分明细：\n"
        f"   协议({proto_score}) + 安全({security_score}) + 端口({port_score}) + DNS({dns_score}) + 外网({outside_score}) + 速度({speed_score}) + 稳定性({stability_score}) + IP类型({ip_type_score}) + 国内IP({cn_score if is_cn else 0}) + 响应异常({rt_score if (response_time < rt_thresholds['min'] or response_time > rt_thresholds['max']) else 0}) = 总分({final_score})"
    )
    
    return final_score

# ========== 协议解析函数 ==========
def parse_vmess(line: str) -> Optional[Dict]:
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
        
        try:
            uuid.UUID(cfg["id"])
            alter_id = int(cfg.get("aid", 0))
            if alter_id < 0 or alter_id > 65535:
                LOG.info(log_msg(f"📝 VMess alterId无效（{alter_id}）", line, "vmess"))
                return None
            
            valid_security = ["auto", "aes-128-gcm", "chacha20-ietf-poly1305"]
            if cfg.get("scy") not in valid_security and cfg.get("scy") is not None:
                LOG.info(log_msg(f"📝 VMess加密方式无效（{cfg.get('scy')}）", line, "vmess"))
                return None
        except (ValueError, KeyError):
            LOG.info(log_msg(f"📝 VMess UUID/alterId格式无效", line, "vmess"))
            return None
        
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
            "ps": cfg["ps"],
            "security_type": "tls" if cfg.get("tls") == "tls" else ("aead" if cfg.get("scy") in ["aes-128-gcm", "chacha20-ietf-poly1305"] else "none")
        }
    except Exception as e:
        LOG.info(log_msg(f"❌ VMess解析错误: {str(e)}", line, "vmess"))
        return None

def parse_vless(line: str) -> Optional[Dict]:
    try:
        core_content, remark = proto_preprocess(line, "vless://")
        vless_parts = core_content.split('?', 1)
        base_part = vless_parts[0]
        param_part = vless_parts[1] if len(vless_parts) > 1 else ''
        
        if '@' not in base_part:
            raise ValueError("缺失UUID@地址格式")
        
        uuid_str, addr_port = base_part.split('@', 1)
        if not uuid_str or not addr_port or ':' not in addr_port:
            raise ValueError("UUID/地址端口错误")
        
        try:
            uuid.UUID(uuid_str)
        except ValueError:
            LOG.info(log_msg(f"📝 VLESS UUID格式无效", line, "vless"))
            return None
        
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
        
        security = params.get('security', 'tls')
        if port != 443 and security not in ['tls', 'reality']:
            LOG.info(log_msg(f"📝 VLESS非443端口无TLS/Reality（{address}:{port}）", line, "vless"))
            return None
        
        if security == 'reality':
            required_reality = ['pbk', 'sid', 'fp']
            missing = [p for p in required_reality if p not in params]
            if missing:
                LOG.info(log_msg(f"📝 VLESS Reality缺失参数：{','.join(missing)}", line, "vless"))
                return None
            
            pbk = params.get('pbk', '')
            if len(pbk) != 44:
                LOG.info(log_msg(f"📝 VLESS Reality pbk长度无效（{len(pbk)}）", line, "vless"))
                return None
        
        cfg = {
            "uuid": uuid_str,
            "address": address,
            "port": port,
            "security": security,
            "sni": params.get('sni', address),
            "network": params.get('type', 'tcp'),
            "remarks": params.get('remarks', 'VLESS节点'),
            "security_type": security
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
        
        if len(password.strip()) < 8:
            LOG.info(log_msg(f"📝 Trojan密码过短（{len(password)}字符）", line, "trojan"))
            return None
        
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        
        params = {}
        for p in param_part.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k.lower()] = v
        
        security = params.get('security', 'tls')
        if port != 443 and security != 'tls':
            LOG.info(log_msg(f"📝 Trojan非443端口无TLS（{address}:{port}）", line, "trojan"))
            return None
        
        cfg = {
            "address": address,
            "port": port,
            "password": password,
            "sni": params.get('sni', address),
            "security": security,
            "label": remark,
            "security_type": security
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
    try:
        ss_core, remark = proto_preprocess(line, "ss://")
        addr_port = ""
        decoded_auth = ""
        
        if '@' in ss_core:
            base64_part, addr_port = ss_core.split('@', 1)
            decoded_auth = b64_safe_decode(base64_part)
        else:
            decoded_auth = b64_safe_decode(ss_core)
            if '@' not in decoded_auth:
                raise ValueError("标准格式但Base64内无@分隔符")
            decoded_auth, addr_port = decoded_auth.split('@', 1)
        
        if not addr_port or ':' not in addr_port:
            raise ValueError("地址端口格式错误（需为IP:端口/域名:端口）")
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        
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
        
        if method not in CONFIG["filter"]["SS_VALID_CIPHERS"]:
            LOG.info(log_msg(f"📝 SS加密方式无效（{method}）", line, "ss"))
            return None
        
        if len(password) < 4:
            LOG.info(log_msg(f"📝 SS密码过短（{len(password)}字符）", line, "ss"))
            return None
        
        cfg = {
            "address": address.strip(),
            "port": port,
            "remark": remark,
            "method": method,
            "password": password,
            "method_valid": True,
            "security_type": "aead" if method in ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"] else "none"
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
    try:
        core_content, remark = proto_preprocess(line, "hysteria://")
        
        if '?' in core_content:
            addr_port_part, param_part = core_content.split('?', 1)
            param_part = param_part.replace(' ', '')
        else:
            addr_port_part = core_content
            param_part = ''
        
        if not addr_port_part or ':' not in addr_port_part:
            raise ValueError("地址端口格式错误（需为IP:端口/域名:端口）")
        address, port_str = addr_port_part.rsplit(':', 1)
        address = address.strip()
        port = validate_port(port_str)
        
        params = {}
        if param_part:
            for p in param_part.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    k_lower = k.lower()
                    params[k_lower] = v.strip()
        
        auth = params.get('auth', params.get('auth_str', ''))
        if not auth:
            raise ValueError("缺失认证信息（auth/auth_str参数）")
        
        alpn = params.get('alpn', 'h3')
        if alpn not in ['h3', 'http/1.1']:
            LOG.info(log_msg(f"📝 Hysteria ALPN无效（{alpn}）", line, "hysteria"))
            return None
        
        cfg = {
            "address": address,
            "port": port,
            "password": auth,
            "obfs": params.get('obfs', ''),
            "alpn": alpn,
            "peer": params.get('peer', address),
            "protocol": params.get('protocol', 'udp'),
            "insecure": params.get('insecure', '1'),
            "downmbps": params.get('downmbps', ''),
            "upmbps": params.get('upmbps', ''),
            "label": remark,
            "security_type": "tls" if params.get('tls', '1') == '1' else "none"
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

# ========== 节点检测函数 ==========
def test_node_final(ip: str, port: int, proto: str, cfg: Dict = None) -> Tuple[bool, float, bool, str, float]:
    """优化后：增加多次检测计算稳定性"""
    port = validate_port(port)
    if not ip or is_private_ip(ip):
        return False, 0.0, False, "private_ip", 0.0
    
    ip_addr = ""
    avg_response_time = 0.0
    outside_ok = False
    fail_reason = ""
    success_count = 0
    response_times = []
    total_tests = CONFIG["detection"]["tcp_retry"]
    
    try:
        ip_addr = socket.gethostbyname(ip)
        
        if is_cn_ip(ip_addr):
            fail_reason = "cn_ip"
            return False, 0.0, False, fail_reason, 0.0
        
        # 多次检测计算稳定性
        for _ in range(total_tests):
            try:
                start_time = time.time()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(CONFIG["detection"]["tcp_timeout"].get(proto, 5))
                    if sock.connect_ex((ip_addr, port)) == 0:
                        success_count += 1
                        response_times.append(time.time() - start_time)
                time.sleep(0.1)
            except Exception:
                continue
        
        # 计算平均响应时间
        avg_response_time = sum(response_times)/len(response_times) if response_times else 0.0
        stability = success_count / total_tests
        
        # 响应时间异常判断（分协议）
        rt_thresholds = CONFIG["detection"]["rt_thresholds"].get(proto, {"min":0.05, "max":6})
        if avg_response_time < rt_thresholds["min"] or avg_response_time > rt_thresholds["max"]:
            fail_reason = "response_time_abnormal"
            return False, avg_response_time, False, fail_reason, stability
        
        # 外网访问验证
        outside_ok, _, _ = test_outside_access(ip, port, proto, cfg)
        if not outside_ok:
            fail_reason = "no_outside_access"
            return False, avg_response_time, outside_ok, fail_reason, stability
        
        # Hysteria UDP验证
        if proto == "hysteria":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                    udp_sock.settimeout(CONFIG["detection"]["tcp_timeout"]["hysteria"])
                    udp_sock.sendto(b"\x00\x01\x02", (ip_addr, port))
            except Exception:
                pass
        
        return True, avg_response_time, outside_ok, "success", stability
    except socket.gaierror:
        fail_reason = "dns_fail"
        return False, 0.0, False, fail_reason, 0.0
    except Exception as e:
        fail_reason = f"error:{str(e)[:20]}"
        return False, 0.0, False, fail_reason, 0.0

def process_single_node_final(node: Union[str, Dict]) -> Tuple[Optional[str], Dict, int]:
    raw_line = node["line"] if isinstance(node, dict) else node
    
    try:
        if not raw_line:
            return None, {}, 0
        
        clean_line = clean_node_content(raw_line)
        if not clean_line:
            LOG.info(log_msg(f"📝 过滤空节点", raw_line))
            return None, {}, 0
        
        ip, domain, port = extract_ip_port(clean_line)
        cfg = None
        proto = ""
        security_type = "none"
        dns_ok = False
        outside_ok = False
        response_time = 0.0
        score = 0
        is_cn = False
        stability = 0.0
        ip_type = "unknown"
        
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
            LOG.info(log_msg(f"📝 过滤未知协议节点", raw_line))
            return None, {}, 0
        
        if not cfg:
            return None, {}, 0
        
        # 提取核心信息
        ip = cfg.get("address", ip)
        domain = cfg.get("sni", domain)
        port = cfg.get("port", port)
        security_type = cfg.get("security_type", "none")
        
        # 过滤私有IP
        if is_private_ip(ip):
            LOG.info(log_msg(f"📝 过滤私有IP：{ip}:{port}", clean_line, proto))
            return None, {}, 0
        
        # 国内IP检测
        is_cn = is_cn_ip(ip)
        if is_cn:
            LOG.info(log_msg(f"📝 检测到国内IP：{ip}:{port}", clean_line, proto))
        
        # DNS有效性校验（IP直连也认可）
        dns_ok, dns_ips = dns_resolve(domain) if domain else (is_ip(ip), [ip])
        
        # IP类型识别
        ip_type = get_ip_type(ip)
        
        # 最终检测（含稳定性）
        tcp_ok, response_time, outside_ok, fail_reason, stability = test_node_final(ip, port, proto, cfg)
        if not tcp_ok:
            LOG.info(log_msg(f"📝 过滤节点（{fail_reason}）：{ip}:{port}", clean_line, proto))
            return None, {}, 0
        
        # 计算评分
        score = calculate_node_score(
            proto=proto,
            security=security_type,
            port=port,
            dns_ok=dns_ok,
            outside_ok=outside_ok,
            response_time=response_time,
            is_cn=is_cn,
            stability=stability,
            ip_type=ip_type
        )
        
        # 动态阈值判断
        dynamic_threshold = adjust_score_threshold([{"score": score}])
        if score < dynamic_threshold:
            LOG.info(log_msg(f"📝 过滤低分节点（{score}分 < {dynamic_threshold}分）：{ip}:{port}", clean_line, proto))
            return None, {}, 0
        
        # 组装节点信息
        node_info = {
            "line": clean_line,
            "proto": proto,
            "ip": ip,
            "port": port,
            "domain": domain,
            "security_type": security_type,
            "score": score,
            "response_time": response_time,
            "dns_ok": dns_ok,
            "outside_ok": outside_ok,
            "is_cn": is_cn,
            "stability": stability,
            "ip_type": ip_type,
            "source_url": node.get("source_url", "") if isinstance(node, dict) else ""
        }
        
        LOG.info(f"✅ 优质节点（{score}分）: {ip}:{port}（{proto}）RT：{response_time:.2f}s | 稳定性：{stability:.1%} | IP类型：{ip_type} | 外网：{'OK' if outside_ok else 'FAIL'}")
        return clean_line, node_info, score
    except Exception as e:
        LOG.info(log_msg(f"❌ 节点处理错误: {str(e)}", raw_line, proto))
        return None, {}, 0

def dedup_nodes_final(nodes: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []
    nodes.sort(key=lambda x: x["weight"], reverse=True)
    proto_list = ["vmess", "vless", "trojan", "ss", "hysteria"]
    
    for node in nodes:
        raw_line = node["line"]
        clean_line = clean_node_content(raw_line)
        proto = "other"
        
        for p in proto_list:
            if clean_line.startswith(f"{p}://"):
                proto = p
                break
        
        ip, _, port = extract_ip_port(clean_line)
        if ip:
            if proto == "vless" or proto == "vmess":
                cfg_match = re.search(r'([0-9a-f-]{8})', clean_line)
                cfg_key = cfg_match.group(1) if cfg_match else ""
            elif proto == "trojan" or proto == "ss":
                cfg_match = re.search(r'@([0-9a-f]{8})', clean_line)
                cfg_key = cfg_match.group(1) if cfg_match else ""
            else:
                cfg_key = ""
            key = f"{ip}:{port}:{proto}:{cfg_key}"
        else:
            key = f"{clean_line[:100]}:{proto}"
        
        if key not in seen:
            seen.add(key)
            unique.append({"line": raw_line, "source_url": node["source_url"], "weight": node["weight"]})
    
    LOG.info(f"🔍 最终去重完成：原始{len(nodes)}条 → 去重后{len(unique)}条")
    return unique

# ========== 数据源与统计 ==========
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
            
            # 第一次过滤
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
            
            # 条件解码
            content = decode_b64_sub(content_after_first_filter)
            
            # 第二次过滤
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
            LOG.error(f"   - {err}")
        return False
    return True

def count_proto(lines: List[Union[str, Dict]]) -> Dict[str, int]:
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

def adjust_score_threshold(valid_nodes_info: List[Dict]) -> int:
    """动态调整阈值：避免无节点输出"""
    base_threshold = CONFIG["detection"]["score_threshold"]
    if not valid_nodes_info:
        return base_threshold
    
    scores = [n["score"] for n in valid_nodes_info if "score" in n]
    if not scores:
        return base_threshold
    
    avg_score = sum(scores)/len(scores)
    # 动态阈值：平均得分的70%，且不低于60，不高于75
    dynamic_threshold = max(60, min(75, int(avg_score * 0.7)))
    
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
    valid_lines = []
    valid_nodes_info = []
    total = len(unique_nodes)
    LOG.info(f"\n🔍 开始处理 {total} 个去重后节点")
    
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
            if line and score >= adjust_score_threshold([node_info]):
                valid_lines.append(line)
                valid_nodes_info.append(node_info)
    
    # 按评分降序排序
    valid_nodes_info.sort(key=lambda x: x["score"], reverse=True)
    valid_lines_sorted = [node["line"] for node in valid_nodes_info]
    
    LOG.info(f"✅ 最终优质节点筛选完成：共{len(valid_lines_sorted)}条（基础阈值{CONFIG['detection']['score_threshold']}分）")
    return valid_lines_sorted, valid_nodes_info

def generate_final_stats(all_nodes: List[Dict], unique_nodes: List[Dict], valid_lines: List[str], 
                        valid_nodes_info: List[Dict], start_time: float) -> None:
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
    
    # 保存所有有效节点（未分级）
    save_nodes(valid_lines, 'final_all.txt', "所有有效节点（≥65分）")
    
    # 统计信息
    total_cost = time.time() - start_time
    avg_response_time = sum([n["response_time"] for n in valid_nodes_info]) / len(valid_nodes_info) if valid_nodes_info else 0
    avg_stability = sum([n["stability"] for n in valid_nodes_info]) / len(valid_nodes_info) if valid_nodes_info else 0
    outside_ok_rate = len([n for n in valid_nodes_info if n["outside_ok"]]) / len(valid_nodes_info) * 100 if valid_nodes_info else 0
    cn_ip_rate = len([n for n in valid_nodes_info if n["is_cn"]]) / len(valid_nodes_info) * 100 if valid_nodes_info else 0
    
    LOG.info(f"\n🏆 最终筛选报告：")
    LOG.info(f"   ├─ 原始节点：{len(all_nodes)} 条 → 去重后：{len(unique_nodes)} 条 → 有效节点：{len(valid_lines)} 条")
    LOG.info(f"   ├─ 节点分级：优质（≥90分）{len(excellent)}条 | 良好（80-89分）{len(good)}条 | 合格（65-79分）{len(qualified)}条")
    LOG.info(f"   ├─ 协议分布：VLESS({proto_count['vless']}) | Trojan({proto_count['trojan']}) | VMess({proto_count['vmess']}) | SS({proto_count['ss']}) | Hysteria({proto_count['hysteria']})")
    LOG.info(f"   ├─ 性能指标：平均响应 {avg_response_time:.2f}s | 平均稳定性 {avg_stability:.1%} | 外网通过率 {outside_ok_rate:.1f}% | 国内IP占比 {cn_ip_rate:.1f}%")
    LOG.info(f"   └─ 总耗时：{total_cost:.2f} 秒 | 输出文件：final_all.txt")

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
    
    generate_final_stats(all_nodes, unique_nodes, valid_lines, valid_nodes_info, start_time)
    
    try:
        SESSION.close()
        LOG.info("🔌 关闭请求会话")
    except Exception as e:
        LOG.warning(f"⚠️ 会话关闭异常: {str(e)[:50]}")
    
    LOG.info("\n✅ 终极筛选完成！有效节点已保存至 final_all.txt")

if __name__ == "__main__":
    main()
