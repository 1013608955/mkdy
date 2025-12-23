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
import json
from urllib.parse import unquote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import lru_cache
import urllib3

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== 核心配置（最终优化版） ==========
CONFIG = {
    "sources": [
        {"url": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub", "weight": 5},
        {"url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt", "weight": 5},
        {"url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray.txt", "weight": 5},
        {"url": "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray", "weight": 4},
        {"url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt", "weight": 4},
        {"url": "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt", "weight": 3},
        {"url": "https://raw.githubusercontent.com/HakurouKen/free-node/main/public", "weight": 3},
        {"url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", "weight": 2}
    ],
    "request": {
        "timeout": 120,
        "retry": 2,
        "retry_delay": 2,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    "github": {
        "token": os.getenv("GITHUB_TOKEN", ""),
        "interval": 0.5,
        "cache_ttl": 3600,
        "cache_max_size": 100 * 1024 * 1024  # 缓存目录最大100MB
    },
    "detection": {
        "tcp_timeout": {"vmess": 8, "vless": 8, "trojan": 8, "ss": 6, "hysteria": 10},
        "tcp_retry": 2,  # TCP探测重试次数（稳定性验证）
        "tcp_retry_interval": 0.5,  # 重试间隔
        "http_validate_urls": [  # 可用性验证URL（优先级从高到低）
            "http://httpbin.org/ip",
            "https://www.google.com/generate_204",
            "http://ip-api.com/json/"
        ],
        "http_validate_timeout": 5,  # 可用性验证超时
        # 分级HTTP验证次数（差异化）
        "http_validate_attempts": {
            "excellent": 1,  # 优质节点仅验证1个URL
            "good": 2,       # 良好节点验证2个URL
            "qualified": 3   # 合格节点验证全部URL
        },
        "score_threshold": 60,  # 保留阈值
        "min_response_time": 0.05,  # 最小有效响应时间
        "max_response_time": 8.0,   # 最大有效响应时间
        # 动态并发配置
        "concurrency": {
            "small": 4,   # 节点数<100
            "medium": 8,  # 100≤节点数<500
            "large": 12   # 节点数≥500
        }
    },
    "filter": {
        "private_ip_patterns": re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1|localhost)"),
        "cn_ip_patterns": re.compile(r"^(223\.|202\.|210\.|10\.|192\.168\.|172\.)"),
        "ports": range(1, 65535),
        "min_line_length": 10,  # 最小节点行长度
        "max_line_length": 5000, # 最大节点行长度
        "DEFAULT_PORT": 443,
        "SS_DEFAULT_CIPHER": "aes-256-gcm",
        "SS_VALID_CIPHERS": ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb"],
        # 评分权重配置（最终优化版）
        "score_weights": {
            # 加分项
            "protocol": {
                "vless": 20,
                "trojan": 18,
                "vmess": 15,
                "hysteria": 12,
                "ss": 8,
                "other": 0
            },
            "security": {
                "reality": 20,
                "tls": 18,
                "none": 0
            },
            "port": {
                443: 8,
                8443: 6,
                "other": 3
            },
            "dns_valid": 5,
            "net_validate": 10,
            "response_speed": {
                "0.05-0.5": 20,
                "0.5-1.0": 15,
                "1.0-3.0": 10,
                "3.0-8.0": 0,
                "<0.05|>8.0": 0
            },
            "availability": {
                "full": 15,  # HTTP访问成功
                "tcp_only": 5,  # 仅TCP通
                "failed": 0
            },
            # 扣分项
            "cn_ip": {
                "pure_cn": -30,
                "cn_relay": -10,
                "non_cn": 0
            },
            "response_time": {
                "<0.05|>8.0": -30,
                "3.0-8.0": -10,
                "0.05-3.0": 0
            }
        },
        # 分级区间（最终优化版）
        "grade_ranges": {
            "excellent": (80, 100),  # 优质
            "good": (70, 79),        # 良好
            "qualified": (60, 69)    # 合格
        },
        # 基础分预过滤阈值（避免无效HTTP验证）
        "base_score_threshold": 50
    }
}

# ========== 日志初始化（最终优化版） ==========
def init_logger() -> logging.Logger:
    logger = logging.getLogger("node_scorer_optimized")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger

LOG = init_logger()

# ========== 核心工具函数（极致粗筛+缓存复用） ==========
# IP/端口解析缓存（扩大缓存容量）
@lru_cache(maxsize=5000)
def extract_ip_port(line: str) -> tuple[str, str, int]:
    """提取节点IP、域名、端口（带缓存）"""
    ip = ""
    domain = ""
    port = CONFIG["filter"]["DEFAULT_PORT"]
    
    try:
        # 匹配@后的IP/域名和端口
        pattern = r"@([a-zA-Z0-9\-\.]+):(\d+)"
        match = re.search(pattern, line)
        if match:
            domain = match.group(1)
            port = int(match.group(2))
            
            # 仅对非私有域名尝试解析IP（避免无效解析）
            if not CONFIG["filter"]["private_ip_patterns"].match(domain):
                try:
                    ip = socket.gethostbyname(domain)
                except (socket.gaierror, ValueError):
                    ip = domain  # 解析失败则用域名代替
    except Exception as e:
        LOG.debug(f"解析IP/端口失败: {line[:50]}... 错误: {str(e)}")
    
    return ip, domain, port

def clean_node_lines(raw_lines: list[str]) -> list[str]:
    """阶段1.1：原始行清洗（极致粗筛第一步）"""
    cleaned = []
    for line in raw_lines:
        line = line.strip()
        # 过滤空行、过短/过长行、特殊字符行
        if (not line or 
            len(line) < CONFIG["filter"]["min_line_length"] or 
            len(line) > CONFIG["filter"]["max_line_length"] or 
            re.search(r"[^\x20-\x7E]", line)):  # 非ASCII可见字符
            continue
        cleaned.append(line)
    LOG.info(f"原始行清洗完成：原{len(raw_lines)}行 → 清洗后{len(cleaned)}行")
    return cleaned

def quick_proto_validate(line: str) -> bool:
    """阶段1.2：协议格式快速校验（低成本粗筛）"""
    line = line.strip()
    if not line:
        return False
    
    # VMess：快速校验Base64合法性
    if line.startswith("vmess://"):
        vmess_part = line.replace("vmess://", "")
        if len(vmess_part) % 4 != 0:  # Base64长度必须是4的倍数
            return False
        try:
            # 仅校验前200字符（避免超长解析）
            base64.b64decode(vmess_part[:200], validate=True)
            return True
        except base64.binascii.Error:
            return False
    
    # VLESS：校验核心格式（@和端口）
    elif line.startswith("vless://"):
        parts = line.split("@")
        if len(parts) < 2:
            return False
        port_part = parts[1].split(":")
        return len(port_part) >= 2 and port_part[1].isdigit()
    
    # Trojan：校验核心格式
    elif line.startswith("trojan://"):
        parts = line.split("@")
        if len(parts) < 2:
            return False
        port_part = parts[1].split(":")
        return len(port_part) >= 2 and port_part[1].split("#")[0].isdigit()
    
    # SS：快速校验Base64合法性
    elif line.startswith("ss://"):
        ss_part = line.replace("ss://", "")
        if len(ss_part) % 4 != 0:
            return False
        try:
            base64.b64decode(ss_part[:200], validate=True)
            return True
        except base64.binascii.Error:
            return False
    
    # Hysteria：校验核心格式
    elif line.startswith("hysteria://"):
        parts = line.split(":")
        return len(parts) >= 2 and parts[1].replace("//", "").isdigit()
    
    # 未知协议
    return False

def pre_deduplicate_nodes(lines: list[str], sources: list[dict]) -> list[str]:
    """阶段1.3：预去重（IP+端口+协议），保留高权重订阅源节点"""
    node_map = {}  # key: proto_ip_port, value: (line, weight)
    
    for line in lines:
        # 先快速解析协议类型
        proto = ""
        if line.startswith("vmess://"):
            proto = "vmess"
        elif line.startswith("vless://"):
            proto = "vless"
        elif line.startswith("trojan://"):
            proto = "trojan"
        elif line.startswith("ss://"):
            proto = "ss"
        elif line.startswith("hysteria://"):
            proto = "hysteria"
        else:
            continue
        
        # 提取IP+端口
        ip, _, port = extract_ip_port(line)
        if not ip or not port:
            continue
        
        # 匹配节点所属订阅源权重
        weight = 1
        for source in sources:
            if source["url"] in line:  # 简单匹配（实际可优化为溯源）
                weight = source["weight"]
                break
        
        # 保留高权重节点
        key = f"{proto}_{ip}_{port}"
        if key not in node_map or weight > node_map[key][1]:
            node_map[key] = (line, weight)
    
    # 提取去重后的节点
    deduped = [v[0] for v in node_map.values()]
    LOG.info(f"节点预去重完成：原{len(lines)}行 → 去重后{len(deduped)}行")
    return deduped

def filter_private_ip_and_invalid_port(lines: list[str]) -> list[str]:
    """阶段1.4-1.5：过滤私有IP+无效端口"""
    filtered = []
    for line in lines:
        ip, _, port = extract_ip_port(line)
        
        # 过滤私有IP
        if is_private_ip(ip):
            LOG.debug(f"过滤私有IP节点：{line[:50]}...")
            continue
        
        # 过滤无效端口
        if port not in CONFIG["filter"]["ports"]:
            LOG.debug(f"过滤无效端口节点：{port} → {line[:50]}...")
            continue
        
        filtered.append(line)
    
    LOG.info(f"私有IP+无效端口过滤完成：原{len(lines)}行 → 过滤后{len(filtered)}行")
    return filtered

def is_private_ip(ip: str) -> bool:
    """判断是否为私有IP"""
    return CONFIG["filter"]["private_ip_patterns"].match(ip) is not None

def judge_cn_ip(ip: str, is_available: bool) -> str:
    """判断IP类型（纯国内/中转/非国内）"""
    if CONFIG["filter"]["cn_ip_patterns"].match(ip):
        # 能访问外网则判定为中转
        return "cn_relay" if is_available else "pure_cn"
    return "non_cn"

def get_response_speed_score(response_time: float) -> int:
    """获取响应速度加分（精细化）"""
    if response_time < CONFIG["filter"]["min_response_time"] or response_time > CONFIG["filter"]["max_response_time"]:
        return 0
    elif 0.05 <= response_time < 0.5:
        return CONFIG["filter"]["score_weights"]["response_speed"]["0.05-0.5"]
    elif 0.5 <= response_time < 1.0:
        return CONFIG["filter"]["score_weights"]["response_speed"]["0.5-1.0"]
    elif 1.0 <= response_time < 3.0:
        return CONFIG["filter"]["score_weights"]["response_speed"]["1.0-3.0"]
    else:  # 3.0-8.0
        return 0

def get_response_time_penalty(response_time: float) -> int:
    """获取响应时间扣分（精细化）"""
    if response_time < CONFIG["filter"]["min_response_time"] or response_time > CONFIG["filter"]["max_response_time"]:
        return CONFIG["filter"]["score_weights"]["response_time"]["<0.05|>8.0"]
    elif 3.0 <= response_time < 8.0:
        return CONFIG["filter"]["score_weights"]["response_time"]["3.0-8.0"]
    else:
        return 0

# ========== 网络探测函数（轻量→重度，逐步升级） ==========
def tcp_probe(ip: str, port: int, proto: str) -> tuple[bool, float]:
    """阶段2.2：TCP探测（稳定性验证：2次探测取平均）"""
    total_time = 0.0
    success_count = 0
    timeout = CONFIG["detection"]["tcp_timeout"].get(proto, 8)
    
    for _ in range(CONFIG["detection"]["tcp_retry"]):
        start = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                success_count += 1
                total_time += (time.time() - start)
            time.sleep(CONFIG["detection"]["tcp_retry_interval"])
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            LOG.debug(f"TCP探测失败：{ip}:{port} → {str(e)}")
            continue
    
    if success_count == 0:
        return False, 0.0
    avg_time = total_time / success_count
    LOG.debug(f"TCP探测成功：{ip}:{port} → 平均响应时间{avg_time:.3f}s")
    return True, avg_time

def http_validate(ip: str, port: int, grade: str) -> str:
    """阶段3.1：分级差异化HTTP可用性验证"""
    attempt_count = CONFIG["detection"]["http_validate_attempts"][grade]
    headers = {"User-Agent": CONFIG["request"]["ua"]}
    
    # 按分级取对应数量的验证URL
    validate_urls = CONFIG["detection"]["http_validate_urls"][:attempt_count]
    
    for url in validate_urls:
        try:
            # 优先用IP访问（避免DNS污染）
            parsed = urlparse(url)
            # 处理443/80端口的特殊情况
            if port in [80, 443]:
                req_url = f"{parsed.scheme}://{ip}{parsed.path}"
            else:
                req_url = f"{parsed.scheme}://{ip}:{port}{parsed.path}"
            
            response = requests.get(
                req_url,
                headers=headers,
                timeout=CONFIG["detection"]["http_validate_timeout"],
                verify=False,
                allow_redirects=True
            )
            if response.status_code in [200, 204]:
                LOG.debug(f"HTTP验证成功：{ip}:{port} → {url}")
                return "full"  # 完全可用
        except (requests.Timeout, requests.ConnectionError, ValueError) as e:
            LOG.debug(f"HTTP验证失败：{ip}:{port} → {url} → {str(e)}")
            continue
    
    return "tcp_only"  # 仅TCP通

# ========== 协议解析（抽象通用逻辑） ==========
class ProtocolParser:
    """协议解析基类（仅解析必要信息，避免深解析）"""
    @staticmethod
    def parse_basic_info(line: str) -> dict | None:
        """解析节点基础信息（协议/安全类型）"""
        line = line.strip()
        if not line:
            return None
        
        # VMess
        if line.startswith("vmess://"):
            try:
                vmess_part = line.replace("vmess://", "")
                decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
                cfg = json.loads(decoded)
                security_type = "tls" if cfg.get("tls") == "tls" else "none"
                return {"protocol": "vmess", "security_type": security_type}
            except (base64.binascii.Error, json.JSONDecodeError, ValueError, KeyError):
                return {"protocol": "vmess", "security_type": "none"}
        
        # VLESS
        elif line.startswith("vless://"):
            security_type = "reality" if "reality=" in line else "tls" if "tls=" in line else "none"
            return {"protocol": "vless", "security_type": security_type}
        
        # Trojan
        elif line.startswith("trojan://"):
            security_type = "tls" if "tls" in line else "none"
            return {"protocol": "trojan", "security_type": security_type}
        
        # SS
        elif line.startswith("ss://"):
            return {"protocol": "ss", "security_type": "none"}
        
        # Hysteria
        elif line.startswith("hysteria://"):
            security_type = "tls" if "tls=" in line else "none"
            return {"protocol": "hysteria", "security_type": security_type}
        
        # 未知协议
        else:
            return {"protocol": "other", "security_type": "none"}

# ========== 评分逻辑（基础分→最终分，分步计算） ==========
def calculate_base_score(node_info: dict, ip: str, port: int, response_time: float) -> tuple[int, dict]:
    """阶段2.3：计算基础分（仅轻量网络信息，无HTTP）"""
    score = 0
    score_detail = {"penalties": {}, "additions": {}, "base_score": 0}
    
    # 1. 扣分项
    # 1.1 响应时间扣分（先扣，无IP信息）
    rt_penalty = get_response_time_penalty(response_time)
    score += rt_penalty
    score_detail["penalties"]["response_time"] = rt_penalty
    
    # 2. 加分项（无HTTP相关）
    # 2.1 协议加分
    proto_score = CONFIG["filter"]["score_weights"]["protocol"].get(node_info["protocol"], 0)
    score += proto_score
    score_detail["additions"]["protocol"] = proto_score
    
    # 2.2 安全类型加分
    sec_key = "reality" if node_info["security_type"] == "reality" else "tls" if node_info["security_type"] == "tls" else "none"
    sec_score = CONFIG["filter"]["score_weights"]["security"][sec_key]
    score += sec_score
    score_detail["additions"]["security"] = sec_score
    
    # 2.3 端口加分
    port_score = CONFIG["filter"]["score_weights"]["port"].get(port, CONFIG["filter"]["score_weights"]["port"]["other"])
    score += port_score
    score_detail["additions"]["port"] = port_score
    
    # 2.4 DNS有效性加分（解析成功才加）
    dns_score = CONFIG["filter"]["score_weights"]["dns_valid"] if ip else 0
    score += dns_score
    score_detail["additions"]["dns_valid"] = dns_score
    
    # 2.5 响应速度加分
    speed_score = get_response_speed_score(response_time)
    score += speed_score
    score_detail["additions"]["response_speed"] = speed_score
    
    # 基础分修正（0~100）
    base_score = max(0, min(score, 100))
    score_detail["base_score"] = base_score
    
    # 预分级（用于后续HTTP验证次数）
    if base_score >= CONFIG["filter"]["grade_ranges"]["excellent"][0]:
        score_detail["pre_grade"] = "excellent"
    elif base_score >= CONFIG["filter"]["grade_ranges"]["good"][0]:
        score_detail["pre_grade"] = "good"
    elif base_score >= CONFIG["filter"]["base_score_threshold"]:
        score_detail["pre_grade"] = "qualified"
    else:
        score_detail["pre_grade"] = "reject"
    
    return base_score, score_detail

def calculate_final_score(base_score: int, base_detail: dict, ip: str, availability: str) -> tuple[int, dict]:
    """阶段3.2：计算最终分（加入HTTP验证+国内IP扣分）"""
    final_score = base_score
    score_detail = base_detail.copy()
    score_detail["final_score"] = 0
    score_detail["grade"] = ""
    
    # 1. 国内IP扣分（依赖可用性）
    cn_ip_type = judge_cn_ip(ip, availability == "full")
    cn_penalty = CONFIG["filter"]["score_weights"]["cn_ip"][cn_ip_type]
    final_score += cn_penalty
    score_detail["penalties"]["cn_ip"] = cn_penalty
    
    # 2. 外网验证加分（HTTP成功才加）
    net_score = CONFIG["filter"]["score_weights"]["net_validate"] if availability == "full" else 0
    final_score += net_score
    score_detail["additions"]["net_validate"] = net_score
    
    # 3. 可用性加分
    avail_score = CONFIG["filter"]["score_weights"]["availability"][availability]
    final_score += avail_score
    score_detail["additions"]["availability"] = avail_score
    
    # 最终分修正
    final_score = max(0, min(final_score, 100))
    score_detail["final_score"] = final_score
    
    # 最终分级
    if final_score >= CONFIG["filter"]["grade_ranges"]["excellent"][0]:
        score_detail["grade"] = "excellent"
    elif final_score >= CONFIG["filter"]["grade_ranges"]["good"][0]:
        score_detail["grade"] = "good"
    elif final_score >= CONFIG["filter"]["grade_ranges"]["qualified"][0]:
        score_detail["grade"] = "qualified"
    else:
        score_detail["grade"] = "reject"
    
    return final_score, score_detail

# ========== 核心业务逻辑（严格按易→难执行） ==========
def load_subscription() -> list[str]:
    """加载订阅源（带缓存优化）"""
    all_nodes = []
    cache_dir = ".cache"
    os.makedirs(cache_dir, exist_ok=True)
    
    # 清理过期/超大缓存
    clean_cache(cache_dir)
    
    with requests.Session() as sess:
        sess.headers["User-Agent"] = CONFIG["request"]["ua"]
        
        for source in CONFIG["sources"]:
            url = source["url"]
            cache_key = hashlib.md5(url.encode()).hexdigest()
            cache_path = os.path.join(cache_dir, f"{cache_key}.json")
            
            # 优先读缓存
            if os.path.exists(cache_path) and time.time() - os.path.getmtime(cache_path) < CONFIG["github"]["cache_ttl"]:
                try:
                    with open(cache_path, "r", encoding="utf-8") as f:
                        cached_nodes = json.load(f)
                    all_nodes.extend(cached_nodes)
                    LOG.info(f"从缓存加载订阅源: {url}，节点数: {len(cached_nodes)}")
                    continue
                except (json.JSONDecodeError, OSError) as e:
                    LOG.warning(f"缓存读取失败: {cache_path} 错误: {str(e)}")
            
            # 拉取订阅源
            try:
                response = sess.get(url, timeout=CONFIG["request"]["timeout"])
                response.raise_for_status()
                
                # 解码订阅内容
                decoded = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                nodes = [line.strip() for line in decoded.split("\n") if line.strip()]
                
                # 保存缓存
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(nodes, f, ensure_ascii=False)
                
                all_nodes.extend(nodes)
                LOG.info(f"拉取订阅源成功: {url}，节点数: {len(nodes)}")
                
                time.sleep(CONFIG["github"]["interval"])
            except (requests.RequestException, base64.binascii.Error) as e:
                LOG.error(f"拉取订阅源失败: {url} 错误: {str(e)}")
                continue
    
    # 原始行去重（粗去重）
    unique_raw = list(dict.fromkeys(all_nodes))
    LOG.info(f"订阅源加载完成，总节点数: {len(all_nodes)}，原始去重后: {len(unique_raw)}")
    
    return unique_raw

def clean_cache(cache_dir: str):
    """清理缓存（过期/超大）"""
    try:
        total_size = 0
        files = []
        
        for f in os.listdir(cache_dir):
            f_path = os.path.join(cache_dir, f)
            if os.path.isfile(f_path):
                f_size = os.path.getsize(f_path)
                total_size += f_size
                files.append((f_path, os.path.getmtime(f_path), f_size))
        
        # 删除过期文件
        for f_path, mtime, _ in files:
            if time.time() - mtime > CONFIG["github"]["cache_ttl"]:
                os.remove(f_path)
                LOG.info(f"删除过期缓存: {f_path}")
        
        # 删除最旧文件直到小于最大限制
        files.sort(key=lambda x: x[1])
        while total_size > CONFIG["github"]["cache_max_size"] and files:
            f_path, _, f_size = files.pop(0)
            os.remove(f_path)
            total_size -= f_size
            LOG.info(f"删除超大缓存: {f_path}")
    
    except OSError as e:
        LOG.error(f"缓存清理失败: {str(e)}")

def process_single_node(line: str) -> tuple[int, dict, str]:
    """处理单个节点（严格按易→难流程）"""
    # 初始化返回值
    final_score = 0
    score_detail = {"grade": "reject"}
    
    # 阶段1：极致粗筛（已前置，此处做二次校验）
    if not quick_proto_validate(line):
        return 0, score_detail, line
    
    # 提取基础信息
    node_info = ProtocolParser.parse_basic_info(line)
    ip, domain, port = extract_ip_port(line)
    
    # 过滤私有IP（二次校验）
    if is_private_ip(ip):
        return 0, score_detail, line
    
    # 阶段2：轻量网络筛
    # 2.1 TCP探测
    tcp_ok, response_time = tcp_probe(ip, port, node_info["protocol"])
    if not tcp_ok:
        return 0, score_detail, line
    
    # 2.2 计算基础分（预过滤）
    base_score, base_detail = calculate_base_score(node_info, ip, port, response_time)
    if base_score < CONFIG["filter"]["base_score_threshold"]:
        LOG.debug(f"基础分预过滤：{base_score}分 → {line[:50]}...")
        return 0, base_detail, line
    
    # 阶段3：重度网络筛（仅基础分达标节点）
    # 3.1 分级差异化HTTP验证
    availability = http_validate(ip, port, base_detail["pre_grade"])
    
    # 3.2 计算最终分
    final_score, final_detail = calculate_final_score(base_score, base_detail, ip, availability)
    
    return final_score, final_detail, line

def batch_process_nodes(nodes: list[str]) -> dict:
    """批量处理节点（动态并发）"""
    results = {
        "excellent": [],
        "good": [],
        "qualified": [],
        "all": []
    }
    
    # 动态调整并发数
    node_count = len(nodes)
    if node_count < 100:
        worker_num = CONFIG["detection"]["concurrency"]["small"]
    elif node_count < 500:
        worker_num = CONFIG["detection"]["concurrency"]["medium"]
    else:
        worker_num = CONFIG["detection"]["concurrency"]["large"]
    
    LOG.info(f"开始批量处理节点，总数: {node_count}，并发数: {worker_num}")
    
    with ThreadPoolExecutor(max_workers=worker_num) as executor:
        # 提交任务
        futures = [executor.submit(process_single_node, line) for line in nodes]
        
        # 处理结果
        processed = 0
        for future in as_completed(futures):
            try:
                score, detail, line = future.result()
                processed += 1
                
                # 按最终分级归类
                if score >= CONFIG["detection"]["score_threshold"]:
                    if detail["grade"] == "excellent":
                        results["excellent"].append(line)
                    elif detail["grade"] == "good":
                        results["good"].append(line)
                    elif detail["grade"] == "qualified":
                        results["qualified"].append(line)
                    results["all"].append(line)
                
                # 进度日志
                if processed % 50 == 0:
                    LOG.info(f"节点处理进度：{processed}/{node_count}")
            except Exception as e:
                LOG.warning(f"处理节点失败: {str(e)}")
    
    LOG.info(f"节点批量处理完成 - 优质: {len(results['excellent'])}，良好: {len(results['good'])}，合格: {len(results['qualified'])}，总计有效: {len(results['all'])}")
    return results

def save_results(results: dict):
    """保存结果（Base64编码）"""
    # 统一Base64编码
    def encode_nodes(nodes: list[str]) -> str:
        if not nodes:
            return ""
        content = "\n".join(nodes)
        return base64.b64encode(content.encode('utf-8')).decode('utf-8')
    
    # 保存各分级文件
    files = [
        ("s1_excellent.txt", results["excellent"], "优质节点（≥80分）"),
        ("s1_good.txt", results["good"], "良好节点（70-79分）"),
        ("s1_qualified.txt", results["qualified"], "合格节点（60-69分）"),
        ("s1.txt", results["all"], "所有有效节点（≥60分）")
    ]
    
    for filename, nodes, desc in files:
        encoded = encode_nodes(nodes)
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(encoded)
            LOG.info(f"✅ 保存{desc}到 {filename}，节点数: {len(nodes)}")
        except OSError as e:
            LOG.error(f"❌ 保存文件失败: {filename} 错误: {str(e)}")

# ========== 主执行函数（严格按易→难流程编排） ==========
def main():
    """主执行函数（最终优化版）"""
    start_time = time.time()
    LOG.info("="*60)
    LOG.info("节点筛选脚本启动（极致粗筛+分级验证版）")
    LOG.info("="*60)
    
    try:
        # ========== 阶段1：极致粗筛（纯本地，无网络IO） ==========
        LOG.info("\n【阶段1：极致粗筛】")
        # 1.1 加载订阅源+原始行清洗
        raw_nodes = load_subscription()
        cleaned_lines = clean_node_lines(raw_nodes)
        
        # 1.2 协议格式快速校验
        valid_proto_lines = [line for line in cleaned_lines if quick_proto_validate(line)]
        LOG.info(f"协议格式校验完成：原{len(cleaned_lines)}行 → 有效{len(valid_proto_lines)}行")
        
        # 1.3 预去重（IP+端口+协议）
        deduped_lines = pre_deduplicate_nodes(valid_proto_lines, CONFIG["sources"])
        
        # 1.4-1.5 过滤私有IP+无效端口
        filtered_lines = filter_private_ip_and_invalid_port(deduped_lines)
        
        # ========== 阶段2+3：网络筛（轻量→重度） ==========
        LOG.info("\n【阶段2+3：网络筛选（轻量→重度）】")
        # 批量处理节点（TCP探测→基础分预过滤→HTTP验证→最终评分）
        results = batch_process_nodes(filtered_lines)
        
        # ========== 结果保存 ==========
        LOG.info("\n【阶段4：结果保存】")
        save_results(results)
        
        # ========== 最终统计 ==========
        total_time = time.time() - start_time
        LOG.info("\n" + "="*60)
        LOG.info(f"✅ 脚本执行完成，总耗时: {total_time:.2f}秒")
        LOG.info(f"📊 最终结果 - 优质节点: {len(results['excellent'])} | 良好节点: {len(results['good'])} | 合格节点: {len(results['qualified'])} | 总计有效: {len(results['all'])}")
        LOG.info("="*60)
    
    except Exception as e:
        LOG.error(f"❌ 脚本执行失败: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()
