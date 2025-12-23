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
import json

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== 核心配置（优化后） ==========
CONFIG: Dict = {
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
        "max_remark_bytes": 200,
        "DEFAULT_PORT": 443,
        "SS_DEFAULT_CIPHER": "aes-256-gcm",
        "SS_VALID_CIPHERS": ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb"],
        # 评分权重配置（优化后）
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
        # 分级区间（优化后）
        "grade_ranges": {
            "excellent": (80, 100),  # 优质
            "good": (70, 79),        # 良好
            "qualified": (60, 69)    # 合格
        }
    }
}

# ========== 日志初始化（优化后） ==========
def init_logger() -> logging.Logger:
    logger = logging.getLogger("node_scorer")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger

LOG = init_logger()

# ========== 工具函数（优化后） ==========
# IP/端口解析缓存
@lru_cache(maxsize=2000)
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
            
            # 尝试解析域名到IP
            try:
                ip = socket.gethostbyname(domain)
            except (socket.gaierror, ValueError):
                ip = domain  # 解析失败则用域名代替
    except Exception as e:
        LOG.warning(f"解析IP/端口失败: {line[:50]}... 错误: {str(e)}")
    
    return ip, domain, port

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
    """获取响应速度加分（优化后精细化）"""
    if response_time < CONFIG["detection"]["min_response_time"] or response_time > CONFIG["detection"]["max_response_time"]:
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
    """获取响应时间扣分（优化后精细化）"""
    if response_time < CONFIG["detection"]["min_response_time"] or response_time > CONFIG["detection"]["max_response_time"]:
        return CONFIG["filter"]["score_weights"]["response_time"]["<0.05|>8.0"]
    elif 3.0 <= response_time < 8.0:
        return CONFIG["filter"]["score_weights"]["response_time"]["3.0-8.0"]
    else:
        return 0

def tcp_probe(ip: str, port: int, proto: str) -> tuple[bool, float]:
    """TCP探测（稳定性验证：2次探测取平均）"""
    total_time = 0.0
    success_count = 0
    timeout = CONFIG["detection"]["tcp_timeout"][proto] if proto in CONFIG["detection"]["tcp_timeout"] else 8
    
    for _ in range(CONFIG["detection"]["tcp_retry"]):
        start = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                success_count += 1
                total_time += (time.time() - start)
            time.sleep(CONFIG["detection"]["tcp_retry_interval"])
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    
    if success_count == 0:
        return False, 0.0
    return True, total_time / success_count  # 返回平均响应时间

def http_validate(ip: str, port: int) -> str:
    """可用性验证：尝试访问外网URL"""
    headers = {"User-Agent": CONFIG["request"]["ua"]}
    
    for url in CONFIG["detection"]["http_validate_urls"]:
        try:
            # 优先用IP访问（避免DNS污染）
            parsed = urlparse(url)
            req_url = f"{parsed.scheme}://{ip}:{port}{parsed.path}" if port != 80 and port != 443 else f"{parsed.scheme}://{ip}{parsed.path}"
            
            response = requests.get(
                req_url,
                headers=headers,
                timeout=CONFIG["detection"]["http_validate_timeout"],
                verify=False,
                allow_redirects=True
            )
            if response.status_code in [200, 204]:
                return "full"  # 完全可用
        except (requests.Timeout, requests.ConnectionError, ValueError):
            continue
    
    return "tcp_only"  # 仅TCP通

# ========== 协议解析（抽象通用逻辑，优化后） ==========
class ProtocolParser:
    """协议解析基类"""
    @staticmethod
    def parse_vmess(line: str) -> dict | None:
        """解析VMess节点"""
        try:
            # 提取VMess核心参数
            vmess_part = line.replace("vmess://", "")
            decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
            cfg = json.loads(decoded)
            
            # 基础校验
            if not all(k in cfg for k in ["add", "port", "id"]):
                return None
            
            # 安全类型判断
            security_type = "tls" if cfg.get("tls") == "tls" else "none"
            
            return {
                "protocol": "vmess",
                "ip": "",
                "domain": cfg["add"],
                "port": int(cfg["port"]),
                "security_type": security_type,
                "remark": cfg.get("ps", ""),
                "raw": line
            }
        except (base64.binascii.Error, json.JSONDecodeError, ValueError, KeyError) as e:
            LOG.warning(f"VMess解析失败: {line[:50]}... 错误: {str(e)}")
            return None
    
    @staticmethod
    def parse_vless(line: str) -> dict | None:
        """解析VLESS节点"""
        try:
            vless_part = line.replace("vless://", "")
            # 拆分参数
            main_part, params_part = vless_part.split("?", 1) if "?" in vless_part else (vless_part, "")
            
            # 提取IP/端口
            ip_port_part = main_part.split("@")[1] if "@" in main_part else ""
            domain, port_str = ip_port_part.split(":", 1) if ":" in ip_port_part else ("", "")
            port = int(port_str) if port_str else CONFIG["filter"]["DEFAULT_PORT"]
            
            # 安全类型判断（Reality/TLS）
            security_type = "reality" if "reality=" in params_part else "tls" if "tls=" in params_part else "none"
            
            return {
                "protocol": "vless",
                "ip": "",
                "domain": domain,
                "port": port,
                "security_type": security_type,
                "remark": "",
                "raw": line
            }
        except (ValueError, IndexError) as e:
            LOG.warning(f"VLESS解析失败: {line[:50]}... 错误: {str(e)}")
            return None
    
    @staticmethod
    def parse_trojan(line: str) -> dict | None:
        """解析Trojan节点"""
        try:
            trojan_part = line.replace("trojan://", "")
            main_part = trojan_part.split("#")[0] if "#" in trojan_part else trojan_part
            
            # 提取IP/端口
            ip_port_part = main_part.split("@")[1] if "@" in main_part else ""
            domain, port_str = ip_port_part.split(":", 1) if ":" in ip_port_part else ("", "")
            port = int(port_str) if port_str else CONFIG["filter"]["DEFAULT_PORT"]
            
            # 安全类型判断
            security_type = "tls" if "tls" in trojan_part else "none"
            
            return {
                "protocol": "trojan",
                "ip": "",
                "domain": domain,
                "port": port,
                "security_type": security_type,
                "remark": trojan_part.split("#")[1] if "#" in trojan_part else "",
                "raw": line
            }
        except (ValueError, IndexError) as e:
            LOG.warning(f"Trojan解析失败: {line[:50]}... 错误: {str(e)}")
            return None
    
    @staticmethod
    def parse_ss(line: str) -> dict | None:
        """解析SS节点"""
        try:
            ss_part = line.replace("ss://", "")
            decoded = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
            
            # 提取IP/端口
            ip_port_part = decoded.split("@")[1] if "@" in decoded else ""
            domain, port_str = ip_port_part.split(":", 1) if ":" in ip_port_part else ("", "")
            port = int(port_str) if port_str else CONFIG["filter"]["DEFAULT_PORT"]
            
            return {
                "protocol": "ss",
                "ip": "",
                "domain": domain,
                "port": port,
                "security_type": "none",  # SS无统一TLS标识
                "remark": "",
                "raw": line
            }
        except (base64.binascii.Error, ValueError, IndexError) as e:
            LOG.warning(f"SS解析失败: {line[:50]}... 错误: {str(e)}")
            return None
    
    @staticmethod
    def parse_hysteria(line: str) -> dict | None:
        """解析Hysteria节点"""
        try:
            hysteria_part = line.replace("hysteria://", "")
            ip_port_part = hysteria_part.split("?")[0] if "?" in hysteria_part else hysteria_part
            domain, port_str = ip_port_part.split(":", 1) if ":" in ip_port_part else ("", "")
            port = int(port_str) if port_str else CONFIG["filter"]["DEFAULT_PORT"]
            
            # 安全类型判断
            security_type = "tls" if "tls=" in hysteria_part else "none"
            
            return {
                "protocol": "hysteria",
                "ip": "",
                "domain": domain,
                "port": port,
                "security_type": security_type,
                "remark": "",
                "raw": line
            }
        except (ValueError, IndexError) as e:
            LOG.warning(f"Hysteria解析失败: {line[:50]}... 错误: {str(e)}")
            return None
    
    @classmethod
    def parse(cls, line: str) -> dict | None:
        """统一解析入口"""
        line = line.strip()
        if not line:
            return None
        
        if line.startswith("vmess://"):
            return cls.parse_vmess(line)
        elif line.startswith("vless://"):
            return cls.parse_vless(line)
        elif line.startswith("trojan://"):
            return cls.parse_trojan(line)
        elif line.startswith("ss://"):
            return cls.parse_ss(line)
        elif line.startswith("hysteria://"):
            return cls.parse_hysteria(line)
        else:
            LOG.debug(f"不支持的协议: {line[:50]}...")
            return None

# ========== 评分核心逻辑（优化后） ==========
def calculate_node_score(node: dict) -> tuple[int, dict]:
    """计算节点分数（优化后完整逻辑）"""
    # 初始化分数和详情
    score = 0
    score_detail = {
        "base_score": 0,
        "penalties": {},
        "additions": {},
        "final_score": 0,
        "grade": ""
    }
    
    # 1. 基础信息补全
    ip, domain, port = extract_ip_port(node["raw"])
    node["ip"] = ip if ip else socket.gethostbyname(node["domain"]) if node["domain"] else ""
    node["port"] = port if port else node["port"]
    
    # 2. 私有IP直接返回0分
    if is_private_ip(node["ip"]):
        score_detail["final_score"] = 0
        return 0, score_detail
    
    # 3. TCP探测（稳定性验证）
    tcp_ok, response_time = tcp_probe(node["ip"], node["port"], node["protocol"])
    if not tcp_ok:
        score_detail["final_score"] = 0
        return 0, score_detail
    
    # 4. 可用性验证
    availability = http_validate(node["ip"], node["port"])
    
    # 5. 扣分项计算
    # 5.1 国内IP扣分
    cn_ip_type = judge_cn_ip(node["ip"], availability == "full")
    cn_penalty = CONFIG["filter"]["score_weights"]["cn_ip"][cn_ip_type]
    score += cn_penalty
    score_detail["penalties"]["cn_ip"] = cn_penalty
    
    # 5.2 响应时间扣分
    rt_penalty = get_response_time_penalty(response_time)
    score += rt_penalty
    score_detail["penalties"]["response_time"] = rt_penalty
    
    # 6. 加分项计算
    # 6.1 协议加分
    proto_score = CONFIG["filter"]["score_weights"]["protocol"].get(node["protocol"], 0)
    score += proto_score
    score_detail["additions"]["protocol"] = proto_score
    
    # 6.2 安全类型加分
    sec_key = "reality" if node["security_type"] == "reality" else "tls" if node["security_type"] == "tls" else "none"
    sec_score = CONFIG["filter"]["score_weights"]["security"][sec_key]
    score += sec_score
    score_detail["additions"]["security"] = sec_score
    
    # 6.3 端口加分
    port_score = CONFIG["filter"]["score_weights"]["port"].get(node["port"], CONFIG["filter"]["score_weights"]["port"]["other"])
    score += port_score
    score_detail["additions"]["port"] = port_score
    
    # 6.4 DNS有效性加分（解析成功才加）
    dns_score = CONFIG["filter"]["score_weights"]["dns_valid"] if node["ip"] else 0
    score += dns_score
    score_detail["additions"]["dns_valid"] = dns_score
    
    # 6.5 外网验证加分（访问成功才加）
    net_score = CONFIG["filter"]["score_weights"]["net_validate"] if availability == "full" else 0
    score += net_score
    score_detail["additions"]["net_validate"] = net_score
    
    # 6.6 响应速度加分
    speed_score = get_response_speed_score(response_time)
    score += speed_score
    score_detail["additions"]["response_speed"] = speed_score
    
    # 6.7 可用性加分
    avail_score = CONFIG["filter"]["score_weights"]["availability"][availability]
    score += avail_score
    score_detail["additions"]["availability"] = avail_score
    
    # 7. 分数修正（0~100）
    final_score = max(0, min(score, 100))
    score_detail["final_score"] = final_score
    
    # 8. 分级判断
    if final_score >= CONFIG["filter"]["grade_ranges"]["excellent"][0]:
        score_detail["grade"] = "excellent"
    elif final_score >= CONFIG["filter"]["grade_ranges"]["good"][0]:
        score_detail["grade"] = "good"
    elif final_score >= CONFIG["filter"]["grade_ranges"]["qualified"][0]:
        score_detail["grade"] = "qualified"
    else:
        score_detail["grade"] = "reject"
    
    return final_score, score_detail

# ========== 核心业务逻辑（优化后） ==========
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
    
    # 去重（原始行去重）
    unique_nodes = list(dict.fromkeys(all_nodes))
    LOG.info(f"订阅源加载完成，总节点数: {len(all_nodes)}，去重后: {len(unique_nodes)}")
    
    return unique_nodes

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

def deduplicate_nodes(nodes: list[str]) -> list[str]:
    """节点去重（IP+端口+协议）"""
    seen = set()
    unique = []
    
    for line in nodes:
        node = ProtocolParser.parse(line)
        if not node:
            continue
        
        ip, _, port = extract_ip_port(line)
        key = f"{node['protocol']}_{ip}_{port}"
        
        if key not in seen:
            seen.add(key)
            unique.append(line)
    
    LOG.info(f"节点去重完成，原数量: {len(nodes)}，去重后: {len(unique)}")
    return unique

def process_nodes(nodes: list[str]) -> dict:
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
    
    LOG.info(f"开始处理节点，总数: {node_count}，并发数: {worker_num}")
    
    with ThreadPoolExecutor(max_workers=worker_num) as executor:
        # 提交任务
        futures = {}
        for line in nodes:
            future = executor.submit(process_single_node, line)
            futures[future] = line
        
        # 处理结果
        for future in as_completed(futures):
            line = futures[future]
            try:
                score, score_detail = future.result()
                if score >= CONFIG["detection"]["score_threshold"]:
                    # 按分级归类
                    if score_detail["grade"] == "excellent":
                        results["excellent"].append(line)
                    elif score_detail["grade"] == "good":
                        results["good"].append(line)
                    elif score_detail["grade"] == "qualified":
                        results["qualified"].append(line)
                    results["all"].append(line)
            except Exception as e:
                LOG.warning(f"处理节点失败: {line[:50]}... 错误: {str(e)}")
    
    LOG.info(f"节点处理完成 - 优质: {len(results['excellent'])}，良好: {len(results['good'])}，合格: {len(results['qualified'])}，总计: {len(results['all'])}")
    return results

def process_single_node(line: str) -> tuple[int, dict]:
    """处理单个节点（线程池任务）"""
    # 解析协议
    node = ProtocolParser.parse(line)
    if not node:
        return 0, {"final_score": 0, "grade": "reject"}
    
    # 计算分数
    score, score_detail = calculate_node_score(node)
    return score, score_detail

def save_results(results: dict):
    """保存结果（优化后命名+编码）"""
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
            LOG.info(f"保存{desc}到 {filename}，节点数: {len(nodes)}")
        except OSError as e:
            LOG.error(f"保存文件失败: {filename} 错误: {str(e)}")

# ========== 主函数 ==========
def main():
    """主执行函数"""
    start_time = time.time()
    LOG.info("="*50)
    LOG.info("节点筛选脚本启动（优化版）")
    LOG.info("="*50)
    
    try:
        # 1. 加载订阅源
        raw_nodes = load_subscription()
        
        # 2. 去重
        unique_nodes = deduplicate_nodes(raw_nodes)
        
        # 3. 处理节点（评分+分级）
        results = process_nodes(unique_nodes)
        
        # 4. 保存结果
        save_results(results)
        
        # 5. 输出统计
        total_time = time.time() - start_time
        LOG.info("="*50)
        LOG.info(f"脚本执行完成，总耗时: {total_time:.2f}秒")
        LOG.info(f"最终结果 - 优质节点: {len(results['excellent'])} | 良好节点: {len(results['good'])} | 合格节点: {len(results['qualified'])} | 总计有效: {len(results['all'])}")
        LOG.info("="*50)
    
    except Exception as e:
        LOG.error(f"脚本执行失败: {str(e)}", exc_info=True)


if __name__ == "__main__":
    main()
