import requests
import re
import socket
import base64
import os
import time
import hashlib
import logging
import json
import asyncio
import aiohttp
from urllib.parse import urlparse  # 移除未使用的unquote
import urllib3

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== 核心配置（清理无效token配置） ==========
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
        "timeout": 180,
        "retry": 3,
        "retry_delay": 3,
        "ua": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    },
    "github": {
        "interval": 1.0,
        "cache_ttl": 3600,
        "cache_dir": "/tmp/node_scorer_cache",
        "cache_max_size": 100 * 1024 * 1024
    },
    "detection": {
        "tcp_timeout_base": {"vmess": 12, "vless": 12, "trojan": 12, "ss": 10, "hysteria": 15},
        "tcp_retry": 2,
        "tcp_retry_interval": 1.0,
        "http_validate_urls": [
            "http://httpbin.org/ip",
            "https://www.google.com/generate_204",
            "http://ip-api.com/json/"
        ],
        "http_validate_timeout_base": 8,
        "http_validate_attempts": {
            "excellent": 1,
            "good": 2,
            "qualified": 3
        },
        "score_threshold": 60,
        "min_response_time": 0.05,
        "max_response_time": 10.0,
        "concurrency": {
            "small": 8,
            "medium": 15,
            "large": 25
        }
    },
    "filter": {
        "private_ip_patterns": re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1|localhost)"),
        "cn_ip_patterns": re.compile(r"^(223\.|202\.|210\.|10\.|192\.168\.|172\.)"),
        "ports": range(1, 65535),
        "min_line_length": 10,
        "max_line_length": 5000,
        "DEFAULT_PORT": 443,
        "score_weights": {
            "protocol": {
                "vless": 15,
                "trojan": 14,
                "vmess": 12,
                "hysteria": 9,
                "ss": 6,
                "other": 0
            },
            "security": {
                "reality": 15,
                "tls": 14,
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
                "1.0-2.0": 12,
                "2.0-3.0": 8,
                "3.0-10.0": 0,
                "<0.05|>10.0": 0
            },
            "tcp_stability": {
                "2_success": 5,
                "1_success": 2,
                "0_success": 0
            },
            "availability": {
                "full": 15,
                "tcp_only": 5,
                "failed": 0
            },
            "cn_ip": {
                "pure_cn": -30,
                "cn_relay": -10,
                "non_cn": 0
            },
            "response_time": {
                "<0.05|>10.0": -30,
                "3.0-10.0": -10,
                "0.05-3.0": 0
            }
        },
        "grade_ranges": {
            "excellent": (80, 100),
            "good": (70, 79),
            "qualified": (60, 69)
        },
        "base_score_threshold": 50
    }
}

# ========== 日志初始化 ==========
def init_logger() -> logging.Logger:
    logger = logging.getLogger("node_scorer_github")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger

LOG = init_logger()

# ========== 核心工具函数（清理未使用的domain变量） ==========
@lru_cache(maxsize=5000)
def extract_ip_port(line: str) -> tuple[str, int]:  # 移除domain返回值
    ip = ""
    port = CONFIG["filter"]["DEFAULT_PORT"]
    
    try:
        pattern = r"@([a-zA-Z0-9\-\.]+):(\d+)"
        match = re.search(pattern, line)
        if match:
            domain_or_ip = match.group(1)
            port = int(match.group(2))
            
            if not CONFIG["filter"]["private_ip_patterns"].match(domain_or_ip):
                try:
                    ip = socket.gethostbyname(domain_or_ip)
                except (socket.gaierror, ValueError):
                    ip = domain_or_ip
    except Exception as e:
        LOG.debug(f"解析IP/端口失败: {line[:50]}... 错误: {str(e)}")
    
    return ip, port  # 仅返回使用到的ip和port

def clean_node_lines(raw_lines: list[str]) -> list[str]:
    cleaned = []
    for line in raw_lines:
        line = line.strip()
        if (not line or 
            len(line) < CONFIG["filter"]["min_line_length"] or 
            len(line) > CONFIG["filter"]["max_line_length"] or 
            re.search(r"[^\x20-\x7E]", line)):
            continue
        cleaned.append(line)
    LOG.info(f"原始行清洗完成：原{len(raw_lines)}行 → 清洗后{len(cleaned)}行")
    return cleaned

def pre_deduplicate_nodes(lines: list[str], sources: list[dict]) -> list[str]:
    node_map = {}
    
    for line in lines:
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
        
        ip, port = extract_ip_port(line)  # 适配返回值变更
        if not ip or not port:
            continue
        
        weight = 1
        for source in sources:
            if source["url"] in line:
                weight = source["weight"]
                break
        
        key = f"{proto}_{ip}_{port}"
        if key not in node_map or weight > node_map[key][1]:
            node_map[key] = (line, weight)
    
    deduped = [v[0] for v in node_map.values()]
    LOG.info(f"节点预去重完成：原{len(lines)}行 → 去重后{len(deduped)}行")
    return deduped

def filter_private_ip_and_invalid_port(lines: list[str]) -> list[str]:
    filtered = []
    for line in lines:
        ip, port = extract_ip_port(line)  # 适配返回值变更
        
        if is_private_ip(ip):
            LOG.debug(f"过滤私有IP节点：{line[:50]}...")
            continue
        
        if port not in CONFIG["filter"]["ports"]:
            LOG.debug(f"过滤无效端口节点：{port} → {line[:50]}...")
            continue
        
        filtered.append(line)
    
    LOG.info(f"私有IP+无效端口过滤完成：原{len(lines)}行 → 过滤后{len(filtered)}行")
    return filtered

def is_private_ip(ip: str) -> bool:
    return CONFIG["filter"]["private_ip_patterns"].match(ip) is not None

def judge_cn_ip(ip: str, is_available: bool) -> str:
    if CONFIG["filter"]["cn_ip_patterns"].match(ip):
        return "cn_relay" if is_available else "pure_cn"
    return "non_cn"

def get_response_speed_score(response_time: float) -> int:
    if response_time < CONFIG["filter"]["min_response_time"] or response_time > CONFIG["filter"]["max_response_time"]:
        return CONFIG["filter"]["score_weights"]["response_speed"]["<0.05|>10.0"]
    elif 0.05 <= response_time < 0.5:
        return CONFIG["filter"]["score_weights"]["response_speed"]["0.05-0.5"]
    elif 0.5 <= response_time < 1.0:
        return CONFIG["filter"]["score_weights"]["response_speed"]["0.5-1.0"]
    elif 1.0 <= response_time < 2.0:
        return CONFIG["filter"]["score_weights"]["response_speed"]["1.0-2.0"]
    elif 2.0 <= response_time < 3.0:
        return CONFIG["filter"]["score_weights"]["response_speed"]["2.0-3.0"]
    else:
        return CONFIG["filter"]["score_weights"]["response_speed"]["3.0-10.0"]

def get_response_time_penalty(response_time: float) -> int:
    if response_time < CONFIG["filter"]["min_response_time"] or response_time > CONFIG["filter"]["max_response_time"]:
        return CONFIG["filter"]["score_weights"]["response_time"]["<0.05|>10.0"]
    elif 3.0 <= response_time < 10.0:
        return CONFIG["filter"]["score_weights"]["response_time"]["3.0-10.0"]
    else:
        return 0

# ========== 网络探测函数 ==========
def tcp_probe(ip: str, port: int, proto: str, pre_grade: str = "qualified") -> tuple[bool, float, int]:
    total_time = 0.0
    success_count = 0
    base_timeout = CONFIG["detection"]["tcp_timeout_base"].get(proto, 12)
    
    if pre_grade == "excellent":
        timeout = 8
    elif pre_grade == "qualified":
        timeout = 15
    else:
        timeout = base_timeout
    
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
        return False, 0.0, 0
    avg_time = total_time / success_count
    LOG.debug(f"TCP探测成功：{ip}:{port} → 平均响应时间{avg_time:.3f}s，成功次数{success_count}")
    return True, avg_time, success_count

async def async_http_validate(ip: str, port: int, grade: str):
    attempt_count = CONFIG["detection"]["http_validate_attempts"][grade]
    headers = {"User-Agent": CONFIG["request"]["ua"]}
    
    base_timeout = CONFIG["detection"]["http_validate_timeout_base"]
    if grade == "excellent":
        timeout = aiohttp.ClientTimeout(total=6)
    elif grade == "qualified":
        timeout = aiohttp.ClientTimeout(total=10)
    else:
        timeout = aiohttp.ClientTimeout(total=base_timeout)
    
    validate_urls = CONFIG["detection"]["http_validate_urls"][:attempt_count]
    
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for url in validate_urls:
            try:
                parsed = urlparse(url)
                if port in [80, 443]:
                    req_url = f"{parsed.scheme}://{ip}{parsed.path}"
                else:
                    req_url = f"{parsed.scheme}://{ip}:{port}{parsed.path}"
                
                async with session.get(
                    req_url,
                    headers=headers,
                    verify_ssl=False,
                    allow_redirects=True
                ) as response:
                    if response.status in [200, 204]:
                        LOG.debug(f"HTTP验证成功：{ip}:{port} → {url}")
                        return "full"
            except (aiohttp.TimeoutError, aiohttp.ClientConnectionError, ValueError) as e:
                LOG.debug(f"HTTP验证失败：{ip}:{port} → {url} → {str(e)}")
                continue
    
    return "tcp_only"

# ========== 协议解析 ==========
class ProtocolParser:
    @staticmethod
    def parse_basic_info(line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None
        
        if line.startswith("vmess://"):
            try:
                vmess_part = line.replace("vmess://", "")
                decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
                cfg = json.loads(decoded)
                security_type = "tls" if cfg.get("security") == "tls" else "none"  # 优化VMess字段解析
                return {"protocol": "vmess", "security_type": security_type}
            except Exception:
                return {"protocol": "vmess", "security_type": "none"}
        
        elif line.startswith("vless://"):
            security_type = "reality" if "reality=" in line else "tls" if "tls=" in line else "none"
            return {"protocol": "vless", "security_type": security_type}
        
        elif line.startswith("trojan://"):
            security_type = "tls" if "tls" in line else "none"
            return {"protocol": "trojan", "security_type": security_type}
        
        elif line.startswith("ss://"):
            return {"protocol": "ss", "security_type": "none"}
        
        elif line.startswith("hysteria://"):
            security_type = "tls" if "tls=" in line else "none"
            return {"protocol": "hysteria", "security_type": "none"}
        
        else:
            return {"protocol": "other", "security_type": "none"}

# ========== 评分逻辑 ==========
def calculate_base_score(node_info: dict, ip: str, port: int, response_time: float, success_count: int) -> tuple[int, dict]:
    score = 0
    score_detail = {"penalties": {}, "additions": {}, "base_score": 0}
    
    rt_penalty = get_response_time_penalty(response_time)
    score += rt_penalty
    score_detail["penalties"]["response_time"] = rt_penalty
    
    proto_score = CONFIG["filter"]["score_weights"]["protocol"].get(node_info["protocol"], 0)
    score += proto_score
    score_detail["additions"]["protocol"] = proto_score
    
    sec_key = "reality" if node_info["security_type"] == "reality" else "tls" if node_info["security_type"] == "tls" else "none"
    sec_score = CONFIG["filter"]["score_weights"]["security"][sec_key]
    score += sec_score
    score_detail["additions"]["security"] = sec_score
    
    port_score = CONFIG["filter"]["score_weights"]["port"].get(port, CONFIG["filter"]["score_weights"]["port"]["other"])
    score += port_score
    score_detail["additions"]["port"] = port_score
    
    dns_score = CONFIG["filter"]["score_weights"]["dns_valid"] if ip else 0
    score += dns_score
    score_detail["additions"]["dns_valid"] = dns_score
    
    speed_score = get_response_speed_score(response_time)
    score += speed_score
    score_detail["additions"]["response_speed"] = speed_score
    
    if success_count == 2:
        stability_score = CONFIG["filter"]["score_weights"]["tcp_stability"]["2_success"]
    elif success_count == 1:
        stability_score = CONFIG["filter"]["score_weights"]["tcp_stability"]["1_success"]
    else:
        stability_score = CONFIG["filter"]["score_weights"]["tcp_stability"]["0_success"]
    score += stability_score
    score_detail["additions"]["tcp_stability"] = stability_score
    
    base_score = max(0, min(score, 100))
    score_detail["base_score"] = base_score
    
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
    final_score = base_score
    score_detail = base_detail.copy()
    score_detail["final_score"] = 0
    score_detail["grade"] = ""
    
    cn_ip_type = judge_cn_ip(ip, availability == "full")
    cn_penalty = CONFIG["filter"]["score_weights"]["cn_ip"][cn_ip_type]
    final_score += cn_penalty
    score_detail["penalties"]["cn_ip"] = cn_penalty
    
    net_score = CONFIG["filter"]["score_weights"]["net_validate"] if availability == "full" else 0
    final_score += net_score
    score_detail["additions"]["net_validate"] = net_score
    
    avail_score = CONFIG["filter"]["score_weights"]["availability"][availability]
    final_score += avail_score
    score_detail["additions"]["availability"] = avail_score
    
    final_score = max(0, min(final_score, 100))
    score_detail["final_score"] = final_score
    
    if final_score >= CONFIG["filter"]["grade_ranges"]["excellent"][0]:
        score_detail["grade"] = "excellent"
    elif final_score >= CONFIG["filter"]["grade_ranges"]["good"][0]:
        score_detail["grade"] = "good"
    elif final_score >= CONFIG["filter"]["grade_ranges"]["qualified"][0]:
        score_detail["grade"] = "qualified"
    else:
        score_detail["grade"] = "reject"
    
    return final_score, score_detail

# ========== 核心业务逻辑 ==========
def load_subscription() -> list[str]:
    all_nodes = []
    cache_dir = CONFIG["github"]["cache_dir"]
    os.makedirs(cache_dir, exist_ok=True)
    
    clean_cache(cache_dir)
    
    with requests.Session() as sess:
        sess.headers["User-Agent"] = CONFIG["request"]["ua"]
        
        for source in CONFIG["sources"]:
            url = source["url"]
            cache_key = hashlib.md5(url.encode()).hexdigest()
            cache_path = os.path.join(cache_dir, f"{cache_key}.json")
            
            if os.path.exists(cache_path) and time.time() - os.path.getmtime(cache_path) < CONFIG["github"]["cache_ttl"]:
                try:
                    with open(cache_path, "r", encoding="utf-8") as f:
                        cached_nodes = json.load(f)
                    all_nodes.extend(cached_nodes)
                    LOG.info(f"从缓存加载订阅源: {url}，节点数: {len(cached_nodes)}")
                    continue
                except Exception as e:
                    LOG.warning(f"缓存读取失败: {cache_path} 错误: {str(e)}")
            
            try:
                response = sess.get(url, timeout=CONFIG["request"]["timeout"])
                response.raise_for_status()
                
                cleaned_text = response.text.encode('ascii', 'ignore').decode('ascii')
                cleaned_text = re.sub(r'[^A-Za-z0-9+/=]', '', cleaned_text)
                cleaned_text = cleaned_text.replace('-', '+').replace('_', '/')
                padding = len(cleaned_text) % 4
                if padding != 0:
                    cleaned_text += '=' * (4 - padding)
                decoded = base64.b64decode(cleaned_text).decode('utf-8', errors='ignore')
                
                nodes = [line.strip() for line in decoded.split("\n") if line.strip()]
                
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(nodes, f, ensure_ascii=False)
                
                all_nodes.extend(nodes)
                LOG.info(f"拉取订阅源成功: {url}，节点数: {len(nodes)}")
                
                time.sleep(CONFIG["github"]["interval"])
            except Exception as e:
                LOG.error(f"拉取订阅源失败: {url} 错误: {str(e)}")
                continue
    
    unique_raw = list(dict.fromkeys(all_nodes))
    LOG.info(f"订阅源加载完成，总节点数: {len(all_nodes)}，原始去重后: {len(unique_raw)}")
    
    return unique_raw

def clean_cache(cache_dir: str):
    try:
        total_size = 0
        files = []
        
        for f in os.listdir(cache_dir):
            f_path = os.path.join(cache_dir, f)
            if os.path.isfile(f_path):
                f_size = os.path.getsize(f_path)
                total_size += f_size
                files.append((f_path, os.path.getmtime(f_path), f_size))
        
        for f_path, mtime, _ in files:
            if time.time() - mtime > CONFIG["github"]["cache_ttl"]:
                os.remove(f_path)
                LOG.info(f"删除过期缓存: {f_path}")
        
        files.sort(key=lambda x: x[1])
        while total_size > CONFIG["github"]["cache_max_size"] and files:
            f_path, _, f_size = files.pop(0)
            os.remove(f_path)
            total_size -= f_size
            LOG.info(f"删除超大缓存: {f_path}")
    except Exception as e:
        LOG.error(f"缓存清理失败: {str(e)}")

async def async_process_single_node(line: str):
    final_score = 0
    score_detail = {"grade": "reject"}
    
    node_info = ProtocolParser.parse_basic_info(line)
    if not node_info:
        return 0, score_detail, line
    
    ip, port = extract_ip_port(line)  # 适配返回值变更
    
    if is_private_ip(ip):
        return 0, score_detail, line
    
    tcp_ok, response_time, success_count = tcp_probe(ip, port, node_info["protocol"], "qualified")
    if not tcp_ok:
        return 0, score_detail, line
    
    base_score, base_detail = calculate_base_score(node_info, ip, port, response_time, success_count)
    if base_score < CONFIG["filter"]["base_score_threshold"]:
        LOG.debug(f"基础分预过滤：{base_score}分 → {line[:50]}...")
        return 0, base_detail, line
    
    availability = await async_http_validate(ip, port, base_detail["pre_grade"])
    
    final_score, final_detail = calculate_final_score(base_score, base_detail, ip, availability)
    
    return final_score, final_detail, line

async def async_batch_process_nodes(nodes: list[str]):
    results = {
        "excellent": [],
        "good": [],
        "qualified": [],
        "all": []
    }
    
    node_count = len(nodes)
    if node_count < 100:
        semaphore = asyncio.Semaphore(CONFIG["detection"]["concurrency"]["small"])
    elif node_count < 500:
        semaphore = asyncio.Semaphore(CONFIG["detection"]["concurrency"]["medium"])
    else:
        semaphore = asyncio.Semaphore(CONFIG["detection"]["concurrency"]["large"])
    
    LOG.info(f"开始批量处理节点，总数: {node_count}，并发数: {semaphore._value}")
    
    async def limited_process(line):
        async with semaphore:
            return await async_process_single_node(line)
    
    tasks = [limited_process(line) for line in nodes]
    processed = 0
    
    for task in asyncio.as_completed(tasks):
        try:
            score, detail, line = await task
            processed += 1
            
            if score >= CONFIG["detection"]["score_threshold"]:
                if detail["grade"] == "excellent":
                    results["excellent"].append(line)
                elif detail["grade"] == "good":
                    results["good"].append(line)
                elif detail["grade"] == "qualified":
                    results["qualified"].append(line)
                results["all"].append(line)
            
            if processed % 50 == 0:
                LOG.info(f"节点处理进度：{processed}/{node_count}")
        except Exception as e:
            LOG.warning(f"处理节点失败: {str(e)}")
    
    LOG.info(f"节点批量处理完成 - 优质: {len(results['excellent'])} | 良好: {len(results['good'])} | 合格: {len(results['qualified'])} | 总计有效: {len(results['all'])}")
    return results

def save_results(results: dict):
    """保存结果到根目录"""
    def encode_nodes(nodes: list[str]) -> str:
        if not nodes:
            return ""
        content = "\n".join(nodes)
        return base64.b64encode(content.encode('utf-8')).decode('utf-8')
    
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
        except Exception as e:
            LOG.error(f"❌ 保存文件失败: {filename} 错误: {str(e)}")

# ========== 主执行函数 ==========
async def main():
    start_time = time.time()
    LOG.info("="*60)
    LOG.info("节点筛选脚本启动（GitHub Actions优化版）")
    LOG.info("="*60)
    
    try:
        LOG.info("\n【阶段1：极致粗筛】")
        raw_nodes = load_subscription()
        cleaned_lines = clean_node_lines(raw_nodes)
        deduped_lines = pre_deduplicate_nodes(cleaned_lines, CONFIG["sources"])
        filtered_lines = filter_private_ip_and_invalid_port(deduped_lines)
        
        LOG.info("\n【阶段2+3：网络筛选（异步模式）】")
        results = await async_batch_process_nodes(filtered_lines)
        
        LOG.info("\n【阶段4：结果保存】")
        save_results(results)
        
        total_time = time.time() - start_time
        LOG.info("\n" + "="*60)
        LOG.info(f"✅ 脚本执行完成，总耗时: {total_time:.2f}秒")
        LOG.info(f"📊 最终结果 - 优质: {len(results['excellent'])} | 良好: {len(results['good'])} | 合格: {len(results['qualified'])} | 总计有效: {len(results['all'])}")
        LOG.info("="*60)
    
    except Exception as e:
        LOG.error(f"❌ 脚本执行失败: {str(e)}", exc_info=True)
        raise e

if __name__ == "__main__":
    asyncio.run(main())
