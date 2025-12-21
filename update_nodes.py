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

# 精简配置结构
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
        "max_remark_bytes": 200  # 增大备注长度限制，减少label too long错误
    }
}

# 定义常量
DNS_CACHE_MAXSIZE = CONFIG["detection"]["dns"]["cache_size"]

# 日志初始化（调整日志级别为DEBUG，便于追踪@）
def init_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)  # 改为DEBUG级别，打印更多细节
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
    """校验并返回合法端口，默认443"""
    try:
        p = int(port)
        return p if p in CONFIG["filter"]["ports"] else 443
    except (ValueError, TypeError):
        return 443

def log_msg(content: str, line: str = "", proto: str = "") -> str:
    """日志格式化"""
    if "保留节点" in content:
        line_part = ""
    else:
        if "解析错误" in content or "过滤无效" in content or "空地址节点" in content:
            line_part = f"（{line[:50]}...）" if line else ""
        else:
            safe_line = line[:20].encode('ascii', 'ignore').decode('ascii')
            line_part = f"（{safe_line}...）" if safe_line else ""
    proto_part = f"（{proto}）" if proto else ""
    return f"{content}{line_part}{proto_part}"

def is_base64(s: str) -> bool:
    """放宽Base64校验，优先解码内容"""
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
    """解码订阅内容（加固：不删除任何符号，仅删空白）"""
    original_text = text.strip()
    clean_for_b64 = re.sub(r'\s+', ' ', original_text)  # 仅替换空白为单个空格，不删除
    
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
        cleaned_lines = [l.strip() for l in original_text.split('\n')]
        plain_line_count = len([l for l in cleaned_lines if l])
        LOG.info(log_msg(f"✅ 明文订阅处理完成，解析出{plain_line_count}个有效节点"))
        return '\n'.join(cleaned_lines)

def split_multi_nodes(line: str) -> List[str]:
    """
    安全拆分拼接节点（核心修复：修复边界计算 + 增加@校验）：
    1. 修复节点边界计算，确保@被完整包含
    2. 增加拆分前后@的日志追踪
    3. 仅拆分完整的协议节点，过滤残缺片段
    """
    if not line:
        LOG.debug("📌 拆分空节点，直接返回空列表")
        return []
    
    # 打印原始节点内容和@的存在性（关键追踪）
    at_count = line.count('@')
    LOG.debug(f"📌 待拆分节点原始内容：{line[:100]}... | @数量：{at_count}")
    
    # 定义各协议的最小长度和必要特征（避免拆出残缺节点）
    proto_rules = {
        "vmess": {"prefix": "vmess://", "min_len": 50, "required": None},
        "vless": {"prefix": "vless://", "min_len": 20, "required": "@"},
        "trojan": {"prefix": "trojan://", "min_len": 20, "required": "@"},
        "ss": {"prefix": "ss://", "min_len": 20, "required": None},
        "hysteria": {"prefix": "hysteria://", "min_len": 20, "required": None}
    }
    
    # 第一步：匹配所有可能的节点前缀位置
    node_positions = []
    for proto, rule in proto_rules.items():
        prefix = rule["prefix"]
        start = 0
        while True:
            pos = line.find(prefix, start)
            if pos == -1:
                break
            # 记录前缀位置和协议规则
            node_positions.append({"pos": pos, "proto": proto, "rule": rule})
            start = pos + len(prefix)
    
    # 第二步：按位置排序，拆分节点（修复边界计算）
    if not node_positions:
        LOG.debug(f"📌 未匹配到协议前缀，返回原节点：{line[:50]}...")
        return [line.strip()]
    
    # 按前缀位置升序排列
    node_positions.sort(key=lambda x: x["pos"])
    nodes = []
    total_len = len(line)
    
    for i, node_info in enumerate(node_positions):
        pos = node_info["pos"]
        proto = node_info["proto"]
        rule = node_info["rule"]
        prefix_len = len(rule["prefix"])
        
        # 修复边界计算：结束位置 = 下一个节点的起始位置（若存在），否则到末尾
        if i < len(node_positions) - 1:
            next_pos = node_positions[i+1]["pos"]
            # 后向校验：如果当前节点需要@，且@在当前节点和下一个节点之间，扩展结束位置到@之后
            if rule["required"] == "@":
                # 查找当前节点范围内的最后一个@
                at_pos = line.find('@', pos, next_pos)
                if at_pos != -1:
                    # 扩展结束位置到@之后的第一个非数字/字母/符号位置（确保@被包含）
                    end_pos = line.find(' ', at_pos, next_pos)
                    if end_pos == -1:
                        end_pos = next_pos
                else:
                    end_pos = next_pos
            else:
                end_pos = next_pos
        else:
            end_pos = total_len
        
        # 提取节点内容（保留完整的@）
        node_str = line[pos:end_pos].strip()
        
        # 打印拆分后的节点和@的存在性
        node_at_count = node_str.count('@')
        LOG.debug(f"📌 拆分出{proto}节点：{node_str[:100]}... | @数量：{node_at_count}")
        
        # 过滤校验：最小长度 + 必要特征
        if len(node_str) < rule["min_len"]:
            LOG.debug(f"🚫 过滤残缺节点（长度不足）：{node_str[:20]}... | 协议：{proto}")
            continue
        if rule["required"] and rule["required"] not in node_str:
            LOG.debug(f"🚫 过滤残缺节点（缺少{rule['required']}）：{node_str[:20]}... | 协议：{proto}")
            continue
        
        nodes.append(node_str)
    
    # 如果没有有效拆分结果，返回原行
    if not nodes:
        LOG.debug(f"📌 拆分无有效节点，返回原节点：{line[:50]}...")
        return [line.strip()]
    
    LOG.debug(f"📌 拆分完成，共拆分出{len(nodes)}个有效节点")
    return nodes

def clean_node_content(line: str) -> str:
    """清洗节点内容（加固：仅删中文，绝对不碰@等符号）"""
    if not line:
        return ""
    # 仅删除中文，保留所有ASCII符号（包括@）
    line = re.sub(r'[\u4e00-\u9fa5\u3000-\u303f\uff00-\uffef]', '', line)
    error_keywords = ["订阅内容解析错误", "解析失败", "无效节点", "缺失字段"]
    for keyword in error_keywords:
        line = line.replace(keyword, "")
    # 打印清洗后的@存在性
    at_count = line.count('@')
    LOG.debug(f"📌 清洗后节点：{line[:100]}... | @数量：{at_count}")
    return line.strip()

def is_private_ip(ip: str) -> bool:
    """判断是否为私有IP"""
    return bool(ip and CONFIG["filter"]["private_ip"].match(ip))

@lru_cache(maxsize=DNS_CACHE_MAXSIZE)
def dns_resolve(domain: str) -> bool:
    """DNS解析（增加重试）"""
    if not domain or domain == "未知":
        return False
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(CONFIG["detection"]["dns"]["timeout"])
    try:
        # 遍历多个DNS服务器重试
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
    """处理节点备注（增加异常捕获，避免label too long崩溃）"""
    if not remark:
        return f"{proto}节点"
    try:
        decoded = unquote(remark)
        # 先过滤不可打印字符和特殊emoji，减少字节数（保留@）
        decoded = re.sub(r'[^\x20-\x7E\u4e00-\u9fa5@]', '', decoded)
        b_remark = decoded.encode('utf-8')
        max_len = CONFIG["filter"]["max_remark_bytes"]
        if len(b_remark) <= max_len:
            return decoded
        
        # 安全截断：从后往前截断，避免乱码
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
    port = validate_port(port_match.group(1)) if port_match else 443
    return ip, domain, port

# ========== 协议解析函数 ==========
def parse_vmess(line: str) -> Optional[Dict]:
    """解析VMess节点：
    1. 仅校验add/port/id三个核心字段
    2. 精准提取Base64串，截断后面所有非Base64字符
    """
    try:
        # 打印解析前的@存在性
        at_count = line.count('@')
        LOG.debug(f"📌 解析VMess节点：{line[:100]}... | @数量：{at_count}")
        
        # 步骤1：提取vmess://后的所有内容
        vmess_raw = line[8:].strip()
        
        # 精准匹配最长的连续Base64字符段（只保留A-Za-z0-9+/=）
        base64_match = re.match(r'^[A-Za-z0-9+/=]+', vmess_raw)
        if not base64_match:
            raise ValueError("未提取到有效Base64字符段")
        vmess_part = base64_match.group(0)
        
        # 步骤2：限制长度（防止超长串）
        vmess_part = vmess_part[:1024]
        
        # 步骤3：校验Base64格式
        if not is_base64(vmess_part):
            raise ValueError("非Base64格式")
        
        # 步骤4：补全填充符并解码
        vmess_part = vmess_part.rstrip('=')
        vmess_part += '=' * (4 - len(vmess_part) % 4) if len(vmess_part) % 4 != 0 else ''
        decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
        
        # 步骤5：提取JSON配置（保留所有符号）
        json_match = re.search(r'\{.*\}', decoded, re.DOTALL)
        if not json_match:
            raise ValueError("未提取到有效JSON配置")
        decoded = json_match.group(0)
        # 仅过滤控制字符，保留@等符号
        decoded = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', decoded)
        cfg = json.loads(decoded)
        
        # 步骤6：仅校验add/port/id三个真正必填字段
        if not validate_fields(cfg, ["add", "port", "id"], "VMess", line):
            return None
        
        # 步骤7：非必填字段默认值兜底（对齐客户端逻辑）
        cfg["ps"] = process_remark(cfg.get('ps', ''), "VMess")
        cfg["port"] = validate_port(cfg.get('port', 443))
        cfg["aid"] = cfg.get('aid', 0)          # aid默认0
        cfg["net"] = cfg.get('net', 'tcp')      # 网络类型默认tcp
        cfg["scy"] = cfg.get('scy', 'auto')     # 加密方式默认auto
        cfg["tls"] = cfg.get('tls', 'none')     # TLS默认关闭
        cfg["host"] = cfg.get('host', cfg["add"])  # host默认同地址
        cfg["sni"] = cfg.get('sni', cfg["add"])    # sni默认同地址

        # 返回解析结果
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
    """解析VLESS节点（增加@追踪）"""
    try:
        # 打印解析前的@存在性
        at_count = line.count('@')
        LOG.debug(f"📌 解析VLESS节点：{line[:100]}... | @数量：{at_count}")
        
        vless_core = line[8:]
        vless_parts = vless_core.split('?', 1)
        base_part = vless_parts[0]
        param_part = vless_parts[1] if len(vless_parts) > 1 else ''
        
        if '@' not in base_part:
            raise ValueError(f"缺失UUID@地址格式（当前@数量：{base_part.count('@')}）")
        
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
    """解析Trojan节点（增加@追踪）"""
    try:
        # 打印解析前的@存在性
        at_count = line.count('@')
        LOG.debug(f"📌 解析Trojan节点：{line[:100]}... | @数量：{at_count}")
        
        trojan_parts = line.split('#', 1)
        label = process_remark(trojan_parts[1], "Trojan") if len(trojan_parts) > 1 else ""
        trojan_core = trojan_parts[0]
        
        trojan_core_parts = trojan_core[8:].split('?', 1)
        trojan_part = trojan_core_parts[0]
        param_part = trojan_core_parts[1] if len(trojan_core_parts) > 1 else ''
        
        if '@' not in trojan_part:
            raise ValueError(f"缺失密码@地址格式（当前@数量：{trojan_part.count('@')}）")
        
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
            "label": label or "Trojan节点"
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
    """解析SS节点（兼容缺少@的不规范格式 + 增加@追踪）"""
    try:
        # 打印解析前的@存在性
        at_count = line.count('@')
        LOG.debug(f"📌 解析SS节点：{line[:100]}... | @数量：{at_count}")
        
        ss_part = line[5:]
        # 处理Base64编码的SS节点
        if is_base64(ss_part.replace(' ', '')):
            try:
                ss_part = ss_part.replace(' ', '')
                ss_part = ss_part.rstrip('=')
                ss_part += '=' * (4 - len(ss_part) % 4) if len(ss_part) % 4 != 0 else ''
                ss_part = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
                LOG.debug(f"📌 SS节点Base64解码后：{ss_part[:100]}... | @数量：{ss_part.count('@')}")
            except:
                LOG.info(log_msg(f"⚠️ SS节点Base64解码失败，尝试直接解析", line[:20]))
        
        # 拆分备注和核心内容
        ss_parts = ss_part.split('#', 1)
        remark = process_remark(ss_parts[1], "SS") if len(ss_parts) > 1 else ""
        ss_core = ss_parts[0]
        
        # 兼容缺少@的情况：按最后一个:拆分端口
        if '@' not in ss_core:
            LOG.warning(log_msg(f"⚠️ SS节点缺少@，尝试兼容解析", ss_core[:20]))
            # 按最后一个:拆分端口
            parts = ss_core.rsplit(':', 1)
            if len(parts) != 2:
                raise ValueError(f"缺失@分隔符且端口格式错误（当前内容：{ss_core[:50]}）")
            auth_part = parts[0]
            addr_port = parts[1]
        else:
            auth_part, addr_port = ss_core.split('@', 1)
            LOG.debug(f"📌 SS节点拆分@后：认证部分={auth_part[:50]} | 地址端口={addr_port[:50]}")
        
        # 拆分地址和端口
        if ':' not in addr_port:
            raise ValueError(f"缺失端口信息（地址端口部分：{addr_port}）")
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        
        # 拆分加密方式和密码
        if ':' not in auth_part:
            raise ValueError(f"缺失加密方式:密码格式（认证部分：{auth_part}）")
        method = auth_part.split(':')[0]
        password = auth_part.split(':')[1]
        
        cfg = {
            "address": address.strip(),
            "port": port,
            "remark": remark or "SS节点",
            "method": method,
            "password": password
        }
        
        if not validate_fields(cfg, ["address", "port", "method", "password"], "SS", line):
            return None
        return cfg
    except ValueError as e:
        LOG.info(log_msg(f"📝 过滤无效SS节点：{str(e)}", line, "ss"))
        return None
    except Exception as e:
        LOG.info(log_msg(f"❌ SS解析错误: {str(e)}", line, "ss"))
        return None

def parse_hysteria(line: str) -> Optional[Dict]:
    """解析Hysteria节点（兼容缺少@的不规范格式 + 增加@追踪）"""
    try:
        # 打印解析前的@存在性
        at_count = line.count('@')
        LOG.debug(f"📌 解析Hysteria节点：{line[:100]}... | @数量：{at_count}")
        
        hysteria_parts = line.split('#', 1)
        label = process_remark(hysteria_parts[1], "Hysteria") if len(hysteria_parts) > 1 else ""
        hysteria_core = hysteria_parts[0]
        
        hysteria_core_parts = hysteria_core[10:].split('?', 1)
        core_part = hysteria_core_parts[0]
        param_part = hysteria_core_parts[1] if len(hysteria_core_parts) > 1 else ''
        
        # 兼容缺少@的情况：按最后一个:拆分端口
        if '@' not in core_part:
            LOG.warning(log_msg(f"⚠️ Hysteria节点缺少@，尝试兼容解析", core_part[:20]))
            parts = core_part.rsplit(':', 1)
            if len(parts) != 2:
                raise ValueError(f"缺失认证@地址格式且端口错误（当前内容：{core_part[:50]}）")
            auth_part = parts[0]
            addr_port = parts[1]
        else:
            auth_part, addr_port = core_part.split('@', 1)
            LOG.debug(f"📌 Hysteria节点拆分@后：认证部分={auth_part[:50]} | 地址端口={addr_port[:50]}")
        
        # 拆分地址和端口
        if ':' not in addr_port:
            raise ValueError(f"缺失端口信息（地址端口部分：{addr_port}）")
        address, port_str = addr_port.rsplit(':', 1)
        port = validate_port(port_str)
        
        # 解析参数
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
            "label": label or "Hysteria节点"
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
    """检测节点可用性（增加超时和异常捕获）"""
    port = validate_port(port)
    if not ip or is_private_ip(ip):
        return False
    
    try:
        timeout = CONFIG["detection"]["tcp_timeout"].get(proto, 5)  # 增加超时时间到5秒
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # 先尝试DNS解析（显式解析，避免隐式失败）
            try:
                ip_addr = socket.gethostbyname(ip)
            except socket.gaierror:
                LOG.info(log_msg(f"⚠️ DNS解析失败: {ip}", proto=proto))
                return False
            # 连接端口
            if sock.connect_ex((ip_addr, port)) != 0:
                return False
    except Exception as e:
        LOG.info(log_msg(f"⚠️ TCP检测失败: {str(e)[:30]}", proto=proto))
        return False
    
    try:
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
    except:
        return False

def process_single_node_raw(raw_line: str, source_url: str = "") -> List[Tuple[Optional[str], str, Optional[str], int, str]]:
    """
    处理单个原始节点行（支持拆分多个拼接节点）
    返回处理后的节点列表
    """
    results = []
    
    # 打印原始节点行的@存在性
    LOG.debug(f"📌 开始处理原始节点行：{raw_line[:100]}... | @数量：{raw_line.count('@')}")
    
    # 第一步：安全拆分拼接的多个节点（过滤残缺）
    split_nodes = split_multi_nodes(raw_line)
    if len(split_nodes) > 1:
        LOG.info(log_msg(f"🔍 检测到{len(split_nodes)}个拼接节点，开始拆分处理", raw_line[:50]))
    
    # 第二步：逐个处理拆分后的节点
    for node_line in split_nodes:
        try:
            if not node_line:
                results.append((None, "", None, 443, ""))
                continue
            
            clean_line = clean_node_content(node_line)
            if not clean_line:
                LOG.info(log_msg(f"📝 过滤空节点（拆分后）", node_line[:20]))
                results.append((None, "", None, 443, source_url))
                continue
            
            ip, domain, port = None, "", 443
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
                LOG.info(log_msg(f"📝 过滤私有IP：{ip}:{port}", clean_line[:20], proto))
                results.append((None, "", None, 443, source_url))
                continue
            
            if ip and cfg and not test_node(ip, port, proto):
                LOG.info(log_msg(f"📝 过滤不可用节点：{ip}:{port}", clean_line[:20], proto))
                results.append((None, "", None, 443, source_url))
                continue
            
            if domain and not dns_resolve(domain):
                LOG.info(log_msg(f"⚠️ 域名{domain}解析失败，但IP{ip}有效", clean_line[:20], proto))
            
            if not ip and not domain:
                LOG.info(log_msg(f"📝 过滤空地址节点", clean_line[:20], proto))
                results.append((None, "", None, 443, source_url))
                continue
            
            LOG.info(f"✅ 保留节点: {ip or domain}:{port}（{proto}）")
            results.append((clean_line, domain, ip, port, source_url))
        
        except Exception as e:
            LOG.info(log_msg(f"❌ 节点处理错误: {str(e)}", node_line[:20], proto))
            results.append((None, "", None, 443, source_url))
    
    return results

def process_single_node(node: Union[str, Dict]) -> List[Tuple[Optional[str], str, Optional[str], int, str]]:
    """兼容原有接口的节点处理函数"""
    raw_line = node["line"] if isinstance(node, dict) else node
    source_url = node.get("source_url", "") if isinstance(node, dict) else ""
    return process_single_node_raw(raw_line, source_url)

def dedup_nodes(nodes: List[Dict]) -> List[Dict]:
    """
    分层去重：
    1. 先按原始行特征去重（恢复拆分前的逻辑）
    2. 对拆分后的节点，补充按“IP+端口+唯一标识”精细化去重
    """
    # 第一阶段：按原始行去重（拆分前的正常逻辑）
    seen_raw = set()
    raw_unique = []
    for node in nodes:
        raw_line = node["line"]
        proto = "other"
        # 识别协议
        for p in ["vmess", "vless", "trojan", "ss", "hysteria"]:
            if raw_line.startswith(f"{p}://"):
                proto = p
                break
        # 去重key：原始行前50字符 + 协议（拆分前的核心逻辑）
        key_raw = f"{raw_line[:50]}:{proto}"
        if key_raw not in seen_raw:
            seen_raw.add(key_raw)
            raw_unique.append(node)
    
    # 第二阶段：对拆分后的有效节点，做精细化去重（避免IP+端口误去重）
    seen_detail = set()
    final_unique = []
    for node in raw_unique:
        raw_line = node["line"]
        # 拆分节点（仅用于提取特征，不改变原始行）
        split_nodes = split_multi_nodes(raw_line)
        is_valid = False
        detail_key = ""
        for split_node in split_nodes:
            # 提取节点的唯一特征（IP+端口+身份标识）
            if split_node.startswith("vmess://"):
                # 解析VMess的id（UUID）
                try:
                    vmess_part = split_node[8:].strip()
                    base64_match = re.match(r'^[A-Za-z0-9+/=]+', vmess_part)
                    if base64_match:
                        b64 = base64_match.group(0).rstrip('=')
                        b64 += '=' * (4 - len(b64) % 4) if len(b64) % 4 != 0 else ''
                        decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                        cfg = json.loads(decoded)
                        ip = cfg.get("add", "")
                        port = cfg.get("port", "")
                        uuid = cfg.get("id", "")
                        detail_key = f"{ip}:{port}:vmess:{uuid}"
                        is_valid = True
                    else:
                        detail_key = f"{split_node[:50]}:vmess"
                        is_valid = True
                except:
                    detail_key = f"{split_node[:50]}:vmess"
                    is_valid = True
            elif split_node.startswith("vless://"):
                # 解析Vless的uuid
                try:
                    vless_part = split_node[8:].split('?')[0]
                    uuid = vless_part.split('@')[0] if '@' in vless_part else ""
                    addr_port = vless_part.split('@')[1] if '@' in vless_part else ""
                    ip = addr_port.split(':')[0] if ':' in addr_port else ""
                    port = addr_port.split(':')[1] if ':' in addr_port else ""
                    detail_key = f"{ip}:{port}:vless:{uuid}"
                    is_valid = True
                except:
                    detail_key = f"{split_node[:50]}:vless"
                    is_valid = True
            elif split_node.startswith("ss://"):
                # 解析SS的method+password
                try:
                    ss_part = split_node[5:].strip()
                    if is_base64(ss_part.replace(' ', '')):
                        ss_part = ss_part.replace(' ', '')
                        ss_part = ss_part.rstrip('=')
                        ss_part += '=' * (4 - len(ss_part) % 4) if len(ss_part) % 4 != 0 else ''
                        ss_part = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
                    ss_core = ss_part.split('#')[0]
                    if '@' in ss_core:
                        auth_part = ss_core.split('@')[0]
                    else:
                        auth_part = ss_core.rsplit(':', 1)[0] if ':' in ss_core else ""
                    method = auth_part.split(':')[0] if ':' in auth_part else ""
                    password = auth_part.split(':')[1] if ':' in auth_part else ""
                    addr_port = ss_core.split('@')[1] if '@' in ss_core else ss_core.rsplit(':', 1)[1] if ':' in ss_core else ""
                    ip = addr_port.split(':')[0] if ':' in addr_port else ""
                    port = addr_port.split(':')[1] if ':' in addr_port else ""
                    detail_key = f"{ip}:{port}:ss:{method}:{password}"
                    is_valid = True
                except:
                    detail_key = f"{split_node[:50]}:ss"
                    is_valid = True
            elif split_node.startswith("hysteria://"):
                # 解析Hysteria的password
                try:
                    hysteria_part = split_node[10:].strip()
                    core_part = hysteria_part.split('?')[0]
                    if '@' in core_part:
                        password = core_part.split('@')[0]
                    else:
                        password = core_part.rsplit(':', 1)[0] if ':' in core_part else ""
                    addr_port = core_part.split('@')[1] if '@' in core_part else core_part.rsplit(':', 1)[1] if ':' in core_part else ""
                    ip = addr_port.split(':')[0] if ':' in addr_port else ""
                    port = addr_port.split(':')[1] if ':' in addr_port else ""
                    detail_key = f"{ip}:{port}:hysteria:{password}"
                    is_valid = True
                except:
                    detail_key = f"{split_node[:50]}:hysteria"
                    is_valid = True
            else:
                # 其他协议：按原始行特征
                detail_key = f"{split_node[:50]}:{proto}"
                is_valid = True
        
        # 精细化去重
        if not detail_key:
            detail_key = f"{raw_line[:50]}:other"
        
        if detail_key not in seen_detail:
            seen_detail.add(detail_key)
            final_unique.append(node)
    
    LOG.info(f"📌 去重统计：原始{len(nodes)}条 → 按行去重{len(raw_unique)}条 → 精细化去重{len(final_unique)}条")
    return final_unique

# ========== 数据源与主逻辑 ==========
def fetch_source_data(url: str, weight: int) -> Tuple[List[str], int]:
    """拉取订阅源数据：先去重原始行，再拆分"""
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
            LOG.info(f"⚠️ 缓存读取失败 {url}: {str(e)[:50]}")
    
    time.sleep(CONFIG["github"]["interval"])
    
    for retry in range(CONFIG["request"]["retry"]):
        try:
            resp = SESSION.get(url, timeout=CONFIG["request"]["timeout"], verify=False)
            resp.raise_for_status()
            content = decode_b64_sub(resp.text)
            # 第一步：提取原始行并去重（恢复拆分前的逻辑）
            raw_lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
            # 原始行去重（按前50字符+协议）
            seen_raw = set()
            raw_unique = []
            for line in raw_lines:
                proto = "other"
                for p in ["vmess", "vless", "trojan", "ss", "hysteria"]:
                    if line.startswith(f"{p}://"):
                        proto = p
                        break
                key = f"{line[:50]}:{proto}"
                if key not in seen_raw:
                    seen_raw.add(key)
                    raw_unique.append(line)
            
            # 第二步：对去重后的原始行做安全拆分（过滤残缺节点）
            expanded_lines = []
            for line in raw_unique:
                split_nodes = split_multi_nodes(line)
                expanded_lines.extend(split_nodes)
            
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(expanded_lines, f, ensure_ascii=False)
            except OSError as e:
                LOG.info(f"⚠️ 缓存写入失败 {url}: {str(e)[:50]}")
            
            LOG.info(f"✅ 拉取成功 {url}：原始{len(raw_lines)}条 → 行去重{len(raw_unique)}条 → 拆分后{len(expanded_lines)}条")
            return expanded_lines, weight
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
    """批量处理节点（适配拆分后的节点）"""
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
                # 每个节点可能返回多个结果（拆分后的）
                node_results = future.result()
                for line, domain, ip, port, source_url in node_results:
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
            except Exception as e:
                LOG.info(f"⚠️ 节点处理异常: {str(e)[:50]}")
                continue
    
    return valid_lines, valid_nodes

def generate_stats(all_nodes: List[Dict], unique_nodes: List[Dict], valid_lines: List[str], 
                   source_records: Dict, valid_nodes: List[Dict], start_time: float) -> None:
    """生成统计信息并保存结果"""
    # 更新保留记录
    for url in source_records:
        retained = [n for n in valid_nodes if n["source_url"] == url]
        source_records[url]["retained_count"] = len(retained)
        source_records[url]["retained_lines"] = retained
    
    # 排序（优先保留带Reality/TLS的节点）
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
    
    # 保存纯净节点到文件
    clean_valid_lines = [clean_node_content(line) for line in valid_lines if clean_node_content(line)]
    encoded = base64.b64encode('\n'.join(clean_valid_lines).encode('utf-8')).decode('utf-8') if clean_valid_lines else ""
    
    try:
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write(encoded)
        LOG.info(f"📄 订阅文件保存至 s1.txt（{len(clean_valid_lines)} 纯净节点）")
    except OSError as e:
        LOG.error(f"❌ 订阅文件保存失败: {str(e)[:50]}")
    
    # 输出统计信息
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
    
    # 校验配置
    if not validate_sources():
        LOG.info("❌ 配置校验失败，退出")
        return
    
    # 清理缓存
    clean_expired_cache()
    LOG.info(f"🚀 开始节点更新（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）")
    
    # 拉取所有源
    all_nodes, source_records = fetch_all_sources()
    LOG.info(f"\n📊 拉取完成，原始节点：{len(all_nodes)} 条")
    
    # 去重（分层去重，恢复拆分前逻辑）
    unique_nodes = dedup_nodes(all_nodes)
    LOG.info(f"🔍 去重后节点：{len(unique_nodes)} 条")
    
    # 处理节点
    valid_lines, valid_nodes = process_nodes(unique_nodes)
    
    # 生成统计
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
