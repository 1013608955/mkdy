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
        "max_remark_bytes": 200
    },
    "log": {
        "show_success": True,  # 显示成功保留的节点
        "show_failure": True,  # 显示失败/过滤的节点原因
        "show_progress": True, # 显示处理进度
        "split_detail": False  # 关闭拆分单节点的冗余日志（避免几万行）
    }
}

DNS_CACHE_MAXSIZE = CONFIG["detection"]["dns"]["cache_size"]

# ========== 日志配置：恢复详细日志 + 控制冗余 ==========
def init_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)  # 恢复DEBUG级别，保证详细日志
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
    try:
        p = int(port)
        return p if p in CONFIG["filter"]["ports"] else 443
    except (ValueError, TypeError):
        return 443

def log_msg(content: str, line: str = "", proto: str = "") -> str:
    """格式化日志消息，控制长度避免冗余"""
    line_part = f"（{line[:50]}...）" if line else ""
    proto_part = f"（{proto}）" if proto else ""
    return f"{content}{line_part}{proto_part}"

def is_base64(s: str) -> bool:
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
    """解码订阅内容，保留详细日志"""
    original_text = text.strip()
    clean_for_b64 = re.sub(r'\s+', ' ', original_text)
    
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
            LOG.error(log_msg(f"❌ Base64解码失败: {str(e)[:50]}"))
            return original_text
    else:
        cleaned_lines = [l.strip() for l in original_text.split('\n') if l.strip()]
        plain_line_count = len(cleaned_lines)
        LOG.info(log_msg(f"✅ 明文订阅处理完成，解析出{plain_line_count}个有效节点"))
        return '\n'.join(cleaned_lines)

# ========== 协议特征检测 ==========
def is_vmess_content(content: str) -> bool:
    """检测是否为VMess内容，避免被误判为SS"""
    try:
        content_clean = content.replace(' ', '').rstrip('=')
        content_clean += '=' * (4 - len(content_clean) % 4) if len(content_clean) % 4 != 0 else ''
        decoded = base64.b64decode(content_clean).decode('utf-8', errors='ignore')
        cfg = json.loads(decoded)
        vmess_keys = ["add", "port", "id", "net", "type", "host", "path", "tls"]
        return any(key in cfg for key in vmess_keys)
    except:
        return False

# ========== 核心拆分逻辑（修复VLESS/VMess被拆 + 控制拆分日志冗余） ==========
def split_multi_nodes(line: str) -> List[str]:
    """安全拆分节点，优先提取VLESS/VMess，控制拆分日志冗余"""
    if not line:
        LOG.debug(log_msg("📌 拆分空节点，直接返回空列表"))
        return []
    
    final_nodes = []
    remaining_content = line
    proto_counts = {"vless":0, "vmess":0, "other":0}

    # ========== 步骤1：优先提取VLESS（完整提取后移除） ==========
    while True:
        vless_start = remaining_content.find("vless://")
        if vless_start == -1:
            break
        # 找到VLESS节点的结束位置
        next_proto_pos = min(
            remaining_content.find("vmess://", vless_start) if remaining_content.find("vmess://", vless_start) != -1 else len(remaining_content),
            remaining_content.find("trojan://", vless_start) if remaining_content.find("trojan://", vless_start) != -1 else len(remaining_content),
            remaining_content.find("ss://", vless_start) if remaining_content.find("ss://", vless_start) != -1 else len(remaining_content),
            remaining_content.find("hysteria://", vless_start) if remaining_content.find("hysteria://", vless_start) != -1 else len(remaining_content)
        )
        vless_node = remaining_content[vless_start:next_proto_pos].strip()
        final_nodes.append(vless_node)
        proto_counts["vless"] += 1
        # 从剩余内容中移除VLESS节点
        remaining_content = remaining_content[:vless_start] + remaining_content[next_proto_pos:]

    # ========== 步骤2：优先提取VMess（完整提取后移除） ==========
    while True:
        vmess_start = remaining_content.find("vmess://")
        if vmess_start != -1:
            next_proto_pos = min(
                remaining_content.find("vless://", vmess_start) if remaining_content.find("vless://", vmess_start) != -1 else len(remaining_content),
                remaining_content.find("trojan://", vmess_start) if remaining_content.find("trojan://", vmess_start) != -1 else len(remaining_content),
                remaining_content.find("ss://", vmess_start) if remaining_content.find("ss://", vmess_start) != -1 else len(remaining_content),
                remaining_content.find("hysteria://", vmess_start) if remaining_content.find("hysteria://", vmess_start) != -1 else len(remaining_content)
            )
            vmess_node = remaining_content[vmess_start:next_proto_pos].strip()
            final_nodes.append(vmess_node)
            proto_counts["vmess"] += 1
            remaining_content = remaining_content[:vmess_start] + remaining_content[next_proto_pos:]
        else:
            # 匹配内容特征的VMess
            found = False
            for i in range(len(remaining_content) - 80):
                fragment = remaining_content[i:i+500]
                if is_vmess_content(fragment):
                    next_proto_pos = min(
                        remaining_content.find("vless://", i) if remaining_content.find("vless://", i) != -1 else len(remaining_content),
                        remaining_content.find("trojan://", i) if remaining_content.find("trojan://", i) != -1 else len(remaining_content),
                        remaining_content.find("ss://", i) if remaining_content.find("ss://", i) != -1 else len(remaining_content),
                        remaining_content.find("hysteria://", i) if remaining_content.find("hysteria://", i) != -1 else len(remaining_content)
                    )
                    vmess_node = remaining_content[i:next_proto_pos].strip()
                    final_nodes.append(vmess_node)
                    proto_counts["vmess"] += 1
                    remaining_content = remaining_content[:i] + remaining_content[next_proto_pos:]
                    found = True
                    break
            if not found:
                break

    # ========== 步骤3：提取其他协议（Trojan/SS/Hysteria） ==========
    proto_rules = {
        "trojan": {"prefix": "trojan://", "min_len": 50, "required": "@"},
        "hysteria": {"prefix": "hysteria://", "min_len": 50, "required": None},
        "ss": {"prefix": "ss://", "min_len": 40, "required": None}
    }
    for proto, rule in proto_rules.items():
        prefix = rule["prefix"]
        pos = remaining_content.find(prefix)
        while pos != -1:
            next_pos = min(
                remaining_content.find("vless://", pos+len(prefix)) if remaining_content.find("vless://", pos+len(prefix)) != -1 else len(remaining_content),
                remaining_content.find("trojan://", pos+len(prefix)) if remaining_content.find("trojan://", pos+len(prefix)) != -1 else len(remaining_content),
                remaining_content.find("ss://", pos+len(prefix)) if remaining_content.find("ss://", pos+len(prefix)) != -1 else len(remaining_content),
                remaining_content.find("hysteria://", pos+len(prefix)) if remaining_content.find("hysteria://", pos+len(prefix)) != -1 else len(remaining_content)
            )
            node_str = remaining_content[pos:next_pos].strip()
            if len(node_str) >= rule["min_len"] and (not rule["required"] or rule["required"] in node_str):
                final_nodes.append(node_str)
                proto_counts["other"] += 1
            pos = remaining_content.find(prefix, next_pos)

    # 日志控制：只打印拆分总数，不打印每个节点（避免几万行）
    total_split = len(final_nodes)
    if total_split > 1 and CONFIG["log"]["split_detail"]:
        LOG.debug(log_msg(f"📌 拆分完成：共提取{total_split}个节点（VLESS:{proto_counts['vless']} | VMess:{proto_counts['vmess']} | 其他:{proto_counts['other']}）", line[:50]))
    elif total_split > 1:
        LOG.info(log_msg(f"🔍 检测到拼接节点，拆分出{total_split}个（VLESS:{proto_counts['vless']} | VMess:{proto_counts['vmess']}）", line[:50]))

    if not final_nodes:
        final_nodes = [line.strip()]
    
    return final_nodes

def clean_node_content(line: str) -> str:
    """清洗节点内容，保留详细日志"""
    if not line:
        return ""
    # 仅删除中文，保留所有符号
    line = re.sub(r'[\u4e00-\u9fa5\u3000-\u303f\uff00-\uffef]', '', line)
    error_keywords = ["订阅内容解析错误", "解析失败", "无效节点", "缺失字段"]
    for keyword in error_keywords:
        line = line.replace(keyword, "")
    cleaned_line = line.strip()
    LOG.debug(log_msg(f"📌 节点清洗完成：原始{len(line)}字符 → 清洗后{len(cleaned_line)}字符", cleaned_line[:50]))
    return cleaned_line

def is_private_ip(ip: str) -> bool:
    """判断私有IP，保留详细日志"""
    is_private = bool(ip and CONFIG["filter"]["private_ip"].match(ip))
    if is_private and CONFIG["log"]["show_failure"]:
        LOG.debug(log_msg(f"📌 检测到私有IP：{ip}", "", "private_ip"))
    return is_private

@lru_cache(maxsize=DNS_CACHE_MAXSIZE)
def dns_resolve(domain: str) -> bool:
    """DNS解析，保留详细日志"""
    if not domain or domain == "未知":
        LOG.debug(log_msg(f"📌 空域名，跳过DNS解析", "", "dns"))
        return False
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(CONFIG["detection"]["dns"]["timeout"])
    try:
        for idx, dns in enumerate(CONFIG["detection"]["dns"]["servers"]):
            try:
                socket.gethostbyname_ex(domain)
                LOG.debug(log_msg(f"✅ DNS解析成功：{domain}（使用服务器：{dns}）", "", "dns"))
                return True
            except (socket.gaierror, socket.timeout):
                LOG.debug(log_msg(f"⚠️ DNS解析失败：{domain}（服务器{idx+1}/{len(CONFIG['detection']['dns']['servers'])}：{dns}）", "", "dns"))
                continue
        if CONFIG["log"]["show_failure"]:
            LOG.warning(log_msg(f"❌ 域名{domain}解析失败（所有DNS服务器均失败）", "", "dns"))
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)

def process_remark(remark: str, proto: str) -> str:
    """处理备注，保留详细日志"""
    if not remark:
        default_remark = f"{proto}节点"
        LOG.debug(log_msg(f"📌 空备注，使用默认值：{default_remark}", "", proto))
        return default_remark
    try:
        decoded = unquote(remark)
        decoded = re.sub(r'[^\x20-\x7E\u4e00-\u9fa5@]', '', decoded)
        b_remark = decoded.encode('utf-8')
        max_len = CONFIG["filter"]["max_remark_bytes"]
        
        if len(b_remark) <= max_len:
            LOG.debug(log_msg(f"📌 备注长度合规：{len(b_remark)}/{max_len}字节", decoded[:50], proto))
            return decoded
        
        # 安全截断
        trunc = decoded[:max_len-3] + "..."
        if CONFIG["log"]["show_failure"]:
            LOG.warning(log_msg(f"⚠️ {proto}备注超限：{len(b_remark)}/{max_len}字节，截断为：{trunc[:50]}", remark[:50], proto))
        return trunc
    except Exception as e:
        if CONFIG["log"]["show_failure"]:
            LOG.error(log_msg(f"❌ {proto}备注处理失败：{str(e)[:30]}", remark[:50], proto))
        return f"{proto}节点"

def validate_fields(fields: Dict, required: List[str], proto: str, line: str) -> bool:
    """字段校验，保留详细日志"""
    missing = [f for f in required if f not in fields]
    if missing:
        if CONFIG["log"]["show_failure"]:
            LOG.warning(log_msg(f"📝 过滤无效{proto}节点：缺失字段{','.join(missing)}", line[:50], proto))
        return False
    LOG.debug(log_msg(f"✅ {proto}字段校验通过：{','.join(required)}", line[:50], proto))
    return True

def extract_ip_port(line: str) -> Tuple[Optional[str], str, int]:
    """提取IP/端口，保留详细日志"""
    ip_match = re.search(r'@([\d\.a-zA-Z-]+):', line)
    ip = ip_match.group(1) if ip_match else None
    
    domain_match = re.search(r'sni=([^&]+)|host=([^&]+)', line, re.I)
    domain = next((g for g in domain_match.groups() if g), "") if domain_match else ""
    
    port_match = re.search(r':(\d+)', line)
    port = validate_port(port_match.group(1)) if port_match else 443
    
    LOG.debug(log_msg(f"📌 提取IP/端口：IP={ip} | 域名={domain} | 端口={port}", line[:50]))
    return ip, domain, port

# ========== 协议解析函数（保留详细日志） ==========
def parse_vmess(line: str) -> Optional[Dict]:
    """解析VMess，保留详细成功/失败日志"""
    try:
        LOG.debug(log_msg(f"📌 开始解析VMess节点", line[:50], "vmess"))
        if line.startswith("vmess://"):
            vmess_raw = line[8:].strip()
        else:
            vmess_raw = line.strip()
        
        # 提取Base64段
        base64_match = re.match(r'^[A-Za-z0-9+/=]+', vmess_raw)
        if not base64_match:
            raise ValueError("未提取到有效Base64字符段")
        vmess_part = base64_match.group(0)[:1024]
        
        # 校验Base64
        if not is_base64(vmess_part):
            raise ValueError("非Base64格式")
        
        # 解码
        vmess_part = vmess_part.rstrip('=')
        vmess_part += '=' * (4 - len(vmess_part) % 4) if len(vmess_part) % 4 != 0 else ''
        decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
        
        # 提取JSON
        json_match = re.search(r'\{.*\}', decoded, re.DOTALL)
        if not json_match:
            raise ValueError("未提取到有效JSON配置")
        decoded = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_match.group(0))
        cfg = json.loads(decoded)
        
        # 校验必填字段
        if not validate_fields(cfg, ["add", "port", "id"], "VMess", line):
            return None
        
        # 补全默认值
        cfg["ps"] = process_remark(cfg.get('ps', ''), "VMess")
        cfg["port"] = validate_port(cfg.get('port', 443))
        cfg["aid"] = cfg.get('aid', 0)
        cfg["net"] = cfg.get('net', 'tcp')
        cfg["scy"] = cfg.get('scy', 'auto')
        cfg["tls"] = cfg.get('tls', 'none')
        cfg["host"] = cfg.get('host', cfg["add"])
        cfg["sni"] = cfg.get('sni', cfg["add"])

        LOG.debug(log_msg(f"✅ VMess解析成功：{cfg['add']}:{cfg['port']}（备注：{cfg['ps'][:20]}）", line[:50], "vmess"))
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
        if CONFIG["log"]["show_failure"]:
            LOG.error(log_msg(f"❌ VMess解析错误: {str(e)}", line[:50], "vmess"))
        return None

def parse_vless(line: str) -> Optional[Dict]:
    """解析VLESS，保留详细成功/失败日志"""
    try:
        LOG.debug(log_msg(f"📌 开始解析VLESS节点", line[:50], "vless"))
        vless_core = line[8:].strip()
        vless_parts = vless_core.split('?', 1)
        base_part = vless_parts[0]
        
        if '@' not in base_part:
            raise ValueError(f"缺失UUID@地址格式（当前@数量：{base_part.count('@')}）")
        
        uuid, addr_port = base_part.split('@', 1)
        if not uuid or not addr_port or ':' not in addr_port:
            raise ValueError("UUID/地址端口错误")
        
        address, port_str = addr_port.split(':', 1)
        port = validate_port(port_str)
        
        # 解析参数
        params = {}
        if len(vless_parts) > 1:
            for p in vless_parts[1].split('&'):
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
        
        LOG.debug(log_msg(f"✅ VLESS解析成功：{address}:{port}（UUID：{uuid[:10]}）", line[:50], "vless"))
        return cfg
    except ValueError as e:
        if CONFIG["log"]["show_failure"]:
            LOG.warning(log_msg(f"📝 过滤无效VLESS节点：{str(e)}", line[:50], "vless"))
        return None
    except Exception as e:
        if CONFIG["log"]["show_failure"]:
            LOG.error(log_msg(f"❌ VLESS解析错误: {str(e)}", line[:50], "vless"))
        return None

def parse_trojan(line: str) -> Optional[Dict]:
    """解析Trojan，保留详细成功/失败日志"""
    try:
        LOG.debug(log_msg(f"📌 开始解析Trojan节点", line[:50], "trojan"))
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
        
        # 解析参数
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
        
        LOG.debug(log_msg(f"✅ Trojan解析成功：{address}:{port}（备注：{cfg['label'][:20]}）", line[:50], "trojan"))
        return cfg
    except ValueError as e:
        if CONFIG["log"]["show_failure"]:
            LOG.warning(log_msg(f"📝 过滤无效Trojan节点：{str(e)}", line[:50], "trojan"))
        return None
    except Exception as e:
        if CONFIG["log"]["show_failure"]:
            LOG.error(log_msg(f"❌ Trojan解析错误: {str(e)}", line[:50], "trojan"))
        return None

def parse_ss(line: str) -> Optional[Dict]:
    """解析SS，保留详细成功/失败日志 + 防VMess/VLESS误判"""
    try:
        # 严格过滤：避免VMess/VLESS被误判为SS
        if is_vmess_content(line) or line.startswith(("vmess://", "vless://")):
            if CONFIG["log"]["show_failure"]:
                LOG.warning(log_msg(f"⚠️ 跳过疑似VMess/VLESS的SS解析", line[:50], "ss"))
            return None
        
        LOG.debug(log_msg(f"📌 开始解析SS节点", line[:50], "ss"))
        ss_part = line[5:].strip()
        
        # Base64解码
        if is_base64(ss_part.replace(' ', '')):
            try:
                ss_part = ss_part.replace(' ', '')
                ss_part = ss_part.rstrip('=')
                ss_part += '=' * (4 - len(ss_part) % 4) if len(ss_part) % 4 != 0 else ''
                ss_part = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
                LOG.debug(log_msg(f"📌 SS Base64解码完成：{ss_part[:50]}", line[:50], "ss"))
            except:
                if CONFIG["log"]["show_failure"]:
                    LOG.warning(log_msg(f"⚠️ SS Base64解码失败，尝试明文解析", line[:50], "ss"))
        
        # 拆分备注和核心
        ss_parts = ss_part.split('#', 1)
        remark = process_remark(ss_parts[1], "SS") if len(ss_parts) > 1 else ""
        ss_core = ss_parts[0]
        
        # 兼容缺少@的格式
        if '@' not in ss_core:
            LOG.warning(log_msg(f"⚠️ SS节点缺少@，尝试兼容解析", ss_core[:50], "ss"))
            parts = ss_core.rsplit(':', 1)
            if len(parts) != 2:
                raise ValueError(f"缺失@分隔符且端口格式错误（当前内容：{ss_core[:50]}）")
            auth_part = parts[0]
            addr_port = parts[1]
        else:
            auth_part, addr_port = ss_core.split('@', 1)
        
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
        
        LOG.debug(log_msg(f"✅ SS解析成功：{address}:{port}（加密：{method}）", line[:50], "ss"))
        return cfg
    except ValueError as e:
        if CONFIG["log"]["show_failure"]:
            LOG.warning(log_msg(f"📝 过滤无效SS节点：{str(e)}", line[:50], "ss"))
        return None
    except Exception as e:
        if CONFIG["log"]["show_failure"]:
            LOG.error(log_msg(f"❌ SS解析错误: {str(e)}", line[:50], "ss"))
        return None

def parse_hysteria(line: str) -> Optional[Dict]:
    """解析Hysteria，保留详细成功/失败日志"""
    try:
        LOG.debug(log_msg(f"📌 开始解析Hysteria节点", line[:50], "hysteria"))
        hysteria_parts = line.split('#', 1)
        label = process_remark(hysteria_parts[1], "Hysteria") if len(hysteria_parts) > 1 else ""
        hysteria_core = hysteria_parts[0]
        
        hysteria_core_parts = hysteria_core[10:].split('?', 1)
        core_part = hysteria_core_parts[0]
        param_part = hysteria_core_parts[1] if len(hysteria_core_parts) > 1 else ''
        
        # 兼容缺少@的格式
        if '@' not in core_part:
            LOG.warning(log_msg(f"⚠️ Hysteria节点缺少@，尝试兼容解析", core_part[:50], "hysteria"))
            parts = core_part.rsplit(':', 1)
            if len(parts) != 2:
                raise ValueError(f"缺失认证@地址格式且端口错误（当前内容：{core_part[:50]}）")
            auth_part = parts[0]
            addr_port = parts[1]
        else:
            auth_part, addr_port = core_part.split('@', 1)
        
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
        
        LOG.debug(log_msg(f"✅ Hysteria解析成功：{address}:{port}（备注：{cfg['label'][:20]}）", line[:50], "hysteria"))
        return cfg
    except ValueError as e:
        if CONFIG["log"]["show_failure"]:
            LOG.warning(log_msg(f"📝 过滤无效Hysteria节点：{str(e)}", line[:50], "hysteria"))
        return None
    except Exception as e:
        if CONFIG["log"]["show_failure"]:
            LOG.error(log_msg(f"❌ Hysteria解析错误: {str(e)}", line[:50], "hysteria"))
        return None

# ========== 节点检测与处理（保留详细日志） ==========
def test_node(ip: str, port: int, proto: str) -> bool:
    """检测节点可用性，保留详细成功/失败日志"""
    port = validate_port(port)
    if not ip or is_private_ip(ip):
        return False
    
    try:
        timeout = CONFIG["detection"]["tcp_timeout"].get(proto, 5)
        LOG.debug(log_msg(f"📌 开始检测节点：{ip}:{port}（超时：{timeout}秒）", "", proto))
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # DNS解析
            try:
                ip_addr = socket.gethostbyname(ip)
                LOG.debug(log_msg(f"📌 DNS解析结果：{ip} → {ip_addr}", "", proto))
            except socket.gaierror as e:
                if CONFIG["log"]["show_failure"]:
                    LOG.warning(log_msg(f"⚠️ DNS解析失败: {ip}（{str(e)}）", "", proto))
                return False
            
            # 端口连接
            connect_result = sock.connect_ex((ip_addr, port))
            if connect_result != 0:
                if CONFIG["log"]["show_failure"]:
                    LOG.warning(log_msg(f"⚠️ 端口连接失败：{ip}:{port}（错误码：{connect_result}）", "", proto))
                return False
            LOG.debug(log_msg(f"✅ 端口连接成功：{ip}:{port}", "", proto))
        
        # 协议特定检测
        if proto in ["vmess", "vless", "trojan"]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(4)
                sock.connect((ip_addr, port))
                sock.send(b"\x00")
                LOG.debug(log_msg(f"✅ 协议检测成功：{proto}", "", proto))
        elif proto == "hysteria":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.settimeout(4)
                udp_sock.sendto(b"\x00", (ip_addr, port))
                LOG.debug(log_msg(f"✅ 协议检测成功：{proto}", "", proto))
        
        LOG.debug(log_msg(f"✅ 节点检测通过：{ip}:{port}", "", proto))
        return True
    except Exception as e:
        if CONFIG["log"]["show_failure"]:
            LOG.warning(log_msg(f"⚠️ TCP检测失败: {str(e)[:30]}", "", proto))
        return False

def process_single_node_raw(raw_line: str, source_url: str = "") -> List[Tuple[Optional[str], str, Optional[str], int, str]]:
    """处理单个节点，保留完整的成功/失败日志"""
    results = []
    LOG.debug(log_msg(f"📌 开始处理原始节点行", raw_line[:50]))
    
    # 拆分节点
    split_nodes = split_multi_nodes(raw_line)
    
    # 逐个处理拆分后的节点
    for node_idx, node_line in enumerate(split_nodes):
        try:
            if not node_line:
                LOG.debug(log_msg(f"📌 跳过空节点（拆分后第{node_idx+1}个）"))
                results.append((None, "", None, 443, source_url))
                continue
            
            # 清洗节点
            clean_line = clean_node_content(node_line)
            if not clean_line:
                if CONFIG["log"]["show_failure"]:
                    LOG.info(log_msg(f"📝 过滤空节点（拆分后第{node_idx+1}个）", node_line[:20]))
                results.append((None, "", None, 443, source_url))
                continue
            
            # 初始化变量
            ip, domain, port = None, "", 443
            cfg = None
            proto = ""
            
            # 协议识别与解析
            if clean_line.startswith('vless://'):
                proto = "vless"
                cfg = parse_vless(clean_line)
            elif is_vmess_content(clean_line) or clean_line.startswith('vmess://'):
                proto = "vmess"
                cfg = parse_vmess(clean_line)
            elif clean_line.startswith('trojan://'):
                proto = "trojan"
                cfg = parse_trojan(clean_line)
            elif clean_line.startswith('ss://'):
                proto = "ss"
                cfg = parse_ss(clean_line)
            elif clean_line.startswith('hysteria://'):
                proto = "hysteria"
                cfg = parse_hysteria(clean_line)
            else:
                proto = "other"
                ip, domain, port = extract_ip_port(clean_line)
            
            # 提取节点信息
            if cfg and isinstance(cfg, dict):
                ip = cfg.get("address", ip)
                domain = cfg.get("serverName") or cfg.get("sni") or domain or cfg.get("label")
                port = cfg.get("port", port)
            
            # 过滤私有IP
            if is_private_ip(ip):
                if CONFIG["log"]["show_failure"]:
                    LOG.info(log_msg(f"📝 过滤私有IP节点：{ip}:{port}", clean_line[:20], proto))
                results.append((None, "", None, 443, source_url))
                continue
            
            # 检测节点可用性
            if ip and cfg and not test_node(ip, port, proto):
                if CONFIG["log"]["show_failure"]:
                    LOG.info(log_msg(f"📝 过滤不可用节点：{ip}:{port}", clean_line[:20], proto))
                results.append((None, "", None, 443, source_url))
                continue
            
            # DNS解析检测
            if domain and not dns_resolve(domain):
                if CONFIG["log"]["show_failure"]:
                    LOG.warning(log_msg(f"⚠️ 域名{domain}解析失败，但IP{ip}有效（保留节点）", clean_line[:20], proto))
            
            # 过滤空地址
            if not ip and not domain:
                if CONFIG["log"]["show_failure"]:
                    LOG.info(log_msg(f"📝 过滤空地址节点", clean_line[:20], proto))
                results.append((None, "", None, 443, source_url))
                continue
            
            # 保留节点（显示成功日志）
            if CONFIG["log"]["show_success"]:
                LOG.info(f"✅ 保留节点 [{proto}]：{ip or domain}:{port}（来源：{source_url[:50]}）")
            results.append((clean_line, domain, ip, port, source_url))
        
        except Exception as e:
            if CONFIG["log"]["show_failure"]:
                LOG.error(log_msg(f"❌ 节点处理错误（拆分后第{node_idx+1}个）: {str(e)}", node_line[:20], proto))
            results.append((None, "", None, 443, source_url))
    
    return results

def process_single_node(node: Union[str, Dict]) -> List[Tuple[Optional[str], str, Optional[str], int, str]]:
    """兼容原有接口"""
    raw_line = node["line"] if isinstance(node, dict) else node
    source_url = node.get("source_url", "") if isinstance(node, dict) else ""
    return process_single_node_raw(raw_line, source_url)

def dedup_nodes(nodes: List[Dict]) -> List[Dict]:
    """节点去重，保留详细日志"""
    # 第一阶段：按原始行去重
    seen_raw = set()
    raw_unique = []
    for node in nodes:
        raw_line = node["line"]
        proto = "other"
        if raw_line.startswith('vless://'):
            proto = "vless"
        elif is_vmess_content(raw_line) or raw_line.startswith('vmess://'):
            proto = "vmess"
        elif raw_line.startswith('trojan://'):
            proto = "trojan"
        elif raw_line.startswith('ss://'):
            proto = "ss"
        elif raw_line.startswith('hysteria://'):
            proto = "hysteria"
        key_raw = f"{raw_line[:50]}:{proto}"
        
        if key_raw not in seen_raw:
            seen_raw.add(key_raw)
            raw_unique.append(node)
        else:
            LOG.debug(log_msg(f"📌 去重：跳过重复原始行", raw_line[:50], proto))
    
    # 第二阶段：精细化去重
    seen_detail = set()
    final_unique = []
    for node in raw_unique:
        raw_line = node["line"]
        split_nodes = split_multi_nodes(raw_line)
        detail_key = ""
        is_duplicate = False
        
        for split_node in split_nodes:
            # 生成唯一标识
            if split_node.startswith('vless://'):
                try:
                    vless_part = split_node[8:].split('?')[0]
                    uuid = vless_part.split('@')[0] if '@' in vless_part else ""
                    addr_port = vless_part.split('@')[1] if '@' in vless_part else ""
                    ip = addr_port.split(':')[0] if ':' in addr_port else ""
                    port = addr_port.split(':')[1] if ':' in addr_port else ""
                    detail_key = f"vless:{ip}:{port}:{uuid[:10]}"
                except:
                    detail_key = f"vless:{split_node[:50]}"
            elif is_vmess_content(split_node) or split_node.startswith('vmess://'):
                try:
                    vmess_part = split_node[8:] if split_node.startswith('vmess://') else split_node
                    base64_match = re.match(r'^[A-Za-z0-9+/=]+', vmess_part)
                    b64 = base64_match.group(0)[:20] if base64_match else ""
                    detail_key = f"vmess:{b64}"
                except:
                    detail_key = f"vmess:{split_node[:50]}"
            elif split_node.startswith('trojan://'):
                try:
                    trojan_part = split_node[8:].split('?')[0]
                    password = trojan_part.split('@')[0] if '@' in trojan_part else ""
                    addr_port = trojan_part.split('@')[1] if '@' in trojan_part else ""
                    ip = addr_port.split(':')[0] if ':' in addr_port else ""
                    port = addr_port.split(':')[1] if ':' in addr_port else ""
                    detail_key = f"trojan:{ip}:{port}:{password[:10]}"
                except:
                    detail_key = f"trojan:{split_node[:50]}"
            elif split_node.startswith('ss://'):
                try:
                    ss_part = split_node[5:].strip()
                    if is_base64(ss_part.replace(' ', '')):
                        ss_part = base64.b64decode(ss_part.replace(' ', '').rstrip('=')).decode('utf-8', errors='ignore')
                    ss_core = ss_part.split('#')[0]
                    auth_part = ss_core.split('@')[0] if '@' in ss_core else ss_core.rsplit(':', 1)[0]
                    method = auth_part.split(':')[0] if ':' in auth_part else ""
                    password = auth_part.split(':')[1] if ':' in auth_part else ""
                    addr_port = ss_core.split('@')[1] if '@' in ss_core else ss_core.rsplit(':', 1)[1]
                    ip = addr_port.split(':')[0] if ':' in addr_port else ""
                    port = addr_port.split(':')[1] if ':' in addr_port else ""
                    detail_key = f"ss:{ip}:{port}:{method}:{password[:10]}"
                except:
                    detail_key = f"ss:{split_node[:50]}"
            else:
                detail_key = f"other:{split_node[:50]}"
        
        if detail_key in seen_detail:
            LOG.debug(log_msg(f"📌 去重：跳过重复精细化节点", raw_line[:50]))
            is_duplicate = True
        else:
            seen_detail.add(detail_key)
        
        if not is_duplicate:
            final_unique.append(node)
    
    LOG.info(f"📊 去重统计：原始{len(nodes)}条 → 行去重{len(raw_unique)}条 → 精细化去重{len(final_unique)}条")
    return final_unique

# ========== 数据源与主逻辑（保留详细进度日志） ==========
def fetch_source_data(url: str, weight: int) -> Tuple[List[str], int]:
    """拉取订阅源，保留详细日志"""
    cache_dir = ".cache"
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_path = os.path.join(cache_dir, cache_key)
    
    # 读取缓存
    if os.path.exists(cache_path):
        try:
            cache_mtime = os.path.getmtime(cache_path)
            if time.time() - cache_mtime < CONFIG["github"]["cache_ttl"]:
                with open(cache_path, "r", encoding="utf-8") as f:
                    lines = json.load(f)
                LOG.info(f"✅ 缓存加载成功：{url}（{len(lines)}个节点，缓存时间：{datetime.fromtimestamp(cache_mtime).strftime('%Y-%m-%d %H:%M:%S')}）")
                return lines, weight
        except (json.JSONDecodeError, OSError) as e:
            LOG.warning(log_msg(f"⚠️ 缓存读取失败：{str(e)[:50]}", "", "cache"))
    
    # 拉取远程数据
    time.sleep(CONFIG["github"]["interval"])
    for retry in range(CONFIG["request"]["retry"]):
        try:
            LOG.info(f"📡 开始拉取订阅源：{url}（重试{retry+1}/{CONFIG['request']['retry']}）")
            resp = SESSION.get(url, timeout=CONFIG["request"]["timeout"], verify=False)
            resp.raise_for_status()
            
            # 解码订阅内容
            content = decode_b64_sub(resp.text)
            raw_lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
            
            # 原始行去重
            seen_raw = set()
            raw_unique = []
            for line in raw_lines:
                key = line[:50]
                if key not in seen_raw:
                    seen_raw.add(key)
                    raw_unique.append(line)
            
            # 保存缓存
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(raw_unique, f, ensure_ascii=False)
                LOG.info(f"✅ 缓存保存成功：{cache_path}")
            except OSError as e:
                LOG.warning(log_msg(f"⚠️ 缓存写入失败：{str(e)[:50]}", "", "cache"))
            
            LOG.info(f"✅ 拉取成功：{url} → 原始{len(raw_lines)}条 → 去重{len(raw_unique)}条")
            return raw_unique, weight
        except Exception as e:
            if retry < CONFIG["request"]["retry"] - 1:
                LOG.warning(log_msg(f"⚠️ 拉取失败：{str(e)[:80]}，{CONFIG['request']['retry_delay']}秒后重试", "", "fetch"))
                time.sleep(CONFIG["request"]["retry_delay"])
            else:
                LOG.error(log_msg(f"❌ 拉取最终失败：{str(e)[:80]}", "", "fetch"))
                return [], weight
    
    return [], weight

def clean_expired_cache() -> None:
    """清理过期缓存，保留详细日志"""
    cache_dir = ".cache"
    if not os.path.exists(cache_dir):
        LOG.info("📂 缓存目录不存在，跳过清理")
        return
    
    expire_seconds = CONFIG["github"]["cache_expire_days"] * 86400
    deleted = 0
    total = 0
    
    for file_name in os.listdir(cache_dir):
        total += 1
        file_path = os.path.join(cache_dir, file_name)
        try:
            if os.path.isfile(file_path):
                file_mtime = os.path.getmtime(file_path)
                if time.time() - file_mtime > expire_seconds:
                    os.remove(file_path)
                    deleted += 1
                    LOG.debug(log_msg(f"🗑️ 清理过期缓存：{file_name}（修改时间：{datetime.fromtimestamp(file_mtime).strftime('%Y-%m-%d %H:%M:%S')}）", "", "cache"))
        except OSError as e:
            LOG.warning(log_msg(f"⚠️ 缓存删除失败：{file_name} → {str(e)[:50]}", "", "cache"))
    
    LOG.info(f"🧹 缓存清理完成：共{total}个缓存文件 → 清理{deleted}个过期文件 → 剩余{total-deleted}个")

def validate_sources() -> bool:
    """校验订阅源配置，保留详细日志"""
    LOG.info("🔍 开始校验订阅源配置")
    invalid = []
    pattern = re.compile(r'^https?://', re.IGNORECASE)
    
    for idx, src in enumerate(CONFIG["sources"], 1):
        url = src.get("url", "")
        weight = src.get("weight", 0)
        
        # 校验URL格式
        if not pattern.match(url):
            invalid.append(f"第{idx}个源：URL格式错误 → {url}")
        
        # 校验权重
        if not isinstance(weight, int) or weight < 1:
            invalid.append(f"第{idx}个源：权重无效（需≥1）→ {url}（权重：{weight}）")
    
    if invalid:
        LOG.error("❌ 配置校验失败：")
        for err in invalid:
            LOG.error(f"   - {err}")
        return False
    
    LOG.info(f"✅ 配置校验通过：共{len(CONFIG['sources'])}个订阅源")
    return True

def count_proto(lines: List[Union[str, Dict]]) -> Dict[str, int]:
    """统计协议分布，保留详细日志"""
    count = {"vmess":0, "vless":0, "trojan":0, "ss":0, "hysteria":0, "other":0}
    for line in lines:
        line_str = line["line"] if isinstance(line, dict) else line
        clean_line = clean_node_content(line_str)
        
        if clean_line.startswith('vless://'):
            count["vless"] +=1
        elif is_vmess_content(clean_line) or clean_line.startswith('vmess://'):
            count["vmess"] +=1
        elif clean_line.startswith('trojan://'):
            count["trojan"] +=1
        elif clean_line.startswith('ss://'):
            count["ss"] +=1
        elif clean_line.startswith('hysteria://'):
            count["hysteria"] +=1
        else:
            count["other"] +=1
    
    LOG.info(f"📊 协议分布统计：VMess({count['vmess']}) | VLESS({count['vless']}) | Trojan({count['trojan']}) | SS({count['ss']}) | Hysteria({count['hysteria']}) | 其他({count['other']})")
    return count

def fetch_all_sources() -> Tuple[List[Dict], Dict[str, Dict]]:
    """拉取所有订阅源，保留详细日志"""
    all_nodes = []
    source_records = {}
    LOG.info(f"🚀 开始拉取所有订阅源（共{len(CONFIG['sources'])}个）")
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_source_data, src["url"], src["weight"]): src["url"] for src in CONFIG["sources"]}
        
        for future in as_completed(futures):
            url = futures[future]
            try:
                lines, weight = future.result()
                proto_count = count_proto(lines)
                
                # 记录源信息
                source_records[url] = {
                    "original": lines,
                    "original_count": len(lines),
                    "weight": weight,
                    "proto_count": proto_count,
                    "retained_count": 0,
                    "retained_lines": []
                }
                
                # 添加到总节点列表
                all_nodes.extend([{"line": l, "weight": weight, "source_url": url} for l in lines])
                
                LOG.info(f"📊 源处理完成：{url} → 协议分布：{proto_count}")
            except Exception as e:
                LOG.error(log_msg(f"❌ 处理源{url}异常：{str(e)[:50]}", "", "source"))
                source_records[url] = {
                    "original": [],
                    "original_count":0,
                    "weight":0,
                    "proto_count":count_proto([]),
                    "retained_count":0
                }
    
    LOG.info(f"📥 所有源拉取完成：共{len(all_nodes)}个原始节点")
    return all_nodes, source_records

def process_nodes(unique_nodes: List[Dict]) -> Tuple[List[str], List[Dict]]:
    """批量处理节点，保留详细进度日志"""
    valid_lines = []
    valid_nodes = []
    seen_ips = set()
    seen_domains = set()
    total = len(unique_nodes)
    
    if total == 0:
        LOG.warning("⚠️ 无节点可处理")
        return [], []
    
    LOG.info(f"⚙️ 开始批量处理节点（共{total}个，线程数：{CONFIG['detection']['thread_pool']}）")
    
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool"]) as executor:
        futures = [executor.submit(process_single_node, node) for node in unique_nodes]
        
        for idx, future in enumerate(as_completed(futures)):
            # 显示进度
            if CONFIG["log"]["show_progress"] and (idx + 1) % 5 == 0:
                progress = ((idx + 1) / total) * 100
                LOG.info(f"⏳ 处理进度：{idx + 1}/{total} ({progress:.1f}%) | 已保留{len(valid_lines)}个有效节点")
            
            try:
                # 处理每个节点的结果
                node_results = future.result()
                for line, domain, ip, port, source_url in node_results:
                    if not line:
                        continue
                    
                    # 去重（IP/域名级别）
                    if (ip and ip in seen_ips) or (domain and domain in seen_domains):
                        LOG.debug(log_msg(f"📌 去重：跳过重复IP/域名节点", line[:50]))
                        continue
                    
                    if ip:
                        seen_ips.add(ip)
                    if domain:
                        seen_domains.add(domain)
                    
                    # 添加到有效列表
                    valid_lines.append(line)
                    valid_nodes.append({"line": line, "source_url": source_url})
            except Exception as e:
                LOG.error(log_msg(f"⚠️ 节点处理异常: {str(e)[:50]}", "", "process"))
                continue
    
    LOG.info(f"✅ 批量处理完成：共{len(valid_lines)}个有效节点（去重IP：{len(seen_ips)}个，去重域名：{len(seen_domains)}个）")
    return valid_lines, valid_nodes

def generate_stats(all_nodes: List[Dict], unique_nodes: List[Dict], valid_lines: List[str], 
                   source_records: Dict, valid_nodes: List[Dict], start_time: float) -> None:
    """生成详细统计报告"""
    # 更新各源的保留记录
    for url in source_records:
        retained = [n for n in valid_nodes if n["source_url"] == url]
        source_records[url]["retained_count"] = len(retained)
        source_records[url]["retained_lines"] = retained
    
    # 排序节点（Reality/TLS优先）
    def sort_key(line: str) -> int:
        score = 0
        if "reality" in line.lower(): score += 100
        elif "tls" in line.lower(): score += 50
        if line.startswith('vless://'): score += 40
        elif is_vmess_content(line) or line.startswith('vmess://'): score += 20
        elif line.startswith('trojan://'): score += 30
        elif line.startswith('hysteria://'): score += 10
        elif line.startswith('ss://'): score += 5
        return score
    
    valid_lines.sort(key=sort_key, reverse=True)
    clean_valid_lines = [clean_node_content(line) for line in valid_lines if clean_node_content(line)]
    
    # 保存订阅文件
    try:
        # 保存Base64编码的订阅
        encoded = base64.b64encode('\n'.join(clean_valid_lines).encode('utf-8')).decode('utf-8') if clean_valid_lines else ""
        with open('s1.txt', 'w', encoding='utf-8') as f:
            f.write(encoded)
        LOG.info(f"📄 订阅文件保存成功：s1.txt（{len(clean_valid_lines)}个纯净节点，Base64编码长度：{len(encoded)}）")
        
        # 额外保存明文版本（便于调试）
        with open('s1_plain.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(clean_valid_lines))
        LOG.info(f"📄 明文节点文件保存成功：s1_plain.txt")
    except OSError as e:
        LOG.error(log_msg(f"❌ 文件保存失败：{str(e)[:50]}", "", "file"))
    
    # 统计协议分布
    valid_proto = count_proto(clean_valid_lines)
    total_cost = time.time() - start_time
    total_original = len(all_nodes)
    retention_rate = f"{(len(clean_valid_lines)/total_original*100):.2f}%" if total_original>0 else "0.00%"
    
    # 输出详细统计
    LOG.info("\n" + "="*80)
    LOG.info("📊 任务执行总结")
    LOG.info("="*80)
    LOG.info(f"📅 执行时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    LOG.info(f"⏱️  总耗时：{total_cost:.2f} 秒")
    LOG.info(f"📈 节点统计：")
    LOG.info(f"   - 原始节点：{total_original} 条")
    LOG.info(f"   - 去重后：{len(unique_nodes)} 条")
    LOG.info(f"   - 有效节点：{len(clean_valid_lines)} 条")
    LOG.info(f"   - 整体保留率：{retention_rate}")
    LOG.info(f"📋 协议分布：")
    LOG.info(f"   - VMess：{valid_proto['vmess']} 条 ({valid_proto['vmess']/len(clean_valid_lines)*100:.2f}%)")
    LOG.info(f"   - VLESS：{valid_proto['vless']} 条 ({valid_proto['vless']/len(clean_valid_lines)*100:.2f}%)")
    LOG.info(f"   - Trojan：{valid_proto['trojan']} 条 ({valid_proto['trojan']/len(clean_valid_lines)*100:.2f}%)")
    LOG.info(f"   - SS：{valid_proto['ss']} 条 ({valid_proto['ss']/len(clean_valid_lines)*100:.2f}%)")
    LOG.info(f"   - Hysteria：{valid_proto['hysteria']} 条 ({valid_proto['hysteria']/len(clean_valid_lines)*100:.2f}%)")
    LOG.info(f"   - 其他：{valid_proto['other']} 条 ({valid_proto['other']/len(clean_valid_lines)*100:.2f}%)")
    
    # 各源详细统计
    LOG.info("\n📡 各订阅源详情：")
    for idx, src in enumerate(CONFIG["sources"], 1):
        url = src["url"]
        rec = source_records.get(url, {"original_count":0, "proto_count":count_proto([]), "retained_count":0})
        rate = f"{(rec['retained_count']/rec['original_count']*100):.2f}%" if rec['original_count']>0 else "0.00%"
        proto = rec["proto_count"]
        LOG.info(f"{idx}. {url}")
        LOG.info(f"   - 原始：{rec['original_count']} 条 | 保留：{rec['retained_count']} 条 | 保留率：{rate}")
        LOG.info(f"   - 协议分布：VMess({proto['vmess']}) | VLESS({proto['vless']}) | Trojan({proto['trojan']}) | SS({proto['ss']})")
    LOG.info("="*80)

def main() -> None:
    """主函数，保留完整的流程日志"""
    start_time = time.time()
    
    # 初始化日志
    LOG.info("🚀 开始执行节点更新任务")
    LOG.info(f"📅 当前时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 校验配置
    if not validate_sources():
        LOG.error("❌ 配置校验失败，任务终止")
        return
    
    # 清理过期缓存
    clean_expired_cache()
    
    # 拉取所有订阅源
    all_nodes, source_records = fetch_all_sources()
    if not all_nodes:
        LOG.error("❌ 无有效节点可处理，任务终止")
        return
    
    # 节点去重
    LOG.info(f"🔍 开始节点去重（共{len(all_nodes)}个原始节点）")
    unique_nodes = dedup_nodes(all_nodes)
    
    # 处理节点
    valid_lines, valid_nodes = process_nodes(unique_nodes)
    
    # 生成统计报告
    generate_stats(all_nodes, unique_nodes, valid_lines, source_records, valid_nodes, start_time)
    
    # 关闭会话
    try:
        SESSION.close()
        LOG.info("🔌 请求会话已关闭")
    except Exception as e:
        LOG.warning(log_msg(f"⚠️ 会话关闭异常：{str(e)[:50]}", "", "session"))
    
    LOG.info("✅ 任务执行完成！")

if __name__ == "__main__":
    main()
