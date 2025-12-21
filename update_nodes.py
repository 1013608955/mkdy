import requests
import re
import socket
import base64
import json
import binascii
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====================== 配置项 ======================
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
        "timeout": 60,
        "retry_times": 3,
        "retry_delay": 2,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    "detection": {
        "tcp_timeout": 3,
        "tcp_retry": 1,
        "thread_pool_size": 15,
        "dns_servers": ["8.8.8.8", "1.1.1.1", "223.5.5.5"],
        "dns_timeout": 5
    },
    "filter": {
        "private_ips": [
            re.compile(r"^192\.168\.\d+\.\d+$"),
            re.compile(r"^10\.\d+\.\d+\.\d+$"),
            re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$"),
            re.compile(r"^127\.\d+\.\d+\.\d+$"),
            re.compile(r"^0\.0\.0\.0$")
        ],
        "valid_ports": range(1, 65535)
    }
}

# ====================== 工具函数 ======================
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
            print(f"✅ Base64解码成功，解析出明文内容（长度：{len(decoded)}）")
            return decoded
        except Exception as e:
            print(f"❌ Base64解码失败: {str(e)[:50]}")
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
    if not domain or domain == "未知":
        return False
    socket.setdefaulttimeout(CONFIG["detection"]["dns_timeout"])
    for dns_server in CONFIG["detection"]["dns_servers"]:
        try:
            original_dns = socket.getaddrinfo
            def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
                return socket._socket.getaddrinfo(host, port, family, type, proto, flags)
            socket.getaddrinfo = custom_getaddrinfo
            socket.gethostbyname_ex(domain)
            socket.getaddrinfo = original_dns
            return True
        except (socket.gaierror, socket.timeout):
            continue
        finally:
            socket.getaddrinfo = original_dns
    print(f"⚠️ 域名{domain}解析失败（所有DNS源均失败），将尝试IP直连检测")
    return False

def extract_vmess_config(vmess_line):
    try:
        vmess_part = vmess_line[8:].strip()
        vmess_part = vmess_part.encode('ascii', 'ignore').decode('ascii')
        padding = 4 - len(vmess_part) % 4
        if padding != 4:
            vmess_part += '=' * padding
        try:
            decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
            cfg = json.loads(decoded)
            return {
                "address": cfg.get('add'),
                "port": int(cfg.get('port', 443)),
                "id": cfg.get('id', ''),
                "alterId": cfg.get('aid', 0),
                "security": cfg.get('security', 'auto'),
                "network": cfg.get('net', 'tcp'),
                "tls": cfg.get('tls', ''),
                "serverName": cfg.get('host') or cfg.get('sni', '')
            }
        except json.JSONDecodeError:
            decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
            ip_match = re.search(r'"add":"([\d\.a-zA-Z-]+)"', decoded)
            port_match = re.search(r'"port":"?(\d+)"?', decoded)
            host_match = re.search(r'"host":"([^"]+)"|\"sni\":\"([^"]+)"', decoded)
            if ip_match and port_match:
                return {
                    "address": ip_match.group(1),
                    "port": int(port_match.group(1)),
                    "id": "", "alterId": 0, "security": "auto",
                    "network": "tcp", "tls": "",
                    "serverName": host_match.group(1) if host_match else ""
                }
            else:
                raise Exception("核心字段（IP/端口）提取失败")
    except Exception as e:
        print(f"⚠️ VMess解析部分失败（{vmess_line[:20]}...）: {str(e)[:50]}")
        return None

def extract_vless_config(vless_line):
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
                params[k.lower()] = v
        return {
            "uuid": uuid,
            "address": address,
            "port": port if port in CONFIG["filter"]["valid_ports"] else 443,
            "security": params.get('security', 'tls'),
            "sni": params.get('sni') or params.get('SNI'),
            "network": params.get('type', 'tcp') or params.get('Type')
        }
    except Exception as e:
        print(f"⚠️ VLESS解析部分失败（{vless_line[:20]}...）: {str(e)[:50]}")
        ip_port_match = re.search(r'@([\d\.a-zA-Z-]+):(\d+)', vless_line)
        if ip_port_match:
            return {
                "uuid": "",
                "address": ip_port_match.group(1),
                "port": int(ip_port_match.group(2)),
                "security": "tls",
                "sni": "",
                "network": "tcp"
            }
        return None

def extract_trojan_config(trojan_line):
    """优化版：容错处理标签异常，仅核心字段无效时剔除"""
    try:
        # 第一步：剥离#后的标签部分，避免标签干扰核心解析
        if '#' in trojan_line:
            trojan_part = trojan_line.split('#')[0]  # 只保留#前的核心链接
            label = trojan_line.split('#')[1] if len(trojan_line.split('#'))>1 else ""
            # 容错：空标签/过长标签处理
            if not label:
                print(f"⚠️ Trojan节点标签为空，已忽略（{trojan_line[:20]}...）")
            elif len(label) > 64:  # 截断过长标签（64字符为常见限制）
                label = label[:64]
                print(f"⚠️ Trojan节点标签过长，已截断为64字符（{trojan_line[:20]}...）")
        else:
            trojan_part = trojan_line
            label = ""
        
        # 继续解析核心字段（密码/地址/端口）
        trojan_part = trojan_part[8:].strip()
        trojan_part = trojan_part.encode('ascii', 'ignore').decode('ascii')
        password_addr = trojan_part.split('?')[0]
        
        # 兼容密码/地址分割异常
        if '@' not in password_addr:
            # 正则提取核心字段
            ip_port_match = re.search(r'@([\d\.a-zA-Z-]+):(\d+)', trojan_part)
            if not ip_port_match:
                raise Exception("核心字段（IP/端口）提取失败")
            password = ""
            address = ip_port_match.group(1)
            port = int(ip_port_match.group(2))
        else:
            password, addr_port = password_addr.split('@')
            try:
                address, port = addr_port.split(':')
                port = int(port)
            except:
                address = addr_port
                port = 443
        
        # 解析参数（兼容大小写）
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
            "label": label  # 即使标签为空/过长，仍保留（不影响节点有效性）
        }
    except Exception as e:
        # 区分异常类型：仅核心字段失败才提示，标签异常忽略
        if "label" in str(e).lower() or "empty" in str(e).lower() or "too long" in str(e).lower():
            print(f"⚠️ Trojan节点标签异常（非核心，保留节点）：{str(e)[:50]}（{trojan_line[:20]}...）")
            # 尝试最后一次提取核心字段
            ip_port_match = re.search(r'@([\d\.a-zA-Z-]+):(\d+)', trojan_line)
            if ip_port_match:
                return {
                    "address": ip_port_match.group(1),
                    "port": int(ip_port_match.group(2)),
                    "password": "",
                    "sni": "",
                    "security": "tls",
                    "label": ""
                }
        else:
            print(f"❌ Trojan核心字段解析失败（{trojan_line[:20]}...）: {str(e)[:50]}")
        return None

def test_tcp_connect(ip, port):
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

def fetch_source(url):
    headers = {"User-Agent": CONFIG["request"]["user_agent"]}
    for retry in range(CONFIG["request"]["retry_times"]):
        try:
            resp = requests.get(url, timeout=CONFIG["request"]["timeout"], headers=headers)
            resp.raise_for_status()
            decoded_content = decode_base64_sub(resp.text)
            lines = [l.strip() for l in decoded_content.split('\n') if l.strip() and not l.startswith('#')]
            print(f"✅ 拉取成功 {url}，有效节点 {len(lines)} 条（重试：{retry}）")
            return lines
        except Exception as e:
            error_msg = str(e)[:80]
            if retry < CONFIG["request"]["retry_times"] - 1:
                print(f"⚠️ 拉取失败 {url}（重试 {retry+1}）: {error_msg}")
                time.sleep(CONFIG["request"]["retry_delay"])
            else:
                print(f"❌ 拉取最终失败 {url}: {error_msg}")
                return []

def process_node(line):
    try:
        if not line:
            return None, "", "", 443
        ip, domain, port = None, "", 443
        if line.startswith('vmess://'):
            cfg = extract_vmess_config(line)
            if cfg:
                ip = cfg["address"]
                domain = cfg["serverName"]
                port = cfg["port"]
        elif line.startswith('vless://'):
            cfg = extract_vless_config(line)
            if cfg:
                ip = cfg["address"]
                domain = cfg["sni"]
                port = cfg["port"]
        elif line.startswith('trojan://'):
            cfg = extract_trojan_config(line)
            if cfg:
                ip = cfg["address"]
                domain = cfg["sni"]
                port = cfg["port"]
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
        if is_private_ip(ip):
            print(f"❌ 过滤私有IP节点：{ip}:{port}")
            return None, "", "", 443
        if ip and not test_tcp_connect(ip, port):
            print(f"❌ 过滤TCP连接失败节点：{ip}:{port}（超时{CONFIG['detection']['tcp_timeout']}秒，重试{CONFIG['detection']['tcp_retry']}次）")
            return None, "", "", 443
        if domain and not test_domain_resolve(domain):
            print(f"⚠️ 域名{domain}解析失败，但IP{ip}连接正常，保留节点")
        return line, domain, ip, port
    except Exception as e:
        print(f"❌ 节点处理异常（{line[:20]}...）: {str(e)[:50]}")
        return None, "", "", 443

# ====================== 主流程 ======================
def main():
    start_time = time.time()
    source_records = {}
    all_lines_set = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(fetch_source, url): url for url in CONFIG["sources"]}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            lines = future.result()
            source_records[url] = {
                "original": lines,
                "original_count": len(lines)
            }
            all_lines_set.update(lines)
    unique_lines = list(all_lines_set)
    print(f"\n📊 全局去重后总节点：{len(unique_lines)} 条")

    reality_lines = [l for l in unique_lines if 'reality' in l.lower()]
    tls_lines = [l for l in unique_lines if 'tls' in l.lower() and l not in reality_lines]
    normal_lines = [l for l in unique_lines if l not in reality_lines + tls_lines]
    processing_order = reality_lines + tls_lines + normal_lines
    print(f"📌 优先级拆分 - Reality节点：{len(reality_lines)} 条 | TLS节点：{len(tls_lines)} 条 | 普通节点：{len(normal_lines)} 条")

    valid_lines = []
    seen_ips = set()
    seen_domains = set()
    total_nodes = len(processing_order)
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool_size"]) as executor:
        futures = [executor.submit(process_node, line) for line in processing_order]
        for idx, future in enumerate(as_completed(futures)):
            if idx % 100 == 0:
                progress = (idx / total_nodes) * 100
                print(f"\n🔄 处理进度：{idx}/{total_nodes} ({progress:.1f}%)")
            try:
                result = future.result()
            except Exception as e:
                print(f"⚠️ 节点处理异常: {str(e)[:50]}")
                continue
            if not result:
                continue
            line, domain, ip, port = result
            if not line:
                continue
            if domain and domain in seen_domains:
                continue
            if ip and ip in seen_ips:
                continue
            seen_domains.add(domain)
            seen_ips.add(ip)
            valid_lines.append(line)
            print(f"✅ 保留节点: {'IP' if ip else '域名'} - {ip or domain}:{port}")

    combined = '\n'.join(valid_lines)
    encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
    with open('s1.txt', 'w', encoding='utf-8') as f:
        f.write(encoded)

    source_stats = {}
    for url, record in source_records.items():
        original_count = record["original_count"]
        retained_count = len([line for line in record["original"] if line in valid_lines])
        retention_rate = (retained_count / original_count * 100) if original_count > 0 else 0.0
        source_stats[url] = {
            "original": original_count,
            "retained": retained_count,
            "retention_rate": round(retention_rate, 2)
        }

    total_cost = time.time() - start_time
    print(f"\n🎉 最终处理完成：")
    print(f"   - 原始总节点：{len(unique_lines)} 条")
    print(f"   - 过滤后可用节点：{len(valid_lines)} 条")
    print(f"   - 独特IP：{len(seen_ips)} 个")
    print(f"   - 独特域名：{len(seen_domains)} 个")
    print(f"   - TCP检测规则：超时{CONFIG['detection']['tcp_timeout']}秒，重试{CONFIG['detection']['tcp_retry']}次")
    print(f"   - 总耗时：{total_cost:.2f} 秒（{total_cost/60:.2f} 分钟）")
    print(f"   - 节点已保存至：s1.txt（Base64编码格式）")

    print("\n📈 各数据源详细统计：")
    for idx, (url, stats) in enumerate(source_stats.items(), 1):
        print(f"   {idx}. {url}")
        print(f"      - 原始获取：{stats['original']} 条 | 最终保留：{stats['retained']} 条 | 保留率：{stats['retention_rate']}%")

if __name__ == "__main__":
    main()
