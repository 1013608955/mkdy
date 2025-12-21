import requests
import re
import socket
import base64
import json
import binascii
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====================== 配置项（调整为字节数限制） ======================
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
        "valid_ports": range(1, 65535),
        "max_remark_bytes": 120  # 关键修改：按字节数限制（留8字节余量，避免超128）
    }
}

# ====================== 工具函数（核心修改：按字节数截断） ======================
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
        print(f"⚠️ 清理VMess JSON乱码失败：{str(e)[:50]}")
        return decoded_str

def truncate_remark(remark):
    """核心修改：按UTF-8字节数截断备注，避免label too long"""
    if not remark:
        return ""
    
    # 计算备注的UTF-8字节数
    remark_bytes = remark.encode('utf-8')
    max_bytes = CONFIG["filter"]["max_remark_bytes"]
    
    if len(remark_bytes) <= max_bytes:
        return remark
    
    # 按字节数截断，避免截断到中文/emoji的中间（导致乱码）
    truncated_bytes = remark_bytes[:max_bytes]
    # 尝试解码，若解码失败（截断到字符中间），再往前退1-2字节
    try:
        truncated_remark = truncated_bytes.decode('utf-8')
    except UnicodeDecodeError:
        truncated_bytes = remark_bytes[:max_bytes-2]  # 退2字节，兼容中文/emoji
        truncated_remark = truncated_bytes.decode('utf-8', errors='ignore')
    
    # 加省略号（确保总字节数仍不超）
    if len(truncated_remark.encode('utf-8')) + 3 <= max_bytes:
        truncated_remark += "..."
    print(f"⚠️ 备注字节数超限（原{len(remark_bytes)}字节），已截断为{len(truncated_remark.encode('utf-8'))}字节：{truncated_remark[:20]}...")
    return truncated_remark

# ====================== 节点提取函数（逻辑不变，复用新的truncate_remark） ======================
def extract_vmess_config(vmess_line):
    """VMess解析：乱码清理 + 按字节数截断备注"""
    try:
        vmess_part = vmess_line[8:].strip()
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
        
        # 用新的truncate_remark截断ps字段
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
        print(f"⚠️ VMess JSON解析失败（{vmess_line[:20]}...）: {str(e)[:50]}")
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
    except Exception as e:
        print(f"⚠️ VMess解析失败（{vmess_line[:20]}...）: {str(e)[:50]}")
        return None

def extract_vless_config(vless_line):
    """VLESS解析：按字节数截断remarks"""
    try:
        vless_part = vless_line[8:].strip()
        vless_part = vless_part.encode('ascii', 'ignore').decode('ascii')
        base_part, param_part = (vless_part.split('?') + [''])[:2]
        uuid_addr_port = base_part.split('@')
        
        # 解析核心字段
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
        
        # 解析参数 + 截断remarks
        params = {}
        for param in param_part.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                if k.lower() == "remarks":
                    v = truncate_remark(v)  # 用新的截断函数
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
        print(f"⚠️ VLESS解析失败（{vless_line[:20]}...）: {str(e)[:50]}")
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
    """Trojan解析：按字节数截断label"""
    try:
        # 剥离标签 + 截断
        if '#' in trojan_line:
            trojan_part = trojan_line.split('#')[0]
            label = trojan_line.split('#')[1] if len(trojan_line.split('#'))>1 else ""
            label = truncate_remark(label)  # 用新的截断函数
            if not label:
                print(f"⚠️ Trojan节点标签为空，已忽略（{trojan_line[:20]}...）")
        else:
            trojan_part = trojan_line
            label = ""
        
        trojan_part = trojan_part[8:].strip()
        trojan_part = trojan_part.encode('ascii', 'ignore').decode('ascii')
        password_addr = trojan_part.split('?')[0]
        
        # 解析核心字段
        if '@' not in password_addr:
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
            "port": port if port in CONFIG["filter"]["valid_ports"] else 443,
            "password": password,
            "sni": params.get('sni') or params.get('SNI'),
            "security": params.get('security', 'tls'),
            "label": label
        }
    except Exception as e:
        if "label" in str(e).lower() or "empty" in str(e).lower() or "too long" in str(e).lower():
            print(f"⚠️ Trojan节点标签异常（非核心，保留节点）：{str(e)[:50]}（{trojan_line[:20]}...）")
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

def extract_ss_config(ss_line):
    """SS解析：按字节数截断备注"""
    try:
        ss_part = ss_line[5:].strip()
        
        # 处理Base64编码
        if is_base64(ss_part):
            padding = 4 - len(ss_part) % 4
            if padding != 4:
                ss_part += '=' * padding
            try:
                decoded = base64.b64decode(ss_part).decode('utf-8', errors='ignore')
                ss_part = decoded
            except Exception as e:
                print(f"⚠️ SS Base64解码失败（{ss_line[:20]}...）: {str(e)[:50]}")
        
        # 剥离备注 + 截断
        remark = ""
        if '#' in ss_part:
            ss_part, remark = ss_part.split('#', 1)
            remark = truncate_remark(remark)  # 用新的截断函数
        
        # 解析核心字段
        if '@' in ss_part:
            auth_part, addr_port_part = ss_part.split('@', 1)
            if ':' in addr_port_part:
                address, port_str = addr_port_part.rsplit(':', 1)
                port = int(port_str) if port_str.isdigit() else 443
            else:
                address = addr_port_part
                port = 443
            
            if not address or address.strip() == "":
                raise Exception("SS节点地址为空")
            
            return {
                "address": address.strip(),
                "port": port if port in CONFIG["filter"]["valid_ports"] else 443,
                "remark": remark
            }
        else:
            raise Exception("SS节点格式错误（无@分隔符）")
    except Exception as e:
        print(f"⚠️ SS解析失败（{ss_line[:20]}...）: {str(e)[:50]}")
        return None

# ====================== 其他工具函数 + 主流程（逻辑不变） ======================
def test_tcp_connect(ip, port):
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
        ip, domain, port, remark = None, "", 443, ""
        
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
                remark = truncate_remark(remark)
        
        # 过滤逻辑
        if is_private_ip(ip):
            print(f"❌ 过滤私有IP节点：{ip}:{port}（备注：{remark[:20]}...）")
            return None, "", "", 443
        
        if ip and not test_tcp_connect(ip, port):
            print(f"❌ 过滤TCP连接失败节点：{ip}:{port}（备注：{remark[:20]}...）")
            return None, "", "", 443
        
        if domain and not test_domain_resolve(domain):
            print(f"⚠️ 域名{domain}解析失败，但IP{ip}连接正常（备注：{remark[:20]}...）")
        
        if not ip and not domain:
            print(f"❌ 过滤空地址节点：{line[:20]}...（备注：{remark[:20]}...）")
            return None, "", "", 443
        
        return line, domain, ip, port
    except Exception as e:
        print(f"❌ 节点处理异常（{line[:20]}...）: {str(e)[:50]}")
        return None, "", "", 443

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

    # 优先级排序
    reality_lines = [l for l in unique_lines if 'reality' in l.lower()]
    tls_lines = [l for l in unique_lines if 'tls' in l.lower() and l not in reality_lines]
    ss_lines = [l for l in unique_lines if l.startswith('ss://') and l not in reality_lines + tls_lines]
    normal_lines = [l for l in unique_lines if l not in reality_lines + tls_lines + ss_lines]
    processing_order = reality_lines + tls_lines + ss_lines + normal_lines
    print(f"📌 优先级拆分 - Reality节点：{len(reality_lines)} 条 | TLS节点：{len(tls_lines)} 条 | SS节点：{len(ss_lines)} 条 | 普通节点：{len(normal_lines)} 条")

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
            # 输出截断后的备注
            if '#' in line:
                remark = line.split('#')[1][:20] + "..."
            else:
                remark = "无备注"
            print(f"✅ 保留节点: {'IP' if ip else '域名'} - {ip or domain}:{port}（备注：{remark}）")

    # 保存节点
    combined = '\n'.join(valid_lines)
    encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
    with open('s1.txt', 'w', encoding='utf-8') as f:
        f.write(encoded)

    # 统计
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
    print(f"   - 备注最大字节数：{CONFIG['filter']['max_remark_bytes']}（UTF-8）")
    print(f"   - 总耗时：{total_cost:.2f} 秒（{total_cost/60:.2f} 分钟）")
    print(f"   - 节点已保存至：s1.txt（Base64编码格式）")

    print("\n📈 各数据源详细统计：")
    for idx, (url, stats) in enumerate(source_stats.items(), 1):
        print(f"   {idx}. {url}")
        print(f"      - 原始获取：{stats['original']} 条 | 最终保留：{stats['retained']} 条 | 保留率：{stats['retention_rate']}%")

if __name__ == "__main__":
    main()
