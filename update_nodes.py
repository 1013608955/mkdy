import requests
import re
import socket
import base64
import json
import binascii
import subprocess
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====================== 配置项（保留原版，仅注释测试URL） ======================
CONFIG = {
    "sources": [
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
        "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
        "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    ],
    "request": {
        "timeout": 60,
        "retry_times": 3,
        "retry_delay": 2,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    "detection": {
        "tcp_timeout": 0.5,  # 原版超时
        "proxy_test_timeout": 3,  # 保留但不再使用
        "thread_pool_size": 20,   
        "test_url": "http://www.google.com/generate_204"  # 保留但不再使用
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

# ====================== 工具函数（核心修改：关闭代理测试） ======================
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
    """检测域名是否能解析"""
    if not domain or domain == "未知":
        return False
    try:
        socket.gethostbyname_ex(domain)
        return True
    except socket.gaierror:
        return False

def extract_vmess_config(vmess_line):
    """解析VMess节点为V2Ray配置格式"""
    try:
        vmess_part = vmess_line[8:].strip()
        vmess_part = vmess_part.encode('ascii', 'ignore').decode('ascii')
        padding = 4 - len(vmess_part) % 4
        if padding != 4:
            vmess_part += '=' * padding
        decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
        cfg = json.loads(decoded)
        return {
            "address": cfg.get('add'),
            "port": cfg.get('port', 443),
            "id": cfg.get('id'),
            "alterId": cfg.get('aid', 0),
            "security": cfg.get('security', 'auto'),
            "network": cfg.get('net', 'tcp'),
            "tls": cfg.get('tls', ''),
            "serverName": cfg.get('host') or cfg.get('sni')
        }
    except Exception as e:
        return None

def test_proxy_valid(node_line):
    """【核心修改】关闭所有代理测试，所有节点直接返回有效"""
    return True

def test_tcp_connect(ip, port):
    if not ip or port not in CONFIG["filter"]["valid_ports"]:
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONFIG["detection"]["tcp_timeout"])
            return sock.connect_ex((ip, port)) == 0
    except (socket.gaierror, socket.timeout, OSError):
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
    """处理单个节点（保留原版逻辑）"""
    try:
        if not line:
            return None, "", "", 443
        
        # 提取节点信息
        ip, domain, port = None, "", 443
        if line.startswith('vmess://'):
            vmess_cfg = extract_vmess_config(line)
            if vmess_cfg:
                ip = vmess_cfg["address"]
                domain = vmess_cfg["serverName"]
                port = vmess_cfg["port"]
        else:
            # 非VMess节点提取IP/域名（简化）
            ip_match = re.search(r'@([\d\.]+):', line)
            if ip_match:
                ip = ip_match.group(1)
            domain_match = re.search(r'sni=([^&]+)|host=([^&]+)', line, re.IGNORECASE)
            if domain_match:
                domain = next((g for g in domain_match.groups() if g), "")
            port_match = re.search(r':(\d+)', line)
            if port_match:
                port = int(port_match.group(1)) if port_match.group(1) in CONFIG["filter"]["valid_ports"] else 443

        # 过滤私有IP
        if is_private_ip(ip):
            return None, "", "", 443
        
        # 域名解析检测
        if domain and not test_domain_resolve(domain):
            return None, "", "", 443
        
        # TCP端口检测
        if ip and not test_tcp_connect(ip, port):
            return None, "", "", 443
        
        # 代理测试已关闭，直接返回有效
        return line, domain, ip, port
    except Exception as e:
        print(f"❌ 节点处理异常（{line[:20]}...）: {str(e)[:50]}")
        return None, "", "", 443

# ====================== 主流程（保留原版逻辑） ======================
def main():
    start_time = time.time()
    # 拉取数据源
    all_lines = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(fetch_source, url): url for url in CONFIG["sources"]}
        for future in as_completed(future_to_url):
            lines = future.result()
            all_lines.update(lines)
    
    unique_lines = list(all_lines)
    print(f"\n📊 全局去重后总节点：{len(unique_lines)} 条")

    # 优先级筛选（Reality > TLS > 普通）
    reality_lines = [l for l in unique_lines if 'reality' in l.lower()]
    tls_lines = [l for l in unique_lines if 'tls' in l.lower() and l not in reality_lines]
    normal_lines = [l for l in unique_lines if l not in reality_lines + tls_lines]
    processing_order = reality_lines + tls_lines + normal_lines
    print(f"📌 优先级拆分 - Reality节点：{len(reality_lines)} 条 | TLS节点：{len(tls_lines)} 条 | 普通节点：{len(normal_lines)} 条")

    # 多线程处理节点（保留原版IP/域名去重）
    valid_lines = []
    seen_ips = set()
    seen_domains = set()
    
    total_nodes = len(processing_order)
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool_size"]) as executor:
        futures = [executor.submit(process_node, line) for line in processing_order]
        for idx, future in enumerate(as_completed(futures)):
            # 进度可视化（百分比）
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

            # 原版IP/域名去重逻辑
            if domain and domain in seen_domains:
                continue
            if ip and ip in seen_ips:
                continue
            
            seen_domains.add(domain)
            seen_ips.add(ip)
            valid_lines.append(line)
            print(f"✅ 保留有效节点: {'IP' if ip else '域名'} - {ip or domain}:{port}")

    # 生成订阅文件
    combined = '\n'.join(valid_lines)
    encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
    with open('s1.txt', 'w', encoding='utf-8') as f:
        f.write(encoded)

    # 详细统计输出
    total_cost = time.time() - start_time
    print(f"\n🎉 最终处理完成：")
    print(f"   - 原始总节点：{len(unique_lines)} 条")
    print(f"   - 有效节点：{len(valid_lines)} 条")
    print(f"   - 有效率：{len(valid_lines)/len(unique_lines)*100:.2f}%" if unique_lines else "   - 有效率：0.00%")
    print(f"   - 独特IP：{len(seen_ips)} 个")
    print(f"   - 独特域名：{len(seen_domains)} 个")
    print(f"   - 订阅文件大小：{len(encoded)} 字符")
    print(f"   - 总耗时：{total_cost:.2f} 秒（{total_cost/60:.2f} 分钟）")

if __name__ == "__main__":
    main()
