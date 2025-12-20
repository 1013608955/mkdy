import requests
import re
import socket
import base64
import json
import binascii
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# ====================== 配置项抽离（便于维护） ======================
CONFIG = {
    "sources": [
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
        "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
        "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    ],
    "request": {
        "timeout": 60,
        "retry_times": 3,
        "retry_delay": 2,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    "detection": {
        "tcp_timeout": 1,
        "thread_pool_size": 20,
        "test_url": "http://www.google.com/generate_204"
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

# ====================== 工具函数优化 ======================
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
            print(f"❌ Base64解码失败，使用原文本: {str(e)[:50]}")
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

def extract_ip_domain_port(line):
    if not line:
        return None, None, 443
    
    ip = domain = None
    port = 443

    # 提取端口并验证有效性
    port_match = re.search(r':(\d+)', line)
    if port_match:
        port = int(port_match.group(1))
        if port not in CONFIG["filter"]["valid_ports"]:
            port = 443

    # 解析VMess节点（核心修复：清理非ASCII字符）
    if line.startswith('vmess://'):
        try:
            vmess_part = line[8:].strip()
            if not vmess_part:
                return None, None, 443
            
            # 关键修复：过滤非ASCII字符（base64解码仅支持ASCII）
            vmess_part = vmess_part.encode('ascii', 'ignore').decode('ascii')
            
            # 补位并解码
            padding = 4 - len(vmess_part) % 4
            if padding != 4:
                vmess_part += '=' * padding
            decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
            cfg = json.loads(decoded)
            ip = cfg.get('add')
            domain = cfg.get('host') or cfg.get('sni')
            port = cfg.get('port', 443)
            
            if is_private_ip(ip):
                ip = None
        except (json.JSONDecodeError, binascii.Error, ValueError, TypeError):
            # 捕获所有解码相关异常，避免中断
            return None, None, 443

    # 提取非VMess节点的IP
    if not ip:
        ip_match = re.search(r'@([\d\.]+):', line)
        if ip_match:
            ip = ip_match.group(1)
            if is_private_ip(ip):
                ip = None

    # 提取非VMess节点的域名
    if not domain:
        domain_match = re.search(r'sni=([^&]+)|host=([^&]+)|peer=([^&]+)', line, re.IGNORECASE)
        if domain_match:
            domain = next((g for g in domain_match.groups() if g), None)

    if port not in CONFIG["filter"]["valid_ports"]:
        port = 443

    return ip, domain or "", port

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
            lines = []
            for line in decoded_content.split('\n'):
                l = line.strip()
                if l and not l.startswith('#'):
                    lines.append(l)
            print(f"✅ 拉取成功 {url}，有效节点 {len(lines)} 条（重试次数：{retry}）")
            return lines
        except Exception as e:
            error_msg = str(e)[:80]
            if retry < CONFIG["request"]["retry_times"] - 1:
                print(f"⚠️ 拉取失败 {url}（重试 {retry+1}/{CONFIG['request']['retry_times']}）: {error_msg}")
                time.sleep(CONFIG["request"]["retry_delay"])
            else:
                print(f"❌ 拉取最终失败 {url}: {error_msg}")
                return []

def process_node(line):
    if not line:
        return None, "", "", 443
    
    ip, domain, port = extract_ip_domain_port(line)
    domain_key = domain if domain else ""
    ip_key = ip if ip else ""
    
    if is_private_ip(ip):
        return None, domain_key, ip_key, port
    
    if ip and not test_tcp_connect(ip, port):
        return None, domain_key, ip_key, port
    
    return line, domain_key, ip_key, port

# ====================== 主流程 ======================
def main():
    all_lines = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(fetch_source, url): url for url in CONFIG["sources"]}
        for future in as_completed(future_to_url):
            lines = future.result()
            all_lines.update(lines)
    
    unique_lines = list(all_lines)
    print(f"\n📊 全局去重后总节点：{len(unique_lines)} 条")

    priority_lines = []
    normal_lines = []
    for line in unique_lines:
        lower_line = line.lower()
        if 'reality' in lower_line or 'tls' in lower_line:
            priority_lines.append(line)
        else:
            normal_lines.append(line)
    
    processing_order = priority_lines + normal_lines
    print(f"📌 优先（Reality/TLS）节点：{len(priority_lines)} 条，普通节点：{len(normal_lines)} 条")

    valid_lines = []
    seen_ips = set()
    seen_domains = set()
    
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool_size"]) as executor:
        futures = [executor.submit(process_node, line) for line in processing_order]
        for idx, future in enumerate(as_completed(futures)):
            if idx % 500 == 0:
                print(f"\n🔄 处理进度：{idx}/{len(processing_order)}")
            
            try:
                result = future.result()
            except Exception as e:
                print(f"⚠️ 节点处理异常: {str(e)[:50]}")
                continue
            
            if not result:
                continue
            line, domain_key, ip_key, port = result
            
            if not line:
                continue

            if domain_key and domain_key in seen_domains:
                continue
            if domain_key:
                seen_domains.add(domain_key)

            if ip_key and ip_key in seen_ips:
                continue
            if ip_key:
                seen_ips.add(ip_key)

            valid_lines.append(line)
            if ip_key:
                print(f"✅ 保留IP节点: {ip_key}:{port}")
            else:
                print(f"✅ 保留域名节点: {domain_key or '未知'}")

    combined = '\n'.join(valid_lines)
    encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')

    with open('s1.txt', 'w', encoding='utf-8') as f:
        f.write(encoded)

    print(f"\n🎉 最终处理完成：")
    print(f"   - 有效节点总数：{len(valid_lines)} 条")
    print(f"   - 独特IP数量：{len(seen_ips)} 个")
    print(f"   - 独特域名数量：{len(seen_domains)} 个")
    print(f"   - 订阅文件大小：{len(encoded)} 个Base64字符")

if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f"\n⏱️  总运行时间：{time.time() - start_time:.2f} 秒")
