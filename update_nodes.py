import requests
import re
import socket
import base64
import json
import binascii

# 数据源（支持返回明文/Base64编码的订阅链接）
sources = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
]

def is_base64(s):
    """判断字符串是否为合法的Base64编码"""
    if not s:
        return False
    try:
        # 处理Base64补位（确保长度是4的倍数）
        padding = 4 - len(s) % 4
        if padding != 4:
            s += '=' * padding
        base64.b64decode(s, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False

def decode_base64_sub(text):
    """解码Base64订阅文本，失败则返回原文本"""
    # 先去除空白字符（换行、空格、制表符）
    clean_text = re.sub(r'\s+', '', text.strip())
    if not clean_text:
        return text
    
    # 检测是否为Base64编码，是则解码
    if is_base64(clean_text):
        try:
            padding = 4 - len(clean_text) % 4
            if padding != 4:
                clean_text += '=' * padding
            # 解码为UTF-8，忽略无法解码的字符
            decoded = base64.b64decode(clean_text).decode('utf-8', errors='ignore')
            print(f"成功解码Base64订阅文本，解析出明文内容")
            return decoded
        except Exception as e:
            print(f"Base64解码失败，使用原文本: {e}")
            return text
    else:
        return text

def extract_ip_domain_port(line):
    """提取节点的IP、域名、端口（保留原逻辑）"""
    ip = domain = None
    port = 443

    # 提取端口（通用正则）
    port_match = re.search(r':(\d+)', line)
    if port_match:
        port = int(port_match.group(1))

    # 解析VMess节点
    if line.startswith('vmess://'):
        try:
            vmess_part = line[8:].strip()
            padding = 4 - len(vmess_part) % 4
            if padding != 4:
                vmess_part += '=' * padding
            decoded = base64.b64decode(vmess_part).decode('utf-8', errors='ignore')
            cfg = json.loads(decoded)
            ip = cfg.get('add')
            domain = cfg.get('host') or cfg.get('sni')
            port = cfg.get('port', 443)
        except:
            pass

    # 提取非VMess节点的IP
    if not ip:
        ip_match = re.search(r'@([\d\.]+):', line)
        if ip_match:
            ip = ip_match.group(1)

    # 提取非VMess节点的域名
    if not domain:
        domain_match = re.search(r'sni=([^&]+)|host=([^&]+)|peer=([^&]+)', line, re.IGNORECASE)
        if domain_match:
            domain = next((g for g in domain_match.groups() if g), None)

    return ip, domain or "", port

# 第一步：拉取所有数据源并解码（兼容Base64/明文）
all_lines = set()
for url in sources:
    try:
        # 增加超时和重试（适配GitHub网络环境）
        resp = requests.get(
            url, 
            timeout=60,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        )
        resp.raise_for_status()
        
        # 核心修改：先解码Base64（若需要）
        raw_content = resp.text
        decoded_content = decode_base64_sub(raw_content)
        
        # 拆分行并过滤无效行
        count = 0
        for line in decoded_content.split('\n'):
            l = line.strip()
            if l and not l.startswith('#'):
                all_lines.add(l)
                count += 1
        print(f"拉取成功 {url}，新增有效节点 {count} 条")
    except Exception as e:
        print(f"拉取失败 {url}: {str(e)[:100]}")  # 截断过长错误信息

unique_lines = list(all_lines)
print(f"全局去重后总节点：{len(unique_lines)} 条")

# 第二步：优先级筛选（Reality/TLS节点优先）
priority_lines = []
normal_lines = []
for line in unique_lines:
    lower_line = line.lower()
    if 'reality' in lower_line or 'tls' in lower_line:
        priority_lines.append(line)
    else:
        normal_lines.append(line)

processing_order = priority_lines + normal_lines
print(f"优先（Reality/TLS）节点：{len(priority_lines)} 条，普通节点：{len(normal_lines)} 条")

# 第三步：IP/域名去重 + 可用性检测
valid_lines = []
seen_ips = set()
seen_domains = set()

for idx, line in enumerate(processing_order):
    if idx % 500 == 0:
        print(f"处理进度：{idx}/{len(processing_order)}")

    ip, domain, port = extract_ip_domain_port(line)

    # 域名去重（优先）
    if domain and domain in seen_domains:
        continue
    if domain:
        seen_domains.add(domain)

    # IP去重
    if ip and ip in seen_ips:
        continue
    if ip:
        seen_ips.add(ip)

    # IP节点可用性检测（仅TCP端口连通性）
    if ip:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result != 0:
                continue
            print(f"IP可用保留: {ip}:{port}")
        except Exception as e:
            continue
    else:
        print(f"域名节点保留: {domain or '未知'}")

    valid_lines.append(line)

# 第四步：生成最终Base64订阅文件
combined = '\n'.join(valid_lines)
# 编码为Base64（标准订阅格式）
encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')

# 保存到文件（GitHub Actions中可直接读取该文件）
with open('s1.txt', 'w', encoding='utf-8') as f:
    f.write(encoded)

print(f"最终有效节点：{len(valid_lines)} 条（独特IP {len(seen_ips)} + 独特域名 {len(seen_domains)}）")
print(f"订阅文件已保存到 s1.txt，共 {len(encoded)} 个Base64字符")
