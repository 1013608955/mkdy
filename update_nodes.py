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

# ====================== 配置项（优化后） ======================
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
        "tcp_timeout": 0.5,  # 缩短TCP检测超时
        "proxy_test_timeout": 3,  # 缩短代理测试超时
        "thread_pool_size": 20,   # 提升线程数
        "test_url": "http://www.google.com/generate_204",
        "max_delay": 200  # 最大延迟阈值（ms），超过则过滤
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

# ====================== 工具函数（优化后） ======================
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
        print(f"❌ VMess解析失败: {str(e)[:50]}")
        return None

def extract_vless_config(vless_line):
    """解析VLESS节点配置（核心字段：uuid、address、port、security、sni）"""
    try:
        # 1. 拆分基础部分和参数部分
        vless_part = vless_line[8:].strip()
        vless_part = vless_part.encode('ascii', 'ignore').decode('ascii')
        base_part, param_part = (vless_part.split('?') + [''])[:2]
        
        # 2. 解析uuid@address:port
        uuid_addr_port = base_part.split('@')
        if len(uuid_addr_port) != 2:
            return None
        uuid = uuid_addr_port[0].strip()
        addr_port = uuid_addr_port[1].strip()
        address, port = addr_port.split(':')
        port = int(port)
        
        # 3. 解析参数（security、sni、network等）
        params = {}
        for param in param_part.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                params[k.lower()] = v
        
        return {
            "uuid": uuid,
            "address": address,
            "port": port,
            "security": params.get('security', 'tls'),
            "sni": params.get('sni'),
            "network": params.get('type', 'tcp')
        }
    except Exception as e:
        print(f"❌ VLESS解析失败（{vless_line[:30]}...）: {str(e)[:50]}")
        return None

def extract_trojan_config(trojan_line):
    """解析Trojan节点配置"""
    try:
        trojan_part = trojan_line[8:].strip()
        trojan_part = trojan_part.encode('ascii', 'ignore').decode('ascii')
        password_addr = trojan_part.split('?')[0]
        password, addr_port = password_addr.split('@')
        address, port = addr_port.split(':')
        port = int(port)
        
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
            "port": port,
            "password": password,
            "sni": params.get('sni'),
            "security": params.get('security', 'tls')
        }
    except Exception as e:
        print(f"❌ Trojan解析失败: {str(e)[:50]}")
        return None

def get_node_core_id(line):
    """提取节点核心标识（用于去重：协议+地址+端口+核心密钥）"""
    if line.startswith('vless://'):
        cfg = extract_vless_config(line)
        if cfg:
            return f"vless_{cfg['address']}_{cfg['port']}_{cfg['uuid']}"
    elif line.startswith('vmess://'):
        cfg = extract_vmess_config(line)
        if cfg:
            return f"vmess_{cfg['address']}_{cfg['port']}_{cfg['id']}"
    elif line.startswith('trojan://'):
        cfg = extract_trojan_config(line)
        if cfg:
            return f"trojan_{cfg['address']}_{cfg['port']}_{cfg['password']}"
    return f"unknown_{hash(line)}"

def test_proxy_valid(node_line):
    """支持VMess/VLESS/Trojan的代理测试，返回(是否有效, 延迟ms)"""
    temp_config = None
    # 处理VLESS节点
    if node_line.startswith('vless://'):
        vless_cfg = extract_vless_config(node_line)
        if not vless_cfg or not vless_cfg["uuid"] or not vless_cfg["address"]:
            return (False, 9999)
        temp_config = {
            "inbounds": [
                {
                    "port": 1080,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True}
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": vless_cfg["address"],
                                "port": vless_cfg["port"],
                                "users": [{"id": vless_cfg["uuid"], "encryption": "none", "level": 0}]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": vless_cfg["network"],
                        "security": vless_cfg["security"],
                        "tlsSettings": {"serverName": vless_cfg["sni"]} if vless_cfg["sni"] else {}
                    }
                }
            ]
        }
    # 处理VMess节点
    elif node_line.startswith('vmess://'):
        vmess_cfg = extract_vmess_config(node_line)
        if not vmess_cfg or not vmess_cfg["address"] or not vmess_cfg["id"]:
            return (False, 9999)
        temp_config = {
            "inbounds": [
                {
                    "port": 1080,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True}
                }
            ],
            "outbounds": [
                {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": vmess_cfg["address"],
                                "port": vmess_cfg["port"],
                                "users": [
                                    {
                                        "id": vmess_cfg["id"],
                                        "alterId": vmess_cfg["alterId"],
                                        "security": vmess_cfg["security"]
                                    }
                                ]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": vmess_cfg["network"],
                        "security": vmess_cfg["tls"],
                        "tlsSettings": {"serverName": vmess_cfg["serverName"]} if vmess_cfg["tls"] else {}
                    }
                }
            ]
        }
    # 处理Trojan节点
    elif node_line.startswith('trojan://'):
        trojan_cfg = extract_trojan_config(node_line)
        if not trojan_cfg or not trojan_cfg["address"] or not trojan_cfg["password"]:
            return (False, 9999)
        temp_config = {
            "inbounds": [
                {
                    "port": 1080,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True}
                }
            ],
            "outbounds": [
                {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [
                            {
                                "address": trojan_cfg["address"],
                                "port": trojan_cfg["port"],
                                "password": trojan_cfg["password"]
                            }
                        ]
                    },
                    "streamSettings": {
                        "security": trojan_cfg["security"],
                        "tlsSettings": {"serverName": trojan_cfg["sni"]} if trojan_cfg["sni"] else {}
                    }
                }
            ]
        }
    # 不支持的协议（如SS）直接过滤
    else:
        print(f"⚠️ 暂不支持的协议（{node_line[:20]}...），过滤该节点")
        return (False, 9999)

    # 启动V2Ray并测试代理
    temp_config_path = f"/tmp/v2ray_{hash(node_line)}.json"
    v2ray_process = None
    try:
        with open(temp_config_path, 'w') as f:
            json.dump(temp_config, f, indent=2)
        
        # 启动V2Ray进程
        v2ray_process = subprocess.Popen(
            ["v2ray", "-config", temp_config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True
        )
        time.sleep(1.5)  # 等待V2Ray完全启动
        
        # 测试代理连通性并计算延迟
        start_time = time.time()
        proxies = {"http": "socks5://127.0.0.1:1080", "https": "socks5://127.0.0.1:1080"}
        resp = requests.get(CONFIG["detection"]["test_url"], proxies=proxies, timeout=CONFIG["detection"]["proxy_test_timeout"])
        delay = (time.time() - start_time) * 1000  # 转换为毫秒
        return (resp.status_code == 204, delay)
    except Exception as e:
        return (False, 9999)
    finally:
        # 强制清理V2Ray进程和临时文件
        if v2ray_process:
            subprocess.run(["pkill", "-f", f"v2ray -config {temp_config_path}"], check=False, stderr=subprocess.PIPE)
        if os.path.exists(temp_config_path):
            os.remove(temp_config_path)
        # 每50个节点清理一次残留V2Ray进程
        if hash(node_line) % 50 == 0:
            subprocess.run(["pkill", "-9", "v2ray"], check=False, stderr=subprocess.PIPE)

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
    """处理单个节点，返回(节点行, 域名, IP, 端口, 延迟)"""
    try:
        if not line:
            return None, "", "", 443, 9999
        
        # 提取节点基础信息
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
            # 其他协议简化提取
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
            return None, "", "", 443, 9999
        
        # 域名解析检测
        if domain and not test_domain_resolve(domain):
            return None, "", "", 443, 9999
        
        # TCP端口连通性检测
        if ip and not test_tcp_connect(ip, port):
            return None, "", "", 443, 9999
        
        # 代理有效性+延迟测试
        is_valid, delay = test_proxy_valid(line)
        if not is_valid:
            return None, "", "", 443, 9999
        
        # 兜底显示地址
        display_addr = ip or domain or "未知地址"
        print(f"✅ 节点检测通过: {display_addr}:{port}（延迟{delay:.1f}ms）")
        return line, domain, ip, port, delay
    except Exception as e:
        print(f"❌ 节点处理异常（{line[:20]}...）: {str(e)[:50]}")
        return None, "", "", 443, 9999

# ====================== 主流程（优化后） ======================
def main():
    start_time = time.time()
    # 1. 拉取并合并所有数据源
    all_lines = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(fetch_source, url): url for url in CONFIG["sources"]}
        for future in as_completed(future_to_url):
            lines = future.result()
            all_lines.update(lines)
    
    unique_lines = list(all_lines)
    print(f"\n📊 全局去重后总节点：{len(unique_lines)} 条")

    # 2. 按优先级排序（Reality > TLS > 普通）
    reality_lines = [l for l in unique_lines if 'reality' in l.lower()]
    tls_lines = [l for l in unique_lines if 'tls' in l.lower() and l not in reality_lines]
    normal_lines = [l for l in unique_lines if l not in reality_lines + tls_lines]
    processing_order = reality_lines + tls_lines + normal_lines
    print(f"📌 优先级拆分 - Reality节点：{len(reality_lines)} 条 | TLS节点：{len(tls_lines)} 条 | 普通节点：{len(normal_lines)} 条")

    # 3. 多线程处理节点
    valid_nodes = []  # 存储(延迟, 节点行)
    seen_core_ids = set()  # 核心配置去重
    total_nodes = len(processing_order)
    
    with ThreadPoolExecutor(max_workers=CONFIG["detection"]["thread_pool_size"]) as executor:
        futures = [executor.submit(process_node, line) for line in processing_order]
        for idx, future in enumerate(as_completed(futures)):
            # 进度可视化
            if idx % 100 == 0:
                progress = (idx / total_nodes) * 100
                print(f"\n🔄 处理进度：{idx}/{total_nodes} ({progress:.1f}%)")
            
            try:
                line, domain, ip, port, delay = future.result()
            except Exception as e:
                print(f"⚠️ 异步处理异常: {str(e)[:50]}")
                continue
            
            if not line:
                continue

            # 核心配置去重（避免同配置节点重复）
            core_id = get_node_core_id(line)
            if core_id in seen_core_ids:
                continue
            seen_core_ids.add(core_id)

            # 延迟过滤（超过阈值则跳过）
            if delay > CONFIG["detection"]["max_delay"]:
                print(f"⚠️ 节点延迟过高（{delay:.1f}ms），过滤：{ip or domain or '未知地址'}:{port}")
                continue
            
            valid_nodes.append( (delay, line) )

    # 4. 按延迟排序，保留低延迟节点
    valid_nodes.sort(key=lambda x: x[0])
    valid_lines = [line for (delay, line) in valid_nodes]

    # 5. 生成Base64编码的订阅文件
    combined = '\n'.join(valid_lines)
    encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
    with open('s1.txt', 'w', encoding='utf-8') as f:
        f.write(encoded)

    # 6. 输出详细统计
    total_cost = time.time() - start_time
    print(f"\n🎉 最终处理完成：")
    print(f"   - 原始总节点：{len(unique_lines)} 条")
    print(f"   - 有效节点：{len(valid_lines)} 条")
    print(f"   - 有效率：{len(valid_lines)/len(unique_lines)*100:.2f}%" if unique_lines else "   - 有效率：0.00%")
    print(f"   - 独特核心配置数：{len(seen_core_ids)} 个")
    print(f"   - 订阅文件大小：{len(encoded)} 字符")
    print(f"   - 总耗时：{total_cost:.2f} 秒（{total_cost/60:.2f} 分钟）")
    print(f"   - 平均延迟：{sum([d for d, _ in valid_nodes])/len(valid_nodes):.1f}ms" if valid_nodes else "   - 平均延迟：无")

if __name__ == "__main__":
    main()
