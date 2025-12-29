import base64
import re
import yaml
from pathlib import Path
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# 协议解析正则表达式
PROTOCOL_PATTERNS = {
    'vless': re.compile(r'vless://([^@]+)@([^:]+):(\d+)\?(.+)'),
    'trojan': re.compile(r'trojan://([^@]+)@([^:]+):(\d+)\?(.+)'),
    'vmess': re.compile(r'vmess://(.+)'),
    'ss': re.compile(r'ss://([^@]+)@([^:]+):(\d+)'),
    'hysteria': re.compile(r'hysteria://([^@]+)@([^:]+):(\d+)\?(.+)')
}

def decode_base64_file(file_path):
    """解码Base64文件内容"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            encoded = f.read().strip()
        decoded = base64.b64decode(encoded).decode('utf-8')
        return decoded.splitlines()
    except Exception as e:
        logger.error(f"解码文件 {file_path} 失败: {str(e)}")
        return []

def parse_vmess(encoded):
    """解析VMess节点"""
    try:
        vmess_info = base64.b64decode(encoded).decode('utf-8')
        info = yaml.safe_load(vmess_info)
        return {
            'name': info.get('ps', 'VMess节点'),
            'type': 'vmess',
            'server': info.get('add', ''),
            'port': info.get('port', 0),
            'uuid': info.get('id', ''),
            'alterId': info.get('aid', 0),
            'cipher': info.get('scy', 'auto'),
            'tls': info.get('tls', '') == 'tls',
            'network': info.get('net', 'tcp'),
            'ws-path': info.get('path', '') if info.get('net') == 'ws' else '',
            'ws-headers': {'Host': info.get('host', '')} if info.get('net') == 'ws' else {}
        }
    except Exception as e:
        logger.warning(f"解析VMess节点失败: {str(e)}")
        return None

def parse_ss(encoded_part):
    """解析Shadowsocks节点"""
    try:
        decoded = base64.b64decode(encoded_part).decode('utf-8')
        cipher, password = decoded.split(':', 1)
        return cipher, password
    except Exception as e:
        logger.warning(f"解析SS节点失败: {str(e)}")
        return None, None

def parse_general(protocol, match):
    """解析VLESS/Trojan/Hysteria节点"""
    try:
        if protocol in ['vless', 'trojan', 'hysteria']:
            password, server, port, params = match.groups()
            params_dict = dict(re.findall(r'([^&=]+)=([^&=]+)', params))
            return {
                'name': f"{protocol}节点_{server}",
                'type': protocol,
                'server': server,
                'port': int(port),
                'password': password,
                'tls': params_dict.get('tls') == '1',
                'sni': params_dict.get('sni', ''),
                'alpn': params_dict.get('alpn', '').split(',') if params_dict.get('alpn') else []
            }
    except Exception as e:
        logger.warning(f"解析{protocol}节点失败: {str(e)}")
        return None

def convert_node(line):
    """转换单条节点为Clash格式"""
    for proto, pattern in PROTOCOL_PATTERNS.items():
        match = pattern.match(line)
        if match:
            if proto == 'vmess':
                return parse_vmess(match.group(1))
            elif proto == 'ss':
                cipher, password = parse_ss(match.group(1))
                if cipher and password:
                    return {
                        'name': f"SS节点_{match.group(2)}",
                        'type': 'ss',
                        'server': match.group(2),
                        'port': int(match.group(3)),
                        'cipher': cipher,
                        'password': password
                    }
            else:
                return parse_general(proto, match)
    logger.warning(f"不支持的节点格式: {line[:50]}...")
    return None

def generate_clash_config(nodes):
    """生成完整的Clash配置"""
    proxies = [node for node in nodes if node]
    if not proxies:
        return None

    return {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'proxies': proxies,
        'proxy-groups': [
            {
                'name': '自动选择',
                'type': 'url-test',
                'proxies': [p['name'] for p in proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            },
            {
                'name': '代理',
                'type': 'select',
                'proxies': ['自动选择'] + [p['name'] for p in proxies]
            }
        ],
        'rules': [
            'DOMAIN-SUFFIX,google.com,代理',
            'DOMAIN-SUFFIX,github.com,代理',
            'DOMAIN-SUFFIX,youtube.com,代理',
            'GEOIP,CN,DIRECT',
            'MATCH,代理'
        ]
    }

def process_file(input_path, output_path):
    """处理单个文件转换"""
    logger.info(f"开始处理 {input_path}")
    lines = decode_base64_file(input_path)
    if not lines:
        logger.warning(f"文件 {input_path} 没有有效内容")
        return

    nodes = [convert_node(line) for line in lines]
    clash_config = generate_clash_config(nodes)
    if not clash_config:
        logger.warning(f"没有生成有效的Clash配置 for {input_path}")
        return

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        logger.info(f"转换完成，已保存到 {output_path}")
    except Exception as e:
        logger.error(f"保存文件 {output_path} 失败: {str(e)}")

def main():
    # 修正：源文件在根目录，输出文件改为yaml后缀
    file_mapping = {
        's.txt': 's-clash.yaml',
        's1.txt': 's1-clash.yaml',
        's2.txt': 's2-clash.yaml'
    }

    # 处理所有文件
    for input_path, output_path in file_mapping.items():
        if Path(input_path).exists():
            process_file(input_path, output_path)
        else:
            logger.warning(f"输入文件 {input_path} 不存在，跳过处理")

if __name__ == "__main__":
    main()
