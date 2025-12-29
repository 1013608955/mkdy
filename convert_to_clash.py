import base64
import re
import yaml
from pathlib import Path
import logging

# 配置日志（更详细，便于排查问题）
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 协议解析正则表达式（优化匹配精度）
PROTOCOL_PATTERNS = {
    'vless': re.compile(r'vless://([^@]+)@([^:]+):(\d+)\?(.*)'),
    'trojan': re.compile(r'trojan://([^@]+)@([^:]+):(\d+)\?(.*)'),
    'vmess': re.compile(r'vmess://([A-Za-z0-9+/=]+)'),  # 仅匹配Base64编码部分
    'ss': re.compile(r'ss://([A-Za-z0-9+/=]+)@([^:]+):(\d+)'),
    'hysteria': re.compile(r'hysteria://([^@]+)@([^:]+):(\d+)\?(.*)')
}

# 各协议必填字段定义（确保节点完整性）
REQUIRED_FIELDS = {
    'vmess': ['server', 'port', 'uuid', 'type'],
    'vless': ['server', 'port', 'password', 'type'],
    'trojan': ['server', 'port', 'password', 'type'],
    'ss': ['server', 'port', 'cipher', 'password', 'type'],
    'hysteria': ['server', 'port', 'password', 'type']
}

def decode_base64_file(file_path):
    """解码Base64文件内容（增加容错，处理非标准Base64）"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            encoded = f.read().strip()
        
        # 处理Base64填充不完整的情况
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(encoded, errors='ignore').decode('utf-8', errors='ignore')
        return [line.strip() for line in decoded.splitlines() if line.strip()]
    except Exception as e:
        logger.error(f"解码文件 {file_path} 失败: {str(e)}")
        return []

def parse_vmess(encoded):
    """解析VMess节点（严格校验字段类型和完整性）"""
    try:
        # 处理VMess的Base64编码
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        
        vmess_info = base64.b64decode(encoded, errors='ignore').decode('utf-8', errors='ignore')
        info = yaml.safe_load(vmess_info)
        if not info:
            return None
        
        # 标准化字段，确保类型正确
        node = {
            'name': info.get('ps', f"VMess_{info.get('add', 'unknown')}"),
            'type': 'vmess',
            'server': info.get('add', '').strip(),
            'port': int(info.get('port', 0)) if info.get('port') else 0,
            'uuid': info.get('id', '').strip(),
            'alterId': int(info.get('aid', 0)) if info.get('aid') else 0,
            'cipher': info.get('scy', 'auto').strip(),
            'tls': info.get('tls', '').lower() == 'tls',
            'network': info.get('net', 'tcp').strip(),
            'servername': info.get('host', '').strip() or info.get('add', '').strip(),
        }
        
        # 补充WS相关字段（仅当network为ws时）
        if node['network'] == 'ws':
            node['ws-path'] = info.get('path', '').strip()
            node['ws-headers'] = {'Host': info.get('host', '').strip()} if info.get('host') else {}
        
        # 校验必填字段
        if all(node.get(f) for f in REQUIRED_FIELDS['vmess']) and node['port'] > 0:
            return node
        else:
            logger.warning(f"VMess节点缺少必填字段: {info}")
            return None
    except Exception as e:
        logger.warning(f"解析VMess节点失败: {str(e)} | 原始内容: {encoded[:50]}")
        return None

def parse_ss(encoded_part, server, port):
    """解析Shadowsocks节点（严格校验）"""
    try:
        # 处理SS的Base64编码
        missing_padding = len(encoded_part) % 4
        if missing_padding:
            encoded_part += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(encoded_part, errors='ignore').decode('utf-8', errors='ignore')
        if ':' not in decoded:
            return None
        
        cipher, password = decoded.split(':', 1)
        cipher = cipher.strip()
        password = password.strip()
        
        # 构造节点信息
        node = {
            'name': f"SS_{server}",
            'type': 'ss',
            'server': server.strip(),
            'port': int(port) if port else 0,
            'cipher': cipher,
            'password': password
        }
        
        # 校验必填字段
        if all(node.get(f) for f in REQUIRED_FIELDS['ss']) and node['port'] > 0:
            return node
        else:
            logger.warning(f"SS节点缺少必填字段: {cipher=}, {password=}, {server=}, {port=}")
            return None
    except Exception as e:
        logger.warning(f"解析SS节点失败: {str(e)} | 编码内容: {encoded_part[:50]}")
        return None

def parse_general(protocol, match):
    """解析VLESS/Trojan/Hysteria节点（严格校验）"""
    try:
        password, server, port, params = match.groups()
        port = int(port) if port else 0
        server = server.strip()
        password = password.strip()
        
        # 解析参数
        params_dict = {}
        if params:
            for param in params.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params_dict[k.strip()] = v.strip()
        
        # 构造节点信息
        node = {
            'name': f"{protocol.upper()}_{server}",
            'type': protocol,
            'server': server,
            'port': port,
            'password': password,
            'tls': params_dict.get('tls', '0') == '1',
            'servername': params_dict.get('sni', '').strip() or server,
        }
        
        # 补充ALPN字段（如有）
        if params_dict.get('alpn'):
            node['alpn'] = [a.strip() for a in params_dict['alpn'].split(',') if a.strip()]
        
        # 校验必填字段
        if all(node.get(f) for f in REQUIRED_FIELDS[protocol]) and node['port'] > 0:
            return node
        else:
            logger.warning(f"{protocol.upper()}节点缺少必填字段: {server=}, {port=}, {password=}")
            return None
    except Exception as e:
        logger.warning(f"解析{protocol.upper()}节点失败: {str(e)}")
        return None

def convert_node(line):
    """转换单条节点为Clash格式（增加全量校验）"""
    if not line or not line.startswith(('vless://', 'trojan://', 'vmess://', 'ss://', 'hysteria://')):
        logger.warning(f"无效的节点格式: {line[:50]}")
        return None
    
    for proto, pattern in PROTOCOL_PATTERNS.items():
        match = pattern.match(line)
        if match:
            if proto == 'vmess':
                return parse_vmess(match.group(1))
            elif proto == 'ss':
                return parse_ss(match.group(1), match.group(2), match.group(3))
            else:
                return parse_general(proto, match)
    
    logger.warning(f"不支持的节点协议: {line[:50]}")
    return None

def generate_clash_config(nodes):
    """生成完整的Clash配置（确保YAML格式合法）"""
    # 过滤无效节点
    valid_proxies = [node for node in nodes if node is not None]
    if not valid_proxies:
        logger.error("没有有效节点，无法生成Clash配置")
        return None
    
    logger.info(f"共生成 {len(valid_proxies)} 个有效节点")
    
    # 标准Clash配置模板（符合官方规范）
    clash_config = {
        'port': 7890,
        'socks-port': 7891,
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'Rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': valid_proxies,
        'proxy-groups': [
            {
                'name': '🚀 自动选择',
                'type': 'url-test',
                'proxies': [p['name'] for p in valid_proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            },
            {
                'name': '🌍 代理',
                'type': 'select',
                'proxies': ['🚀 自动选择'] + [p['name'] for p in valid_proxies]
            },
            {
                'name': '🎯 直连',
                'type': 'select',
                'proxies': ['DIRECT']
            }
        ],
        'rules': [
            'DOMAIN-SUFFIX,local,DIRECT',
            'DOMAIN-SUFFIX,cn,DIRECT',
            'GEOIP,CN,DIRECT',
            'DOMAIN-SUFFIX,google.com,🌍 代理',
            'DOMAIN-SUFFIX,github.com,🌍 代理',
            'DOMAIN-SUFFIX,youtube.com,🌍 代理',
            'MATCH,🌍 代理'
        ]
    }
    return clash_config

def process_file(input_path, output_path):
    """处理单个文件转换（端到端完整流程）"""
    logger.info(f"===== 开始处理文件: {input_path} =====")
    
    # 读取并解码源文件
    lines = decode_base64_file(input_path)
    if not lines:
        logger.warning(f"文件 {input_path} 无有效内容，跳过")
        return False
    
    logger.info(f"从 {input_path} 读取到 {len(lines)} 行节点数据")
    
    # 转换所有节点
    nodes = [convert_node(line) for line in lines]
    
    # 生成Clash配置
    clash_config = generate_clash_config(nodes)
    if not clash_config:
        logger.error(f"无法为 {input_path} 生成Clash配置")
        return False
    
    # 写入YAML文件（严格符合Clash格式规范）
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(
                clash_config,
                f,
                allow_unicode=True,    # 支持中文
                sort_keys=False,       # 保持字段顺序
                indent=2,              # 标准2空格缩进
                default_flow_style=False,  # 块式输出（Clash推荐）
                width=float('inf')     # 避免行折叠
            )
        logger.info(f"===== 转换完成: {output_path} =====")
        return True
    except Exception as e:
        logger.error(f"写入文件 {output_path} 失败: {str(e)}")
        return False

def main():
    """主函数：处理所有文件"""
    # 源文件 & 输出文件映射（根目录，yaml后缀）
    file_mapping = {
        's.txt': 's-clash.yaml',
        's1.txt': 's1-clash.yaml',
        's2.txt': 's2-clash.yaml'
    }
    
    # 遍历处理每个文件
    for input_file, output_file in file_mapping.items():
        input_path = Path(input_file)
        if not input_path.exists():
            logger.error(f"源文件不存在: {input_file}")
            continue
        
        # 执行转换
        process_file(input_path, output_file)

if __name__ == "__main__":
    main()
