import base64
import yaml
import sys
import json

def decode_vmess_to_clash(vmess_link: str) -> dict:
    """将vmess链接解析为Clash节点配置（匹配目标格式）"""
    try:
        # 提取base64部分并补全padding
        vmess_b64 = vmess_link.strip().replace("vmess://", "")
        vmess_b64 += "=" * ((4 - len(vmess_b64) % 4) % 4)
        # 解码为JSON并转换为Clash格式
        vmess_json = base64.b64decode(vmess_b64).decode("utf-8")
        vmess_conf = json.loads(vmess_json)  # 用json解析更稳定
        
        # 构建与目标格式完全一致的vmess节点配置
        node = {
            "name": vmess_conf.get("ps", "Unnamed-Vmess"),
            "server": vmess_conf["add"],
            "port": int(vmess_conf["port"]),
            "type": "vmess",
            "uuid": vmess_conf["id"],
            "alterId": int(vmess_conf.get("aid", 0)),
            "cipher": vmess_conf.get("scy", "auto"),
            "tls": vmess_conf.get("tls") == "tls",
            "skip-cert-verify": True,
            "udp": True
        }
        
        # 处理ws网络配置
        network = vmess_conf.get("net", "tcp")
        if network == "ws":
            node["network"] = "ws"
            node["ws-path"] = vmess_conf.get("path", "")
            if vmess_conf.get("host"):
                node["ws-headers"] = {"Host": vmess_conf["host"]}
        
        return node
    except Exception as e:
        print(f"解析VMess节点失败: {e}", file=sys.stderr)
        return None

def decode_ss_to_clash(ss_link: str) -> dict:
    """解析Shadowsocks链接（补充支持ss协议）"""
    try:
        ss_link = ss_link.strip().replace("ss://", "")
        # 分割加密方式+密码 和 服务器信息
        auth_part, server_part = ss_link.split("@")
        auth_b64 = auth_part + "=" * ((4 - len(auth_part) % 4) % 4)
        auth = base64.b64decode(auth_b64).decode("utf-8")
        cipher, password = auth.split(":", 1)
        
        # 解析服务器和端口
        server, port = server_part.split(":", 1)
        
        return {
            "name": f"SS-{server}",
            "server": server,
            "port": int(port),
            "type": "ss",
            "cipher": cipher,
            "password": password,
            "skip-cert-verify": True,
            "udp": True
        }
    except Exception as e:
        print(f"解析SS节点失败: {e}", file=sys.stderr)
        return None

def decode_trojan_to_clash(trojan_link: str) -> dict:
    """解析Trojan链接（补充支持trojan协议）"""
    try:
        trojan_link = trojan_link.strip().replace("trojan://", "")
        # 分割密码和服务器信息
        password, server_part = trojan_link.split("@")
        server, port = server_part.split(":", 1)
        
        return {
            "name": f"Trojan-{server}",
            "server": server,
            "port": int(port),
            "type": "trojan",
            "password": password,
            "skip-cert-verify": True,
            "udp": True
        }
    except Exception as e:
        print(f"解析Trojan节点失败: {e}", file=sys.stderr)
        return None

# 1. 读取并解码s.txt的base64订阅
try:
    with open("s.txt", "r", encoding="utf-8") as f:
        sub_b64 = f.read().strip()
    sub_content = base64.b64decode(sub_b64).decode("utf-8")
except Exception as e:
    print(f"读取/解码订阅文件失败: {e}", file=sys.stderr)
    sys.exit(1)

# 2. 解析所有类型的节点链接
new_proxies = []
for line in sub_content.splitlines():
    line = line.strip()
    if not line:
        continue
    
    if line.startswith("vmess://"):
        node = decode_vmess_to_clash(line)
    elif line.startswith("ss://"):
        node = decode_ss_to_clash(line)
    elif line.startswith("trojan://"):
        node = decode_trojan_to_clash(line)
    else:
        print(f"不支持的链接类型: {line[:20]}...", file=sys.stderr)
        continue
    
    if node:
        new_proxies.append(node)

if not new_proxies:
    print("未解析到任何有效节点", file=sys.stderr)
    sys.exit(0)

# 3. 读取s2-clash.yaml的基础配置
try:
    with open("s2-clash.yaml", "r", encoding="utf-8") as f:
        # 用safe_load保持原有结构
        clash_conf = yaml.safe_load(f)
except Exception as e:
    print(f"读取基础配置文件失败: {e}", file=sys.stderr)
    sys.exit(1)

# 4. 添加新节点到proxies列表（确保proxies字段存在）
if "proxies" not in clash_conf:
    clash_conf["proxies"] = []
clash_conf["proxies"].extend(new_proxies)

# 5. 将新节点加入“♻️ 自动选择”分组
new_proxy_names = [p["name"] for p in new_proxies]
for group in clash_conf.get("proxy-groups", []):
    if group["name"] == "♻️ 自动选择":
        # 去重并添加新节点名称
        existing_proxies = group.get("proxies", [])
        for name in new_proxy_names:
            if name not in existing_proxies:
                existing_proxies.append(name)
        group["proxies"] = existing_proxies
        break

# 6. 自定义YAML转储器，生成单行流式格式
class FlowStyleDumper(yaml.Dumper):
    def represent_sequence(self, tag, sequence, flow_style=None):
        # 对proxies下的列表项使用流式格式
        if self.current_node and self.current_node.tag == 'tag:yaml.org,2002:map':
            parent_key = list(self.current_node.value[-1][0].value.keys())[-1]
            if parent_key == "proxies":
                return super().represent_sequence(tag, sequence, flow_style=True)
        return super().represent_sequence(tag, sequence, flow_style=flow_style)

# 7. 保存为s-clash.yaml（严格匹配目标格式）
try:
    with open("s-clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(
            clash_conf, 
            f,
            Dumper=FlowStyleDumper,
            allow_unicode=True,
            sort_keys=False,  # 保持字段顺序
            default_flow_style=False,  # 全局非流式
            indent=2,  # 保持2空格缩进
            width=10000  # 禁用行截断
        )
    print(f"成功生成配置文件，新增 {len(new_proxies)} 个节点")
except Exception as e:
    print(f"保存配置文件失败: {e}", file=sys.stderr)
    sys.exit(1)
