import base64
import yaml
import sys

def decode_vmess_to_clash(vmess_link: str) -> dict:
    """将vmess链接解析为Clash节点配置（匹配s2-clash.yaml格式）"""
    try:
        # 提取base64部分并补全padding
        vmess_b64 = vmess_link.strip().replace("vmess://", "")
        vmess_b64 += "=" * ((4 - len(vmess_b64) % 4) % 4)
        # 解码为JSON并转换为Clash格式
        vmess_json = base64.b64decode(vmess_b64).decode("utf-8")
        vmess_conf = yaml.safe_load(vmess_json)
        
        # 构建基础配置
        clash_node = {
            "name": vmess_conf.get("ps", "Unnamed-Vmess"),
            "type": "vmess",
            "server": vmess_conf["add"],
            "port": int(vmess_conf["port"]),
            "uuid": vmess_conf["id"],
            "alterId": int(vmess_conf.get("aid", 0)),
            "cipher": vmess_conf.get("scy", "auto"),
            "tls": vmess_conf.get("tls") == "tls",
            "skip-cert-verify": True,  # 与原配置保持一致
            "udp": True  # 原配置中所有节点均启用udp
        }
        
        # 处理网络类型（ws需要额外参数）
        network = vmess_conf.get("net", "tcp")
        clash_node["network"] = network
        if network == "ws":
            clash_node["ws-path"] = vmess_conf.get("path", "")
            clash_node["ws-headers"] = {"Host": vmess_conf.get("host", "")}
        
        return clash_node
    except Exception as e:
        print(f"解析节点失败: {e}", file=sys.stderr)
        return None

# 1. 读取并解码s.txt的base64订阅
with open("s.txt", "r", encoding="utf-8") as f:
    sub_b64 = f.read().strip()
sub_content = base64.b64decode(sub_b64).decode("utf-8")
vmess_links = [line for line in sub_content.splitlines() if line.startswith("vmess://")]

# 2. 解析所有vmess节点为Clash格式
new_proxies = [p for link in vmess_links if (p := decode_vmess_to_clash(link))]

# 3. 读取s2-clash.yaml的基础配置
with open("s2-clash.yaml", "r", encoding="utf-8") as f:
    clash_conf = yaml.safe_load(f)

# 4. 添加新节点到proxies列表（保持原文件的顺序和格式）
clash_conf["proxies"].extend(new_proxies)

# 5. 将新节点加入“♻️ 自动选择”分组
for group in clash_conf["proxy-groups"]:
    if group["name"] == "♻️ 自动选择":  # 匹配原文件中的分组名称（带特殊符号）
        new_proxy_names = [p["name"] for p in new_proxies]
        # 去重并保持顺序（先保留原有节点，再添加新节点）
        existing_proxies = group["proxies"]
        for name in new_proxy_names:
            if name not in existing_proxies:
                existing_proxies.append(name)
        group["proxies"] = existing_proxies
        break

# 6. 保存为s-clash.yaml（保持原文件的YAML格式风格）
with open("s-clash.yaml", "w", encoding="utf-8") as f:
    yaml.dump(
        clash_conf, f,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        indent=2,
        width=1000  # 避免长行被截断
    )
