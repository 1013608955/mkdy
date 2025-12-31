import base64
import yaml
import sys
import json
import re

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
        # 处理包含备注的SS链接
        if "#" in ss_link:
            ss_link, remark = ss_link.split("#", 1)
            try:
                remark = base64.b64decode(remark).decode("utf-8")
            except:
                remark = remark
        else:
            remark = ""
        
        # 分割加密方式+密码 和 服务器信息
        auth_part, server_part = ss_link.split("@")
        auth_b64 = auth_part + "=" * ((4 - len(auth_part) % 4) % 4)
        auth = base64.b64decode(auth_b64).decode("utf-8")
        cipher, password = auth.split(":", 1)
        
        # 解析服务器和端口（容错处理）
        server_port = server_part.split(":")
        server = server_port[0]
        port = server_port[1].split("?")[0] if len(server_port) > 1 else "8080"
        
        # 构建节点名称
        name = remark if remark else f"SS-{server}:{port}"
        
        return {
            "name": name,
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
    """解析Trojan链接（修复端口解析错误，生成完整字段）"""
    try:
        trojan_link = trojan_link.strip().replace("trojan://", "")
        # 去掉链接中的参数部分（?后面的内容）
        if "?" in trojan_link:
            trojan_link, _ = trojan_link.split("?", 1)
        
        # 分割密码和服务器信息（容错处理）
        if "@" not in trojan_link:
            raise ValueError("无效的Trojan链接格式")
        
        password, server_part = trojan_link.split("@", 1)
        
        # 解析服务器和端口（处理端口后有多余字符的情况）
        server_port = server_part.split(":")
        server = server_port[0]
        port = server_port[1] if len(server_port) > 1 else "443"
        # 提取纯数字端口
        port = re.findall(r'\d+', port)[0] if re.findall(r'\d+', port) else "443"
        
        # 构建节点名称（模仿示例格式）
        name = f"Trojan-{server}({port})"
        
        # 生成完整的Trojan节点配置（匹配示例格式）
        return {
            "name": name,
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

def decode_vless_to_clash(vless_link: str) -> dict:
    """新增：解析VLESS链接（支持vless协议，生成完整字段）"""
    try:
        vless_link = vless_link.strip().replace("vless://", "")
        # 去掉参数部分
        if "?" in vless_link:
            vless_core, vless_params = vless_link.split("?", 1)
        else:
            vless_core = vless_link
            vless_params = ""
        
        # 解析UUID和服务器信息
        if "@" not in vless_core:
            raise ValueError("无效的VLESS链接格式")
        
        uuid, server_part = vless_core.split("@", 1)
        server_port = server_part.split(":")
        server = server_port[0]
        port = server_port[1] if len(server_port) > 1 else "443"
        port = re.findall(r'\d+', port)[0] if re.findall(r'\d+', port) else "443"
        
        # 解析参数
        params = {}
        if vless_params:
            for param in vless_params.split("&"):
                if "=" in param:
                    k, v = param.split("=", 1)
                    params[k] = v
        
        # 构建节点名称（模仿示例格式）
        name = params.get("remarks", f"VLESS-{server}({port})")
        
        # 生成完整的VLESS节点配置
        node = {
            "name": name,
            "server": server,
            "port": int(port),
            "type": "vless",
            "uuid": uuid,
            "skip-cert-verify": True,
            "udp": True
        }
        
        # 添加TLS配置
        if params.get("security") == "tls" or params.get("tls") == "tls":
            node["tls"] = True
            if params.get("sni"):
                node["servername"] = params.get("sni")
        
        # 处理WS配置
        if params.get("type") == "ws":
            node["network"] = "ws"
            if params.get("path"):
                node["ws-path"] = params.get("path")
            if params.get("host"):
                node["ws-headers"] = {"Host": params.get("host")}
        
        return node
    except Exception as e:
        print(f"解析VLESS节点失败: {e}", file=sys.stderr)
        return None

def main():
    # 1. 读取并解码s.txt的base64订阅
    try:
        with open("s.txt", "r", encoding="utf-8") as f:
            sub_b64 = f.read().strip()
        # 处理可能的URL安全Base64
        sub_b64 = sub_b64.replace("-", "+").replace("_", "/")
        sub_content = base64.b64decode(sub_b64).decode("utf-8", errors="ignore")
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
        elif line.startswith("vless://"):
            node = decode_vless_to_clash(line)
        else:
            print(f"不支持的链接类型: {line[:30]}...", file=sys.stderr)
            continue
        
        if node:
            new_proxies.append(node)

    if not new_proxies:
        print("未解析到任何有效节点", file=sys.stderr)
        sys.exit(0)

    # 3. 读取s2-clash.yaml的基础配置
    try:
        with open("s2-clash.yaml", "r", encoding="utf-8") as f:
            clash_conf = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"读取基础配置文件失败: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. 添加新节点到proxies列表（确保proxies字段存在）
    if "proxies" not in clash_conf:
        clash_conf["proxies"] = []
    # 去重添加（避免重复节点）
    existing_names = [p.get("name") for p in clash_conf["proxies"]]
    new_added = 0
    for proxy in new_proxies:
        if proxy["name"] not in existing_names:
            clash_conf["proxies"].append(proxy)
            existing_names.append(proxy["name"])
            new_added += 1

    # 5. 将新节点加入“♻️ 自动选择”分组
    new_proxy_names = [p["name"] for p in new_proxies]
    for group in clash_conf.get("proxy-groups", []):
        if group["name"] == "♻️ 自动选择":
            # 去重并添加新节点名称
            existing_group_proxies = group.get("proxies", [])
            for name in new_proxy_names:
                if name not in existing_group_proxies:
                    existing_group_proxies.append(name)
            group["proxies"] = existing_group_proxies
            break

    # 6. 直接生成单行流式的proxies格式（核心修复：不再分步收集字段）
    try:
        # 先备份原有proxies，重新构建流式格式的proxies
        original_proxies = clash_conf["proxies"]
        clash_conf["proxies"] = []  # 清空临时列表
        
        # 生成最终的YAML内容
        yaml_parts = []
        
        # 处理除proxies外的其他配置
        for key, value in clash_conf.items():
            if key != "proxies":
                # 生成其他配置的YAML
                part = yaml.dump({key: value}, allow_unicode=True, sort_keys=False, default_flow_style=False, indent=2)
                yaml_parts.append(part.strip())
        
        # 单独处理proxies，生成单行流式格式
        proxies_lines = ["proxies:"]
        for proxy in original_proxies:
            # 为每个代理生成单行流式字符串
            flow_proxy = yaml.dump(proxy, allow_unicode=True, sort_keys=False, default_flow_style=True).strip()
            proxies_lines.append(f"  - {flow_proxy}")
        proxies_yaml = "\n".join(proxies_lines)
        yaml_parts.append(proxies_yaml)
        
        # 合并所有部分
        final_yaml = "\n\n".join(yaml_parts)
        
        # 保存文件
        with open("s-clash.yaml", "w", encoding="utf-8") as f:
            f.write(final_yaml)
        
        print(f"✅ 脚本执行成功！")
        print(f"📊 新增有效节点数: {new_added}")
        print(f"📁 生成文件: s-clash.yaml")
        
    except Exception as e:
        print(f"保存配置文件失败: {e}", file=sys.stderr)
        print(f"错误详情: {sys.exc_info()[1]}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
