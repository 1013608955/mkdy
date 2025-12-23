def download_nodes(source):
    try:
        if source.startswith('http'):
            resp = requests.get(source, headers=HEADERS, timeout=20)
            resp.raise_for_status()
            raw_content = resp.text.strip()
        else:
            # source 本身是 Base64
            raw_content = base64.b64decode(source).decode('utf-8', errors='ignore').strip()

        nodes = []

        # 方法1: 直接提取明文节点
        for line in raw_content.split('\n'):
            line = line.strip()
            if line.startswith(('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria://')):
                nodes.append(line)

        # 方法2: 如果整行是 Base64（米贝77常见），尝试解码每行
        if not nodes:  # 如果没找到明文，再试 Base64 解码
            for line in raw_content.split('\n'):
                line = line.strip()
                if len(line) > 50 and re.match(r'^[A-Za-z0-9+/=]+$', line):
                    try:
                        decoded = base64.b64decode(line, validate=True).decode('utf-8', errors='ignore')
                        for sub_line in decoded.split('\n'):
                            sub_line = sub_line.strip()
                            if sub_line.startswith(('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria://')):
                                nodes.append(sub_line)
                    except:
                        continue

        print(f"  → {source[:60]}... 获取 {len(nodes)} 个节点")
        return nodes
    except Exception as e:
        print(f"  → 下载/解析失败：{e}")
        return []
