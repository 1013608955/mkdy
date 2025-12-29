import requests
import re
import base64
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import time

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
}
HOME_URL = "https://www.mibei77.com/"
NODE_OUTPUT_FILE = "s2.txt"
CLASH_YAML_OUTPUT = "s2-clash.yaml"

def get_latest_article_url():
    try:
        resp = requests.get(HOME_URL, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')

        today = datetime.now().strftime("%Y%m%d")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")

        candidates = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.get_text(strip=True) + (a.get('title', ''))
            if ("节点" in text or "订阅" in text or "免费" in text) and any(d in href for d in [today, yesterday]):
                if href.startswith("http"):
                    candidates.append((href, text))

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            print(f"找到最新文章：{candidates[0][1]}")
            print(f"链接：{candidates[0][0]}")
            return candidates[0][0]

        print("未找到最新文章（可能当天未更新）")
        return None
    except Exception as e:
        print(f"获取首页失败：{e}")
        return None

def extract_sub_links(article_url):
    try:
        resp = requests.get(article_url, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        text = resp.text
        soup = BeautifulSoup(text, 'html.parser')

        sub_links = set()  # 节点订阅源链接
        yaml_links = set()  # Clash YAML配置链接
        exclude = ["reddit", "telegram", "twitter", "facebook", "tumblr", "linkedin", "pinterest"]

        # 1. 提取节点相关链接（.txt）
        # 优先mm域名下的.txt
        mm_txt_links = re.findall(r'https?://mm\.mibei77\.com/[^\s<>"\']*\.txt', text)
        sub_links.update(mm_txt_links)
        # 其他含关键词的.txt
        other_txt = re.findall(r'https?://[^\s<>"\']*\.txt', text)
        for link in other_txt:
            if any(k in link.lower() for k in ["bagtr", "bagr", "sub", "node", "clash", "v2ray"]):
                sub_links.add(link)

        # 2. 提取Clash YAML链接（.yaml）
        # 优先mm域名下的.yaml
        mm_yaml_links = re.findall(r'https?://mm\.mibei77\.com/[^\s<>"\']*\.yaml', text)
        yaml_links.update(mm_yaml_links)
        # 其他含Clash关键词的.yaml
        other_yaml = re.findall(r'https?://[^\s<>"\']*\.yaml', text)
        for link in other_yaml:
            if "clash" in link.lower():
                yaml_links.add(link)

        # 排除社交链接
        sub_links = {l for l in sub_links if not any(ex in l for ex in exclude)}
        yaml_links = {l for l in yaml_links if not any(ex in l for ex in exclude)}

        # 3. 提取Base64格式的节点订阅
        for tag in soup.find_all(['pre', 'code', 'p', 'div']):
            parts = re.split(r'\s+', tag.get_text())
            for part in parts:
                part = part.strip()
                if len(part) > 100 and re.match(r'^[A-Za-z0-9+/=]+$', part):
                    try:
                        base64.b64decode(part, validate=True)
                        sub_links.add(part)
                    except:
                        pass

        # 输出提取结果
        print(f"\n提取到 {len(sub_links)} 个节点订阅源：")
        for l in sorted(sub_links):
            print(f"  → {l}")
        print(f"\n提取到 {len(yaml_links)} 个Clash YAML配置链接：")
        for l in sorted(yaml_links):
            print(f"  → {l}")
        
        return list(sub_links), list(yaml_links)
    except Exception as e:
        print(f"解析文章失败：{e}")
        return [], []

def download_clash_yaml(yaml_url, output_file):
    """下载Clash YAML配置并保存到文件"""
    try:
        resp = requests.get(yaml_url, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        yaml_content = resp.text.strip()
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        print(f"\n✅ 成功将Clash配置保存到 {output_file}")
        return True
    except Exception as e:
        print(f"❌ 下载YAML失败 [{yaml_url}]：{e}")
        return False

def download_nodes(source):
    try:
        if source.startswith('http'):
            resp = requests.get(source, headers=HEADERS, timeout=20)
            resp.raise_for_status()
            raw_content = resp.text.strip()
        else:
            raw_content = base64.b64decode(source).decode('utf-8', errors='ignore').strip()

        nodes = []

        # 提取明文节点
        for line in raw_content.split('\n'):
            line = line.strip()
            if line.startswith(('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria://')):
                nodes.append(line)

        # 尝试解析Base64编码的节点
        if not nodes:
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

        print(f"  → 从 [{source[:50]}...] 获取到 {len(nodes)} 个节点")
        return nodes
    except Exception as e:
        print(f"  → 处理 [{source[:50]}...] 失败：{e}")
        return []

def main():
    print("开始抓取米贝77最新资源...\n")
    article_url = get_latest_article_url()
    if not article_url:
        print("脚本结束")
        return

    # 提取节点源和YAML链接
    sub_sources, yaml_sources = extract_sub_links(article_url)

    # 先处理Clash YAML配置
    if yaml_sources:
        print("\n开始下载Clash YAML配置：")
        # 下载第一个可用的YAML（也可以去掉break下载所有）
        for yaml_url in yaml_sources:
            if download_clash_yaml(yaml_url, CLASH_YAML_OUTPUT):
                break
    else:
        print("\n未找到Clash YAML配置链接")

    # 再处理节点订阅
    if not sub_sources:
        print("\n未找到节点订阅链接")
        return

    all_nodes = []
    for src in sub_sources:
        nodes = download_nodes(src)
        all_nodes.extend(nodes)
        time.sleep(0.5)

    # 节点去重
    unique_nodes = []
    seen = set()
    for node in all_nodes:
        if node not in seen:
            seen.add(node)
            unique_nodes.append(node)

    if unique_nodes:
        content = '\n'.join(unique_nodes)
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        with open(NODE_OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(encoded)
        print(f"\n✅ 成功保存 {len(unique_nodes)} 个节点到 {NODE_OUTPUT_FILE}（Base64编码）")
    else:
        print("\n未获取到有效节点")

if __name__ == "__main__":
    main()
