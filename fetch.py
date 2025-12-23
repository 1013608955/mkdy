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
OUTPUT_FILE = "s2.txt"

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

        sub_links = set()

        # 优先：mm.mibei77.com 下的 .txt 文件
        mm_links = re.findall(r'https?://mm\.mibei77\.com/[^\s<>"\']*\.txt', text)
        sub_links.update(mm_links)

        # 其他 .txt 链接（含关键词）
        other_txt = re.findall(r'https?://[^\s<>"\']*\.txt', text)
        for link in other_txt:
            if any(k in link.lower() for k in ["bagtr", "bagr", "sub", "node", "clash", "v2ray"]):
                sub_links.add(link)

        # 排除社交分享链接
        exclude = ["reddit", "telegram", "twitter", "facebook", "tumblr", "linkedin", "pinterest"]
        sub_links = {l for l in sub_links if not any(ex in l for ex in exclude)}

        # Base64 订阅（文章中直接出现的长字符串）
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

        print(f"精准提取到 {len(sub_links)} 个有效订阅源")
        for l in sorted(sub_links):
            print(f"  → {l}")
        return list(sub_links)
    except Exception as e:
        print(f"解析文章失败：{e}")
        return []

def download_nodes(source):
    try:
        if source.startswith('http'):
            resp = requests.get(source, headers=HEADERS, timeout=20)
            resp.raise_for_status()
            raw_content = resp.text.strip()
        else:
            raw_content = base64.b64decode(source).decode('utf-8', errors='ignore').strip()

        nodes = []

        # 方法1: 直接提取明文节点
        for line in raw_content.split('\n'):
            line = line.strip()
            if line.startswith(('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria://')):
                nodes.append(line)

        # 方法2: 如果没有明文，尝试每行是 Base64 编码的节点列表（米贝77常见）
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

        print(f"  → {source[:60]}... 获取 {len(nodes)} 个节点")
        return nodes
    except Exception as e:
        print(f"  → 下载/解析失败：{e}")
        return []

def main():
    print("开始抓取米贝77最新免费节点...\n")
    article_url = get_latest_article_url()
    if not article_url:
        print("脚本结束")
        return

    sources = extract_sub_links(article_url)
    if not sources:
        print("未找到订阅链接")
        return

    all_nodes = []
    for src in sources:
        nodes = download_nodes(src)
        all_nodes.extend(nodes)
        time.sleep(0.5)  # 防请求过快

    # 去重（保持顺序）
    unique_nodes = []
    seen = set()
    for node in all_nodes:
        if node not in seen:
            seen.add(node)
            unique_nodes.append(node)

    if unique_nodes:
        content = '\n'.join(unique_nodes)
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(encoded)
        print(f"\n成功保存 {len(unique_nodes)} 个唯一节点到 {OUTPUT_FILE}（Base64编码）")
        print("可直接复制文件内容导入客户端使用")
    else:
        print("未获取到任何有效节点")

if __name__ == "__main__":
    main()
