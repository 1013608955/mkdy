import requests
import re
import base64
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import os
import time

# ==================== 配置 ====================
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
}
HOME_URL = "https://www.mibei77.com/"
OUTPUT_FILE = "s2.txt"  # 最终保存的节点文件（Base64 编码）
CACHE_DIR = ".cache"    # 可选缓存目录，避免重复下载
# =============================================

def get_latest_article_url():
    """从首页找到最新的节点文章链接（根据日期匹配）"""
    try:
        resp = requests.get(HOME_URL, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')

        today = datetime.now().strftime("%Y%m%d")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")

        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.get_text(strip=True) + a.get('title', '')

            # 判断是否为节点文章 + 包含日期
            if ("节点" in text or "订阅" in text or "v2ray" in text.lower() or "clash" in text.lower()) \
               and any(date in href for date in [today, yesterday]):
                if href.startswith("http"):
                    print(f"找到最新文章：{text}")
                    print(f"链接：{href}")
                    return href

        print("未找到符合条件的最新文章（可能网站更新了结构）")
        return None
    except Exception as e:
        print(f"获取首页失败：{e}")
        return None

def extract_sub_links_from_article(article_url):
    """从文章页面提取所有订阅链接（包括图片中文字识别的链接）"""
    try:
        resp = requests.get(article_url, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')

        sub_links = set()

        # 方法1：直接找所有 http/https 链接
        for link in re.findall(r'https?://[^\s<>"\']+', resp.text):
            if any(k in link.lower() for k in ["txt", "sub", "yaml", "clash", "v2ray", "node", "base64"]):
                sub_links.add(link.strip())

        # 方法2：找图片中的文字（常见米贝77把链接放图片里）
        for img in soup.find_all('img', src=True):
            img_url = img['src']
            if not img_url.startswith('http'):
                img_url = article_url.rstrip('/') + '/' + img_url.lstrip('/')
            alt = img.get('alt', '')
            if any(k in alt.lower() for k in ["订阅", "链接", "地址", "txt"]):
                print(f"发现可能包含链接的图片：{img_url}")
                # 这里我们假设图片下方或 alt 中有文字链接，但更常见是直接在正文
                # 实际多为正文文字，已被上面正则捕获

        # 方法3：找 <pre>、<code>、<p> 中的长字符串（Base64 订阅）
        for tag in soup.find_all(['pre', 'code', 'p']):
            text = tag.get_text()
            # 典型的 Base64 订阅：很长、无空格、只含特定字符
            candidates = [s.strip() for s in text.split('\n') if len(s.strip()) > 100]
            for c in candidates:
                if re.match(r'^[A-Za-z0-9+/=]+$', c):
                    try:
                        # 简单验证能否解码
                        base64.b64decode(c, validate=True)
                        sub_links.add(c)
                    except:
                        pass

        print(f"从文章提取到 {len(sub_links)} 个订阅源")
        return list(sub_links)
    except Exception as e:
        print(f"解析文章失败：{e}")
        return []

def download_subscription_content(sub_url_or_b64):
    """下载订阅内容（支持直链或 Base64 字符串）"""
    try:
        if sub_url_or_b64.startswith('http'):
            resp = requests.get(sub_url_or_b64, headers=HEADERS, timeout=20)
            resp.raise_for_status()
            content = resp.text.strip()
        else:
            # 已经是 Base64
            content = base64.b64decode(sub_url_or_b64).decode('utf-8', errors='ignore')

        # 提取有效节点行
        nodes = []
        for line in content.split('\n'):
            line = line.strip()
            if line and (line.startswith(('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria://'))):
                nodes.append(line)

        print(f"  → 获取到 {len(nodes)} 个节点")
        return nodes
    except Exception as e:
        print(f"  → 下载失败：{e}")
        return []

def main():
    print("开始抓取米贝77最新免费节点订阅...\n")

    article_url = get_latest_article_url()
    if not article_url:
        print("无法找到文章，脚本结束")
        return

    sub_sources = extract_sub_links_from_article(article_url)
    if not sub_sources:
        print("未找到任何订阅链接")
        return

    all_nodes = []
    for source in sub_sources:
        print(f"正在下载订阅源：{source[:60]}...")
        nodes = download_subscription_content(source)
        all_nodes.extend(nodes)
        time.sleep(0.5)  # 礼貌访问

    # 去重
    unique_nodes = list(dict.fromkeys(all_nodes))  # 保留顺序去重

    print(f"\n总计获取到 {len(unique_nodes)} 个唯一节点")

    if unique_nodes:
        # 保存为 Base64（方便导入）
        content = '\n'.join(unique_nodes)
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')

        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(encoded)

        print(f"\n节点已保存到 {OUTPUT_FILE}（Base64 编码，共 {len(unique_nodes)} 条）")
        print("可直接复制文件内容导入 v2rayNG / Clash / Shadowrocket 等客户端")
    else:
        print("未获取到任何有效节点")

if __name__ == "__main__":
    main()
