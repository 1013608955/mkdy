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
            # 按日期排序取最新
            candidates.sort(key=lambda x: x[0], reverse=True)
            print(f"找到最新文章：{candidates[0][1]}")
            print(f"链接：{candidates[0][0]}")
            return candidates[0][0]

        print("未找到最新文章")
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
        for link in mm_links:
            sub_links.add(link)

        # 通用 .txt 订阅链接
        txt_links = re.findall(r'https?://[^\s<>"\']*\.txt', text)
        for link in txt_links:
            if any(k in link for k in ["bagtr", "bagr", "sub", "node", "2025"]):
                sub_links.add(link)

        # 社交分享链接过滤（排除无效）
        exclude_patterns = ["reddit.com", "telegram.me", "twitter.com", "facebook.com", "tumblr.com", "linkedin.com", "pinterest.com"]
        sub_links = {l for l in sub_links if not any(p in l for p in exclude_patterns)}

        # Base64 订阅提取（加强）
        for tag in soup.find_all(['pre', 'code', 'p', 'div', 'span']):
            content = tag.get_text()
            parts = re.split(r'\s+', content)
            for part in parts:
                part = part.strip()
                if len(part) > 100 and re.match(r'^[A-Za-z0-9+/=]+$', part):
                    try:
                        base64.b64decode(part, validate=True)
                        sub_links.add(part)
                    except:
                        pass

        # 图片 alt 或附近文字可能含链接
        for img in soup.find_all('img', alt=True):
            alt = img['alt'].lower()
            if any(k in alt for k in ["订阅", "链接", "txt", "bagtr"]):
                # 取图片附近文字尝试匹配链接
                parent_text = img.find_parent().get_text()
                potential = re.findall(r'https?://mm\.mibei77\.com/[^\s<>"\']*\.txt', parent_text)
                sub_links.update(potential)

        print(f"精准提取到 {len(sub_links)} 个有效订阅源：")
        for l in sub_links:
            print(f"  → {l}")
        return list(sub_links)
    except Exception as e:
        print(f"解析文章失败：{e}")
        return []

# download_nodes 函数保持不变（你原版的即可）

def main():
    # ... 原 main 函数不变 ...

if __name__ == "__main__":
    main()
