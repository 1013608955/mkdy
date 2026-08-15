import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime

URL = "https://tuijianvpn.com/1044"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
}

try:
    resp = requests.get(URL, headers=HEADERS, timeout=15)
    resp.raise_for_status()
except Exception as e:
    print(f"请求页面失败: {e}")
    exit(1)

soup = BeautifulSoup(resp.text, "html.parser")
link = None

for code in soup.find_all(["pre", "code"]):
    text = code.get_text(strip=True)
    matches = re.findall(r'https?://[^\s"\'<>]+', text)
    for m in matches:
        if 'tosslk.xyz' in m and len(m.split('/')[-1]) >= 32:  # 更精确匹配长 hex
            link = m
            break
    if link:
        break

if not link:
    # fallback - 你原方法
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("https://") and 'tosslk.xyz' in href and len(href) > 60:
            link = href
            break

if not link:
    print("没有找到订阅链接！页面结构可能变了。")
    exit(1)

print(f"找到订阅链接：{link}")

# 保存链接（Clash/v2rayN 直接订阅这个 raw txt 即可）
with open("latest_tuijian.txt", "w", encoding="utf-8") as f:
    f.write(link + "\n")

# 历史记录（可选）
ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
with open("history_tuijian.txt", "a", encoding="utf-8") as f:
    f.write(f"{ts} | {link}\n")
