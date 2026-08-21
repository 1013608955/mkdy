"""fetch_tuijian.py — 抓取 tuijianvpn 推荐订阅链接。

重构（P1#5）：原脚本在 import 阶段就 requests.get 并 exit，无法在 CI 不联网时
import/单测。现抽出纯函数 extract_link(html)，main() 负责网络与落盘，可用
requests_mock / monkeypatch 打桩测试，import 不再触发任何副作用。
"""
import sys
import re
from datetime import datetime

import requests
from bs4 import BeautifulSoup

URL = "https://tuijianvpn.com/1044"
OUT_FILE = "latest_tuijian.txt"
HISTORY_FILE = "history_tuijian.txt"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
}


def extract_link(html: str) -> "str | None":
    """从页面 HTML 提取订阅链接（纯函数，无网络/IO 副作用，可单测）。

    匹配规则：含 tosslk.xyz 且路径末段为 >=32 位长 hex 的 https 链接；
    先用 <pre>/<code> 文本精确匹配，失败再退回 <a href> 兜底匹配。
    """
    soup = BeautifulSoup(html, "html.parser")
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

    return link


def main() -> int:
    try:
        resp = requests.get(URL, headers=HEADERS, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        print(f"请求页面失败: {e}")
        return 1

    link = extract_link(resp.text)
    if not link:
        print("没有找到订阅链接！页面结构可能变了。")
        return 1

    print(f"找到订阅链接：{link}")

    # 保存链接（Clash/v2rayN 直接订阅这个 raw txt 即可）
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(link + "\n")

    # 历史记录（可选）
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(f"{ts} | {link}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
