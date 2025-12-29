import requests
import re
import base64
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import time

# 核心配置（明确每个网站的YAML输出文件）
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
}
# 目标网站列表：绑定每个网站的名称、首页URL、专属YAML输出文件
TARGET_SITES = [
    {
        "name": "米贝77",
        "url": "https://www.mibei77.com/",
        "yaml_file": "s2-clash.yaml"  # 米贝77的YAML单独存这个文件
    },
    {
        "name": "Datiya",
        "url": "https://free.datiya.com",
        "yaml_file": "s2-clash-2.yaml"  # Datiya的YAML单独存这个文件
    }
]
NODE_OUTPUT_FILE = "s2.txt"  # 所有网站的txt节点合并到这个文件

def get_latest_article_url(site):
    """适配不同网站，获取最新的节点/订阅文章链接（放宽米贝77的筛选条件）"""
    site_name = site["name"]
    home_url = site["url"]
    print(f"\n========== 开始处理 [{site_name}] 网站 ==========")
    
    try:
        resp = requests.get(home_url, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        article_candidates = []
        today = datetime.now().strftime("%Y%m%d")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")
        recent_dates = [today, yesterday]  # 近2天的日期

        if site_name == "米贝77":
            # 【修复点1】放宽筛选：只要链接含近2天日期，且是文章链接（即使标题无关键词）
            for a in soup.find_all('a', href=True):
                href = a['href']
                text = a.get_text(strip=True) + (a.get('title', ''))
                # 条件：链接是http开头 + 含近2天日期 + （标题有关键词 或 链接含订阅相关后缀）
                if (href.startswith("http") 
                    and any(d in href for d in recent_dates)
                    and (("节点" in text or "订阅" in text or "免费" in text) 
                         or any(suffix in href for suffix in [".txt", ".yaml"]))):
                    article_candidates.append((href, text))
            # 按链接排序取最新
            if article_candidates:
                article_candidates.sort(key=lambda x: x[0], reverse=True)
                latest_url, latest_title = article_candidates[0]
                print(f"✅ [{site_name}] 找到最新文章：{latest_title}")
                print(f"   链接：{latest_url}")
                return latest_url

        elif site_name == "Datiya":
            # 适配datiya的链接特征：/post/日期/格式+关键词
            for a in soup.find_all('a', href=True):
                href = a['href']
                title = a.get_text(strip=True) or a.get('title', '')
                if ("节点" in title or "订阅" in title or "免费" in title) and href.startswith("/post/"):
                    date_str = href.replace("/post/", "").strip("/")
                    try:
                        # 只筛选近2天的文章
                        article_date = datetime.strptime(date_str, "%Y%m%d")
                        if (datetime.now() - article_date).days <= 1:
                            full_url = f"{home_url}{href}"
                            article_candidates.append((article_date, full_url, title))
                    except:
                        continue
            # 按日期排序取最新
            if article_candidates:
                article_candidates.sort(key=lambda x: x[0], reverse=True)
                _, latest_url, latest_title = article_candidates[0]
                print(f"✅ [{site_name}] 找到最新文章：{latest_title}")
                print(f"   链接：{latest_url}")
                return latest_url

        print(f"❌ [{site_name}] 未找到近2天的最新文章")
        return None

    except Exception as e:
        print(f"❌ [{site_name}] 获取首页失败：{e}")
        return None

def extract_sub_links(article_url, site_name):
    """从文章中提取txt和yaml链接（优化米贝77的txt链接提取）"""
    try:
        resp = requests.get(article_url, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        text = resp.text
        soup = BeautifulSoup(text, 'html.parser')

        sub_links = set()  # .txt节点链接/Base64节点
        yaml_links = set() # .yaml配置链接
        exclude_domains = ["reddit", "telegram", "twitter", "facebook"]

        # 【修复点2】米贝77的mm子域名txt链接：直接保留（无需关键词过滤）
        if site_name == "米贝77":
            mm_txt_links = re.findall(r'https?://mm\.mibei77\.com/[^\s<>"\']*\.txt', text)
            sub_links.update(mm_txt_links)
            # 其他域名的txt链接再过滤关键词
            other_txt = re.findall(r'https?://(?!mm\.mibei77\.com)[^\s<>"\']*\.txt', text)
        else:
            # Datiya的txt链接正常过滤关键词
            other_txt = re.findall(r'https?://[^\s<>"\']*\.txt', text)
        
        # 过滤其他txt链接的关键词
        for link in other_txt:
            if any(k in link.lower() for k in ["sub", "node", "v2ray", "clash", "bagtr"]):
                sub_links.add(link)

        # 提取所有.yaml链接（含clash关键词）
        yaml_links_raw = re.findall(r'https?://[^\s<>"\']*\.yaml', text)
        for link in yaml_links_raw:
            if "clash" in link.lower():
                yaml_links.add(link)

        # 提取文章内的Base64格式节点（直接写的长字符串）
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

        # 过滤社交类无用链接
        sub_links = {l for l in sub_links if not any(ex in l for ex in exclude_domains)}
        yaml_links = {l for l in yaml_links if not any(ex in l for ex in exclude_domains)}

        # 日志输出提取结果（清晰展示数量和具体链接）
        print(f"\n📌 [{site_name}] 提取结果：")
        print(f"   - 有效.txt/Base64节点源：{len(sub_links)} 个")
        for i, l in enumerate(sorted(sub_links), 1):
            print(f"     {i}. {l[:70]}..." if len(l) > 70 else f"     {i}. {l}")
        print(f"   - 有效.yaml配置源：{len(yaml_links)} 个")
        for i, l in enumerate(sorted(yaml_links), 1):
            print(f"     {i}. {l[:70]}..." if len(l) > 70 else f"     {i}. {l}")

        return list(sub_links), list(yaml_links)

    except Exception as e:
        print(f"❌ [{site_name}] 解析文章失败：{e}")
        return [], []

def download_nodes(source):
    """下载单个txt/Base64源，返回节点列表（含详细日志）"""
    try:
        # 区分是URL链接还是Base64字符串
        if source.startswith('http'):
            resp = requests.get(source, headers=HEADERS, timeout=20)
            resp.raise_for_status()
            raw_content = resp.text.strip()
        else:
            raw_content = base64.b64decode(source).decode('utf-8', errors='ignore').strip()

        nodes = []
        # 提取明文节点（覆盖主流协议）
        for line in raw_content.split('\n'):
            line = line.strip()
            if line.startswith(('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria://')):
                nodes.append(line)

        # 若没有明文节点，尝试解析每行的Base64编码节点（部分网站的存储方式）
        if not nodes:
            for line in raw_content.split('\n'):
                line = line.strip()
                if len(line) > 50 and re.match(r'^[A-Za-z0-9+/=]+$', line):
                    try:
                        decoded = base64.b64decode(line, validate=True).decode('utf-8', errors='ignore')
                        for sub_line in decoded.split('\n'):
                            sub_line = sub_line.strip()
                            if sub_line.startswith(('vmess://', 'vless://', 'trojan://')):
                                nodes.append(sub_line)
                    except:
                        continue

        print(f"   ✨ 从 [{source[:50]}...] 提取到 {len(nodes)} 个有效节点")
        return nodes

    except Exception as e:
        print(f"   ❌ 处理 [{source[:50]}...] 失败：{e}")
        return []

def download_and_save_yaml(yaml_url, output_file, site_name):
    """下载指定YAML链接并保存到专属文件，返回是否成功"""
    try:
        resp = requests.get(yaml_url, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        yaml_content = resp.text.strip()
        # 保存到该网站专属的YAML文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        print(f"✅ [{site_name}] YAML配置已保存到：{output_file}")
        return True
    except Exception as e:
        print(f"❌ [{site_name}] 下载YAML失败 [{yaml_url[:70]}...]：{e}")
        return False

def main():
    print("========== 开始抓取两个网站的最新资源 ==========")
    all_nodes = []  # 存储所有网站的节点（去重前）

    # 遍历每个目标网站，逐个处理
    for site in TARGET_SITES:
        site_name = site["name"]
        yaml_output = site["yaml_file"]
        
        # 1. 获取该网站最新文章链接
        article_url = get_latest_article_url(site)
        if not article_url:
            continue
        
        # 2. 从文章中提取txt节点源和yaml配置链接
        sub_links, yaml_links = extract_sub_links(article_url, site_name)
        
        # 3. 下载并收集该网站的txt节点（用于后续合并）
        if sub_links:
            print(f"\n📥 [{site_name}] 开始下载节点源：")
            for src in sub_links:
                nodes = download_nodes(src)
                all_nodes.extend(nodes)
                time.sleep(0.5)  # 防请求过快被拦截
        
        # 4. 下载并保存该网站的YAML配置（优先第一个可用的）
        if yaml_links:
            print(f"\n📥 [{site_name}] 开始下载YAML配置：")
            yaml_downloaded = False
            for yaml_url in yaml_links:
                if download_and_save_yaml(yaml_url, yaml_output, site_name):
                    yaml_downloaded = True
                    break
            if not yaml_downloaded:
                print(f"❌ [{site_name}] 所有YAML链接下载失败，{yaml_output} 未生成")
        else:
            print(f"\n❌ [{site_name}] 未找到任何YAML配置链接，{yaml_output} 未生成")

    # ========== 处理所有网站的节点：合并、去重、保存 ==========
    print("\n========== 所有节点合并去重 ==========")
    # 节点去重（保持顺序，避免重复）
    seen_nodes = set()
    unique_nodes = []
    for node in all_nodes:
        if node not in seen_nodes:
            seen_nodes.add(node)
            unique_nodes.append(node)
    
    # 保存合并后的节点到s2.txt（Base64编码，兼容客户端导入）
    if unique_nodes:
        node_content = '\n'.join(unique_nodes)
        encoded_content = base64.b64encode(node_content.encode('utf-8')).decode('utf-8')
        with open(NODE_OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(encoded_content)
        print(f"✅ 两个网站节点合并完成：共 {len(unique_nodes)} 个唯一节点")
        print(f"   已保存到 {NODE_OUTPUT_FILE}（Base64编码）")
    else:
        print(f"❌ 未提取到任何有效节点，{NODE_OUTPUT_FILE} 未生成")

    print("\n========== 抓取任务全部完成 ==========")

if __name__ == "__main__":
    main()
