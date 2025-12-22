import re
import requests
import os
from urllib.parse import urlparse

def extract_urls(file_path):
    """从文本文件中提取所有 http(s)://...apk 的 URL"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        text = file.read()
    urls = re.findall(r'https?://[^\s"]+?\.apk', text, re.IGNORECASE)
    return list(set(urls))  # 去重

def filter_urls(urls, exclude_keywords):
    """过滤掉包含特定关键词的 URL"""
    filtered = []
    for url in urls:
        if not any(keyword in url.lower() for keyword in exclude_keywords):
            filtered.append(url)
    return filtered

def download_apk(url, download_dir="downloads"):
    """尝试下载 APK 文件"""
    try:
        # 检查 URL 是否有效
        head_response = requests.head(url, allow_redirects=True, timeout=10)
        if head_response.status_code != 200:
            print(f"[SKIP] 无法访问: {url} (HTTP {head_response.status_code})")
            return False

        # 获取文件名
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        if not filename.endswith('.apk'):
            filename = "downloaded.apk"

        # 创建下载目录
        os.makedirs(download_dir, exist_ok=True)
        filepath = os.path.join(download_dir, filename)

        # 下载文件
        print(f"[DOWNLOADING] {url}")
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()

        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[SUCCESS] 下载完成: {filepath}")
        return True

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] 下载失败: {url} - {str(e)}")
        return False

def main():
    # 输入文件路径
    input_file = "D:\\Documents\\Working\\实验室\\赌博诈骗apk处理\\mitm_apk_string_search.txt"  # 替换为你的 TXT 文件路径
    if not os.path.exists(input_file):
        print(f"错误: 文件 {input_file} 不存在！")
        return

    # 提取 URL
    urls = extract_urls(input_file)
    print(f"找到 {len(urls)} 个 APK URL")

    # 过滤关键词（可自定义）
    exclude_keywords = ["static.yximgs.com","KSAdSDk","babybus","ks_","mumu",'netease']
    filtered_urls = filter_urls(urls, exclude_keywords)
    print(f"过滤后剩余 {len(filtered_urls)} 个 URL")

    for url in filtered_urls:
        print(url)
    # 依次测试下载
    for url in filtered_urls:
        download_apk(url, "try_apks_direct_string_search_mitm")

#"http://down.nishuoa.com/fengwocps.apk";
if __name__ == "__main__":
    main()
