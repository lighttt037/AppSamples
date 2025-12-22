#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
from collections import defaultdict

def parse_search_results(file_path):
    """
    解析txt文件，提取包含not found URL的APK信息
    """
    # 排除列表
    exclude_domains = [
        'wocloud.cn',
        'dnsvip1.net',
        'aliyunceng.com',
        'dcloud.net.cn',
        'appbsl.net',
        'bilibili.com',
        'googleapis.com',
        'imtt.qq.com',
        'android.com',
        'netease.com',
        'yimenyun.cn',
        'yimenseo.cn',
        'yimenseo.net'
    ]

    # 存储结果
    apk_records = []
    unique_hashes = set()

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"读取文件失败: {e}")
        return apk_records, unique_hashes

    # 按==================================================分割子类
    sections = content.split('==================================================')

    for section in sections:
        if not section.strip():
            continue

        # 提取APK包名和哈希值
        apk_info = extract_apk_info(section)
        if not apk_info:
            continue

        # 查找not found的URL
        not_found_urls = find_not_found_urls(section, exclude_domains)

        if not_found_urls:
            # 记录这个APK
            record = {
                'package_name': apk_info['package_name'],
                'hash': apk_info['hash'],
                'not_found_urls': not_found_urls
            }
            apk_records.append(record)
            unique_hashes.add(apk_info['hash'])

    return apk_records, unique_hashes

def extract_apk_info(section):
    """
    从section中提取APK包名和哈希值
    """
    # 提取PCAP文件名（作为包名）
    pcap_match = re.search(r'\[.*\] Processing PCAP file: (.+?)\.txt', section)
    if not pcap_match:
        return None

    package_name = pcap_match.group(1)

    # 提取哈希值
    hash_match = re.search(r'\[.*\] Extracted hash: ([a-f0-9]{32})', section)
    if not hash_match:
        return None

    hash_value = hash_match.group(1)

    return {
        'package_name': package_name,
        'hash': hash_value
    }

def find_not_found_urls(section, exclude_domains):
    """
    查找section中not found的URL，排除指定域名
    """
    not_found_urls = []

    # 先找到所有的"URL not found"行，然后提取URL
    lines = section.split('\n')
    for line in lines:
        # 匹配 "[-] URL not found in project: xxxxx" 格式
        match = re.search(r'\[-\] URL not found in project: (.+)', line)
        if match:
            url = match.group(1).strip()
            # 检查是否在排除列表中
            should_exclude = False
            for exclude_domain in exclude_domains:
                if exclude_domain in url:
                    should_exclude = True
                    break

            if not should_exclude:
                not_found_urls.append(url)

    return not_found_urls

def main():
    if len(sys.argv) != 2:
        print("使用方法: python analysis_searchurl.py <txt文件路径>")
        sys.exit(1)

    file_path = sys.argv[1]
    output_file = "analysis_searchurl_result_new.txt"

    print("开始解析文件...")
    apk_records, unique_hashes = parse_search_results(file_path)

    # 写入结果到文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=== 分析结果 ===\n")
        f.write(f"共找到 {len(apk_records)} 个包含not found URL的APK\n")
        f.write(f"涉及 {len(unique_hashes)} 个不同的哈希值\n")

        f.write("\n=== 详细记录 ===\n")
        for i, record in enumerate(apk_records, 1):
            f.write(f"\n{i}. APK信息:\n")
            f.write(f"   包名: {record['package_name']}\n")
            f.write(f"   哈希: {record['hash']}\n")
            f.write(f"   未找到的URL ({len(record['not_found_urls'])}个):\n")
            for url in record['not_found_urls']:
                f.write(f"     - {url}\n")

        f.write(f"\n=== 统计汇总 ===\n")
        f.write(f"不同哈希值列表:\n")
        for hash_value in sorted(unique_hashes):
            f.write(f"  - {hash_value}\n")

        f.write(f"\n总计: {len(unique_hashes)} 个不同的哈希值\n")

    print(f"解析完成，结果已保存到: {output_file}")
    print(f"共找到 {len(apk_records)} 个包含not found URL的APK")
    print(f"涉及 {len(unique_hashes)} 个不同的哈希值")

if __name__ == "__main__":
    main()