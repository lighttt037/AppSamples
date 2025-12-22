#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITM数据分析脚本
解析txt文件，过滤JS请求和指定域名请求，统计剩余请求的文件名称和个数
"""

import re
import os
from collections import defaultdict

# 排除域名列表
EXCLUDED_DOMAINS = [
    'mumu.163.com',
    'netease.com',
    'vscode-cdn.net',
    'login.live.com',
    'baidu.com',
    'bilibili.com',
    'sohu.com',
    'edge.microsoft.com',
    'netease.im',
    'update.googleapis.com'
]

def is_js_request(url):
    """判断是否为JS请求"""
    return url.lower().endswith('.js') or '/js/' in url.lower()

def is_excluded_domain(url):
    """判断URL是否包含排除的域名"""
    for domain in EXCLUDED_DOMAINS:
        if domain in url:
            return True
    return False

def parse_mitm_file(file_path):
    """解析MITM文件"""
    results = defaultdict(list)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"读取文件失败: {e}")
        return results

    # 按文件分割内容
    file_sections = re.split(r'文件:\s*([^\n]+)', content)[1:]  # 去除第一个空元素

    for i in range(0, len(file_sections), 2):
        if i + 1 >= len(file_sections):
            break

        filename = file_sections[i].strip()
        file_content = file_sections[i + 1]

        # 提取URL
        url_pattern = r'URL:\s*(https?://[^\s\n]+)'
        urls = re.findall(url_pattern, file_content)

        for url in urls:
            # 过滤JS请求和排除域名
            if not is_js_request(url) and not is_excluded_domain(url):
                results[filename].append(url)

    return results

def analyze_results(results, output_file="analysis_mitm.txt"):
    """分析结果并输出到文件"""
    # 准备输出内容
    output_lines = []
    output_lines.append("=" * 60)
    output_lines.append("MITM数据分析结果")
    output_lines.append("=" * 60)

    # 统计有效文件（去除过滤后仍有请求的文件）
    valid_files = {filename: urls for filename, urls in results.items() if urls}

    output_lines.append(f"总文件数: {len(results)}")
    output_lines.append(f"过滤后仍有请求的文件数: {len(valid_files)}")
    output_lines.append("")

    if not valid_files:
        output_lines.append("没有找到符合条件的请求")
        # 输出到文件和控制台
        output_content = "\n".join(output_lines)
        print(output_content)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_content)
        return

    output_lines.append("详细统计:")
    output_lines.append("-" * 40)

    total_requests = 0
    for filename, urls in valid_files.items():
        request_count = len(urls)
        total_requests += request_count
        output_lines.append(f"文件: {filename}")
        output_lines.append(f"  请求数: {request_count}")

        # 显示前5个URL作为示例
        output_lines.append("  示例URL:")
        for url in urls[:5]:
            output_lines.append(f"    {url}")
        if len(urls) > 5:
            output_lines.append(f"    ... 还有 {len(urls) - 5} 个URL")
        output_lines.append("")

    output_lines.append("=" * 60)
    output_lines.append(f"总计过滤后的请求数: {total_requests}")
    output_lines.append("=" * 60)

    # 输出到文件和控制台
    output_content = "\n".join(output_lines)
    print(output_content)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_content)
        print(f"\n分析结果已保存到: {output_file}")
    except Exception as e:
        print(f"\n保存文件失败: {e}")

def main():
    # 默认文件路径
    default_file = "mitm_result_new.txt"

    # 检查文件是否存在
    if os.path.exists(default_file):
        file_path = default_file
    else:
        file_path = input("请输入MITM数据文件路径: ").strip()
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            return

    print(f"正在分析文件: {file_path}")
    print(f"排除域名: {', '.join(EXCLUDED_DOMAINS)}")
    print("排除JS请求")
    print()

    # 解析文件
    results = parse_mitm_file(file_path)

    # 分析结果
    analyze_results(results,'analysis_mitm_new.txt')

if __name__ == "__main__":
    main()