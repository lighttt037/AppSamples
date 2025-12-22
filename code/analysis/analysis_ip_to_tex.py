#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP地址归属地和运营商统计分析脚本
读取ip_analysis_processed.txt和ip_region_analysis_split_package.txt
统计各个运营商和归属地的IP数量和APP数量
"""

import re
from datetime import datetime

def parse_ip_processed_file(filepath):
    """解析ip_analysis_processed.txt文件"""
    ip_data = {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    # 解析格式: IP地址  数量  归属地信息  数量
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        count = int(parts[1])
                        # 归属地信息在第三个位置
                        location_info = parts[2]
                        ip_data[ip] = {
                            'count': count,
                            'location': location_info
                        }
    except FileNotFoundError:
        print(f"文件 {filepath} 未找到")
    except Exception as e:
        print(f"解析文件 {filepath} 时出错: {e}")

    return ip_data

def parse_ip_region_split_file(filepath):
    """解析ip_region_analysis_split_package.txt文件"""
    ip_region_data = {}
    current_ip = None
    current_location = None
    current_apps = []
    in_apps_section = False

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                original_line = line
                line = line.strip()

                # 匹配IP地址行
                if line.startswith('IP地址:'):
                    # 保存上一个IP的数据
                    if current_ip:
                        ip_region_data[current_ip] = {
                            'location': current_location,
                            'apps': current_apps.copy()
                        }

                    # 开始新的IP记录
                    current_ip = line.split(':', 1)[1].strip()
                    current_apps = []
                    current_location = None
                    in_apps_section = False

                # 匹配归属地行
                elif line.startswith('归属地:'):
                    current_location = line.split(':', 1)[1].strip()
                    # 处理可能的前导空格问题
                    if current_location.startswith(' '):
                        current_location = current_location.strip()
                    in_apps_section = False

                # 匹配关联的应用标题行
                elif line.startswith('关联的应用:'):
                    in_apps_section = True

                # 在应用区域内，匹配应用包名行
                elif in_apps_section:
                    # 匹配应用包名行 - 支持多种格式
                    if line.startswith('  - 包名:') or line.startswith('- 包名:') or line.startswith('包名:'):
                        app_name = line.split(':', 1)[1].strip()
                        current_apps.append(app_name)

                # 匹配分隔符行，表示当前IP记录结束
                elif line.startswith('----'):
                    in_apps_section = False

        # 保存最后一个IP的数据
        if current_ip:
            ip_region_data[current_ip] = {
                'location': current_location,
                'apps': current_apps.copy()
            }

    except FileNotFoundError:
        print(f"文件 {filepath} 未找到")
    except Exception as e:
        print(f"解析文件 {filepath} 时出错: {e}")

    return ip_region_data

def extract_provider_and_location(location_str):
    """从归属地字符串中提取运营商和地理位置信息"""
    if not location_str:
        return "未知", "未知"

    # 处理格式: 中国|天津市|天津|tencent 或 美国|0|华盛顿|0|亚马逊
    parts = location_str.split('|')

    # 提取运营商(最后一个部分)
    provider = parts[-1] if parts else "未知"

    # 提取地理位置(前几个部分)
    if len(parts) >= 3:
        country = parts[0]
        province = parts[1] if parts[1] != '0' else ''
        city = parts[2] if parts[2] != '0' else ''

        location_parts = [country]
        if province:
            location_parts.append(province)
        if city:
            location_parts.append(city)

        location = '|'.join(location_parts)
    else:
        location = location_str

    return provider, location

def generate_statistics(ip_processed_data, ip_region_data):
    """生成统计数据"""
    provider_stats = {}
    location_stats = {}
    country_stats = {}

    for ip, processed_info in ip_processed_data.items():
        # 从processed文件获取基本信息
        provider, location = extract_provider_and_location(processed_info['location'])

        # 尝试从region文件获取更详细的应用信息
        apps = set()
        if ip in ip_region_data:
            region_info = ip_region_data[ip]
            apps = set(region_info['apps'])

            # 如果region文件有更详细的归属地信息，使用它
            if region_info['location']:
                provider_alt, location_alt = extract_provider_and_location(region_info['location'])
                if provider_alt != "未知":
                    provider = provider_alt
                if location_alt != "未知":
                    location = location_alt

        # 提取国家信息
        country = location.split('|')[0] if '|' in location else location

        # 更新运营商统计
        if provider not in provider_stats:
            provider_stats[provider] = {'ip_count': 0, 'app_count': 0, 'apps': set()}
        provider_stats[provider]['ip_count'] += 1
        provider_stats[provider]['apps'].update(apps)
        provider_stats[provider]['app_count'] = len(provider_stats[provider]['apps'])

        # 更新归属地统计
        if location not in location_stats:
            location_stats[location] = {'ip_count': 0, 'app_count': 0, 'apps': set()}
        location_stats[location]['ip_count'] += 1
        location_stats[location]['apps'].update(apps)
        location_stats[location]['app_count'] = len(location_stats[location]['apps'])

        # 更新国家统计
        if country not in country_stats:
            country_stats[country] = {'ip_count': 0, 'app_count': 0, 'apps': set(), 'locations': set()}
        country_stats[country]['ip_count'] += 1
        country_stats[country]['apps'].update(apps)
        country_stats[country]['app_count'] = len(country_stats[country]['apps'])
        country_stats[country]['locations'].add(location)

    return provider_stats, location_stats, country_stats

def write_tex_output(provider_stats, location_stats, country_stats, output_file):
    """将统计结果写入LaTeX格式的文件"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("% IP地址归属地和运营商统计分析报告\n")
            f.write("% 生成时间: " + str(datetime.now()) + "\n\n")

            # 运营商统计表格
            f.write("\\section{运营商统计}\n")
            f.write("\\begin{table}[h]\n")
            f.write("\\centering\n")
            f.write("\\caption{各运营商IP数量和APP数量统计}\n")
            f.write("\\begin{tabular}{|l|c|c|}\n")
            f.write("\\hline\n")
            f.write("运营商 & IP数量 & APP数量 \\\\\n")
            f.write("\\hline\n")

            # 按IP数量排序
            sorted_providers = sorted(provider_stats.items(),
                                    key=lambda x: x[1]['ip_count'], reverse=True)

            for provider, stats in sorted_providers:
                f.write(f"{provider} & {stats['ip_count']} & {stats['app_count']} \\\\\n")
                f.write("\\hline\n")

            f.write("\\end{tabular}\n")
            f.write("\\end{table}\n\n")

            # 归属地统计表格
            f.write("\\section{归属地统计}\n")
            f.write("\\begin{table}[h]\n")
            f.write("\\centering\n")
            f.write("\\caption{各归属地IP数量和APP数量统计}\n")
            f.write("\\begin{tabular}{|l|c|c|}\n")
            f.write("\\hline\n")
            f.write("归属地 & IP数量 & APP数量 \\\\\n")
            f.write("\\hline\n")

            # 按IP数量排序
            sorted_locations = sorted(location_stats.items(),
                                    key=lambda x: x[1]['ip_count'], reverse=True)

            for location, stats in sorted_locations:
                f.write(f"{location} & {stats['ip_count']} & {stats['app_count']} \\\\\n")
                f.write("\\hline\n")

            f.write("\\end{tabular}\n")
            f.write("\\end{table}\n\n")

            # 国家统计表格
            f.write("\\section{国家统计}\n")
            f.write("\\begin{table}[h]\n")
            f.write("\\centering\n")
            f.write("\\caption{各国家IP数量、APP数量和归属地数量统计}\n")
            f.write("\\begin{tabular}{|l|c|c|c|}\n")
            f.write("\\hline\n")
            f.write("国家 & IP数量 & APP数量 & 归属地数量 \\\\\n")
            f.write("\\hline\n")

            # 按IP数量排序
            sorted_countries = sorted(country_stats.items(),
                                    key=lambda x: x[1]['ip_count'], reverse=True)

            for country, stats in sorted_countries:
                location_count = len(stats['locations'])
                f.write(f"{country} & {stats['ip_count']} & {stats['app_count']} & {location_count} \\\\\n")
                f.write("\\hline\n")

            f.write("\\end{tabular}\n")
            f.write("\\end{table}\n\n")

            # 总体统计
            total_ips = sum(stats['ip_count'] for stats in provider_stats.values())
            total_apps = len(set().union(*[stats['apps'] for stats in provider_stats.values()]))

            f.write("\\section{总体统计}\n")
            f.write(f"总IP数量: {total_ips}\\\\\n")
            f.write(f"总APP数量: {total_apps}\\\\\n")
            f.write(f"运营商数量: {len(provider_stats)}\\\\\n")
            f.write(f"归属地数量: {len(location_stats)}\\\\\n")
            f.write(f"国家数量: {len(country_stats)}\\\\\n")

    except Exception as e:
        print(f"写入输出文件时出错: {e}")

def main():
    """主函数"""

    # 输入文件路径
    ip_processed_file = "ip_analysis_processed.txt"
    ip_region_file = "ip_region_analysis_split_package.txt"
    output_file = "analyasis_ip_to_tex.txt"

    print("开始分析IP地址数据...")

    # 解析输入文件
    print("解析ip_analysis_processed.txt...")
    ip_processed_data = parse_ip_processed_file(ip_processed_file)
    print(f"解析到 {len(ip_processed_data)} 个IP地址")

    print("解析ip_region_analysis_split_package.txt...")
    ip_region_data = parse_ip_region_split_file(ip_region_file)
    print(f"解析到 {len(ip_region_data)} 个IP地址的详细信息")

    # 添加调试信息：检查应用解析是否正确
    app_count = sum(len(data['apps']) for data in ip_region_data.values())
    print(f"总共解析到 {app_count} 个应用关联")

    # 显示前几个有应用的IP示例
    sample_count = 0
    for ip, data in ip_region_data.items():
        if data['apps'] and sample_count < 3:
            print(f"示例: IP {ip} 关联应用: {data['apps']}")
            sample_count += 1

    # 生成统计数据
    print("生成统计数据...")
    provider_stats, location_stats, country_stats = generate_statistics(ip_processed_data, ip_region_data)

    # 输出结果
    print("生成LaTeX格式报告...")
    write_tex_output(provider_stats, location_stats, country_stats, output_file)

    print(f"分析完成！结果已保存到 {output_file}")
    print(f"运营商统计: {len(provider_stats)} 个运营商")
    print(f"归属地统计: {len(location_stats)} 个归属地")
    print(f"国家统计: {len(country_stats)} 个国家")

if __name__ == "__main__":
    main()