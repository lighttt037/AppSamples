import re
import os
import glob
from typing import List, Dict, Set, Optional
from collections import Counter
import sys

# 添加ip2region库路径
sys.path.append(r".\ip2region-master\binding\python")
from xdbSearcher import XdbSearcher

def get_public_ips(content: str) -> List[str]:
    """提取Public IP Addresses段落中的所有IP地址"""
    pattern = r"======== Public IP Addresses ========\s*([\s\S]*?)(?=\n=|$)"
    match = re.search(pattern, content)

    if match:
        result = match.group(1).strip()
        # 提取IP地址
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, result)
        return ips
    return []

def get_apk_info(filename: str) -> Dict[str, Optional[str]]:
    """
    根据文件名推断对应的APK信息

    Args:
        filename: pcap结果文件名 (如: aavnhm.ttbu.lwtly.zqgw.txt)

    Returns:
        包含包名和应用名的字典
    """
    # 多个搜索目录
    search_dirs = [
        r"D:\Documents\Working\实验室\赌博诈骗apk处理\permissionandcert\apkinfo",
        r"D:\Documents\Working\实验室\赌博诈骗apk处理\apkinfo",
        r"D:\Documents\Working\实验室\赌博诈骗apk处理\apkinfonew"
    ]

    # 从文件名中提取可能的包名部分
    base_name = os.path.splitext(filename)[0]

    # 在所有目录中搜索匹配的文件
    for apk_info_dir in search_dirs:
        if not os.path.exists(apk_info_dir):
            continue

        # 搜索包含相似名称的文件
        for apk_file in os.listdir(apk_info_dir):
            if apk_file.endswith('.txt') and base_name in apk_file:
                try:
                    apk_info_file = os.path.join(apk_info_dir, apk_file)

                    # 从文件名中提取包名
                    if '.apk_' in apk_file:
                        package_name = apk_file.split('.apk_')[1].replace('.txt', '')
                    else:
                        package_name = "未知包名"

                    # 读取文件内容提取应用名
                    with open(apk_info_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # 提取application-label
                    app_name_match = re.search(r"application-label:'([^']+)'", content)
                    app_name = app_name_match.group(1) if app_name_match else "未知应用名"

                    return {"package_name": package_name, "app_name": app_name}

                except Exception as e:
                    print(f"处理APK信息文件时发生错误: {e}")
                    continue

    # 没有找到匹配文件
    return {"package_name": "未找到", "app_name": "未找到"}

def query_ip_region(ip: str, searcher: XdbSearcher) -> str:
    """查询IP地址的归属地信息"""
    try:
        region_str = searcher.searchByIPStr(ip)
        return region_str if region_str else "未知地区"
    except Exception as e:
        return f"查询错误: {e}"

def process_pcap_files(directory: str, output_file: str) -> None:
    """
    处理指定目录下的所有pcap结果文件

    Args:
        directory: pcap结果文件目录
        output_file: 输出结果文件路径
    """
    # 初始化ip2region查询器
    db_path = r".\ip2region-master\data\ip2region.xdb"
    if not os.path.exists(db_path):
        print(f"错误: 找不到ip2region数据库文件 {db_path}")
        return

    searcher = XdbSearcher(dbfile=db_path)

    try:
        # 统计数据
        all_ips = []  # 所有IP地址
        ip_region_counter = Counter()  # IP归属地统计
        ip_app_mapping = {}  # IP与应用的关联
        file_count = 0

        # 遍历目录中的所有txt文件
        for filename in os.listdir(directory):
            if filename.endswith(".txt"):
                file_count += 1
                file_path = os.path.join(directory, filename)

                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # 提取Public IP地址
                    public_ips = get_public_ips(content)

                    if public_ips:
                        # 获取APK信息
                        apk_info = get_apk_info(filename)

                        # 处理每个IP地址
                        for ip in public_ips:
                            all_ips.append(ip)

                            # 查询IP归属地
                            region_info = query_ip_region(ip, searcher)
                            ip_region_counter[region_info] += 1

                            # 记录IP与应用的关联
                            if ip not in ip_app_mapping:
                                ip_app_mapping[ip] = []
                            ip_app_mapping[ip].append({
                                'filename': filename,
                                'package_name': apk_info['package_name'],
                                'app_name': apk_info['app_name'],
                                'region': region_info
                            })

                except Exception as e:
                    print(f"处理文件 {filename} 时发生错误: {e}")
                    continue

        # 统计IP频次
        ip_counter = Counter(all_ips)

        # 按国家/省份统计
        country_province_counter = Counter()
        country_province_apps = {}  # 存储每个国家/省份关联的应用
        # 按运营商统计
        isp_counter = Counter()
        isp_apps = {}  # 存储每个运营商关联的应用

        for region_str, count in ip_region_counter.items():
            # 获取该归属地所有相关IP的应用信息
            related_apps = set()
            for ip, apps in ip_app_mapping.items():
                if apps[0]['region'] == region_str:
                    for app in apps:
                        related_apps.add(f"{app['package_name']}_{app['app_name']}")

            # 解析归属地信息: 格式通常为 "国家|0|省份|城市|运营商"
            parts = region_str.split('|')
            if len(parts) >= 5:
                country = parts[0] if parts[0] else "未知国家"
                province = parts[2] if parts[2] and parts[2] != "0" else ""
                isp = parts[4] if parts[4] and parts[4] != "0" else "未知运营商"

                # 构建国家/省份标识
                if province:
                    country_province = f"{country}|{province}"
                else:
                    country_province = country

                country_province_counter[country_province] += count
                if country_province not in country_province_apps:
                    country_province_apps[country_province] = set()
                country_province_apps[country_province].update(related_apps)

                isp_counter[isp] += count
                if isp not in isp_apps:
                    isp_apps[isp] = set()
                isp_apps[isp].update(related_apps)
            else:
                # 处理格式不标准的情况
                country_province_counter["格式异常"] += count
                isp_counter["格式异常"] += count
                if "格式异常" not in country_province_apps:
                    country_province_apps["格式异常"] = set()
                if "格式异常" not in isp_apps:
                    isp_apps["格式异常"] = set()
                country_province_apps["格式异常"].update(related_apps)
                isp_apps["格式异常"].update(related_apps)

        # 写入结果文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("Public IP地址分析报告\n")
            f.write("=" * 80 + "\n")
            f.write(f"处理的文件总数: {file_count}\n")
            f.write(f"提取的IP地址总数: {len(all_ips)}\n")
            f.write(f"去重的IP地址总数: {len(ip_counter)}\n")
            f.write("=" * 80 + "\n\n")

            # IP归属地统计
            f.write("IP归属地统计 (按频次排序)\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'归属地':<50}{'频次':<10}\n")
            f.write("-" * 80 + "\n")
            for region, count in ip_region_counter.most_common():
                f.write(f"{region:<50}{count:<10}\n")
            f.write("\n")

            # 按国家/省份统计
            f.write("按国家/省份统计 (按频次排序)\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'国家/省份':<50}{'频次':<10}{'关联应用数':<10}\n")
            f.write("-" * 80 + "\n")
            for country_province, count in country_province_counter.most_common():
                app_count = len(country_province_apps.get(country_province, set()))
                f.write(f"{country_province:<50}{count:<10}{app_count:<10}\n")
            f.write("\n")

            # 按运营商统计
            f.write("按运营商统计 (按频次排序)\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'运营商':<50}{'频次':<10}{'关联应用数':<10}\n")
            f.write("-" * 80 + "\n")
            for isp, count in isp_counter.most_common():
                app_count = len(isp_apps.get(isp, set()))
                f.write(f"{isp:<50}{count:<10}{app_count:<10}\n")
            f.write("\n")

            # IP地址详细信息
            f.write("IP地址详细信息 (按频次排序)\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'IP地址':<16}{'频次':<6}{'归属地':<30}{'关联应用数':<10}\n")
            f.write("-" * 80 + "\n")
            for ip, count in ip_counter.most_common():
                if ip in ip_app_mapping:
                    region = ip_app_mapping[ip][0]['region']
                    app_count = len(set(app['package_name'] for app in ip_app_mapping[ip]))
                    f.write(f"{ip:<16}{count:<6}{region:<30}{app_count:<10}\n")
            f.write("\n")

            # IP与应用关联详情
            f.write("IP与应用关联详情\n")
            f.write("-" * 80 + "\n")
            for ip in sorted(ip_app_mapping.keys()):
                f.write(f"\nIP地址: {ip}\n")
                f.write(f"归属地: {ip_app_mapping[ip][0]['region']}\n")
                f.write(f"关联的应用:\n")

                # 去重显示关联的应用
                unique_apps = {}
                for app_info in ip_app_mapping[ip]:
                    key = f"{app_info['package_name']}_{app_info['app_name']}"
                    if key not in unique_apps:
                        unique_apps[key] = app_info

                for app_info in unique_apps.values():
                    f.write(f"  - 包名: {app_info['package_name']}\n")
                    f.write(f"    应用名: {app_info['app_name']}\n")
                    f.write(f"    来源文件: {app_info['filename']}\n")
                f.write("-" * 40 + "\n")

        print(f"处理完成！")
        print(f"处理的文件总数: {file_count}")
        print(f"提取的IP地址总数: {len(all_ips)}")
        print(f"去重的IP地址总数: {len(ip_counter)}")
        print(f"结果已保存到: {output_file}")

    finally:
        searcher.close()

def main():
    """主函数"""
    print("Public IP地址归属地分析工具")
    print("=" * 30)

    # 设置输入目录和输出文件
    input_directory = r"D:\Documents\Working\实验室\赌博诈骗apk处理\result\1"
    output_file = "ip_region_analysis.txt"

    if not os.path.exists(input_directory):
        print(f"错误: 输入目录 {input_directory} 不存在")
        return

    # 执行处理
    process_pcap_files(input_directory, output_file)

if __name__ == "__main__":
    main()