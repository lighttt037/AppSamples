# filepath: d:\Documents\Working\实验室\赌博诈骗apk处理\analysis_result.py

import re
import os
import glob
from typing import Set, Dict, List, Optional, Tuple, Any

def get_apk_info(package_name: str) -> Dict[str, Any]:
    """
    根据包名搜索对应的APK信息文件，验证包名是否真实存在

    Args:
        package_name: Android包名

    Returns:
        包含包名验证结果和应用名的字典
    """
    # 多个搜索目录
    search_dirs = [
        r"D:\Documents\Working\实验室\赌博诈骗apk处理\permissionandcert\apkinfo",
        r"D:\Documents\Working\实验室\赌博诈骗apk处理\apkinfo",
        r"D:\Documents\Working\实验室\赌博诈骗apk处理\apkinfonew"
    ]

    # 在所有目录中搜索匹配的文件
    for apk_info_dir in search_dirs:
        if not os.path.exists(apk_info_dir):
            continue

        # 搜索包含该包名的文件 *.apk_{包名}.txt
        pattern = os.path.join(apk_info_dir, f"*.apk_{package_name}.txt")
        matching_files = glob.glob(pattern)

        if matching_files:
            # 找到匹配文件，处理第一个
            apk_info_file = matching_files[0]

            try:
                # 读取文件内容提取应用名
                with open(apk_info_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # 提取application-label
                app_name_match = re.search(r"application-label:'([^']+)'", content)
                app_name = app_name_match.group(1) if app_name_match else None

                return {"exists": True, "app_name": app_name, "file_path": apk_info_file}

            except Exception as e:
                print(f"处理APK信息文件时发生错误: {e}")
                continue

    # 所有目录都没有找到匹配文件
    return {"exists": False, "app_name": None, "file_path": None}

def extract_package_name_from_filename(filename: str) -> Optional[str]:
    """
    从文件名中提取包名

    Args:
        filename: 文件名

    Returns:
        提取的包名，如果无法提取则返回None
    """
    # 移除文件扩展名
    name_without_ext = os.path.splitext(filename)[0]

    # 尝试多种包名提取模式
    patterns = [
        r'([a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+)',  # 标准包名格式
        r'([a-zA-Z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*)+)',  # 宽松包名格式
    ]

    for pattern in patterns:
        matches = re.findall(pattern, name_without_ext)
        if matches:
            # 返回最长的匹配项（通常是完整包名）
            return max(matches, key=len)

    return None

def parse_result_detail_file(file_path: str, exclude_urls: Set[str]) -> Dict:
    """
    解析结果详情文件，提取文件信息和URL数据

    Args:
        file_path: 结果详情文件路径
        exclude_urls: 需要排除的URL集合

    Returns:
        解析结果字典
    """
    results = {
        "total_files": 0,
        "files_with_urls": [],
        "files_without_urls": [],
        "url_statistics": {
            "only_in_1_total": 0,
            "only_in_2_total": 0,
            "only_in_1_after_filter": 0,
            "only_in_2_after_filter": 0
        }
    }

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 分割文件块
        file_blocks = content.split('================')

        for block in file_blocks:
            block = block.strip()
            if not block:
                continue

            lines = block.split('\n')
            if len(lines) < 3:
                continue

            # 提取文件名
            file_line = lines[0].strip()
            if not file_line.startswith('File:'):
                continue

            filename = file_line.replace('File:', '').strip()
            results["total_files"] += 1

            # 提取Only in 1和Only in 2的内容
            only_in_1_urls = set()
            only_in_2_urls = set()

            current_section = None
            for line in lines[1:]:
                line = line.strip()
                if line.startswith('Only in 1:'):
                    current_section = "only_in_1"
                    url_content = line.replace('Only in 1:', '').strip()
                    if url_content:
                        urls = [url.strip() for url in url_content.split(',') if url.strip()]
                        only_in_1_urls.update(urls)
                elif line.startswith('Only in 2:'):
                    current_section = "only_in_2"
                    url_content = line.replace('Only in 2:', '').strip()
                    if url_content:
                        urls = [url.strip() for url in url_content.split(',') if url.strip()]
                        only_in_2_urls.update(urls)
                elif current_section == "only_in_1" and line and not line.startswith('Only in'):
                    urls = [url.strip() for url in line.split(',') if url.strip()]
                    only_in_1_urls.update(urls)
                elif current_section == "only_in_2" and line and not line.startswith('Only in'):
                    urls = [url.strip() for url in line.split(',') if url.strip()]
                    only_in_2_urls.update(urls)

            # 统计原始URL数量
            results["url_statistics"]["only_in_1_total"] += len(only_in_1_urls)
            results["url_statistics"]["only_in_2_total"] += len(only_in_2_urls)

            # 过滤排除的URL
            filtered_only_in_1 = only_in_1_urls - exclude_urls
            filtered_only_in_2 = only_in_2_urls - exclude_urls

            # 统计过滤后URL数量
            results["url_statistics"]["only_in_1_after_filter"] += len(filtered_only_in_1)
            results["url_statistics"]["only_in_2_after_filter"] += len(filtered_only_in_2)

            # 判断文件是否仍有URL
            if filtered_only_in_1 or filtered_only_in_2:
                file_info = {
                    "filename": filename,
                    "only_in_1_count": len(filtered_only_in_1),
                    "only_in_2_count": len(filtered_only_in_2),
                    "only_in_1_urls": list(filtered_only_in_1),
                    "only_in_2_urls": list(filtered_only_in_2),
                    "package_name": extract_package_name_from_filename(filename)
                }
                results["files_with_urls"].append(file_info)
            else:
                results["files_without_urls"].append(filename)

    except Exception as e:
        print(f"解析文件时发生错误: {e}")

    return results

def analyze_package_names(files_with_urls: List[Dict]) -> Dict:
    """
    分析包名的真实性

    Args:
        files_with_urls: 包含URL的文件信息列表

    Returns:
        包名分析结果
    """
    package_analysis = {
        "total_files_with_package": 0,
        "existing_packages": [],
        "non_existing_packages": [],
        "no_package_extracted": []
    }

    for file_info in files_with_urls:
        package_name = file_info.get("package_name")

        if package_name:
            package_analysis["total_files_with_package"] += 1

            # 验证包名是否存在
            apk_info = get_apk_info(package_name)

            if apk_info["exists"]:
                package_analysis["existing_packages"].append({
                    "filename": file_info["filename"],
                    "package_name": package_name,
                    "app_name": apk_info["app_name"],
                    "apk_file_path": apk_info["file_path"],
                    "url_count": file_info["only_in_1_count"] + file_info["only_in_2_count"]
                })
            else:
                package_analysis["non_existing_packages"].append({
                    "filename": file_info["filename"],
                    "package_name": package_name,
                    "url_count": file_info["only_in_1_count"] + file_info["only_in_2_count"]
                })
        else:
            package_analysis["no_package_extracted"].append({
                "filename": file_info["filename"],
                "url_count": file_info["only_in_1_count"] + file_info["only_in_2_count"]
            })

    return package_analysis

def generate_analysis_report(results: Dict, package_analysis: Dict, output_file: str) -> None:
    """
    生成分析报告

    Args:
        results: 解析结果
        package_analysis: 包名分析结果
        output_file: 输出文件路径
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("URL分析和包名验证报告\n")
        f.write("=" * 80 + "\n\n")

        # 总体统计
        f.write("总体统计:\n")
        f.write("-" * 40 + "\n")
        f.write(f"总文件数量: {results['total_files']}\n")
        f.write(f"过滤后仍有URL的文件数量: {len(results['files_with_urls'])}\n")
        f.write(f"过滤后无URL的文件数量: {len(results['files_without_urls'])}\n\n")

        # URL统计
        f.write("URL统计:\n")
        f.write("-" * 40 + "\n")
        url_stats = results["url_statistics"]
        f.write(f"Only in 1 原始URL总数: {url_stats['only_in_1_total']}\n")
        f.write(f"Only in 2 原始URL总数: {url_stats['only_in_2_total']}\n")
        f.write(f"Only in 1 过滤后URL总数: {url_stats['only_in_1_after_filter']}\n")
        f.write(f"Only in 2 过滤后URL总数: {url_stats['only_in_2_after_filter']}\n\n")

        # 包名分析统计
        f.write("包名验证统计:\n")
        f.write("-" * 40 + "\n")
        f.write(f"成功提取包名的文件数量: {package_analysis['total_files_with_package']}\n")
        f.write(f"包名真实存在的文件数量: {len(package_analysis['existing_packages'])}\n")
        f.write(f"包名不存在的文件数量: {len(package_analysis['non_existing_packages'])}\n")
        f.write(f"未能提取包名的文件数量: {len(package_analysis['no_package_extracted'])}\n\n")

        # 详细信息
        f.write("详细分析结果:\n")
        f.write("=" * 80 + "\n\n")

        # 包名真实存在的文件
        if package_analysis['existing_packages']:
            f.write("1. 包名真实存在的文件:\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'序号':<4}{'文件名':<40}{'包名':<25}{'应用名':<15}{'URL数量':<8}\n")
            f.write("-" * 80 + "\n")
            for i, pkg_info in enumerate(package_analysis['existing_packages'], 1):
                f.write(f"{i:<4}{pkg_info['filename']:<40}{pkg_info['package_name']:<25}{pkg_info['app_name'] or '未知':<15}{pkg_info['url_count']:<8}\n")
            f.write("\n")

        # 包名不存在的文件
        if package_analysis['non_existing_packages']:
            f.write("2. 包名不存在的文件:\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'序号':<4}{'文件名':<40}{'包名':<25}{'URL数量':<8}\n")
            f.write("-" * 80 + "\n")
            for i, pkg_info in enumerate(package_analysis['non_existing_packages'], 1):
                f.write(f"{i:<4}{pkg_info['filename']:<40}{pkg_info['package_name']:<25}{pkg_info['url_count']:<8}\n")
            f.write("\n")

        # 未能提取包名的文件
        if package_analysis['no_package_extracted']:
            f.write("3. 未能提取包名的文件:\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'序号':<4}{'文件名':<40}{'URL数量':<8}\n")
            f.write("-" * 80 + "\n")
            for i, file_info in enumerate(package_analysis['no_package_extracted'], 1):
                f.write(f"{i:<4}{file_info['filename']:<40}{file_info['url_count']:<8}\n")
            f.write("\n")

        # 所有仍有URL的文件详情
        if results['files_with_urls']:
            f.write("4. 所有过滤后仍有URL的文件详情:\n")
            f.write("-" * 80 + "\n")
            for i, file_info in enumerate(results['files_with_urls'], 1):
                f.write(f"{i}. 文件: {file_info['filename']}\n")
                f.write(f"   包名: {file_info['package_name'] or '未提取到'}\n")
                f.write(f"   Only in 1 URL数量: {file_info['only_in_1_count']}\n")
                f.write(f"   Only in 2 URL数量: {file_info['only_in_2_count']}\n")

                if file_info['only_in_1_urls']:
                    f.write(f"   Only in 1 URLs: {', '.join(file_info['only_in_1_urls'][:5])}")
                    if len(file_info['only_in_1_urls']) > 5:
                        f.write(f" ... (共{len(file_info['only_in_1_urls'])}个)")
                    f.write("\n")

                if file_info['only_in_2_urls']:
                    f.write(f"   Only in 2 URLs: {', '.join(file_info['only_in_2_urls'][:5])}")
                    if len(file_info['only_in_2_urls']) > 5:
                        f.write(f" ... (共{len(file_info['only_in_2_urls'])}个)")
                    f.write("\n")
                f.write("\n")

def main():
    """主函数"""
    # 配置参数
    input_file = r"D:\Documents\Working\实验室\赌博诈骗apk处理\result_detail_new.txt"
    output_file = r"D:\Documents\Working\实验室\赌博诈骗apk处理\analysis_result_report_new.txt"

    # 需要排除的URL列表（可根据需要修改）
    exclude_urls = {
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
    }

    print("URL分析和包名验证工具")
    print("=" * 40)
    print(f"输入文件: {input_file}")
    print(f"输出文件: {output_file}")
    print(f"排除URL数量: {len(exclude_urls)}")
    print()

    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        print(f"错误: 输入文件 {input_file} 不存在")
        return

    # 解析结果详情文件
    print("正在解析结果详情文件...")
    results = parse_result_detail_file(input_file, exclude_urls)

    # 分析包名
    print("正在验证包名真实性...")
    package_analysis = analyze_package_names(results["files_with_urls"])

    # 生成报告
    print("正在生成分析报告...")
    generate_analysis_report(results, package_analysis, output_file)

    # 输出简要统计
    print("\n分析完成！")
    print(f"总文件数量: {results['total_files']}")
    print(f"过滤后仍有URL的文件数量: {len(results['files_with_urls'])}")
    print(f"包名真实存在的文件数量: {len(package_analysis['existing_packages'])}")
    print(f"包名不存在的文件数量: {len(package_analysis['non_existing_packages'])}")
    print(f"报告已保存到: {output_file}")

if __name__ == "__main__":
    main()