# filepath: d:\Documents\Working\实验室\赌博诈骗apk处理\md5_extractor.py

import re
import os
import glob
from typing import Set, Dict, Optional

def get_apk_info(md5_hash: str) -> Dict[str, Optional[str]]:
    """
    根据MD5哈希值搜索对应的APK信息文件，提取包名和应用名

    Args:
        md5_hash: MD5哈希值

    Returns:
        包含包名和应用名的字典
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

        # 搜索匹配的文件 {md5值}.apk_{包名}.txt
        pattern = os.path.join(apk_info_dir, f"{md5_hash}.apk_*.txt")
        matching_files = glob.glob(pattern)

        if matching_files:
            # 找到匹配文件，处理第一个
            apk_info_file = matching_files[0]

            try:
                # 从文件名中提取包名
                filename = os.path.basename(apk_info_file)
                # 格式: {md5值}.apk_{包名}.txt
                package_name = filename.split('.apk_')[1].replace('.txt', '')

                # 读取文件内容提取应用名
                with open(apk_info_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # 提取application-label
                app_name_match = re.search(r"application-label:'([^']+)'", content)
                app_name = app_name_match.group(1) if app_name_match else None

                return {"package_name": package_name, "app_name": app_name}

            except Exception as e:
                print(f"处理APK信息文件时发生错误: {e}")
                continue

    # 所有目录都没有找到匹配文件
    return {"package_name": None, "app_name": None}

def process_multiple_files(input_files: list, merged_result_filename: str = "md5_extractor_result.txt") -> None:
    """
    批量处理多个txt文件，每个文件独立执行处理流程，并输出合并结果

    Args:
        input_files: 输入文件列表
        merged_result_filename: 合并结果输出文件名
    """
    print(f"开始批量处理 {len(input_files)} 个文件...")

    success_count = 0
    all_md5_set: Set[str] = set()  # 存储所有文件的MD5哈希值并集

    # 处理每个文件
    for i, input_file in enumerate(input_files, 1):
        print(f"\n正在处理文件 {i}/{len(input_files)}: {input_file}")

        if not os.path.exists(input_file):
            print(f"  错误: 文件 {input_file} 不存在，跳过")
            continue

        try:
            # 生成输出文件名
            input_basename = os.path.splitext(os.path.basename(input_file))[0]
            output_file = f"md5_{input_basename}.txt"

            # 调用单文件处理函数并获取MD5集合
            file_md5_set = extract_md5_from_file(input_file, output_file)
            all_md5_set.update(file_md5_set)  # 合并到总集合中
            success_count += 1

        except Exception as e:
            print(f"  错误: 处理文件 {input_file} 时发生错误: {e}")

    print(f"\n批量处理完成！")
    print(f"总文件数量: {len(input_files)}")
    print(f"成功处理数量: {success_count}")
    print(f"失败数量: {len(input_files) - success_count}")

    # 生成合并结果文件
    if all_md5_set:
        generate_merged_result(all_md5_set, input_files, success_count, merged_result_filename)

def extract_md5_from_file(input_file: str, output_file: str) -> Set[str]:
    """
    从txt文件中提取MD5哈希值（32位十六进制字符串），去重后统计总数并输出到指定文件

    Args:
        input_file: 输入txt文件路径
        output_file: 输出结果文件路径

    Returns:
        提取到的MD5哈希值集合
    """
    # MD5正则表达式：匹配32位十六进制字符串
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'

    # 存储提取的MD5值（使用set自动去重）
    md5_set: Set[str] = set()

    try:
        # 读取输入文件
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # 提取所有MD5值
        matches = re.findall(md5_pattern, content)

        # 转换为小写并添加到set中（去重）
        for match in matches:
            md5_set.add(match.lower())

        # 将set转换为排序的列表
        md5_list = sorted(list(md5_set))

        # 统计找到APK信息的数量
        found_count = 0
        for md5_hash in md5_list:
            apk_info = get_apk_info(md5_hash)
            if apk_info['package_name'] is not None:
                found_count += 1

        # 写入输出文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"MD5提取结果统计\n")
            f.write(f"=" * 80 + "\n")
            f.write(f"输入文件: {input_file}\n")
            f.write(f"提取的MD5总数: {len(md5_list)}\n")
            f.write(f"去重的MD5总数: {len(md5_list)}\n")
            f.write(f"找到APK信息的MD5总数: {found_count}\n")
            f.write(f"未找到APK信息的MD5总数: {len(md5_list) - found_count}\n")
            f.write(f"=" * 80 + "\n\n")

            f.write("提取的MD5详情:\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'序号':<6}{'MD5值':<34}{'包名':<30}{'应用名':<20}\n")
            f.write("-" * 80 + "\n")

            for i, md5_hash in enumerate(md5_list, 1):
                # 获取APK信息
                apk_info = get_apk_info(md5_hash)
                package_name = apk_info['package_name'] or "未找到"
                app_name = apk_info['app_name'] or "未找到"

                f.write(f"{i:<6}{md5_hash:<34}{package_name:<30}{app_name:<20}\n")

        print(f"处理完成！")
        print(f"输入文件: {input_file}")
        print(f"输出文件: {output_file}")
        print(f"提取的MD5总数: {len(md5_list)}")
        print(f"找到APK信息的MD5总数: {found_count}")
        print(f"未找到APK信息的MD5总数: {len(md5_list) - found_count}")

        return md5_set

    except FileNotFoundError:
        print(f"错误: 找不到输入文件 {input_file}")
        return set()
    except Exception as e:
        print(f"处理过程中发生错误: {e}")
        return set()

def generate_merged_result(all_md5_set: Set[str], input_files: list, success_count: int, output_filename: str = "md5_extractor_result.txt") -> None:
    """
    生成合并后的MD5结果文件

    Args:
        all_md5_set: 所有文件的MD5哈希值集合
        input_files: 输入文件列表
        success_count: 成功处理的文件数量
        output_filename: 输出文件名
    """
    output_file = output_filename

    # 将set转换为排序的列表
    all_md5_list = sorted(list(all_md5_set))

    # 统计找到APK信息的数量
    total_found_count = 0
    for md5_hash in all_md5_list:
        apk_info = get_apk_info(md5_hash)
        if apk_info['package_name'] is not None:
            total_found_count += 1

    # 写入合并结果文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"MD5提取合并结果统计\n")
        f.write(f"=" * 80 + "\n")
        f.write(f"处理的文件列表:\n")
        for i, file in enumerate(input_files, 1):
            f.write(f"  {i}. {file}\n")
        f.write(f"\n")
        f.write(f"成功处理的文件数量: {success_count}\n")
        f.write(f"合并后的MD5总数: {len(all_md5_list)}\n")
        f.write(f"找到APK信息的MD5总数: {total_found_count}\n")
        f.write(f"未找到APK信息的MD5总数: {len(all_md5_list) - total_found_count}\n")
        f.write(f"=" * 80 + "\n\n")

        f.write("合并的MD5详情:\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'序号':<6}{'MD5值':<34}{'包名':<30}{'应用名':<20}\n")
        f.write("-" * 80 + "\n")

        for i, md5_hash in enumerate(all_md5_list, 1):
            # 获取APK信息
            apk_info = get_apk_info(md5_hash)
            package_name = apk_info['package_name'] or "未找到"
            app_name = apk_info['app_name'] or "未找到"

            f.write(f"{i:<6}{md5_hash:<34}{package_name:<30}{app_name:<20}\n")

    print(f"\n合并结果已保存到: {output_file}")
    print(f"合并后的MD5总数: {len(all_md5_list)}")
    print(f"找到APK信息的MD5总数: {total_found_count}")
    print(f"未找到APK信息的MD5总数: {len(all_md5_list) - total_found_count}")

def main():
    """主函数"""
    # 配置合并结果输出文件名
    merged_result_filename = "md5_keepalive_analysis.txt"

    # 直接设置要处理的文件列表
    input_files = [
        r"D:\Documents\Working\实验室\赌博诈骗apk处理\keepalive.txt",
        r"D:\Documents\Working\实验室\赌博诈骗apk处理\search_keepalive_1_new.txt",
        # r"D:\Documents\Working\实验室\赌博诈骗apk处理\search_doh_all_3.txt"
    ]

    print("MD5提取工具 - 批量处理模式")
    print("=" * 30)

    # 执行批量处理
    process_multiple_files(input_files, merged_result_filename)

if __name__ == "__main__":
    main()