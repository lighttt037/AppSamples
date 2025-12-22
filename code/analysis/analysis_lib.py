import os
import glob
import re
from collections import defaultdict

def analyze_lib_files():
    """
    分析每个APP使用的so文件
    遍历apkinfo文件夹，提取hash值和包名，然后查找对应的so文件
    """
    # APK信息文件夹
    apkinfo_dir = r"D:\Documents\Working\实验室\赌博诈骗apk处理\permissionandcert\apkinfo"

    # jadx输出目录列表
    jadx_dirs = [
        r"C:\must\jadx_output1",
        r"C:\must\jadx_output2",
        r"C:\must\jadx_output3",
        r"C:\must\jadx_output4",
        r"C:\mustnew\jadx_output1new",
        r"C:\mustnew\jadx_output2new",
        r"C:\mustnew\jadx_output3new",
        r"C:\mustnew\jadx_output4new"
    ]

    # 输出文件
    output_file = "lib_information_export.txt"
    stats_output_file = "lib_information_export_by_apps.txt"

    # 检查apkinfo目录是否存在
    if not os.path.exists(apkinfo_dir):
        print(f"APK信息目录不存在: {apkinfo_dir}")
        return

    # 获取所有txt文件
    txt_files = glob.glob(os.path.join(apkinfo_dir, "*.txt"))

    # 用于统计每个库文件被多少个应用使用
    lib_usage_stats = defaultdict(set)  # 库文件名 -> 使用该库的应用hash集合

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("=== APK库文件分析结果 ===\n\n")

        app_count = 0
        found_libs_count = 0

        for txt_file in txt_files:
            filename = os.path.basename(txt_file)

            # 使用正则表达式提取hash值和包名
            # 格式: {hash值}.apk_{包名}.txt
            match = re.match(r"([a-fA-F0-9]+)\.apk_(.+)\.txt", filename)

            if not match:
                continue

            hash_value = match.group(1)
            package_name = match.group(2)

            app_count += 1

            f.write(f"应用 #{app_count}\n")
            f.write(f"Hash值: {hash_value}\n")
            f.write(f"包名: {package_name}\n")
            f.write(f"信息文件: {filename}\n")

            print(f"正在分析应用 #{app_count}: {package_name} ({hash_value})")

            # 在jadx输出目录中查找对应的so文件
            lib_files_found = []

            for jadx_dir in jadx_dirs:
                if not os.path.exists(jadx_dir):
                    continue

                hash_path = os.path.join(jadx_dir, hash_value)
                resources_lib_path = os.path.join(hash_path, "resources", "lib")

                if os.path.exists(resources_lib_path):
                    # 遍历架构文件夹
                    arch_dirs = [d for d in os.listdir(resources_lib_path)
                               if os.path.isdir(os.path.join(resources_lib_path, d))]

                    for arch_dir in arch_dirs:
                        arch_path = os.path.join(resources_lib_path, arch_dir)

                        # 获取该架构下的所有so文件
                        so_files = glob.glob(os.path.join(arch_path, "*.so"))

                        for so_file in so_files:
                            so_name = os.path.basename(so_file)
                            lib_files_found.append(f"{arch_dir}/{so_name}")

                            # 统计库文件使用情况（只记录库文件名，不包含架构）
                            lib_usage_stats[so_name].add(hash_value)

            if lib_files_found:
                f.write(f"发现的库文件 ({len(lib_files_found)}个):\n")
                for lib_file in sorted(set(lib_files_found)):
                    f.write(f"  - {lib_file}\n")
                found_libs_count += len(set(lib_files_found))
            else:
                f.write("未发现库文件\n")

            f.write("\n" + "="*50 + "\n\n")

        # 写入统计信息
        f.write(f"统计信息:\n")
        f.write(f"总应用数: {app_count}\n")
        f.write(f"发现的库文件总数: {found_libs_count}\n")

    # 生成按库文件统计的报告
    with open(stats_output_file, "w", encoding="utf-8") as f:
        f.write("=== 库文件使用统计（按应用数量排序） ===\n\n")

        # 按使用该库的应用数量从大到小排序
        sorted_libs = sorted(lib_usage_stats.items(),
                           key=lambda x: len(x[1]), reverse=True)

        f.write(f"总共发现 {len(sorted_libs)} 个不同的库文件\n\n")

        for rank, (lib_name, app_hashes) in enumerate(sorted_libs, 1):
            app_count = len(app_hashes)
            f.write(f"#{rank:3d} - {lib_name}\n")
            f.write(f"       使用应用数: {app_count}\n")
            f.write(f"       使用比例: {app_count/len(txt_files)*100:.1f}%\n")
            f.write("\n")

        # 统计信息
        f.write("="*50 + "\n")
        f.write("统计摘要:\n")
        f.write(f"总应用数: {len(txt_files)}\n")
        f.write(f"总库文件数: {len(sorted_libs)}\n")

        # 使用频率分析
        usage_counts = [len(app_hashes) for _, app_hashes in sorted_libs]
        if usage_counts:
            f.write(f"最常用库文件使用次数: {max(usage_counts)}\n")
            f.write(f"最少用库文件使用次数: {min(usage_counts)}\n")
            f.write(f"平均使用次数: {sum(usage_counts)/len(usage_counts):.1f}\n")

    print(f"分析完成，结果已保存到: {output_file}")
    print(f"库文件统计已保存到: {stats_output_file}")
    print(f"总共分析了 {app_count} 个应用")
    print(f"发现了 {len(lib_usage_stats)} 个不同的库文件")

if __name__ == "__main__":
    analyze_lib_files()