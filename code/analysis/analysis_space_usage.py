# filepath: d:\Documents\Working\实验室\赌博诈骗apk处理\analysis_space_usage.py

import os
import glob

def get_file_size_mb(file_path):
    """获取文件大小（MB）"""
    try:
        size_bytes = os.path.getsize(file_path)
        return size_bytes / (1024 * 1024)
    except OSError:
        return 0

def get_folder_size_mb(folder_path):
    """获取文件夹总大小（MB）"""
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                total_size += get_file_size_mb(file_path)
    except OSError:
        pass
    return total_size

def analyze_file_sizes(folder_path):
    """分析文件夹中文件大小分布"""
    file_sizes = []

    try:
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                size_mb = get_file_size_mb(file_path)
                if size_mb > 0:  # 只记录有大小的文件
                    # 计算相对路径
                    rel_path = os.path.relpath(file_path, folder_path)
                    file_sizes.append((rel_path, size_mb))
    except OSError:
        pass

    # 按大小降序排序
    file_sizes.sort(key=lambda x: x[1], reverse=True)
    return file_sizes

def analyze_space_usage():
    """
    分析每个jadx文件夹下的哈希值文件夹中，大小差别主要体现在哪些方面
    """
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
    output_file = "analysis_space_usage.txt"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("=== JADX文件夹空间使用分析结果 ===\n\n")

        total_folders = 0
        total_size_mb = 0

        for jadx_dir in jadx_dirs:
            if not os.path.exists(jadx_dir):
                print(f"目录不存在，跳过: {jadx_dir}")
                continue

            print(f"正在分析目录: {jadx_dir}")
            f.write(f"JADX目录: {jadx_dir}\n")
            f.write("="*80 + "\n\n")

            # 获取该目录下的所有哈希值文件夹
            hash_folders = []
            for item in os.listdir(jadx_dir):
                item_path = os.path.join(jadx_dir, item)
                if os.path.isdir(item_path):
                    # 检查是否为哈希值文件夹（32位或40位十六进制）
                    if len(item) in [32, 40] and all(c in '0123456789abcdefABCDEF' for c in item):
                        hash_folders.append((item, item_path))

            # 按文件夹大小排序
            hash_folders_with_size = []
            for hash_name, hash_path in hash_folders:
                folder_size = get_folder_size_mb(hash_path)
                hash_folders_with_size.append((hash_name, hash_path, folder_size))

            hash_folders_with_size.sort(key=lambda x: x[2], reverse=True)

            # 分析每个哈希值文件夹
            for hash_name, hash_path, folder_size in hash_folders_with_size:
                if folder_size < 1:  # 跳过小于1MB的文件夹
                    continue

                total_folders += 1
                total_size_mb += folder_size

                f.write("----------------------------------\n")
                f.write(f"哈希值文件夹名：{hash_name}\n")
                f.write(f"总大小 {folder_size:.2f}MB\n")

                print(f"  分析哈希值文件夹: {hash_name} ({folder_size:.2f}MB)")

                # 分析文件大小分布
                file_sizes = analyze_file_sizes(hash_path)

                # 输出前20个最大的文件
                count = 0
                for rel_path, size_mb in file_sizes:
                    if count >= 20:  # 只显示前20个最大的文件
                        break
                    if size_mb >= 0.1:  # 只显示大于0.1MB的文件
                        f.write(f"{rel_path} {size_mb:.2f}MB\n")
                        count += 1

                f.write("\n")

            f.write("\n" + "="*80 + "\n\n")

        # 写入统计信息
        f.write(f"统计信息:\n")
        f.write(f"总文件夹数: {total_folders}\n")
        f.write(f"总大小: {total_size_mb:.2f}MB\n")

    print(f"分析完成，结果已保存到: {output_file}")
    print(f"总共分析了 {total_folders} 个哈希值文件夹")
    print(f"总大小: {total_size_mb:.2f}MB")

if __name__ == "__main__":
    analyze_space_usage()