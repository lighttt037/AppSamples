import os
import glob

def find_lib_files():
    # 搜索的库文件列表
    search_files = [
        "libalive_detected.so",
        # "libdetector.so",
        # "libcheck.so",
        # "libanti.so"
    ]

    # jadx输出目录列表
    jadx_dirs = [
        r"C:\must\jadx_output1",
        r"C:\must\jadx_output2",
        r"C:\must\jadx_output3",
        r"C:\must\jadx_output4"
    ]

    # 输出文件
    output_file = "libalive_detected_results.txt"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("=== 搜索库文件结果 ===\n\n")

        for jadx_dir in jadx_dirs:
            f.write(f"搜索目录: {jadx_dir}\n")
            print(f"正在搜索: {jadx_dir}")

            if not os.path.exists(jadx_dir):
                f.write(f"目录不存在: {jadx_dir}\n\n")
                continue

            # 遍历每个哈希值文件夹
            hash_dirs = [d for d in os.listdir(jadx_dir)
                        if os.path.isdir(os.path.join(jadx_dir, d))]

            for hash_dir in hash_dirs:
                hash_path = os.path.join(jadx_dir, hash_dir)
                resources_lib_path = os.path.join(hash_path, "resources", "lib")

                if os.path.exists(resources_lib_path):
                    # 遍历架构文件夹 (如 x86, arm64-v8a, armeabi-v7a 等)
                    arch_dirs = [d for d in os.listdir(resources_lib_path)
                               if os.path.isdir(os.path.join(resources_lib_path, d))]

                    for arch_dir in arch_dirs:
                        arch_path = os.path.join(resources_lib_path, arch_dir)

                        # 检查每个搜索文件
                        for lib_file in search_files:
                            lib_path = os.path.join(arch_path, lib_file)

                            if os.path.exists(lib_path):
                                result_line = f"库文件: {lib_file}, 哈希值: {hash_dir}, 文件路径: {lib_path}\n"
                                f.write(result_line)
                                print(result_line.strip())

            f.write("\n")

    print(f"搜索完成，结果已保存到: {output_file}")

if __name__ == "__main__":
    find_lib_files()