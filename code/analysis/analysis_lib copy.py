import os
import glob
import re
from collections import Counter
from typing import Dict, List, Set

def get_key_lib_patterns():
    """
    定义关键库文件模式（加壳、保护、混淆等）
    """
    return {
        "加壳/保护": [
            "libjiagu", "libprotect", "libsecshell", "libuvmp", "libddog",
            "libnqshield", "libbaiduprotect", "libkwscmm", "libapkprotect",
            "libsecneo", "libtup", "libegis", "libDexHelper", "libmobisec",
            "libbangcle", "libexec", "libnProtect", "libqdbh", "libshell"
        ],
        "反调试": [
            "libanti", "libantidebug", "libcheck", "libdetect", "libhook_prevent",
            "libfrida_detect", "libxposed_detect", "libroot_detect"
        ],
        "网络/通信": [
            "libcurl", "libssl", "libcrypto", "libhttp", "libwebsocket",
            "libnet", "libtcp", "libudp"
        ],
        "加密/混淆": [
            "libencrypt", "libobfuscate", "libcipher", "libaes", "libdes",
            "librsa", "libmd5", "libsha", "libbase64"
        ],
        "游戏引擎": [
            "libunity", "libcocos", "libue4", "libgodot", "libcryengine"
        ],
        "广告SDK": [
            "libgdt", "libcsj", "libkuaishou", "libbaidu", "libtoutiao",
            "libadmob", "libfacebook", "libmopub"
        ]
    }

def categorize_lib(lib_name: str, patterns: Dict[str, List[str]]) -> str:
    """
    根据库文件名分类
    """
    lib_lower = lib_name.lower()

    for category, pattern_list in patterns.items():
        for pattern in pattern_list:
            if pattern.lower() in lib_lower:
                return category

    return "其他"

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
    analysis_file = "analysis_lib.txt"

    # 获取关键库模式
    key_patterns = get_key_lib_patterns()

    # 用于统计的数据结构
    all_libs = Counter()  # 所有库文件频次
    category_libs = {}  # 按分类统计的库文件
    app_lib_info = []  # 每个APP的库文件信息

    for category in key_patterns.keys():
        category_libs[category] = Counter()
    category_libs["其他"] = Counter()

    # 检查apkinfo目录是否存在
    if not os.path.exists(apkinfo_dir):
        print(f"APK信息目录不存在: {apkinfo_dir}")
        return

    # 获取所有txt文件
    txt_files = glob.glob(os.path.join(apkinfo_dir, "*.txt"))

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
            app_libs_by_category = {}
            for category in key_patterns.keys():
                app_libs_by_category[category] = []
            app_libs_by_category["其他"] = []

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

                            # 统计库文件频次
                            all_libs[so_name] += 1

                            # 分类统计
                            category = categorize_lib(so_name, key_patterns)
                            category_libs[category][so_name] += 1
                            app_libs_by_category[category].append(so_name)

            if lib_files_found:
                f.write(f"发现的库文件 ({len(lib_files_found)}个):\n")

                # 按分类显示库文件
                for category, libs in app_libs_by_category.items():
                    if libs:
                        f.write(f"  [{category}]:\n")
                        for lib in sorted(set(libs)):
                            f.write(f"    - {lib}\n")

                found_libs_count += len(set(lib_files_found))

                # 保存APP信息
                app_lib_info.append({
                    "hash": hash_value,
                    "package": package_name,
                    "libs": lib_files_found,
                    "libs_by_category": app_libs_by_category
                })
            else:
                f.write("未发现库文件\n")

            f.write("\n" + "="*50 + "\n\n")

        # 写入统计信息
        f.write(f"统计信息:\n")
        f.write(f"总应用数: {app_count}\n")
        f.write(f"发现的库文件总数: {found_libs_count}\n")

    # 写入分析文件
    with open(analysis_file, "w", encoding="utf-8") as f:
        f.write("=== SO库文件频次统计与关键分析 ===\n\n")

        f.write(f"分析总览:\n")
        f.write(f"- 总应用数量: {app_count}\n")
        f.write(f"- 发现的库文件种类: {len(all_libs)}\n")
        f.write(f"- 库文件总出现次数: {sum(all_libs.values())}\n\n")

        # 整体频次统计 - 前50个最常见的库
        f.write("=== 最常见的SO库文件 (前50) ===\n")
        f.write(f"{'排名':<4} {'库文件名':<40} {'出现次数':<8} {'出现率':<8}\n")
        f.write("-" * 70 + "\n")
        for i, (lib_name, count) in enumerate(all_libs.most_common(50), 1):
            rate = f"{count/app_count*100:.1f}%"
            f.write(f"{i:<4} {lib_name:<40} {count:<8} {rate:<8}\n")
        f.write("\n")

        # 按分类统计关键库文件
        f.write("=== 关键库文件分类统计 ===\n\n")

        for category, libs_counter in category_libs.items():
            if libs_counter:
                f.write(f"[{category}] - 共{len(libs_counter)}种库文件:\n")
                f.write(f"{'库文件名':<40} {'出现次数':<8} {'出现率':<8}\n")
                f.write("-" * 60 + "\n")

                for lib_name, count in libs_counter.most_common():
                    rate = f"{count/app_count*100:.1f}%"
                    f.write(f"{lib_name:<40} {count:<8} {rate:<8}\n")
                f.write("\n")

        # 关键发现汇总
        f.write("=== 关键发现汇总 ===\n")

        # 加壳/保护类库统计
        protection_apps = 0
        for app_info in app_lib_info:
            if app_info["libs_by_category"]["加壳/保护"]:
                protection_apps += 1

        f.write(f"使用加壳/保护技术的应用: {protection_apps}/{app_count} ({protection_apps/app_count*100:.1f}%)\n")

        # 反调试类库统计
        antidebug_apps = 0
        for app_info in app_lib_info:
            if app_info["libs_by_category"]["反调试"]:
                antidebug_apps += 1

        f.write(f"使用反调试技术的应用: {antidebug_apps}/{app_count} ({antidebug_apps/app_count*100:.1f}%)\n")

        # 加密/混淆类库统计
        crypto_apps = 0
        for app_info in app_lib_info:
            if app_info["libs_by_category"]["加密/混淆"]:
                crypto_apps += 1

        f.write(f"使用加密/混淆技术的应用: {crypto_apps}/{app_count} ({crypto_apps/app_count*100:.1f}%)\n\n")

        # 高风险应用识别（同时使用多种保护技术）
        f.write("=== 高风险应用识别 ===\n")
        f.write("同时使用多种保护技术的应用:\n\n")

        high_risk_count = 0
        for app_info in app_lib_info:
            protection_count = 0
            protection_types = []

            if app_info["libs_by_category"]["加壳/保护"]:
                protection_count += 1
                protection_types.append("加壳/保护")
            if app_info["libs_by_category"]["反调试"]:
                protection_count += 1
                protection_types.append("反调试")
            if app_info["libs_by_category"]["加密/混淆"]:
                protection_count += 1
                protection_types.append("加密/混淆")

            if protection_count >= 2:
                high_risk_count += 1
                f.write(f"应用: {app_info['package']}\n")
                f.write(f"Hash: {app_info['hash']}\n")
                f.write(f"保护技术: {', '.join(protection_types)}\n")
                f.write(f"相关库文件:\n")
                for ptype in protection_types:
                    if app_info["libs_by_category"][ptype]:
                        f.write(f"  [{ptype}]: {', '.join(set(app_info['libs_by_category'][ptype]))}\n")
                f.write("-" * 50 + "\n")

        f.write(f"\n高风险应用总数: {high_risk_count}/{app_count} ({high_risk_count/app_count*100:.1f}%)\n")

    print(f"分析完成，结果已保存到: {output_file}")
    print(f"库文件统计分析已保存到: {analysis_file}")
    print(f"总共分析了 {app_count} 个应用")

if __name__ == "__main__":
    analyze_lib_files()