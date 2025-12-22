import os
import re
from pathlib import Path

def load_dangerous_permissions(file_path):
    """加载危险权限列表"""
    dangerous_permissions = set()

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 提取权限名称，匹配大写字母开头的权限
        permission_pattern = r'([A-Z_][A-Z0-9_]*)\s*-'
        permissions = re.findall(permission_pattern, content)

        for perm in permissions:
            # 添加完整的权限名称
            dangerous_permissions.add(f'android.permission.{perm}')

    except FileNotFoundError:
        print(f"危险权限文件未找到: {file_path}")
        return set()
    except Exception as e:
        print(f"读取危险权限文件时出错: {e}")
        return set()

    return dangerous_permissions

def parse_apk_info(file_path):
    """解析APK信息文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"读取文件失败 {file_path}: {e}")
        return None, None, []

    # 提取文件名中的hash值和包名
    filename = os.path.basename(file_path)
    # 文件名格式: {hash值}.apk_{包名}.txt
    match = re.match(r'([a-fA-F0-9]+)\.apk_(.+)\.txt$', filename)
    if not match:
        print(f"文件名格式不正确: {filename}")
        return None, None, []

    hash_value = match.group(1)
    package_name = match.group(2)

    # 提取权限信息
    permissions = []
    permission_pattern = r"uses-permission: name='([^']+)'"
    matches = re.findall(permission_pattern, content)

    for match in matches:
        permissions.append(match)

    return hash_value, package_name, permissions

def analyze_permissions(apk_info_dir, dangerous_permissions_file, output_file):
    """分析APK权限"""
    # 加载危险权限列表
    dangerous_permissions = load_dangerous_permissions(dangerous_permissions_file)
    print(f"加载了 {len(dangerous_permissions)} 个危险权限")

    # 获取所有APK信息文件
    apk_info_dir = Path(apk_info_dir)
    if not apk_info_dir.exists():
        print(f"目录不存在: {apk_info_dir}")
        return

    txt_files = list(apk_info_dir.glob("*.txt"))
    if not txt_files:
        print(f"目录中没有找到txt文件: {apk_info_dir}")
        return

    print(f"找到 {len(txt_files)} 个APK信息文件")

    # 分析结果
    results = []

    for txt_file in txt_files:
        hash_value, package_name, permissions = parse_apk_info(txt_file)

        if hash_value is None or package_name is None:
            continue

        # 找出危险权限
        found_dangerous_permissions = []
        for perm in permissions:
            if perm in dangerous_permissions:
                found_dangerous_permissions.append(perm)

        if found_dangerous_permissions:
            results.append({
                'hash': hash_value,
                'package': package_name,
                'dangerous_permissions': found_dangerous_permissions,
                'total_permissions': len(permissions)
            })

    # 输出结果
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("APK危险权限分析结果\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"分析文件数量: {len(txt_files)}\n")
            f.write(f"发现危险权限的APK数量: {len(results)}\n\n")

            for i, result in enumerate(results, 1):
                f.write(f"{i}. APK信息:\n")
                f.write(f"   Hash值: {result['hash']}\n")
                f.write(f"   包名: {result['package']}\n")
                f.write(f"   总权限数: {result['total_permissions']}\n")
                f.write(f"   危险权限数: {len(result['dangerous_permissions'])}\n")
                f.write(f"   危险权限列表:\n")

                for perm in result['dangerous_permissions']:
                    f.write(f"     - {perm}\n")
                f.write("\n")

            # 统计信息
            f.write("\n" + "=" * 50 + "\n")
            f.write("统计信息:\n")

            # 统计每个危险权限的使用频次
            permission_count = {}
            for result in results:
                for perm in result['dangerous_permissions']:
                    permission_count[perm] = permission_count.get(perm, 0) + 1

            f.write("危险权限使用频次:\n")
            for perm, count in sorted(permission_count.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {perm}: {count}次\n")

        print(f"分析完成，结果已保存到: {output_file}")
        print(f"共分析 {len(txt_files)} 个文件，发现 {len(results)} 个APK使用了危险权限")

    except Exception as e:
        print(f"写入结果文件时出错: {e}")

def main():
    # 设置路径
    apk_info_dir = r"D:\Documents\Working\实验室\赌博诈骗apk处理\permissionandcert\apkinfo"
    dangerous_permissions_file = r"D:\Documents\Working\实验室\赌博诈骗apk处理\permissionandcert\dangerous_permissions.txt"
    output_file = r"D:\Documents\Working\实验室\赌博诈骗apk处理\dangerous_permissions_export.txt"

    print("开始分析APK权限...")
    analyze_permissions(apk_info_dir, dangerous_permissions_file, output_file)

if __name__ == "__main__":
    main()