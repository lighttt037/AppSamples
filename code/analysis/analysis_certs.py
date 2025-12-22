import os
import re
from collections import defaultdict

def extract_cert_info(file_path):
    """从文件中提取证书信息"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 提取关键证书信息
        cert_info = {}

        # 提取应用名称
        app_name_match = re.search(r'应用名称：(.+)', content)
        if app_name_match:
            cert_info['app_name'] = app_name_match.group(1).strip()

        # 提取证书DN（Distinguished Name）
        dn_match = re.search(r'certificate DN:\s*(.+)', content)
        if dn_match:
            cert_info['dn'] = dn_match.group(1).strip()

        # 提取SHA-256指纹
        sha256_match = re.search(r'SHA-256 digest:\s*([a-fA-F0-9]+)', content)
        if sha256_match:
            cert_info['sha256'] = sha256_match.group(1).strip()

        # 提取SHA-1指纹
        sha1_match = re.search(r'SHA-1 digest:\s*([a-fA-F0-9]+)', content)
        if sha1_match:
            cert_info['sha1'] = sha1_match.group(1).strip()

        # 提取MD5指纹
        md5_match = re.search(r'MD5 digest:\s*([a-fA-F0-9]+)', content)
        if md5_match:
            cert_info['md5'] = md5_match.group(1).strip()

        return cert_info

    except Exception as e:
        print(f"读取文件 {file_path} 时出错: {e}")
        return {}

def parse_filename(filename):
    """解析文件名，提取hash值"""
    # 文件名格式：{hash值}_info.txt
    match = re.match(r'([a-fA-F0-9]+)_info\.txt$', filename)
    if match:
        hash_value = match.group(1)
        return hash_value
    return None

def create_cert_signature(cert_info):
    """创建证书签名用于识别相同证书"""
    # 使用SHA1或MD5指纹作为主要标识
    if 'sha1' in cert_info and cert_info['sha1']:
        return cert_info['sha1']
    elif 'md5' in cert_info and cert_info['md5']:
        return cert_info['md5']
    elif 'sha256' in cert_info and cert_info['sha256']:
        return cert_info['sha256']
    else:
        # 如果没有指纹信息，使用DN作为标识
        return cert_info.get('dn', 'unknown')

def extract_package_name_from_apkinfo(hash_value):
    """从apkinfo文件名中提取包名"""
    apkinfo_dir = r"D:\Documents\Working\实验室\赌博诈骗apk处理\permissionandcert\apkinfo"

    try:
        # 遍历apkinfo文件夹中的文件
        for filename in os.listdir(apkinfo_dir):
            if filename.endswith('.txt'):
                # 文件名格式: {hash值}.apk_{包名}.txt
                match = re.match(r'([a-fA-F0-9]+)\.apk_(.+)\.txt$', filename)
                if match:
                    file_hash = match.group(1)
                    package_name = match.group(2)

                    # 如果hash值匹配，返回包名
                    if file_hash == hash_value:
                        return package_name

        return None

    except Exception as e:
        print(f"从apkinfo提取包名时出错: {e}")
        return None

def main():
    folder_path = r"D:\Documents\Working\实验室\赌博诈骗apk处理\permissionandcert\apktcerts"
    output_file = r"D:\Documents\Working\实验室\赌博诈骗apk处理\certs_information_export.txt"
    same_certs_output = r"D:\Documents\Working\实验室\赌博诈骗apk处理\same_certs_information_export.txt"
    same_package_output = r"D:\Documents\Working\实验室\赌博诈骗apk处理\same_package_name_certs_information_export.txt"

    # 检查文件夹是否存在
    if not os.path.exists(folder_path):
        print(f"文件夹不存在: {folder_path}")
        return

    # 用于记录相同证书的应用
    cert_groups = defaultdict(list)
    # 用于记录相同包名的应用
    package_groups = defaultdict(list)

    # 遍历文件夹中的所有txt文件
    for filename in os.listdir(folder_path):
        if filename.endswith('.txt'):
            file_path = os.path.join(folder_path, filename)

            # 解析文件名
            hash_value = parse_filename(filename)
            if not hash_value:
                print(f"无法解析文件名: {filename}")
                continue

            # 提取证书信息
            cert_info = extract_cert_info(file_path)
            if not cert_info:
                print(f"无法提取证书信息: {filename}")
                continue

            # 从apkinfo文件名中提取包名
            package_name = extract_package_name_from_apkinfo(hash_value)
            if not package_name:
                package_name = "unknown"

            # 创建证书签名
            cert_signature = create_cert_signature(cert_info)

            # 记录应用信息
            app_info = {
                'filename': filename,
                'hash': hash_value,
                'package': package_name,
                'cert_info': cert_info,
                'cert_signature': cert_signature
            }

            cert_groups[cert_signature].append(app_info)
            package_groups[package_name].append(app_info)

    # 输出结果
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("证书信息分析报告\n")
        f.write("=" * 50 + "\n\n")

        # 统计信息
        total_apps = sum(len(apps) for apps in cert_groups.values())
        total_certs = len(cert_groups)

        f.write(f"总共分析了 {total_apps} 个应用\n")
        f.write(f"发现 {total_certs} 个不同的证书\n\n")

        # 按证书分组输出
        for i, (cert_signature, apps) in enumerate(cert_groups.items(), 1):
            f.write(f"证书组 {i} (共{len(apps)}个应用):\n")
            f.write("-" * 40 + "\n")

            # 输出证书信息
            if apps:
                cert_info = apps[0]['cert_info']
                f.write(f"证书签名: {cert_signature}\n")
                if 'app_name' in cert_info:
                    f.write(f"应用名称: {cert_info['app_name']}\n")
                if 'dn' in cert_info:
                    f.write(f"证书DN: {cert_info['dn']}\n")
                if 'sha256' in cert_info:
                    f.write(f"SHA-256: {cert_info['sha256']}\n")
                if 'sha1' in cert_info:
                    f.write(f"SHA-1: {cert_info['sha1']}\n")
                if 'md5' in cert_info:
                    f.write(f"MD5: {cert_info['md5']}\n")

            f.write("\n使用此证书的应用:\n")
            for app in apps:
                f.write(f"  文件名: {app['filename']}\n")
                f.write(f"  Hash值: {app['hash']}\n")
                f.write(f"  包名: {app['package']}\n")
                f.write("\n")

            f.write("\n")

        # 输出相同证书的应用统计
        f.write("相同证书应用统计:\n")
        f.write("=" * 50 + "\n")

        multiple_cert_groups = [(cert_sig, apps) for cert_sig, apps in cert_groups.items() if len(apps) > 1]

        if multiple_cert_groups:
            f.write(f"发现 {len(multiple_cert_groups)} 个证书被多个应用使用:\n\n")

            for cert_signature, apps in multiple_cert_groups:
                f.write(f"证书签名: {cert_signature}\n")
                f.write(f"应用数量: {len(apps)}\n")
                f.write("应用列表:\n")
                for app in apps:
                    f.write(f"  - {app['package']} ({app['hash']})\n")
                f.write("\n")
        else:
            f.write("未发现相同证书的应用\n")

    # 输出相同证书的应用到专门文件
    multiple_cert_groups = [(cert_sig, apps) for cert_sig, apps in cert_groups.items() if len(apps) > 1]

    with open(same_certs_output, 'w', encoding='utf-8') as f:
        f.write("相同证书应用分析报告\n")
        f.write("=" * 50 + "\n\n")

        f.write(f"发现 {len(multiple_cert_groups)} 个证书被多个应用使用\n")
        f.write(f"涉及应用总数: {sum(len(apps) for _, apps in multiple_cert_groups)} 个\n\n")

        for i, (cert_signature, apps) in enumerate(multiple_cert_groups, 1):
            f.write(f"相同证书组 {i} (共{len(apps)}个应用):\n")
            f.write("-" * 40 + "\n")

            # 输出证书信息
            if apps:
                cert_info = apps[0]['cert_info']
                f.write(f"证书签名: {cert_signature}\n")
                if 'app_name' in cert_info:
                    f.write(f"应用名称: {cert_info['app_name']}\n")
                if 'dn' in cert_info:
                    f.write(f"证书DN: {cert_info['dn']}\n")
                if 'sha256' in cert_info:
                    f.write(f"SHA-256: {cert_info['sha256']}\n")
                if 'sha1' in cert_info:
                    f.write(f"SHA-1: {cert_info['sha1']}\n")
                if 'md5' in cert_info:
                    f.write(f"MD5: {cert_info['md5']}\n")

            f.write("\n使用此证书的应用:\n")
            for app in apps:
                f.write(f"  文件名: {app['filename']}\n")
                f.write(f"  Hash值: {app['hash']}\n")
                f.write(f"  包名: {app['package']}\n")
                f.write("\n")

            f.write("\n")

    # 输出相同包名不同证书的应用到专门文件
    multiple_package_groups = [(pkg_name, apps) for pkg_name, apps in package_groups.items() if len(apps) > 1 and pkg_name != "unknown"]

    with open(same_package_output, 'w', encoding='utf-8') as f:
        f.write("相同包名不同证书应用分析报告\n")
        f.write("=" * 50 + "\n\n")

        f.write(f"发现 {len(multiple_package_groups)} 个包名有多个不同版本/证书的应用\n")
        f.write(f"涉及应用总数: {sum(len(apps) for _, apps in multiple_package_groups)} 个\n\n")

        for i, (package_name, apps) in enumerate(multiple_package_groups, 1):
            # 统计不同证书数量
            cert_signatures = set(app['cert_signature'] for app in apps)

            f.write(f"包名组 {i}: {package_name} (共{len(apps)}个应用，{len(cert_signatures)}个不同证书):\n")
            f.write("-" * 60 + "\n")

            # 按证书分组显示
            cert_app_groups = defaultdict(list)
            for app in apps:
                cert_app_groups[app['cert_signature']].append(app)

            for j, (cert_sig, cert_apps) in enumerate(cert_app_groups.items(), 1):
                f.write(f"  证书 {j}: {cert_sig}\n")
                f.write(f"  应用数量: {len(cert_apps)}\n")

                # 显示证书详细信息
                if cert_apps:
                    cert_info = cert_apps[0]['cert_info']
                    if 'app_name' in cert_info:
                        f.write(f"  应用名称: {cert_info['app_name']}\n")
                    if 'dn' in cert_info:
                        f.write(f"  证书DN: {cert_info['dn']}\n")

                f.write("  使用此证书的应用:\n")
                for app in cert_apps:
                    f.write(f"    - Hash: {app['hash']}\n")
                    f.write(f"      文件: {app['filename']}\n")
                f.write("\n")

            f.write("\n")

    print(f"分析完成！")
    print(f"主报告已保存到: {output_file}")
    print(f"相同证书应用报告已保存到: {same_certs_output}")
    print(f"相同包名不同证书应用报告已保存到: {same_package_output}")
    print(f"共分析了 {total_apps} 个应用，发现 {total_certs} 个不同的证书")

    if multiple_cert_groups:
        print(f"发现 {len(multiple_cert_groups)} 个证书被多个应用使用")

    if multiple_package_groups:
        print(f"发现 {len(multiple_package_groups)} 个包名有多个不同版本/证书的应用")

if __name__ == "__main__":
    main()