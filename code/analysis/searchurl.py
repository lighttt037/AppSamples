import os
import re
import shutil  # 用于复制文件
import glob
from typing import List, Optional

"""
用于动态分析与静态分析结果互为验证
"""

def get_all_host(content) -> List[str]:
    """提取所有主机网络信息段落"""
    pattern = r"======== All Host Network Information \(Union\) ========\s*([\s\S]*?)(?=\n=|$)"
    match = re.search(pattern, content)

    strip_strings = [
        "mumu.163.com",
        "sentry.netease.com",
        "android.bugly.qq.com"
    ]

    if match:
        result = match.group(1).strip()
        # 去除result中包含mumu.163.com,sentry.netease.com,android.bugly.qq.com等的行
        for strip_string in strip_strings:
            result = re.sub(r'^.*' + re.escape(strip_string) + r'.*$', '', result, flags=re.MULTILINE)
        ret = result.splitlines()
    else:
        ret = []
    # 去除''
    ret = [line.strip() for line in ret if line.strip()]
    return ret

def search_url_in_file_content(file_path, url_pattern):
    """
    在单个文件内容中搜索URL。
    对于.so文件转换后的.txt文件，使用errors='ignore'来处理潜在的编码问题。
    """
    try:
        # 尝试多种常用编码，特别是处理反编译代码和二进制转文本的情况
        encodings_to_try = ['utf-8', 'latin-1', 'gbk', 'windows-1252']
        content = None
        for enc in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    content = f.read()
                break  # 如果成功读取，则跳出循环
            except UnicodeDecodeError:
                continue  # 尝试下一种编码

        if content is None:
            # 如果所有尝试的编码都失败了，可以记录一个警告或跳过此文件
            # 为了尽可能搜索，这里我们尝试用 'ignore' errors 最后一次
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e_read:
                print(f"    [!] Warning: Could not read file {file_path} even with errors='ignore': {e_read}")
                return False

        if re.search(url_pattern, content):
            return True
    except IOError as e:
        print(f"    [!] Error reading file {file_path}: {e}")
    except Exception as e_gen:
        print(f"    [!] An unexpected error occurred while processing file {file_path}: {e_gen}")
    return False


def find_urls_in_project_from_pcap(pcap_result_file, project_root_dir):
    """
    从pcap分析结果文件中提取URL并在项目目录中查找。

    :param pcap_result_file: pcap分析结果文件路径
    :param project_root_dir: JADX逆向分析得到的项目根文件夹路径。
    """
    if not os.path.isfile(pcap_result_file):
        print(f"[Error] PCAP result file not found: {pcap_result_file}")
        return

    if not os.path.isdir(project_root_dir):
        print(f"[Error] Project directory not found: {project_root_dir}")
        return

    # 从pcap结果文件中提取URL列表
    with open(pcap_result_file, 'r', encoding='utf-8') as f:
        content = f.read()

    urls_to_search = get_all_host(content)

    if not urls_to_search:
        print("[Info] No URLs to search in the PCAP result file.")
        return

    print(f"[*] Starting search for {len(urls_to_search)} URL(s) extracted from PCAP result in project: {project_root_dir}\n")

    for url in urls_to_search:
        print(f"[*] Searching for URL: {url}")
        found_in_project = False
        # 对URL进行转义，以便在正则表达式中作为字面量字符串进行匹配
        url_pattern = re.compile(re.escape(url))  # re.escape会处理所有特殊字符

        for root, _, files in os.walk(project_root_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                search_path = file_path
                is_temp_so_txt = False

                if filename.endswith('.so'):
                    temp_txt_path = file_path + '.txt'
                    try:
                        shutil.copy2(file_path, temp_txt_path)  # copy2保留元数据
                        search_path = temp_txt_path
                        is_temp_so_txt = True
                    except Exception as e:
                        print(f"    [!] Error copying .so file {file_path} to {temp_txt_path}: {e}")
                        continue  # 跳过这个.so文件

                if os.path.isfile(search_path):  # 确保路径确实是一个文件
                    if search_url_in_file_content(search_path, url_pattern):
                        print(f"    [+] Found in: {file_path}")  # 报告原始文件路径
                        found_in_project = True

                if is_temp_so_txt:
                    try:
                        os.remove(search_path)
                    except Exception as e:
                        print(f"    [!] Error removing temporary file {search_path}: {e}")

        if not found_in_project:
            print(f"    [-] URL not found in project: {url}")
        print("-" * 30)  # 分隔每个URL的搜索结果

    print("\n[*] Search finished.")


def find_urls_in_project(url_list_file, project_root_dir):
    """
    主函数，用于在项目目录中查找URL列表。

    :param url_list_file: 包含URL列表的txt文件路径，每行一个URL。
    :param project_root_dir: JADX逆向分析得到的项目根文件夹路径。
    """
    if not os.path.isfile(url_list_file):
        print(f"[Error] URL list file not found: {url_list_file}")
        return

    if not os.path.isdir(project_root_dir):
        print(f"[Error] Project directory not found: {project_root_dir}")
        return

    with open(url_list_file, 'r', encoding='utf-8') as f:
        urls_to_search = [line.strip() for line in f if line.strip()]

    if not urls_to_search:
        print("[Info] No URLs to search in the list file.")
        return

    print(f"[*] Starting search for {len(urls_to_search)} URL(s) in project: {project_root_dir}\n")

    for url in urls_to_search:
        print(f"[*] Searching for URL: {url}")
        found_in_project = False
        # 对URL进行转义，以便在正则表达式中作为字面量字符串进行匹配
        # 例如，. 会匹配任何字符，所以需要转义为 \.
        # 同时，为了匹配协议不敏感（http/https）或域名前缀（www.）等情况，
        # 可以构建更灵活的正则，但这里根据要求“未混淆出现”，我们先做精确匹配。
        # 如果需要更灵活的匹配，可以调整此处的url_pattern
        url_pattern = re.compile(re.escape(url))  # re.escape会处理所有特殊字符

        for root, _, files in os.walk(project_root_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                search_path = file_path
                is_temp_so_txt = False

                if filename.endswith('.so'):
                    temp_txt_path = file_path + '.txt'
                    try:
                        shutil.copy2(file_path, temp_txt_path)  # copy2保留元数据
                        search_path = temp_txt_path
                        is_temp_so_txt = True
                        # print(f"    [+] Copied .so file to {temp_txt_path} for searching")
                    except Exception as e:
                        print(f"    [!] Error copying .so file {file_path} to {temp_txt_path}: {e}")
                        continue  # 跳过这个.so文件

                if os.path.isfile(search_path):  # 确保路径确实是一个文件
                    if search_url_in_file_content(search_path, url_pattern):
                        print(f"    [+] Found in: {file_path}")  # 报告原始文件路径
                        found_in_project = True
                        # 注意：这里没有break，会继续查找该URL在项目中的其他出现位置

                if is_temp_so_txt:
                    try:
                        os.remove(search_path)
                        # print(f"    [-] Removed temporary file {search_path}")
                    except Exception as e:
                        print(f"    [!] Error removing temporary file {search_path}: {e}")

        if not found_in_project:
            print(f"    [-] URL not found in project: {url}")
        print("-" * 30)  # 分隔每个URL的搜索结果

    print("\n[*] Search finished.")


def find_apk_info_file(pcap_filename: str, apkinfo_dir: str) -> Optional[str]:
    """
    根据PCAP文件名在apkinfo目录中查找对应的APK信息文件

    :param pcap_filename: PCAP文件名 (如 aavnhm.ttbu.lwtly.zqgw.txt)
    :param apkinfo_dir: apkinfo目录路径
    :return: 找到的APK信息文件路径，如果没找到返回None
    """
    # 去掉.txt后缀
    base_name = pcap_filename.replace('.txt', '')

    # 查找匹配的文件：*.apk_base_name.txt
    pattern = os.path.join(apkinfo_dir, f"*.apk_{base_name}.txt")
    matching_files = glob.glob(pattern)

    if matching_files:
        return matching_files[0]  # 返回第一个匹配的文件
    return None


def extract_hash_from_apk_info(apk_info_file: str) -> Optional[str]:
    """
    从APK信息文件名中提取32位哈希值

    :param apk_info_file: APK信息文件路径 (如 B.aavnhm.ttbu.lwtly.zqgw.txt)
    :return: 提取的哈希值，如果提取失败返回None
    """
    filename = os.path.basename(apk_info_file)
    # 提取第一个.之前的部分作为哈希值
    hash_part = filename.split('.')[0]

    # 验证是否为32位哈希值（通常是MD5格式）
    if len(hash_part) == 32 and re.match(r'^[a-f0-9]+$', hash_part):
        return hash_part
    return None


def find_jadx_project_dir(hash_value: str, jadx_base_dirs: List[str]) -> Optional[str]:
    """
    在JADX输出目录中查找对应的项目文件夹

    :param hash_value: 32位哈希值
    :param jadx_base_dirs: JADX输出基础目录列表
    :return: 找到的JADX项目目录路径，如果没找到返回None
    """
    for base_dir in jadx_base_dirs:
        if not os.path.exists(base_dir):
            continue

        target_dir = os.path.join(base_dir, hash_value)
        if os.path.isdir(target_dir):
            return target_dir
    return None


def process_all_pcap_files():
    """
    遍历所有PCAP文件并处理对应的JADX项目
    """
    # 定义目录路径
    pcap_files_dir = r'D:\Documents\Working\实验室\赌博诈骗apk处理\result\1'
    apkinfo_dir = r'D:\Documents\Working\实验室\赌博诈骗apk处理\apkinfo'
    jadx_base_dirs = [
        r'C:\must\jadx_output1',
        r'C:\must\jadx_output2',
        r'C:\must\jadx_output3',
        r'C:\must\jadx_output4'
    ]

    if not os.path.exists(pcap_files_dir):
        print(f"[Error] PCAP files directory not found: {pcap_files_dir}")
        return

    if not os.path.exists(apkinfo_dir):
        print(f"[Error] APK info directory not found: {apkinfo_dir}")
        return

    # 遍历pcap_files目录中的所有txt文件
    pcap_files = glob.glob(os.path.join(pcap_files_dir, "*.txt"))

    if not pcap_files:
        print("[Info] No PCAP files found in the directory.")
        return

    print(f"[*] Found {len(pcap_files)} PCAP files to process.\n")

    processed_count = 0
    for pcap_file in pcap_files:
        pcap_filename = os.path.basename(pcap_file)
        print(f"[*] Processing PCAP file: {pcap_filename}")

        # 查找对应的APK信息文件
        apk_info_file = find_apk_info_file(pcap_filename, apkinfo_dir)
        if not apk_info_file:
            print(f"    [!] No matching APK info file found for {pcap_filename}")
            print("-" * 50)
            continue

        print(f"    [+] Found APK info file: {os.path.basename(apk_info_file)}")

        # 提取哈希值
        hash_value = extract_hash_from_apk_info(apk_info_file)
        if not hash_value:
            print(f"    [!] Could not extract hash from APK info file: {os.path.basename(apk_info_file)}")
            print("-" * 50)
            continue

        print(f"    [+] Extracted hash: {hash_value}")

        # 查找对应的JADX项目目录
        jadx_project_dir = find_jadx_project_dir(hash_value, jadx_base_dirs)
        if not jadx_project_dir:
            print(f"    [!] No JADX project directory found for hash: {hash_value}")
            print("-" * 50)
            continue

        print(f"    [+] Found JADX project: {jadx_project_dir}")

        # 执行URL搜索
        print(f"    [*] Starting URL search...")
        find_urls_in_project_from_pcap(pcap_file, jadx_project_dir)

        processed_count += 1
        print("=" * 50)

    print(f"\n[*] Processing completed. Successfully processed {processed_count}/{len(pcap_files)} files.")


# --- 使用示例 ---
if __name__ == '__main__':
    # # 1. 创建一个包含URL的txt文件 (例如 urls_to_find.txt)
    # # 示例 urls_to_find.txt 内容:
    # # http://example.com/api/login
    # # https://another-service.net/config
    # # http://www.unknown-domain.org/resource.json
    # # content://com.example.app.provider/data

    # # 请将下面的路径替换为您的实际路径
    # # path_to_url_list = '/Users/gyc/Desktop/aaa.txt'  # 您的URL列表文件
    # pcap_result_file = r'd:\Documents\Working\实验室\赌博诈骗apk处理\sample.txt'  # PCAP 分析结果文件
    # path_to_jadx_project = '/Users/gyc/Desktop/黑产逆向结果/all/new191'  # JADX输出的项目文件夹

    # # 为了测试，您可以手动创建示例文件和目录结构：
    # # os.makedirs("test_jadx_project/sources/com/app", exist_ok=True)
    # # os.makedirs("test_jadx_project/libs", exist_ok=True)
    # # with open("urls_to_find.txt", "w") as f:
    # #     f.write("http://example.com/api/login\n")
    # #     f.write("https://notfound.com/api\n")
    # #     f.write("test.specific.string\n") # 也可以搜索非URL字符串
    # # with open("test_jadx_project/sources/com/app/MainActivity.java", "w") as f:
    # #     f.write("String apiUrl = \"http://example.com/api/login\";\n")
    # #     f.write("String another = \"test.specific.string.in.code\";\n")
    # # with open("test_jadx_project/config.xml", "w") as f:
    # #     f.write("<config><url>http://example.com/api/login</url></config>\n")
    # # # 创建一个假的 .so 文件
    # # with open("test_jadx_project/libs/nativelib.so", "wb") as f:
    # #     f.write(b"Some binary data with test.specific.string and http://example.com/api/login embedded")
    # #
    # # path_to_url_list = 'urls_to_find.txt'
    # # path_to_jadx_project = 'test_jadx_project' # 使用测试目录

    # print("[*] Using PCAP result file as URL source...")
    # find_urls_in_project_from_pcap(pcap_result_file, path_to_jadx_project)

    # # 传统的从 URL 列表文件搜索（备用方法）
    # # path_to_url_list = '/Users/gyc/Desktop/aaa.txt'  # 您的URL列表文件
    # # find_urls_in_project(path_to_url_list, path_to_jadx_project)

    # # 清理测试文件 (如果创建了)
    # # if os.path.exists("test_jadx_project"):
    # #     shutil.rmtree("test_jadx_project")
    # # if os.path.exists("urls_to_find.txt"):
    # #     os.remove("urls_to_find.txt")

    # 处理所有PCAP文件
    process_all_pcap_files()

    # 启动命令 searchurl.py | Tee-Object -FilePath searchurl.txt