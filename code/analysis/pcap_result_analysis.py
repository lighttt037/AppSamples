import re, os
from typing import List

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

# with open('sample.txt', 'r', encoding='utf-8') as file:
#     content = file.read()

# print(get_all_host(content))


def main():
    # 遍历D:\Documents\Working\实验室\赌博诈骗apk处理\result\1
    directory1 = r"D:\Documents\Working\实验室\赌博诈骗apk处理\result\1"
    directory2 = r"D:\Documents\Working\实验室\赌博诈骗apk处理\result\2"
    file_count = 0

    for filename in os.listdir(directory1):
        if filename.endswith(".txt"):
            file_count = file_count + 1
            with open(os.path.join(directory1, filename), 'r', encoding='utf-8') as file:
                content1 = file.read()
            try:
                with open(os.path.join(directory2, filename), 'r', encoding='utf-8') as file:
                    content2 = file.read()
            except FileNotFoundError:
                with open('result_detail.txt', 'a', encoding='utf-8') as file:
                    file.write(f"File: {filename} not found in directory2\n")
                    file.write("================\n")
                    file.write("\n")
                continue
            all_host1 = set(get_all_host(content1))
            all_host2 = set(get_all_host(content2))
            diff1 = all_host1 - all_host2
            diff2 = all_host2 - all_host1
            # 将结果写入result_detail.txt
            with open('result_detail.txt', 'a', encoding='utf-8') as file:
                file.write(f"File: {filename}\n")
                file.write(f"Only in 1: {', '.join(diff1)}\n")
                file.write(f"Only in 2: {', '.join(diff2)}\n")
                file.write("================\n")
                file.write("\n")
            if diff1 or diff2:
                with open('result.txt', 'a', encoding='utf-8') as file:
                    file.write(f"File: {filename}\n")
    print(f"Processed {file_count} files.")

if __name__ == "__main__":
    main()