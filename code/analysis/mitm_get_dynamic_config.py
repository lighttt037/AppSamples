import re
import os

def extract_blocks(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 匹配所有 REQUEST 和 RESPONSE 区块
    pattern = r"=== (REQUEST|RESPONSE) ===\s*([\s\S]*?)(?=== REQUEST ===|=== RESPONSE ===|$)"
    blocks = re.findall(pattern, content)
    results = []
    for block_type, block in blocks:
        # 提取URL
        url_match = re.search(r"URL:\s*(.+)", block)
        url = url_match.group(1).strip() if url_match else ""

        # 提取Body
        body_match = re.search(r"Body:\s*([\s\S]*?)(?:=+\n|$)", block)
        body = body_match.group(1).strip() if body_match else ""

        # 判断条件①
        exclude_domains = ['qq.com', 'vscode-cdn.net', 'settings-bd.feishu.cn', 'mumu.163.com']
        if any(x in url.lower() for x in [
            # 'config', 'json', 'txt',
            'apk']) and not any(domain in url.lower() for domain in exclude_domains):
            results.append((block_type, url, body))
            continue

        # 判断条件②
        if re.search(r'\.apk', body):
            results.append((block_type, url, body))

    return results

def main():
    directory = r"D:\Documents\Working\实验室\赌博诈骗apk处理\mitm"
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            filepath = os.path.join(directory, filename)
            results = extract_blocks(filepath)
            if results:
                with open("mitm_apk_result.txt", "a", encoding="utf-8") as out_f:
                    out_f.write(f"文件: {filename}\n")
                    for block_type, url, body in results:
                        out_f.write(f"Type: {block_type}\n")
                        out_f.write(f"URL: {url}\n")
                        out_f.write(f"Body: {body[:200]}\n")
                        out_f.write("="*40 + "\n")

if __name__ == "__main__":
    main()

