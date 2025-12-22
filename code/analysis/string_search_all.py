import subprocess

# 搜索的字符串列表
search_strings = [
    "DohResolver",
    "DohNet",
    "httpdns"
]

# 搜索的目录
search_dirs = [
    r"C:\must\jadx_output1",
    r"C:\must\jadx_output2",
    r"C:\must\jadx_output3",
    r"C:\must\jadx_output4",
    r"C:\mustnew\jadx_output1new",
    r"C:\mustnew\jadx_output2new",
    r"C:\mustnew\jadx_output3new",
    r"C:\mustnew\jadx_output4new"
]

# rg.exe 路径
rg_path = r"C:\Users\luyu2\AppData\Local\Programs\Microsoft VS Code\resources\app\node_modules\@vscode\ripgrep\bin\rg.exe"

for idx, search_string in enumerate(search_strings, 1):
    output_file = f"search_doh_all_{idx}.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        cmd = [rg_path, "-i", "-n", search_string] + search_dirs  # 添加 -i 参数忽略大小写
        f.write(f"=== 搜索: {search_string} ===\n")
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, shell=False)