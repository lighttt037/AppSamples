import subprocess

# 搜索的字符串列表
search_strings = [
    # "EmulatorDetector",
    # r"import io.dcloud.common.util.emulator.EmulatorCheckUtil;",
    r"\.apk"
    # "super_user_security_tips",
    # "devices_yes_root"
]

# 搜索的目录
search_dirs = [
    r"C:\must\jadx_output1",
    r"C:\must\jadx_output2",
    r"C:\must\jadx_output3",
    r"C:\must\jadx_output4"
]

# rg.exe 路径
rg_path = r"C:\Users\luyu2\AppData\Local\Programs\Microsoft VS Code\resources\app\node_modules\@vscode\ripgrep\bin\rg.exe"

for idx, search_string in enumerate(search_strings, 1):
    output_file = f"search_apk_link_{idx}.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        cmd = [rg_path, "-n", search_string] + search_dirs
        f.write(f"=== 搜索: {search_string} ===\n")
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, shell=False)