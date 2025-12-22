import os
import subprocess
from multiprocessing import Pool

JADX_PATH = r'D:\Downloads\jadx-1.5.2\bin\jadx.bat'
APK_DIR = r'C:\must'
OUTPUT_BASE = r'C:\must'

NUM_PROCESSES = 4

def process_apks(args):
    apk_list, output_folder = args
    output_base = os.path.join(OUTPUT_BASE, output_folder)
    if not os.path.exists(output_base):
        os.makedirs(output_base)
    for apk_path in apk_list:
        filename = os.path.basename(apk_path)
        output_dir = os.path.join(output_base, os.path.splitext(filename)[0])
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        print(f'正在解包: {apk_path}')
        cmd = [JADX_PATH, '-d', output_dir, apk_path]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print(f'输出目录: {output_dir}')
        except subprocess.CalledProcessError as e:
            print(f'解包失败: {apk_path}')
            print(f'错误码: {e.returncode}')
            print(f'stdout: {e.stdout}')
            print(f'stderr: {e.stderr}')

if __name__ == '__main__':
    apk_files = [os.path.join(APK_DIR, f) for f in os.listdir(APK_DIR) if f.lower().endswith('.apk')]
    apk_files.sort()
    # 分成4份
    chunks = [apk_files[i::NUM_PROCESSES] for i in range(NUM_PROCESSES)]
    output_folders = [f'jadx_output{i+1}' for i in range(NUM_PROCESSES)]
    args_list = list(zip(chunks, output_folders))
    with Pool(NUM_PROCESSES) as pool:
        pool.map(process_apks, args_list)