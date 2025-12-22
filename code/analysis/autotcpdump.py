import os
import subprocess
import time
import threading
import re
import uiautomator2 as u2

# 修改为你的APK文件夹路径
APK_FOLDER = "C:\\Users\\gyc\\Desktop\\newresult"
PCAP_SAVE_DIR = "/sdcard"

# 获取包名
def get_package_name(apk_path):
    try:
        output = subprocess.check_output(['D:\\Android\\Sdk\\build-tools\\30.0.3\\aapt.exe', 'dump', 'badging', apk_path], stderr=subprocess.STDOUT)
        match = re.search(r"package: name='(.*?)'", output.decode())
        if match:
            return match.group(1)
    except subprocess.CalledProcessError as e:
        print(f"Error extracting package name: {e.output.decode()}")
    return None

# 启动tcpdump
def start_tcpdump(package_name):
    pcap_path = os.path.join(PCAP_SAVE_DIR, f"{package_name}.pcap")
    cmd = f"adb shell \"export PATH=$PATH:/system/bin/; su -c 'tcpdump -w /sdcard/Pictures/{package_name}.pcap'\""
    subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# 停止tcpdump
def stop_tcpdump():
    cmd = f"adb shell \"export PATH=$PATH:/system/bin/; su -c 'pkill tcpdump'\""

    subprocess.call(cmd, shell=True)

# 自动点击按钮
def auto_click_buttons(duration=30):
    try:
        d = u2.connect()  # 自动连接已授权的设备
        print("[点击线程] 成功连接设备")

        start_time = time.time()
        while time.time() - start_time < duration:
            # 遍历所有按钮
            clicked = False
            for btn in d.xpath("//android.widget.Button").all():
                try:
                    btn.click()
                    print("[点击线程] 点击按钮")
                    clicked = True
                    break
                except Exception as e:
                    print(f"[点击线程] 按钮点击失败: {e}")

            if not clicked:
                # 如果没找到按钮，就点击屏幕中央 fallback
                print("[点击线程] 未发现按钮，点击屏幕中央")
                d.click(0.5, 0.5)

            time.sleep(2.5)
    except Exception as e:
        print(f"[点击线程] 自动点击失败: {e}")

# 安装并运行APK
def run_apk(apk_path):
    print(f"\n开始处理: {apk_path}")
    package_name = get_package_name(apk_path)
    if not package_name:
        print("无法获取包名，跳过")
        return

    print(f"包名: {package_name}")

    try:
        # 安装
        subprocess.check_call(f"adb install -r \"{apk_path}\"", shell=True)
        print("安装成功")

        # time.sleep(2)
        # 启动APP
        subprocess.call(f"adb shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1", shell=True)
        print("应用启动成功")

        # 启动tcpdump
        start_tcpdump(package_name)
        print("抓包开始")

        # 延迟5秒后截屏
        time.sleep(2)
        screenshot_path = f"/sdcard/Pictures/{package_name}.png"
        subprocess.call(f"adb shell screencap -p \"{screenshot_path}\"", shell=True)
        print(f"截图已保存：{screenshot_path}")

        # 启动自动点击线程
        # click_thread = threading.Thread(target=auto_click_buttons, args=(30,))
        # click_thread.start()

        # 等待30秒
        time.sleep(30)
        # 停止抓包
        stop_tcpdump()
        print("抓包停止")
        # 停止APP
        subprocess.call(f"adb shell am force-stop {package_name}", shell=True)
        print("应用被停止")
        # 卸载APP
        subprocess.call(f"adb uninstall {package_name}", shell=True)
        print("卸载完成")

    except subprocess.CalledProcessError as e:
        print(f"处理 {apk_path} 失败: {e}")

# 主函数
def main():
    if not os.path.exists(APK_FOLDER):
        print("APK 文件夹不存在")
        return

    for file in os.listdir(APK_FOLDER):
        if file.endswith(".apk"):
            apk_path = os.path.join(APK_FOLDER, file)
            run_apk(apk_path)

if __name__ == "__main__":
    main()