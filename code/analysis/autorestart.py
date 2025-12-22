#!/usr/bin/env python3
import os
import subprocess
import re
import time
import sys
import argparse
from datetime import datetime


def run_command(command):
    """执行命令并返回结果"""
    try:
        result = subprocess.run(command, shell=True, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"错误: 执行命令 '{command}' 失败")
        print(f"错误信息: {e.stderr}")
        return None


def get_package_name(apk_path):
    """从APK文件获取包名"""
    cmd = f"aapt dump badging {apk_path} | grep package"
    result = run_command(cmd)
    if result:
        match = re.search(r"package: name='(.*?)'", result)
        if match:
            return match.group(1)
    print("无法获取包名，请确保已安装aapt并且APK文件有效")
    return None


def install_apk(apk_path):
    """安装APK文件"""
    print(f"正在安装 {apk_path}...")
    result = run_command(f"adb install -r {apk_path}")
    if result is not None:
        print("APK安装成功")
        return True
    return False


def start_app(package_name):
    """启动应用"""
    print(f"正在启动应用 {package_name}...")
    # 获取应用的主Activity
    cmd = f"adb shell cmd package resolve-activity --brief {package_name} | tail -n 1"
    main_activity = run_command(cmd).strip()

    if not main_activity or "/" not in main_activity:
        print("无法获取主Activity，尝试使用monkey启动应用")
        run_command(f"adb shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1")
    else:
        run_command(f"adb shell am start -n {main_activity}")

    print(f"应用 {package_name} 已启动")
    return True


def kill_app(package_name):
    """终止应用运行"""
    print(f"正在终止应用 {package_name}...")
    run_command(f"adb shell am force-stop {package_name}")
    print(f"应用 {package_name} 已终止")


def uninstall_app(package_name):
    """卸载应用"""
    print(f"正在卸载应用 {package_name}...")
    run_command(f"adb shell pm uninstall {package_name}")
    print(f"应用 {package_name} 已卸载")


def start_logcat(log_file):
    """开始记录logcat"""
    print("开始记录logcat...")
    # 清除之前的logcat记录
    run_command("adb logcat -c")
    # 启动logcat并将输出重定向到文件
    logcat_process = subprocess.Popen(
        ["adb", "logcat"],
        stdout=open(log_file, "w"),
        stderr=subprocess.PIPE
    )
    return logcat_process


def stop_logcat(logcat_process):
    """停止记录logcat"""
    print("停止记录logcat...")
    logcat_process.terminate()
    time.sleep(1)  # 给一点时间让进程终止


def analyze_log(log_file, package_name):
    """分析日志文件，检查自启动行为和广播弹窗行为"""
    print(f"正在分析日志文件 {log_file}...")

    auto_start_patterns = [
        # 检测服务重启
        rf"Scheduling restart of crashed service {package_name}.*for start-requested",
        rf"Start proc.*{package_name}.*for service",
        # 检测系统启动的服务
        rf"Starting service: Intent.*{package_name}",
        # 守护进程相关
        rf"DaemonService.*{package_name}",
        rf"KeepAliveService.*{package_name}"
    ]

    notification_patterns = [
        # 检测通知和Toast
        rf"NotificationService.*pkg={package_name}",
        rf"Toast.*pkg={package_name}",
        rf"ShowToast.*{package_name}",
        # 广播接收器
        rf"Broadcast.*{package_name}",
        rf"BroadcastReceiver.*{package_name}"
    ]

    auto_start_found = False
    notification_found = False
    auto_start_evidence = []
    notification_evidence = []

    try:
        with open(log_file, 'r', errors='replace') as f:
            for line in f:
                # 检查自启动行为
                for pattern in auto_start_patterns:
                    if re.search(pattern, line):
                        auto_start_found = True
                        auto_start_evidence.append(line.strip())

                # 检查广播弹窗行为
                for pattern in notification_patterns:
                    if re.search(pattern, line):
                        notification_found = True
                        notification_evidence.append(line.strip())
    except Exception as e:
        print(f"读取日志文件时出错: {e}")
        return False, False, [], []

    return auto_start_found, notification_found, auto_start_evidence, notification_evidence


def main():
    parser = argparse.ArgumentParser(description='APK自启动和广播弹窗行为分析工具')
    parser.add_argument('apk_path', help='APK文件路径')
    parser.add_argument('--wait-time', type=int, default=30,
                        help='应用运行时间(秒), 默认30秒')
    args = parser.parse_args()

    apk_path = args.apk_path
    wait_time = args.wait_time

    if not os.path.exists(apk_path):
        print(f"错误: APK文件 '{apk_path}' 不存在")
        return

    # 创建日志目录
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = f"apk_analysis_{timestamp}"
    os.makedirs(log_dir, exist_ok=True)

    # 日志文件路径
    device_log_file = f"/sdcard/logcat_{timestamp}.txt"
    local_log_file = os.path.join(log_dir, f"logcat_{timestamp}.txt")

    # 获取包名
    package_name = get_package_name(apk_path)
    if not package_name:
        return

    # 记录分析信息
    analysis_file = os.path.join(log_dir, "analysis_report.txt")
    with open(analysis_file, 'w') as f:
        f.write(f"APK分析报告 - {timestamp}\n")
        f.write(f"APK路径: {apk_path}\n")
        f.write(f"包名: {package_name}\n\n")

    # 开始记录logcat
    logcat_process = start_logcat(local_log_file)

    try:
        # 安装APK
        if not install_apk(apk_path):
            raise Exception("安装APK失败")

        # 启动应用
        if not start_app(package_name):
            raise Exception("启动应用失败")

        print(f"等待应用运行 {wait_time} 秒...")
        time.sleep(wait_time)

        # 终止应用
        kill_app(package_name)

        # 再等待一段时间，观察是否有自启动行为
        print("等待10秒，观察可能的自启动行为...")
        time.sleep(10)

        # 卸载应用
        uninstall_app(package_name)

    except Exception as e:
        print(f"错误: {e}")
    finally:
        # 停止记录logcat
        stop_logcat(logcat_process)

    # 分析日志
    auto_start, notification, auto_start_evidence, notification_evidence = analyze_log(
        local_log_file, package_name)

    # 写入分析结果
    with open(analysis_file, 'a') as f:
        f.write("=== 分析结果 ===\n\n")

        f.write("1. 自启动行为检测:\n")
        if auto_start:
            f.write("   [发现] 应用存在自启动行为\n\n")
            f.write("   证据:\n")
            for evidence in auto_start_evidence:
                f.write(f"   - {evidence}\n")
        else:
            f.write("   [未发现] 未检测到自启动行为\n")

        f.write("\n2. 广播弹窗行为检测:\n")
        if notification:
            f.write("   [发现] 应用存在广播弹窗行为\n\n")
            f.write("   证据:\n")
            for evidence in notification_evidence:
                f.write(f"   - {evidence}\n")
        else:
            f.write("   [未发现] 未检测到广播弹窗行为\n")

    # 打印分析结果
    print("\n=== 分析结果 ===")
    print(f"分析报告已保存到: {analysis_file}")
    print(f"日志文件已保存到: {local_log_file}")

    if auto_start:
        print("\n[发现] 应用存在自启动行为")
        print("部分证据:")
        for evidence in auto_start_evidence[:5]:  # 只显示前5条
            print(f"- {evidence}")
        if len(auto_start_evidence) > 5:
            print(f"... 还有 {len(auto_start_evidence) - 5} 条记录")
    else:
        print("\n[未发现] 未检测到自启动行为")

    if notification:
        print("\n[发现] 应用存在广播弹窗行为")
        print("部分证据:")
        for evidence in notification_evidence[:5]:  # 只显示前5条
            print(f"- {evidence}")
        if len(notification_evidence) > 5:
            print(f"... 还有 {len(notification_evidence) - 5} 条记录")
    else:
        print("\n[未发现] 未检测到广播弹窗行为")


if __name__ == "__main__":
    main()