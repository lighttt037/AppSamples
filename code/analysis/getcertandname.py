#!/usr/bin/env python3
"""
遍历指定目录下的所有 APK 文件，使用 aapt 提取应用名称，使用 apksigner 提取签名证书信息，
并将结果写入指定的输出文本文件。
"""

import os
import re
import subprocess
import argparse
from pathlib import Path

def get_app_label(aapt_path: str, apk_path: str) -> str:
    """
    使用 aapt dump badging 获取 APK 的 application-label。
    """
    try:
        out = subprocess.check_output(
            [aapt_path, "dump", "badging", apk_path],
            stderr=subprocess.DEVNULL,
            text=True
        )
    except subprocess.CalledProcessError:
        return ""
    # 匹配 application-label 或者带地区后缀的 application-label-xx
    m = re.search(r"application-label(?:-[\w-]+)?:'([^']*)'", out)
    return m.group(1) if m else ""

def get_certificate_info(apksigner_path: str, apk_path: str) -> str:
    """
    使用 apksigner verify --print-certs 获取 APK 的签名证书信息。
    """
    try:
        out = subprocess.check_output(
            [apksigner_path, "verify", "--print-certs", apk_path],
            stderr=subprocess.STDOUT,
            text=True
        )
    except subprocess.CalledProcessError as e:
        # apksigner 非零返回码也会输出证书详情
        out = e.output
    return out.strip()

def process_apks(aapt_path: str, apksigner_path: str, apk_dir: str, output_txt: str):
    apk_dir = Path(apk_dir)
    with open(output_txt, "w", encoding="utf-8") as f_out:
        for apk_file in sorted(apk_dir.glob("*.apk")):
            apk_path = str(apk_file)
            label = get_app_label(aapt_path, apk_path)
            cert_info = get_certificate_info(apksigner_path, apk_path)

            f_out.write(f"=== APK 文件：{apk_file.name} ===\n")
            f_out.write(f"应用名称：{label or '未知'}\n")
            f_out.write("证书信息：\n")
            f_out.write(cert_info + "\n")
            f_out.write("\n")

    print(f"已处理 {apk_dir.glob('*.apk').__length_hint__()} 个 APK，结果已写入：{output_txt}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="批量提取 APK 名称与签名证书信息")
    parser.add_argument("aapt", help="aapt 可执行文件的完整路径")
    parser.add_argument("apksigner", help="apksigner 可执行文件的完整路径")
    parser.add_argument("apk_dir", help="存放 APK 文件的目录")
    parser.add_argument("output", help="输出结果的文本文件路径（.txt）")
    args = parser.parse_args()

    process_apks(args.aapt, args.apksigner, args.apk_dir, args.output)
