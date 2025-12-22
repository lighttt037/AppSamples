#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import logging
import requests
import csv
from datetime import datetime, date
from bs4 import BeautifulSoup  # pip3 install beautifulsoup4

URL = "https://mogua.co"

# 保存目录（务必使用绝对路径）
SAVE_DIR = ("./result/")

# 日志文件路径（绝对路径）
LOG_FILE = "./fetch_webpage.log"

# 每天定时爬取的 6 个时刻（24 小时制，HH:MM）
FETCH_TIMES = ["08:04", "10:05", "13:06", "15:07", "17:09", "20:11"]

def setup_logging():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def fetch_and_save():
    """只尝试一次，失败则跳过本次"""
    os.makedirs(SAVE_DIR, exist_ok=True)
    try:
        logging.info(f"开始 GET {URL}")
        resp = requests.get(URL, timeout=10)
        resp.raise_for_status()

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(SAVE_DIR, f"page_{ts}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(resp.text)
        logging.info(f"HTML 保存到 {html_path}")

        csv_path = os.path.join(SAVE_DIR, f"page_{ts}.csv")
        parse_html_to_csv(html_path, csv_path)
    except Exception as e:
        logging.error(f"抓取或解析失败（已跳过本次）：{e}")

def parse_html_to_csv(html_file, csv_file):
    """解析 HTML 中 #table_malware 的每个 <tr>，写入 CSV"""
    with open(html_file, encoding="utf-8") as f:
        soup = BeautifulSoup(f, "html.parser")

    table = soup.find("table", id="table_malware")
    if not table:
        raise RuntimeError("未找到 id='table_malware' 的表格")

    rows = table.find("tbody").find_all("tr")
    if not rows:
        raise RuntimeError("表格中没有数据行")

    # 打开 CSV，写入 header + 每行数据
    with open(csv_file, "w", newline="", encoding="utf-8") as fcsv:
        writer = csv.writer(fcsv)
        writer.writerow(["App", "Filename", "Hash", "AnalysisTime"])
        for tr in rows:
            tds = tr.find_all("td")
            # APP 信息在第 0 列的 <strong> 标签
            app_str = tds[0].find("strong")
            app = app_str.get_text(strip=True) if app_str else tds[0].get_text(strip=True)
            # Filename 在第 1 列
            filename = tds[1].get_text(strip=True)
            # Hash 在第 3 列
            hashv = tds[3].get_text(strip=True)
            # AnalysisTime 在第 4 列
            atime = tds[4].get_text(strip=True)
            writer.writerow([app, filename, hashv, atime])

    logging.info(f"解析完成，CSV 保存到 {csv_file}")

def main():
    setup_logging()
    logging.info("定时抓取并解析脚本启动")

    last_run_date = date.today()
    run_times_today = set()

    while True:
        now = datetime.now()
        # 每天零点重置
        if now.date() != last_run_date:
            last_run_date = now.date()
            run_times_today.clear()
            logging.info("新的一天，已重置运行记录")

        hhmm = now.strftime("%H:%M")
        if hhmm in FETCH_TIMES and hhmm not in run_times_today:
            run_times_today.add(hhmm)
            fetch_and_save()

        time.sleep(30)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("脚本手动终止")
        sys.exit(0)