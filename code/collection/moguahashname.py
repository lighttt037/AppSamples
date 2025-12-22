import os

import csv

import requests
from bs4 import BeautifulSoup

from mogua_crawl.moguakeywords import parse_html_to_csv


def fetch_and_parse_second_strong(key):
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
        # "Cookie": "UM_distinctid=195b7567e4427a-09a371ec7f0b06-26011d51-144000-195b7567e4577b; sessionid=optzzjpxpk13uxnbswm2zf7q9whjzqt1; CNZZDATA1281141868=1539957107-1742537654-%7C1742537835",
        "Host": "mogua.co",
        "Referer": f"https://mogua.co/souku?key={key}&type=md5",
        "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
    }
    file_name = f"/Users/gyc/Documents/PycharmProjects/pythonProject/mogua_crawl/html_temp/{key}.html"  # 保存为HTML文件

    if not os.path.exists(file_name):
        url = f"https://mogua.co/souku?key={key}&type=md5"

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        with open(file_name, "w", encoding="utf-8") as file:
            file.write(response.text)




    #if response.status_code == 200:
    csv_name = f"/Users/gyc/Documents/PycharmProjects/pythonProject/mogua_crawl/csv_temp/{key}.csv"  # 保存为HTML文件

    parse_html_to_csv(file_name, csv_name)
    # 使用BeautifulSoup解析HTML
    #     soup = BeautifulSoup(response.text, "html.parser")
    #     all_strong_tags = soup.find_all("strong")  # 获取所有<strong>标签
    #
    #     if len(all_strong_tags) >= 2:
    #         second_strong = all_strong_tags[1].text.strip()  # 索引1表示第二个标签
    #         print(f"第二个<strong>标签内容: {second_strong}")
    #     else:
    #         print("未找到足够的<strong>标签（至少需要2个）")
    #
    # except requests.exceptions.RequestException as e:
    #     print(f"请求失败: {e}")

def parse_html_to_csv(html_path, csv_path):
    # 初始化CSV写入器
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, delimiter='\t')
        writer.writerow(['应用名称及版本', '文件名', 'MD5哈希', '时间'])

        # 解析HTML
        with open(html_path, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')

            # 定位所有tr标签
            for tr in soup.select('table#table_malware tbody tr'):
                tds = tr.find_all('td')
                if len(tds) < 6:
                    continue

                # 解析应用名称和版本
                app_info = tds[0].find('strong').get_text(strip=True).replace("\u2061","").replace("\u200e","").replace("\u202b","") if tds[0].find('strong') else ''

                # 解析文件名
                filename = tds[1].get_text(strip=True).replace("\u2061","").replace("\u202b","")

                # 解析MD5哈希
                md5_hash = tds[3].get_text(strip=True)

                # 解析时间
                timestamp = tds[4].get_text(strip=True)

                print([app_info, filename, md5_hash, timestamp])



# 使用示例
if __name__ == "__main__":
    list =[]
    i=0
    for a in list:
        i+=1
        fetch_and_parse_second_strong(a)