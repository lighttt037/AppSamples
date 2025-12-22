import os
import pandas as pd

def remove_duplicate_lines(input_file, output_file="unique_lines.txt"):
    """
    读取 TXT 文件，去除重复行，仅保留唯一内容行，并写入新文件。

    :param input_file: 输入的 TXT 文件路径
    :param output_file: 输出的去重后 TXT 文件路径
    """
    from collections import Counter

    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # 统计每一行出现的次数
    line_counts = Counter(lines)

    # 仅保留出现一次的行
    unique_lines = [line for line, count in line_counts.items() if count == 1]

    # 写入新文件
    with open(output_file, "w", encoding="utf-8") as f:
        f.writelines(unique_lines)

    print(f"去重后的 TXT 文件已保存至：{output_file}")


def merge_and_deduplicate_csv(folder_path, output_file):
    """
    合并文件夹下所有 CSV 文件，并去重后保存。

    :param folder_path: CSV 文件所在文件夹路径
    :param output_file: 合并后 CSV 文件的保存路径
    """
    all_dfs = []

    # 遍历文件夹中的所有 CSV 文件
    for file in os.listdir(folder_path):
        if file.endswith(".csv"):
            file_path = os.path.join(folder_path, file)
            df = pd.read_csv(file_path, dtype=str)  # 读取 CSV 并保证数据格式一致
            all_dfs.append(df)

    if not all_dfs:
        print("文件夹中没有 CSV 文件！")
        return

    # 合并所有 DataFrame，并去重
    merged_df = pd.concat(all_dfs, ignore_index=True).drop_duplicates()

    # 保存结果
    merged_df.to_csv(output_file, index=False, encoding="utf-8")
    print(f"合并后的 CSV 文件已保存至：{output_file}")


def filter_csv(input_file, output_file, keywords):
    """
    读取 CSV 文件，检查第一列和第二列是否包含指定关键词，删除包含关键词的行，并将结果保存到新文件。

    :param input_file: 输入的 CSV 文件路径
    :param output_file: 过滤后的 CSV 输出文件路径
    :param keywords: 需要过滤的关键词列表
    """
    # 读取 CSV 文件
    df = pd.read_csv(input_file, dtype=str, encoding="utf-8")

    # 确保 CSV 至少有两列
    if df.shape[1] < 2:
        print("CSV 文件的列数不足 2 列，无法执行过滤操作！")
        return

    # 过滤掉包含关键词的行
    filtered_df = df[~df.iloc[:, 0].str.contains('|'.join(keywords), na=False) &
                     ~df.iloc[:, 1].str.contains('|'.join(keywords), na=False)]

    # 保存结果
    filtered_df.to_csv(output_file, index=False, encoding="utf-8")
    print(f"过滤后的数据已保存至：{output_file}")

def remove_duplicate_third_column(input_file, output_file):
    """
    读取 CSV 文件，检查第三列的值，如果该值已出现过，则删除该行，最终结果写入新的 CSV 文件。

    :param input_file: 输入的 CSV 文件路径
    :param output_file: 处理后的 CSV 输出文件路径
    """
    # 读取 CSV 文件
    df = pd.read_csv(input_file, dtype=str, encoding="utf-8")

    # 确保 CSV 至少有 3 列
    if df.shape[1] < 3:
        print("CSV 文件的列数不足 3 列，无法执行去重操作！")
        return

    # 使用集合记录已经出现过的第三列值
    seen_values = set()
    unique_rows = []

    # 遍历 CSV 每一行
    for index, row in df.iterrows():
        third_column_value = row.iloc[2]  # 取第三列的值
        if third_column_value not in seen_values:
            seen_values.add(third_column_value)
            unique_rows.append(row)  # 只有第三列没出现过的行才保留

    # 转换为 DataFrame 并写入 CSV
    filtered_df = pd.DataFrame(unique_rows)
    filtered_df.to_csv(output_file, index=False, encoding="utf-8")

    print(f"去重后的数据已保存至：{output_file}")

def filter_csv_by_third_column(file1, file2, output_file):
    # 读取 file1.csv
    df1 = pd.read_csv(file1, dtype=str, encoding="utf-8")

    # 确保文件一至少有 3 列
    if df1.shape[1] < 3:
        print("错误：文件1的列数不足 3 列，无法执行操作！")
        return

    # 记录文件一第三列的所有值
    third_column_values = set(df1.iloc[:, 2].dropna())  # 使用集合加快查找速度
    # 读取 file2.csv
    df2 = pd.read_csv(file2, dtype=str, encoding="utf-8")

    # 确保文件二至少有 3 列
    if df2.shape[1] < 3:
        print("错误：文件2的列数不足 3 列，无法执行操作！")
        return

    # 过滤文件二，删除第三列出现在文件一第三列中的行
    filtered_df2 = df2[~df2.iloc[:, 2].isin(third_column_values)]
    # 保存结果
    filtered_df2.to_csv(output_file, index=False, encoding="utf-8")
    print(f"过滤后的数据已保存至：{output_file}")


if __name__ == '__main__':
    # 合并 下载全部csv
    merge_and_deduplicate_csv("/Users/mymac/Documents/PycharmProjects/pythonProject/mogua_crawl/csvname",
                              "merged1_06121.txt")
    # 移除重复，意义似不大
'''    remove_duplicate_lines("/Users/mymac/Documents/PycharmProjects/pythonProject/mogua_crawl/md5_list.txt")
    # 移除含关键词的行
    filter_csv("merged1_yuanshi.csv", "./merged1_new.csv", ["aa"])
    # 移除md5相同的内容
    remove_duplicate_third_column("./merged1_new.csv","./merged1_new_output.csv")
    # 待下载的中移除已下载的
    filter_csv_by_third_column("merged_new.csv", "merged1_new_output.csv", "merged2_new_output.csv")
'''