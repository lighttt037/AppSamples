#!/usr/bin/env python3
"""
分析 JADX 逆向输出的项目文件，检测是否存在模拟器检测逻辑：
即在检测到 emulator 相关字符串的上下文（±5 行）内出现退出调用（System.exit 或 Runtime.exit）。
"""

import os
import re
import argparse
from pathlib import Path

# 模拟器检测关键词（可根据需要扩充）
EMULATOR_PATTERNS = [
    r"emulator",
    r"generic",
    r"goldfish",
    r"sdk",
    r"ANDROID_EMULATOR",
    r"android\.os\.Build\.MODEL",
    r"android\.os\.Build\.FINGERPRINT"
]
# 退出调用关键词
EXIT_PATTERNS = [
    r"System\.exit\s*\(",
    r"Runtime\.getRuntime\(\)\.exit\s*\("
]

# 编译成正则
emulator_regex = re.compile("|".join(EMULATOR_PATTERNS), re.IGNORECASE)
exit_regex     = re.compile("|".join(EXIT_PATTERNS))

def analyze_file(file_path, context_lines=5):
    """
    分析单个文件，返回存在检测逻辑的 (line_num_emulator, line_num_exit) 列表。
    """
    findings = []
    try:
        with open(file_path, encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return findings

    # 记录所有 emulator 关键词行号
    emulator_lines = [i for i, line in enumerate(lines) if emulator_regex.search(line)]
    # 对每个 emulator 关键词，检查 ±context_lines 范围内的 exit 调用
    for i in emulator_lines:
        start = max(0, i - context_lines)
        end   = min(len(lines), i + context_lines + 1)
        for j in range(start, end):
            if exit_regex.search(lines[j]):
                findings.append((i + 1, j + 1))  # 行号从 1 开始
                break  # 每个 emulator 关键词只记录一次
    return findings

def traverse_and_analyze(root_dir, output_path):
    """
    遍历目录，分析所有文件，输出检测到的模拟器检测逻辑到 output_path。
    """
    root = Path(root_dir)
    results = []

    for path in root.rglob('*'):
        if path.is_file():
            rel = path.relative_to(root_dir)
            hits = analyze_file(str(path))
            if hits:
                for emu_line, exit_line in hits:
                    results.append(f"{rel}: emulator＠line {emu_line} → exit＠line {exit_line}")

    # 写入结果
    with open(output_path, 'w', encoding='utf-8') as out:
        if not results:
            out.write("未检测到模拟器检测逻辑。\n")
        else:
            out.write("检测到以下模拟器检测逻辑：\n")
            for r in results:
                out.write(r + "\n")

    print(f"分析完成，共在 {len(results)} 处发现检测逻辑，详情请查看 {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="检测 APK 反编译项目中是否存在模拟器检测（emulator + exit）逻辑")
    parser.add_argument("src_dir", help="JADX 逆向输出的项目根目录")
    parser.add_argument("output", help="结果输出文件 (.txt)")
    args = parser.parse_args()

    traverse_and_analyze(args.src_dir, args.output)
