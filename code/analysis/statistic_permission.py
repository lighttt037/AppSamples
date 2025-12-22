import os
import re
from pathlib import Path
from collections import Counter, defaultdict
import statistics
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from matplotlib import rcParams

def load_dangerous_permissions(file_path):
    """加载危险权限列表"""
    dangerous_permissions = set()

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 提取权限名称，匹配大写字母开头的权限
        permission_pattern = r'([A-Z_][A-Z0-9_]*)\s*-'
        permissions = re.findall(permission_pattern, content)

        for perm in permissions:
            # 添加完整的权限名称
            dangerous_permissions.add(f'android.permission.{perm}')

    except FileNotFoundError:
        print(f"危险权限文件未找到: {file_path}")
        return set()
    except Exception as e:
        print(f"读取危险权限文件时出错: {e}")
        return set()

    return dangerous_permissions

def parse_apk_info(file_path):
    """解析APK信息文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"读取文件失败 {file_path}: {e}")
        return None, None, []

    # 提取文件名中的hash值和包名
    filename = os.path.basename(file_path)
    # 文件名格式: {hash值}.apk_{包名}.txt
    match = re.match(r'([a-fA-F0-9]+)\.apk_(.+)\.txt$', filename)
    if not match:
        print(f"文件名格式不正确: {filename}")
        return None, None, []

    hash_value = match.group(1)
    package_name = match.group(2)

    # 提取权限信息
    permissions = []
    permission_pattern = r"uses-permission: name='([^']+)'"
    matches = re.findall(permission_pattern, content)

    for match in matches:
        permissions.append(match)

    return hash_value, package_name, permissions

def calculate_statistics(apk_info_dir, dangerous_permissions_file, output_file):
    """计算权限统计信息"""
    # 加载危险权限列表
    dangerous_permissions = load_dangerous_permissions(dangerous_permissions_file)
    print(f"加载了 {len(dangerous_permissions)} 个危险权限")

    # 获取所有APK信息文件
    apk_info_dir = Path(apk_info_dir)
    if not apk_info_dir.exists():
        print(f"目录不存在: {apk_info_dir}")
        return

    txt_files = list(apk_info_dir.glob("*.txt"))
    if not txt_files:
        print(f"目录中没有找到txt文件: {apk_info_dir}")
        return

    print(f"找到 {len(txt_files)} 个APK信息文件")

    # 数据收集
    apk_data = []
    all_permissions = Counter()
    dangerous_permission_usage = Counter()
    total_permissions_per_app = []
    dangerous_permissions_per_app = []

    successful_parsed = 0
    failed_parsed = 0

    for txt_file in txt_files:
        hash_value, package_name, permissions = parse_apk_info(txt_file)

        if hash_value is None or package_name is None:
            failed_parsed += 1
            continue

        successful_parsed += 1

        # 统计所有权限
        all_permissions.update(permissions)

        # 找出危险权限
        found_dangerous_permissions = []
        for perm in permissions:
            if perm in dangerous_permissions:
                found_dangerous_permissions.append(perm)
                dangerous_permission_usage[perm] += 1

        # 记录数据
        apk_data.append({
            'hash': hash_value,
            'package': package_name,
            'all_permissions': permissions,
            'dangerous_permissions': found_dangerous_permissions,
            'total_permission_count': len(permissions),
            'dangerous_permission_count': len(found_dangerous_permissions)
        })

        total_permissions_per_app.append(len(permissions))
        dangerous_permissions_per_app.append(len(found_dangerous_permissions))

    # 计算统计数据
    print("正在计算统计数据...")

    # 横向统计（每个APP的统计）
    apps_with_dangerous_permissions = len([app for app in apk_data if app['dangerous_permission_count'] > 0])

    # 纵向统计（权限在不同APP中的分布）
    unique_permissions = len(all_permissions)
    unique_dangerous_permissions_used = len(dangerous_permission_usage)

    # 输出统计结果
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("APK权限统计分析报告\n")
            f.write("=" * 60 + "\n\n")

            # 基本信息
            f.write("📊 基本信息统计\n")
            f.write("-" * 30 + "\n")
            f.write(f"总APK文件数: {len(txt_files)}\n")
            f.write(f"成功解析的APK数: {successful_parsed}\n")
            f.write(f"解析失败的APK数: {failed_parsed}\n")
            f.write(f"解析成功率: {successful_parsed/len(txt_files)*100:.2f}%\n\n")

            # 1. 平均每个APP申请权限数量（横向统计）
            f.write("📱 APP权限申请统计（横向分析）\n")
            f.write("-" * 30 + "\n")
            f.write(f"平均每个APP申请权限数量: {statistics.mean(total_permissions_per_app):.2f}\n")
            f.write(f"权限申请数量中位数: {statistics.median(total_permissions_per_app):.2f}\n")
            f.write(f"权限申请数量标准差: {statistics.stdev(total_permissions_per_app):.2f}\n")
            f.write(f"最少权限申请数: {min(total_permissions_per_app)}\n")
            f.write(f"最多权限申请数: {max(total_permissions_per_app)}\n")

            # 权限申请数量分布
            permission_ranges = {
                "0-10个权限": len([x for x in total_permissions_per_app if 0 <= x <= 10]),
                "11-20个权限": len([x for x in total_permissions_per_app if 11 <= x <= 20]),
                "21-30个权限": len([x for x in total_permissions_per_app if 21 <= x <= 30]),
                "31-40个权限": len([x for x in total_permissions_per_app if 31 <= x <= 40]),
                "40个以上权限": len([x for x in total_permissions_per_app if x > 40])
            }

            f.write("\n权限申请数量分布:\n")
            for range_name, count in permission_ranges.items():
                percentage = count / successful_parsed * 100
                f.write(f"  {range_name}: {count}个APP ({percentage:.1f}%)\n")

            # 2. 危险权限数量统计（横向统计）
            f.write(f"\n🚨 危险权限统计（横向分析）\n")
            f.write("-" * 30 + "\n")
            f.write(f"使用危险权限的APP数量: {apps_with_dangerous_permissions}\n")
            f.write(f"使用危险权限的APP比例: {apps_with_dangerous_permissions/successful_parsed*100:.2f}%\n")
            f.write(f"平均每个APP使用危险权限数量: {statistics.mean(dangerous_permissions_per_app):.2f}\n")
            f.write(f"危险权限使用数量中位数: {statistics.median(dangerous_permissions_per_app):.2f}\n")

            if dangerous_permissions_per_app and max(dangerous_permissions_per_app) > 0:
                f.write(f"危险权限使用数量标准差: {statistics.stdev(dangerous_permissions_per_app):.2f}\n")

            f.write(f"最少危险权限使用数: {min(dangerous_permissions_per_app)}\n")
            f.write(f"最多危险权限使用数: {max(dangerous_permissions_per_app)}\n")

            # 危险权限使用数量分布
            dangerous_ranges = {
                "0个危险权限": len([x for x in dangerous_permissions_per_app if x == 0]),
                "1-3个危险权限": len([x for x in dangerous_permissions_per_app if 1 <= x <= 3]),
                "4-6个危险权限": len([x for x in dangerous_permissions_per_app if 4 <= x <= 6]),
                "7-9个危险权限": len([x for x in dangerous_permissions_per_app if 7 <= x <= 9]),
                "10个以上危险权限": len([x for x in dangerous_permissions_per_app if x >= 10])
            }

            f.write("\n危险权限使用数量分布:\n")
            for range_name, count in dangerous_ranges.items():
                percentage = count / successful_parsed * 100
                f.write(f"  {range_name}: {count}个APP ({percentage:.1f}%)\n")

            # 3. 危险权限在不同APP中的出现统计（纵向统计）
            f.write(f"\n🔍 危险权限使用频次统计（纵向分析）\n")
            f.write("-" * 30 + "\n")
            f.write(f"系统定义的危险权限总数: {len(dangerous_permissions)}\n")
            f.write(f"实际被使用的危险权限数: {unique_dangerous_permissions_used}\n")
            f.write(f"危险权限使用覆盖率: {unique_dangerous_permissions_used/len(dangerous_permissions)*100:.2f}%\n\n")

            f.write("危险权限使用频次排行榜（前20名）:\n")
            top_20_dangerous = dangerous_permission_usage.most_common(20)
            for i, (perm, count) in enumerate(top_20_dangerous, 1):
                percentage = count / successful_parsed * 100
                f.write(f"  {i:2d}. {perm}: {count}个APP ({percentage:.1f}%)\n")

            # 权限使用频次分布
            f.write(f"\n危险权限使用频次分布:\n")
            frequency_ranges = {
                "使用1-10次": len([count for count in dangerous_permission_usage.values() if 1 <= count <= 10]),
                "使用11-50次": len([count for count in dangerous_permission_usage.values() if 11 <= count <= 50]),
                "使用51-100次": len([count for count in dangerous_permission_usage.values() if 51 <= count <= 100]),
                "使用101-500次": len([count for count in dangerous_permission_usage.values() if 101 <= count <= 500]),
                "使用500次以上": len([count for count in dangerous_permission_usage.values() if count > 500])
            }

            for range_name, count in frequency_ranges.items():
                f.write(f"  {range_name}: {count}个权限\n")

            # 详细的APP危险权限使用情况
            f.write(f"\n📋 高危险权限APP列表（使用5个以上危险权限）\n")
            f.write("-" * 30 + "\n")

            high_risk_apps = [app for app in apk_data if app['dangerous_permission_count'] >= 5]
            high_risk_apps.sort(key=lambda x: x['dangerous_permission_count'], reverse=True)

            for i, app in enumerate(high_risk_apps[:50], 1):  # 只显示前50个
                f.write(f"{i:2d}. {app['package']}\n")
                f.write(f"    Hash: {app['hash']}\n")
                f.write(f"    总权限数: {app['total_permission_count']}\n")
                f.write(f"    危险权限数: {app['dangerous_permission_count']}\n")
                f.write(f"    危险权限: {', '.join(app['dangerous_permissions'])}\n\n")

            # 全部权限使用统计
            f.write(f"\n📊 全部权限使用统计\n")
            f.write("-" * 30 + "\n")
            f.write(f"系统中发现的权限总数: {unique_permissions}\n")
            f.write(f"最常用权限排行榜（前15名）:\n")

            top_15_all = all_permissions.most_common(15)
            for i, (perm, count) in enumerate(top_15_all, 1):
                percentage = count / successful_parsed * 100
                is_dangerous = "🚨" if perm in dangerous_permissions else "✅"
                f.write(f"  {i:2d}. {is_dangerous} {perm}: {count}个APP ({percentage:.1f}%)\n")

            # 添加权限组分析
            f.write(f"\n🔍 权限组使用分析\n")
            f.write("-" * 30 + "\n")

            group_usage = analyze_permission_groups(dangerous_permission_usage)
            top_10_groups = sorted(group_usage.items(), key=lambda x: x[1], reverse=True)[:10]

            group_chinese = {
                'LOCATION': '位置权限组',
                'CAMERA': '相机权限组',
                'MICROPHONE': '麦克风权限组',
                'STORAGE': '存储权限组',
                'CONTACTS': '联系人权限组',
                'PHONE': '电话权限组',
                'SMS': '短信权限组',
                'CALENDAR': '日历权限组',
                'SENSORS': '传感器权限组',
                'CALL_LOG': '通话记录权限组',
                'NEARBY_DEVICES': '附近设备权限组',
                'MEDIA_AUDIO': '音频权限组',
                'MEDIA_IMAGES': '图片权限组',
                'MEDIA_VIDEO': '视频权限组',
                'NOTIFICATIONS': '通知权限组'
            }

            f.write("权限组使用频次排行榜（前10名）:\n")
            for i, (group, count) in enumerate(top_10_groups, 1):
                percentage = count / successful_parsed * 100
                group_name = group_chinese.get(group, group)
                f.write(f"  {i:2d}. {group_name}: {count}个APP ({percentage:.1f}%)\n")

        print(f"统计分析完成，结果已保存到: {output_file}")

        # 生成图表
        print("正在生成可视化图表...")
        if create_permission_charts(dangerous_permission_usage, group_usage, Path(output_file).parent):
            print("图表生成成功！")
        else:
            print("图表生成失败，但统计报告已完成。")
            print("提示：如需生成图表，请安装matplotlib: pip install matplotlib")

    except Exception as e:
        print(f"写入统计结果时出错: {e}")

def get_permission_groups():
    """定义权限组映射"""
    permission_groups = {
        'LOCATION': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION'],
        'CAMERA': ['CAMERA'],
        'MICROPHONE': ['RECORD_AUDIO'],
        'STORAGE': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE'],
        'CONTACTS': ['READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS'],
        'PHONE': ['READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'CALL_PHONE', 'ANSWER_PHONE_CALLS',
                  'ADD_VOICEMAIL', 'USE_SIP', 'ACCEPT_HANDOVER'],
        'SMS': ['SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'RECEIVE_WAP_PUSH', 'RECEIVE_MMS'],
        'CALENDAR': ['READ_CALENDAR', 'WRITE_CALENDAR'],
        'SENSORS': ['BODY_SENSORS', 'BODY_SENSORS_BACKGROUND'],
        'CALL_LOG': ['READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS'],
        'NEARBY_DEVICES': ['BLUETOOTH_ADVERTISE', 'BLUETOOTH_CONNECT', 'BLUETOOTH_SCAN', 'UWB_RANGING'],
        'MEDIA_AUDIO': ['READ_MEDIA_AUDIO'],
        'MEDIA_IMAGES': ['READ_MEDIA_IMAGES'],
        'MEDIA_VIDEO': ['READ_MEDIA_VIDEO'],
        'NOTIFICATIONS': ['POST_NOTIFICATIONS']
    }
    return permission_groups

def analyze_permission_groups(dangerous_permission_usage):
    """分析权限组使用情况"""
    permission_groups = get_permission_groups()
    group_usage = defaultdict(int)

    for perm, count in dangerous_permission_usage.items():
        # 移除android.permission.前缀
        perm_short = perm.replace('android.permission.', '')

        # 查找权限所属的组
        for group_name, permissions in permission_groups.items():
            if perm_short in permissions:
                group_usage[group_name] += count
                break

    return group_usage

def create_permission_charts(dangerous_permission_usage, group_usage, output_dir):
    """创建权限使用图表"""
    try:
        # 创建图表目录
        charts_dir = Path(output_dir) / "charts"
        charts_dir.mkdir(exist_ok=True)

        # 1. 危险权限使用频次图表
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 16))

        # 获取前15个危险权限
        top_15_dangerous = dangerous_permission_usage.most_common(15)
        permissions = [perm.replace('android.permission.', '') for perm, _ in top_15_dangerous]
        counts = [count for _, count in top_15_dangerous]

        # 创建颜色映射
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8',
                  '#F7DC6F', '#BB8FCE', '#85C1E9', '#F8C471', '#82E0AA', '#F1948A', '#85C1E9', '#D5A6BD']

        # 绘制危险权限柱状图
        bars1 = ax1.barh(range(len(permissions)), counts, color=colors[:len(permissions)])
        ax1.set_yticks(range(len(permissions)))
        ax1.set_yticklabels(permissions, fontsize=10)
        ax1.set_xlabel('Number of Apps', fontsize=12)
        ax1.set_title('Dangerous Permissions Usage Statistics (Top 15)', fontsize=14, fontweight='bold')
        ax1.grid(True, alpha=0.3)

        # 添加数值标签
        for i, (bar, count) in enumerate(zip(bars1, counts)):
            ax1.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height()/2,
                    str(count), ha='left', va='center', fontsize=9)

        # 2. 权限组使用频次图表
        top_10_groups = sorted(group_usage.items(), key=lambda x: x[1], reverse=True)[:10]
        group_names = [group for group, _ in top_10_groups]
        group_counts = [count for _, count in top_10_groups]

        # 权限组英文名称映射
        group_english = {
            'LOCATION': 'Location',
            'CAMERA': 'Camera',
            'MICROPHONE': 'Microphone',
            'STORAGE': 'Storage',
            'CONTACTS': 'Contacts',
            'PHONE': 'Phone',
            'SMS': 'SMS',
            'CALENDAR': 'Calendar',
            'SENSORS': 'Sensors',
            'CALL_LOG': 'Call Log',
            'NEARBY_DEVICES': 'Nearby Devices',
            'MEDIA_AUDIO': 'Media Audio',
            'MEDIA_IMAGES': 'Media Images',
            'MEDIA_VIDEO': 'Media Video',
            'NOTIFICATIONS': 'Notifications'
        }

        group_labels = [group_english.get(group, group) for group in group_names]

        # 绘制权限组柱状图
        colors_groups = ['#FF9999', '#66B2FF', '#99FF99', '#FFCC99', '#FF99CC',
                        '#99CCFF', '#FFD700', '#FF6347', '#98FB98', '#DDA0DD']

        bars2 = ax2.barh(range(len(group_labels)), group_counts, color=colors_groups[:len(group_labels)])
        ax2.set_yticks(range(len(group_labels)))
        ax2.set_yticklabels(group_labels, fontsize=10)
        ax2.set_xlabel('Number of Apps', fontsize=12)
        ax2.set_title('Dangerous Permission Groups Usage Statistics (Top 10)', fontsize=14, fontweight='bold')
        ax2.grid(True, alpha=0.3)

        # 添加数值标签
        for i, (bar, count) in enumerate(zip(bars2, group_counts)):
            ax2.text(bar.get_width() + max(group_counts) * 0.01, bar.get_y() + bar.get_height()/2,
                    str(count), ha='left', va='center', fontsize=9)

        plt.tight_layout()
        plt.savefig(charts_dir / "dangerous_permissions_analysis.png", dpi=300, bbox_inches='tight')
        plt.close()

        # 3. 创建单独的危险权限图表（类似论文图表风格）
        fig, ax = plt.subplots(figsize=(12, 8))

        # 取前12个权限
        top_12_dangerous = dangerous_permission_usage.most_common(12)
        permissions_12 = [perm.replace('android.permission.', '') for perm, _ in top_12_dangerous]
        counts_12 = [count for _, count in top_12_dangerous]

        # 使用蓝色和橙色配色方案（类似论文图表）
        colors_paper = ['#1f77b4', '#ff7f0e'] * 6

        bars = ax.barh(range(len(permissions_12)), counts_12, color=colors_paper[:len(permissions_12)])
        ax.set_yticks(range(len(permissions_12)))
        ax.set_yticklabels(permissions_12, fontsize=11)
        ax.set_xlabel('Number of Apps', fontsize=12)
        ax.set_title('Dangerous Permissions Usage Statistics', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')

        # 添加数值标签
        for i, (bar, count) in enumerate(zip(bars, counts_12)):
            ax.text(bar.get_width() + max(counts_12) * 0.01, bar.get_y() + bar.get_height()/2,
                    str(count), ha='left', va='center', fontsize=10)

        plt.tight_layout()
        plt.savefig(charts_dir / "dangerous_permissions_paper_style.png", dpi=300, bbox_inches='tight')
        plt.close()

        print(f"图表已保存到: {charts_dir}")
        return True

    except Exception as e:
        print(f"创建图表时出错: {e}")
        return False

def main():
    # 设置路径
    apk_info_dir = r"D:\Documents\Working\实验室\赌博诈骗apk处理\permissionandcert\apkinfo"
    dangerous_permissions_file = r"D:\Documents\Working\实验室\赌博诈骗apk处理\permissionandcert\dangerous_permissions.txt"
    output_file = r"D:\Documents\Working\实验室\赌博诈骗apk处理\permission_statistics_report.txt"

    print("开始统计APK权限...")
    calculate_statistics(apk_info_dir, dangerous_permissions_file, output_file)

if __name__ == "__main__":
    main()