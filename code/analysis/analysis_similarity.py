#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK相似性分析脚本
分析四个类别文件夹中的APK信息并比较差异
"""

import os
import re
from collections import defaultdict, Counter
from pathlib import Path

class APKAnalyzer:
    def __init__(self, base_path):
        self.base_path = Path(base_path)
        self.categories = [
            "0a12be5ff2b87d32e536f996505ef24a",
            "1cde87b0b63d7ba829259542a3b6f1da",
            "2b4c02f608e861ed5e58236a31e01fd0",
            "24c258236f8d6cf6ca1d615ccb665751",
            "606a410cf1df67c1605291d9f946c1c3",
            "8130b2e95b3df861b03ee3e13aa114b7",
            "9981fe05e0223c2cfaf842f7bc921199",
            "ad2c411a388320955111f0ef23a17cd3",
            "bda97ee5b4a5fadb8838cfbc1ebaef8d",
            "fa19a517191d8cf48e4cb11b34dc7d28" # TODO
        ]
        self.data = {}

    def parse_apk_info(self, file_path):
        """解析单个APK信息文件"""
        info = {
            'package_name': '',
            'version_code': '',
            'version_name': '',
            'compile_sdk_version': '',
            'target_sdk_version': '',
            'min_sdk_version': '',
            'permissions': [],
            'application_label': '',
            'native_code': [],
            'locales': [],
            'densities': [],
            'features': [],
            'uses_libraries': []
        }

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 解析包信息
            package_match = re.search(r"package: name='([^']+)'", content)
            if package_match:
                info['package_name'] = package_match.group(1)

            version_code_match = re.search(r"versionCode='([^']+)'", content)
            if version_code_match:
                info['version_code'] = version_code_match.group(1)

            version_name_match = re.search(r"versionName='([^']+)'", content)
            if version_name_match:
                info['version_name'] = version_name_match.group(1)

            compile_sdk_match = re.search(r"compileSdkVersion='([^']+)'", content)
            if compile_sdk_match:
                info['compile_sdk_version'] = compile_sdk_match.group(1)

            target_sdk_match = re.search(r"targetSdkVersion:'([^']+)'", content)
            if target_sdk_match:
                info['target_sdk_version'] = target_sdk_match.group(1)

            min_sdk_match = re.search(r"sdkVersion:'([^']+)'", content)
            if min_sdk_match:
                info['min_sdk_version'] = min_sdk_match.group(1)

            # 解析权限
            permissions = re.findall(r"uses-permission: name='([^']+)'", content)
            # 标准化权限名称，去掉包名前缀
            normalized_permissions = []
            for perm in permissions:
                # 提取权限名称的最后一部分（去掉包名前缀）
                if '.permission.' in perm:
                    # 找到最后一个.permission.并提取其后的部分
                    last_permission_index = perm.rfind('.permission.')
                    permission_name = perm[last_permission_index + len('.permission.'):]
                    normalized_permissions.append(permission_name)
                elif '.' in perm:
                    # 对于其他包含点的权限，提取最后一个点后的部分
                    # 例如: com.asus.msa.SupplementaryDID.ACCESS -> ACCESS
                    # 例如: com.example.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION -> DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
                    permission_name = perm.split('.')[-1]
                    normalized_permissions.append(permission_name)
                else:
                    # 如果没有点，保留原权限名
                    normalized_permissions.append(perm)
            info['permissions'] = normalized_permissions

            # 解析应用标签
            app_label_match = re.search(r"application-label:'([^']+)'", content)
            if app_label_match:
                info['application_label'] = app_label_match.group(1)

            # 解析本地代码架构
            native_code_match = re.search(r"native-code: (.+)", content)
            if native_code_match:
                native_codes = re.findall(r"'([^']+)'", native_code_match.group(1))
                info['native_code'] = native_codes

            # 解析支持的语言
            locales_match = re.search(r"locales: (.+)", content)
            if locales_match:
                locales = re.findall(r"'([^']+)'", locales_match.group(1))
                info['locales'] = locales

            # 解析屏幕密度
            densities_match = re.search(r"densities: (.+)", content)
            if densities_match:
                densities = re.findall(r"'([^']+)'", densities_match.group(1))
                info['densities'] = densities

            # 解析特性
            features = re.findall(r"uses-feature[^:]*: name='([^']+)'", content)
            info['features'] = features

            # 解析使用的库
            libraries = re.findall(r"uses-library[^:]*:'([^']+)'", content)
            info['uses_libraries'] = libraries

        except Exception as e:
            print(f"解析文件 {file_path} 时出错: {e}")

        return info

    def analyze_category(self, category):
        """分析单个类别文件夹"""
        category_path = self.base_path / "apkinfonewest" / "apkinfo分类" / category # TODO
        category_data = []

        if not category_path.exists():
            print(f"警告: 路径 {category_path} 不存在")
            return category_data

        # 遍历所有txt文件
        for txt_file in category_path.glob("*.txt"):
            apk_info = self.parse_apk_info(txt_file)
            apk_info['file_name'] = txt_file.name
            category_data.append(apk_info)

        return category_data

    def analyze_all_categories(self):
        """分析所有类别"""
        for category in self.categories:
            print(f"正在分析类别: {category}")
            self.data[category] = self.analyze_category(category)
            print(f"类别 {category} 包含 {len(self.data[category])} 个APK文件")

    def get_statistics(self):
        """获取统计信息"""
        stats = {}

        for category, apps in self.data.items():
            stats[category] = {
                'total_apps': len(apps),
                'permissions': Counter(),
                'compile_sdk_versions': Counter(),
                'target_sdk_versions': Counter(),
                'min_sdk_versions': Counter(),
                'native_codes': Counter(),
                'features': Counter(),
                'libraries': Counter(),
                'application_labels': Counter(),
                'package_names': []
            }

            for app in apps:
                # 统计权限
                for perm in app['permissions']:
                    stats[category]['permissions'][perm] += 1

                # 统计SDK版本
                if app['compile_sdk_version']:
                    stats[category]['compile_sdk_versions'][app['compile_sdk_version']] += 1
                if app['target_sdk_version']:
                    stats[category]['target_sdk_versions'][app['target_sdk_version']] += 1
                if app['min_sdk_version']:
                    stats[category]['min_sdk_versions'][app['min_sdk_version']] += 1

                # 统计本地代码架构
                for arch in app['native_code']:
                    stats[category]['native_codes'][arch] += 1

                # 统计特性
                for feature in app['features']:
                    stats[category]['features'][feature] += 1

                # 统计库
                for lib in app['uses_libraries']:
                    stats[category]['libraries'][lib] += 1

                # 统计应用标签
                if app['application_label']:
                    stats[category]['application_labels'][app['application_label']] += 1

                # 收集包名
                if app['package_name']:
                    stats[category]['package_names'].append(app['package_name'])

        return stats

    def find_differences(self, stats):
        """找出类别间的差异"""
        differences = {
            'permissions': {},
            'sdk_versions': {},
            'native_codes': {},
            'features': {},
            'libraries': {}
        }

        # 分析权限差异
        all_permissions = set()
        for category in stats:
            all_permissions.update(stats[category]['permissions'].keys())

        for perm in all_permissions:
            perm_usage = {}
            for category in stats:
                count = stats[category]['permissions'].get(perm, 0)
                total = stats[category]['total_apps']
                perm_usage[category] = f"{count}/{total} ({count/total*100:.1f}%)" if total > 0 else "0/0 (0%)"
            differences['permissions'][perm] = perm_usage

        # 分析SDK版本差异
        for sdk_type in ['compile_sdk_versions', 'target_sdk_versions', 'min_sdk_versions']:
            all_versions = set()
            for category in stats:
                all_versions.update(stats[category][sdk_type].keys())

            for version in all_versions:
                version_usage = {}
                for category in stats:
                    count = stats[category][sdk_type].get(version, 0)
                    total = stats[category]['total_apps']
                    version_usage[category] = f"{count}/{total} ({count/total*100:.1f}%)" if total > 0 else "0/0 (0%)"
                differences['sdk_versions'][f"{sdk_type}_{version}"] = version_usage

        # 分析其他特征差异
        for feature_type in ['native_codes', 'features', 'libraries']:
            all_features = set()
            for category in stats:
                all_features.update(stats[category][feature_type].keys())

            for feature in all_features:
                feature_usage = {}
                for category in stats:
                    count = stats[category][feature_type].get(feature, 0)
                    total = stats[category]['total_apps']
                    feature_usage[category] = f"{count}/{total} ({count/total*100:.1f}%)" if total > 0 else "0/0 (0%)"
                differences[feature_type][feature] = feature_usage

        return differences

    def generate_report(self, stats, differences):
        """生成分析报告"""
        report = []
        report.append("APK相似性分析报告")
        report.append("=" * 50)
        report.append("")

        # 基本统计信息
        report.append("1. 基本统计信息")
        report.append("-" * 30)
        for category, stat in stats.items():
            report.append(f"类别 {category}:")
            report.append(f"  - APK文件数量: {stat['total_apps']}")
            report.append(f"  - 唯一权限数量: {len(stat['permissions'])}")
            report.append(f"  - 唯一特性数量: {len(stat['features'])}")
            report.append(f"  - 唯一库数量: {len(stat['libraries'])}")
            report.append("")

        # 权限差异分析
        report.append("2. 权限使用差异分析")
        report.append("-" * 30)

        # 显示各类别最常用的权限
        report.append("2.1 各类别最常用权限 (Top 10):")
        for category, stat in stats.items():
            report.append(f"\n类别 {category}:")
            top_permissions = stat['permissions'].most_common(10)
            for perm, count in top_permissions:
                percentage = count / stat['total_apps'] * 100 if stat['total_apps'] > 0 else 0
                report.append(f"  - {perm}: {count}/{stat['total_apps']} ({percentage:.1f}%)")

        report.append("\n2.2 权限差异分析:")

        # 找出只在某些类别中出现的权限
        permission_categories = defaultdict(list)
        for perm, usage in differences['permissions'].items():
            categories_with_perm = [cat for cat, count in usage.items() if not count.startswith('0/')]
            if len(categories_with_perm) < len(self.categories):
                permission_categories[tuple(sorted(categories_with_perm))].append(perm)

        for categories, perms in permission_categories.items():
            if len(categories) > 0:
                report.append(f"\n仅在类别 {', '.join(categories)} 中出现的权限:")
                for perm in sorted(perms):  # 显示所有权限，不再限制数量
                    report.append(f"  - {perm}")
                report.append("")

        # SDK版本差异
        report.append("3. SDK版本差异分析")
        report.append("-" * 30)

        for sdk_version, usage in differences['sdk_versions'].items():
            if any(not count.startswith('0/') for count in usage.values()):
                categories_with_version = [cat for cat, count in usage.items() if not count.startswith('0/')]
                if len(categories_with_version) < len(self.categories):
                    report.append(f"{sdk_version}:")
                    for cat, count in usage.items():
                        if not count.startswith('0/'):
                            report.append(f"  - {cat}: {count}")
                    report.append("")

        # 架构支持差异
        report.append("3. 本地代码架构差异")
        report.append("-" * 30)

        for arch, usage in differences['native_codes'].items():
            categories_with_arch = [cat for cat, count in usage.items() if not count.startswith('0/')]
            if len(categories_with_arch) < len(self.categories):
                report.append(f"架构 {arch}:")
                for cat, count in usage.items():
                    if not count.startswith('0/'):
                        report.append(f"  - {cat}: {count}")
                report.append("")

        # 主要差异总结
        report.append("4. 主要差异总结")
        report.append("-" * 30)

        # 分析每个类别的独特特征
        for category in self.categories:
            unique_features = []

            # 检查唯一权限
            unique_perms = []
            for perm, usage in differences['permissions'].items():
                categories_with_perm = [cat for cat, count in usage.items() if not count.startswith('0/')]
                if len(categories_with_perm) == 1 and categories_with_perm[0] == category:
                    unique_perms.append(perm)

            if unique_perms:
                unique_features.append(f"独有权限 {len(unique_perms)} 个")

            # 检查独有特性
            unique_features_count = 0
            for feature, usage in differences['features'].items():
                categories_with_feature = [cat for cat, count in usage.items() if not count.startswith('0/')]
                if len(categories_with_feature) == 1 and categories_with_feature[0] == category:
                    unique_features_count += 1

            if unique_features_count > 0:
                unique_features.append(f"独有特性 {unique_features_count} 个")

            report.append(f"类别 {category} 的独特特征:")
            if unique_features:
                for feature in unique_features:
                    report.append(f"  - {feature}")
            else:
                report.append("  - 无明显独特特征")
            report.append("")

        return "\n".join(report)

def main():
    # 设置基础路径
    base_path = r"d:\Documents\Working\实验室\赌博诈骗apk处理"

    # 创建分析器实例
    analyzer = APKAnalyzer(base_path)

    # 分析所有类别
    print("开始分析APK文件...")
    analyzer.analyze_all_categories()

    # 获取统计信息
    print("生成统计信息...")
    stats = analyzer.get_statistics()

    # 找出差异
    print("分析差异...")
    differences = analyzer.find_differences(stats)

    # 生成报告
    print("生成报告...")
    report = analyzer.generate_report(stats, differences)

    # 保存报告
    output_path = Path(base_path) / "analysis_similarity_newest.txt"
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"分析完成！报告已保存到: {output_path}")

if __name__ == "__main__":
    main()