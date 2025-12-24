#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK Similarity Analysis Module

Analyzes multiple APK samples to find similarities and identify related malware families.
Part of the Profit2Pitfall toolkit.
"""

import os
import re
import argparse
import logging
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class APKAnalyzer:
    """Analyzer for comparing APK samples and identifying similarities."""
    
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.data = {}

    def parse_apk_info(self, file_path: str) -> Dict[str, Any]:
        """Parse a single APK info file."""
        info = {
            'package_name': '', 'version_code': '', 'version_name': '',
            'compile_sdk_version': '', 'target_sdk_version': '', 'min_sdk_version': '',
            'permissions': [], 'application_label': '', 'native_code': [],
            'locales': [], 'densities': [], 'features': [], 'uses_libraries': []
        }

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            if m := re.search(r"package: name='([^']+)'", content):
                info['package_name'] = m.group(1)
            if m := re.search(r"versionCode='([^']+)'", content):
                info['version_code'] = m.group(1)
            if m := re.search(r"targetSdkVersion:'([^']+)'", content):
                info['target_sdk_version'] = m.group(1)
            if m := re.search(r"sdkVersion:'([^']+)'", content):
                info['min_sdk_version'] = m.group(1)
            if m := re.search(r"application-label:'([^']+)'", content):
                info['application_label'] = m.group(1)

            permissions = re.findall(r"uses-permission: name='([^']+)'", content)
            info['permissions'] = [p.split('.')[-1] for p in permissions]

            if m := re.search(r"native-code: (.+)", content):
                info['native_code'] = re.findall(r"'([^']+)'", m.group(1))

            info['features'] = re.findall(r"uses-feature[^:]*: name='([^']+)'", content)
            info['uses_libraries'] = re.findall(r"uses-library[^:]*:'([^']+)'", content)

        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}")

        return info

    def analyze_directory(self, directory: str) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze all APK info files in a directory."""
        result = {}
        dir_path = Path(directory)
        
        if not dir_path.exists():
            logger.error(f"Directory not found: {directory}")
            return result

        subdirs = [d for d in dir_path.iterdir() if d.is_dir()]
        
        if subdirs:
            for subdir in subdirs:
                logger.info(f"Analyzing category: {subdir.name}")
                data = [self.parse_apk_info(str(f)) for f in subdir.glob("*.txt")]
                result[subdir.name] = data
        else:
            data = [self.parse_apk_info(str(f)) for f in dir_path.glob("*.txt")]
            result['default'] = data
        
        return result

    def get_statistics(self, data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Get statistics from analyzed data."""
        stats = {}
        for category, apps in data.items():
            stats[category] = {
                'total_apps': len(apps),
                'permissions': Counter(),
                'target_sdk_versions': Counter(),
                'features': Counter(),
            }
            for app in apps:
                for perm in app.get('permissions', []):
                    stats[category]['permissions'][perm] += 1
                if app.get('target_sdk_version'):
                    stats[category]['target_sdk_versions'][app['target_sdk_version']] += 1
                for feature in app.get('features', []):
                    stats[category]['features'][feature] += 1
        return stats


def analyze_similarity(input_dir: str, output_file: str = None) -> Dict[str, Any]:
    """Main function to analyze APK similarity."""
    analyzer = APKAnalyzer(input_dir)
    data = analyzer.analyze_directory(input_dir)
    stats = analyzer.get_statistics(data)

    results = {'data': data, 'statistics': stats}

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("APK Similarity Analysis Report\n")
            f.write("=" * 60 + "\n\n")
            for category, cat_stats in stats.items():
                f.write(f"Category: {category}\n")
                f.write(f"  Total APKs: {cat_stats['total_apps']}\n")
                f.write(f"  Top permissions:\n")
                for perm, count in cat_stats['permissions'].most_common(10):
                    f.write(f"    - {perm}: {count}\n")
                f.write("\n")
        logger.info(f"Report saved to: {output_file}")

    return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Analyze APK similarity patterns')
    parser.add_argument('--input-dir', '-i', required=True, help='Directory containing APK info files')
    parser.add_argument('--output', '-o', default='similarity_analysis.txt', help='Output file path')
    args = parser.parse_args()

    results = analyze_similarity(args.input_dir, args.output)
    total_apps = sum(s['total_apps'] for s in results['statistics'].values())
    print(f"\nAnalysis complete: {total_apps} APKs in {len(results['statistics'])} categories")


if __name__ == "__main__":
    main()
