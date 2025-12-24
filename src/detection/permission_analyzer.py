#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Permission Analyzer Module

Analyzes APK permissions to identify dangerous permission usage patterns.
Part of the Profit2Pitfall toolkit.
"""

import os
import re
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Set, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_DANGEROUS_PERMISSIONS = {
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.READ_PHONE_STATE',
    'android.permission.CALL_PHONE',
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.GET_ACCOUNTS',
}


def load_dangerous_permissions(file_path: str = None) -> Set[str]:
    """Load dangerous permissions list from file or use defaults."""
    if file_path is None or not os.path.exists(file_path):
        return DEFAULT_DANGEROUS_PERMISSIONS.copy()

    dangerous_permissions = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        permission_pattern = r'([A-Z_][A-Z0-9_]*)\s*-'
        permissions = re.findall(permission_pattern, content)
        for perm in permissions:
            dangerous_permissions.add(f'android.permission.{perm}')
    except Exception as e:
        logger.warning(f"Failed to load permissions file: {e}")
        return DEFAULT_DANGEROUS_PERMISSIONS.copy()

    return dangerous_permissions


def parse_apk_info(file_path: str) -> tuple:
    """Parse APK info file to extract permissions."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Failed to read file {file_path}: {e}")
        return None, None, []

    filename = os.path.basename(file_path)
    match = re.match(r'([a-fA-F0-9]+)\.apk_(.+)\.txt$', filename)
    if not match:
        return None, None, []

    hash_value = match.group(1)
    package_name = match.group(2)
    permissions = re.findall(r"uses-permission: name='([^']+)'", content)

    return hash_value, package_name, permissions


def analyze_permissions(apk_info_dir: str, dangerous_permissions_file: str = None, output_file: str = None) -> Dict[str, Any]:
    """Analyze APK permissions in a directory."""
    dangerous_permissions = load_dangerous_permissions(dangerous_permissions_file)
    logger.info(f"Loaded {len(dangerous_permissions)} dangerous permissions")

    apk_info_path = Path(apk_info_dir)
    if not apk_info_path.exists():
        logger.error(f"Directory not found: {apk_info_dir}")
        return {}

    txt_files = list(apk_info_path.glob("*.txt"))
    if not txt_files:
        logger.error(f"No .txt files found in: {apk_info_dir}")
        return {}

    logger.info(f"Found {len(txt_files)} APK info files")

    results = []
    permission_stats = {}

    for txt_file in txt_files:
        hash_value, package_name, permissions = parse_apk_info(str(txt_file))
        if hash_value is None:
            continue

        found_dangerous = [p for p in permissions if p in dangerous_permissions]
        if found_dangerous:
            results.append({
                'hash': hash_value,
                'package': package_name,
                'dangerous_permissions': found_dangerous,
                'total_permissions': len(permissions)
            })
            for perm in found_dangerous:
                permission_stats[perm] = permission_stats.get(perm, 0) + 1

    analysis = {
        'total_files': len(txt_files),
        'apps_with_dangerous_perms': len(results),
        'permission_frequency': dict(sorted(permission_stats.items(), key=lambda x: x[1], reverse=True)),
        'detailed_results': results
    }

    if output_file:
        _write_report(analysis, output_file)

    return analysis


def _write_report(analysis: Dict[str, Any], output_file: str):
    """Write analysis report to file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("APK Dangerous Permission Analysis Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total files analyzed: {analysis['total_files']}\n")
        f.write(f"APKs with dangerous permissions: {analysis['apps_with_dangerous_perms']}\n\n")
        f.write("Permission Frequency:\n")
        for perm, count in analysis['permission_frequency'].items():
            short_perm = perm.replace('android.permission.', '')
            f.write(f"  {short_perm}: {count}\n")
    logger.info(f"Report saved to: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Analyze APK permissions')
    parser.add_argument('--apk-info-dir', '-d', required=True, help='Directory containing APK info files')
    parser.add_argument('--permissions-file', '-p', help='File containing dangerous permissions list')
    parser.add_argument('--output', '-o', default='permission_analysis.txt', help='Output file path')
    args = parser.parse_args()

    analysis = analyze_permissions(args.apk_info_dir, args.permissions_file, args.output)
    print(f"\nAnalysis complete:")
    print(f"  Total files: {analysis.get('total_files', 0)}")
    print(f"  Apps with dangerous permissions: {analysis.get('apps_with_dangerous_perms', 0)}")


if __name__ == "__main__":
    main()
