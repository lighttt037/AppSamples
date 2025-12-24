#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Native Library Analysis Module

Analyzes native library (.so files) usage patterns in APKs.
Part of the Profit2Pitfall toolkit.
"""

import os
import glob
import re
import argparse
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def analyze_lib_files(jadx_dirs: List[str], apkinfo_dir: str = None, output_file: str = None) -> Dict[str, Any]:
    """
    Analyze native library usage across APK samples.
    
    Args:
        jadx_dirs: List of JADX output directories
        apkinfo_dir: Directory containing APK info files (optional)
        output_file: Output file path (optional)
        
    Returns:
        Analysis results dictionary
    """
    lib_usage_stats = defaultdict(set)
    app_lib_mapping = {}
    
    for jadx_dir in jadx_dirs:
        if not os.path.exists(jadx_dir):
            logger.warning(f"Directory not found: {jadx_dir}")
            continue

        hash_dirs = [d for d in os.listdir(jadx_dir) if os.path.isdir(os.path.join(jadx_dir, d))]

        for hash_dir in hash_dirs:
            resources_lib_path = os.path.join(jadx_dir, hash_dir, "resources", "lib")
            
            if not os.path.exists(resources_lib_path):
                continue

            libs_found = []
            arch_dirs = [d for d in os.listdir(resources_lib_path) if os.path.isdir(os.path.join(resources_lib_path, d))]

            for arch_dir in arch_dirs:
                arch_path = os.path.join(resources_lib_path, arch_dir)
                so_files = glob.glob(os.path.join(arch_path, "*.so"))
                
                for so_file in so_files:
                    so_name = os.path.basename(so_file)
                    libs_found.append(so_name)
                    lib_usage_stats[so_name].add(hash_dir)

            if libs_found:
                app_lib_mapping[hash_dir] = list(set(libs_found))

    results = {
        'total_apps': len(app_lib_mapping),
        'unique_libraries': len(lib_usage_stats),
        'library_stats': {lib: len(apps) for lib, apps in lib_usage_stats.items()},
        'top_libraries': sorted(lib_usage_stats.items(), key=lambda x: len(x[1]), reverse=True)[:50]
    }

    if output_file:
        _write_report(results, output_file)

    return results


def _write_report(results: Dict[str, Any], output_file: str):
    """Write analysis report to file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("Native Library Analysis Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total apps analyzed: {results['total_apps']}\n")
        f.write(f"Unique libraries found: {results['unique_libraries']}\n\n")
        
        f.write("Top Libraries by Usage:\n")
        f.write("-" * 40 + "\n")
        for lib_name, apps in results['top_libraries'][:30]:
            f.write(f"  {lib_name}: {len(apps)} apps\n")
    
    logger.info(f"Report saved to: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Analyze native library usage in APKs')
    parser.add_argument('--jadx-dirs', '-j', nargs='+', required=True, help='JADX output directories')
    parser.add_argument('--apkinfo-dir', '-a', help='APK info directory')
    parser.add_argument('--output', '-o', default='lib_analysis.txt', help='Output file path')
    args = parser.parse_args()

    results = analyze_lib_files(args.jadx_dirs, args.apkinfo_dir, args.output)
    print(f"\nAnalysis complete: {results['total_apps']} apps, {results['unique_libraries']} unique libraries")


if __name__ == "__main__":
    main()
