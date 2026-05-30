#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK Variant Analyzer Module

Compares multiple APK samples to identify variants and code reuse patterns.
Part of the Profit2Pitfall toolkit.
"""

import os
import hashlib
import re
import argparse
import logging
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Dict, List, Any
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ApkVariantAnalyzer:
    """Analyzer for comparing APK variants."""
    
    def __init__(self, app_base_paths: List[str], output_dir: str = "analysis_results"):
        self.app_base_paths = app_base_paths
        self.output_dir = output_dir
        self.app_profiles = {}
        os.makedirs(output_dir, exist_ok=True)

    def analyze_all(self) -> Dict[str, Any]:
        """Analyze all applications."""
        for app_path in self.app_base_paths:
            app_name = os.path.basename(app_path)
            logger.info(f"Analyzing: {app_name}")

            profile = {
                'name': app_name,
                'package_structure': self.analyze_package_structure(app_path),
                'manifest_components': self.analyze_manifest(app_path),
                'code_features': self.extract_code_features(app_path),
            }
            self.app_profiles[app_name] = profile

        return self.compare_apps()

    def analyze_package_structure(self, app_path: str) -> Dict[str, List[str]]:
        """Analyze Java package structure."""
        package_tree = defaultdict(list)
        src_dir = os.path.join(app_path, 'sources')

        if not os.path.exists(src_dir):
            return dict(package_tree)

        for root, dirs, files in os.walk(src_dir):
            if "__pycache__" in root or ".git" in root:
                continue
            rel_path = os.path.relpath(root, src_dir)
            if rel_path == ".":
                continue
            package = rel_path.replace(os.path.sep, '.')
            java_files = [f for f in files if f.endswith('.java')]
            if java_files:
                package_tree[package] = java_files

        return dict(package_tree)

    def analyze_manifest(self, app_path: str) -> Dict[str, Any]:
        """Analyze AndroidManifest.xml."""
        manifest_path = os.path.join(app_path, 'resources', 'AndroidManifest.xml')
        if not os.path.exists(manifest_path):
            return {}

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            ns = {'android': 'http://schemas.android.com/apk/res/android'}

            components = {
                'package': root.get('{http://schemas.android.com/apk/res/android}package'),
                'activities': [],
                'services': [],
                'receivers': [],
                'permissions': []
            }

            for tag, key in [('activity', 'activities'), ('service', 'services'), 
                           ('receiver', 'receivers'), ('uses-permission', 'permissions')]:
                for elem in root.findall(f'.//{tag}', ns):
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    if name:
                        components[key].append(name)

            return components
        except Exception as e:
            logger.error(f"Error analyzing manifest: {e}")
            return {}

    def extract_code_features(self, app_path: str) -> Dict[str, Any]:
        """Extract code features for comparison."""
        features = {
            'sensitive_apis': defaultdict(int),
            'class_count': 0,
            'total_methods': 0
        }

        src_dir = os.path.join(app_path, 'sources')
        if not os.path.exists(src_dir):
            return features

        sensitive_patterns = [
            r'SmsManager\.send',
            r'getDeviceId',
            r'getSubscriberId',
            r'getLastKnownLocation',
            r'Runtime\.getRuntime\(\)\.exec',
            r'DexClassLoader'
        ]

        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith('.java'):
                    features['class_count'] += 1
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            for pattern in sensitive_patterns:
                                if re.search(pattern, content):
                                    features['sensitive_apis'][pattern] += 1
                            features['total_methods'] += len(re.findall(r'(public|private|protected)\s+[\w<>\[\]]+\s+\w+\s*\(', content))
                    except Exception:
                        pass

        features['sensitive_apis'] = dict(features['sensitive_apis'])
        return features

    def compare_apps(self) -> Dict[str, Any]:
        """Compare analyzed apps to find similarities."""
        comparison = {
            'app_count': len(self.app_profiles),
            'common_packages': set(),
            'common_permissions': set(),
            'similarity_matrix': {}
        }

        if len(self.app_profiles) < 2:
            return comparison

        all_packages = [set(p['package_structure'].keys()) for p in self.app_profiles.values()]
        if all_packages:
            comparison['common_packages'] = set.intersection(*all_packages)

        all_permissions = [set(p['manifest_components'].get('permissions', [])) for p in self.app_profiles.values()]
        if all_permissions:
            comparison['common_permissions'] = set.intersection(*all_permissions)

        return comparison


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Compare APK variants')
    parser.add_argument('--app-paths', '-a', nargs='+', required=True, help='Paths to decompiled APKs')
    parser.add_argument('--output-dir', '-o', default='analysis_results', help='Output directory')
    args = parser.parse_args()

    analyzer = ApkVariantAnalyzer(args.app_paths, args.output_dir)
    results = analyzer.analyze_all()

    print(f"\nAnalysis complete:")
    print(f"  Apps analyzed: {results['app_count']}")
    print(f"  Common packages: {len(results['common_packages'])}")
    print(f"  Common permissions: {len(results['common_permissions'])}")


if __name__ == "__main__":
    main()
