#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URL Search Module

Searches for URLs/domains from network traffic in decompiled APK source code
to verify if network endpoints are hardcoded or dynamically generated.

Part of the Profit2Pitfall toolkit.
"""

import os
import re
import shutil
import argparse
import logging
from typing import List, Set
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def get_all_host(content: str) -> List[str]:
    """Extract host network information from traffic analysis file."""
    pattern = r"======== All Host Network Information \(Union\) ========\s*([\s\S]*?)(?=\n=|$)"
    match = re.search(pattern, content)

    strip_strings = ["mumu.163.com", "sentry.netease.com", "android.bugly.qq.com"]

    if match:
        result = match.group(1).strip()
        for strip_string in strip_strings:
            result = re.sub(r'^.*' + re.escape(strip_string) + r'.*$', '', result, flags=re.MULTILINE)
        ret = [line.strip() for line in result.splitlines() if line.strip()]
    else:
        ret = []
    return ret


def search_url_in_file_content(file_path: str, url_pattern) -> bool:
    """Search for URL pattern in file content."""
    encodings = ['utf-8', 'latin-1', 'gbk', 'windows-1252']
    content = None
    
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                content = f.read()
            break
        except UnicodeDecodeError:
            continue

    if content is None:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return False

    return bool(re.search(url_pattern, content))


def find_urls_in_project(urls: List[str], project_dir: str, output_file: str = None) -> dict:
    """
    Search for URLs in a decompiled project directory.
    
    Args:
        urls: List of URLs/domains to search
        project_dir: Root directory of decompiled project
        output_file: Output file path (optional)
        
    Returns:
        Dictionary with search results
    """
    if not os.path.isdir(project_dir):
        logger.error(f"Project directory not found: {project_dir}")
        return {}

    results = {url: [] for url in urls}

    logger.info(f"Searching for {len(urls)} URL(s) in project: {project_dir}")

    for url in urls:
        url_pattern = re.compile(re.escape(url))

        for root, _, files in os.walk(project_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                
                if search_url_in_file_content(file_path, url_pattern):
                    rel_path = os.path.relpath(file_path, project_dir)
                    results[url].append(rel_path)

    summary = {
        'total_urls': len(urls),
        'found_urls': sum(1 for v in results.values() if v),
        'results': results
    }

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("URL Search Results\n")
            f.write("=" * 60 + "\n\n")
            for url, locations in results.items():
                f.write(f"URL: {url}\n")
                if locations:
                    f.write(f"  Found in {len(locations)} file(s):\n")
                    for loc in locations[:10]:
                        f.write(f"    - {loc}\n")
                    if len(locations) > 10:
                        f.write(f"    ... and {len(locations) - 10} more\n")
                else:
                    f.write("  Not found\n")
                f.write("\n")
        logger.info(f"Results saved to: {output_file}")

    return summary


def find_urls_from_pcap_result(pcap_file: str, project_dir: str, output_file: str = None) -> dict:
    """Search for URLs extracted from PCAP analysis in project."""
    if not os.path.isfile(pcap_file):
        logger.error(f"PCAP result file not found: {pcap_file}")
        return {}

    with open(pcap_file, 'r', encoding='utf-8') as f:
        content = f.read()

    urls = get_all_host(content)
    
    if not urls:
        logger.info("No URLs found in PCAP result file")
        return {}

    return find_urls_in_project(urls, project_dir, output_file)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Search for URLs in decompiled APK')
    parser.add_argument('--project-dir', '-p', required=True, help='Decompiled project directory')
    parser.add_argument('--urls', '-u', nargs='+', help='URLs to search for')
    parser.add_argument('--pcap-file', '-f', help='PCAP analysis result file')
    parser.add_argument('--output', '-o', default='url_search_results.txt', help='Output file path')
    args = parser.parse_args()

    if args.pcap_file:
        results = find_urls_from_pcap_result(args.pcap_file, args.project_dir, args.output)
    elif args.urls:
        results = find_urls_in_project(args.urls, args.project_dir, args.output)
    else:
        parser.error("Either --urls or --pcap-file must be provided")
        return

    print(f"\nSearch complete: {results.get('found_urls', 0)}/{results.get('total_urls', 0)} URLs found")


if __name__ == "__main__":
    main()
