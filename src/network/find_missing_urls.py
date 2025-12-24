#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Find Missing URLs Module

Searches for URLs from network traffic that are not found in decompiled source code.
This helps identify dynamically generated or remotely loaded URLs.

Part of the Profit2Pitfall toolkit.
"""

import os
import re
import argparse
import logging
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Dict, List, Set, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# URL extraction patterns
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')
DOMAIN_PATTERN = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')


def extract_urls_from_text(text: str) -> Set[str]:
    """Extract URLs and domains from text."""
    urls = set()
    
    for match in URL_PATTERN.finditer(text):
        url = match.group()
        urls.add(url)
        try:
            parsed = urlparse(url if '://' in url else 'http://' + url)
            if parsed.netloc:
                urls.add(parsed.netloc)
        except Exception:
            pass
    
    for match in DOMAIN_PATTERN.finditer(text):
        domain = match.group()
        if '.' in domain:
            urls.add(domain)
    
    return urls


def read_url_file(filepath: str) -> Set[str]:
    """Read URL file and extract all URLs."""
    urls = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            urls = extract_urls_from_text(content)
    except Exception as e:
        logger.error(f"Error reading {filepath}: {e}")
    return urls


def search_in_decompiled_folder(folder_path: str, urls_to_search: Set[str]) -> tuple:
    """
    Search for URLs in decompiled source code.
    
    Args:
        folder_path: Path to decompiled source folder
        urls_to_search: Set of URLs to search for
        
    Returns:
        Tuple of (found_urls, missing_urls)
    """
    found_urls = set()
    missing_urls = set(urls_to_search)
    
    if not os.path.exists(folder_path):
        return found_urls, missing_urls
    
    searchable_extensions = ('.java', '.smali', '.xml', '.json', '.txt', '.html', '.js', '.kt')
    
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(searchable_extensions):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for url in list(missing_urls):
                            if url in content:
                                found_urls.add(url)
                                missing_urls.discard(url)
                        
                        if not missing_urls:
                            return found_urls, missing_urls
                except Exception:
                    pass
    
    return found_urls, missing_urls


def build_package_mapping(permission_dir: str) -> Dict[str, List[str]]:
    """
    Build mapping from package name to MD5 hash.
    
    Args:
        permission_dir: Directory containing permission files
        
    Returns:
        Dictionary mapping package name to list of MD5 hashes
    """
    package_to_md5 = defaultdict(list)
    
    if not os.path.exists(permission_dir):
        logger.error(f"Permission directory not found: {permission_dir}")
        return package_to_md5
    
    for filename in os.listdir(permission_dir):
        if filename.endswith('.txt'):
            # Format: md5.apk_package.name.txt
            parts = filename.split('.apk_')
            if len(parts) == 2:
                md5_hash = parts[0]
                package_name = parts[1].replace('.txt', '')
                package_to_md5[package_name].append(md5_hash)
    
    return package_to_md5


def process_single_app(
    url_file: str,
    package_name: str,
    package_to_md5: Dict[str, List[str]],
    url_dir: str,
    decompiled_dir: str
) -> Dict[str, Any]:
    """Process a single app to find missing URLs."""
    result = {
        'package_name': package_name,
        'url_file': url_file,
        'total_urls': 0,
        'found_urls': 0,
        'missing_urls': [],
        'md5_folders': [],
        'status': 'error'
    }
    
    url_path = os.path.join(url_dir, url_file)
    urls = read_url_file(url_path)
    
    if not urls:
        result['status'] = 'no_urls'
        return result
    
    result['total_urls'] = len(urls)
    
    md5_list = package_to_md5.get(package_name, [])
    if not md5_list:
        result['status'] = 'no_md5_mapping'
        return result
    
    result['md5_folders'] = md5_list
    
    all_found = set()
    all_missing = set(urls)
    
    for md5_hash in md5_list:
        decompiled_path = os.path.join(decompiled_dir, md5_hash)
        if os.path.exists(decompiled_path):
            found, missing = search_in_decompiled_folder(decompiled_path, all_missing)
            all_found.update(found)
            all_missing = all_missing - found
            
            if not all_missing:
                break
    
    result['found_urls'] = len(all_found)
    result['missing_urls'] = sorted(list(all_missing))
    result['status'] = 'success'
    
    return result


def analyze_missing_urls(
    url_dir: str,
    permission_dir: str,
    decompiled_dir: str,
    output_file: str = None,
    max_workers: int = 4
) -> Dict[str, Any]:
    """
    Analyze which URLs are missing from decompiled source code.
    
    Args:
        url_dir: Directory containing URL files
        permission_dir: Directory containing permission files
        decompiled_dir: Directory containing decompiled APKs
        output_file: Output file path (optional)
        max_workers: Number of parallel workers
        
    Returns:
        Analysis results dictionary
    """
    if not os.path.exists(url_dir):
        logger.error(f"URL directory not found: {url_dir}")
        return {}
    
    package_to_md5 = build_package_mapping(permission_dir)
    logger.info(f"Found {len(package_to_md5)} package mappings")
    
    url_files = [f for f in os.listdir(url_dir) if f.endswith('.txt')]
    logger.info(f"Found {len(url_files)} URL files")
    
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for url_file in url_files:
            package_name = url_file.replace('.txt', '')
            future = executor.submit(
                process_single_app,
                url_file, package_name, package_to_md5,
                url_dir, decompiled_dir
            )
            futures[future] = package_name
        
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logger.error(f"Error processing {futures[future]}: {e}")
    
    # Calculate statistics
    apps_with_missing = [r for r in results if r['missing_urls']]
    total_missing = sum(len(r['missing_urls']) for r in results)
    
    summary = {
        'total_apps': len(results),
        'apps_with_missing_urls': len(apps_with_missing),
        'total_missing_urls': total_missing,
        'results': results
    }
    
    if output_file:
        _write_report(summary, output_file)
    
    return summary


def _write_report(summary: Dict[str, Any], output_file: str):
    """Write analysis report to file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("Missing URL Analysis Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total apps analyzed: {summary['total_apps']}\n")
        f.write(f"Apps with missing URLs: {summary['apps_with_missing_urls']}\n")
        f.write(f"Total missing URLs: {summary['total_missing_urls']}\n\n")
        
        f.write("Apps with Missing URLs:\n")
        f.write("-" * 40 + "\n")
        
        for result in summary['results']:
            if result['missing_urls']:
                f.write(f"\nPackage: {result['package_name']}\n")
                f.write(f"  Total URLs: {result['total_urls']}\n")
                f.write(f"  Found: {result['found_urls']}\n")
                f.write(f"  Missing: {len(result['missing_urls'])}\n")
                for url in result['missing_urls'][:10]:
                    f.write(f"    - {url}\n")
                if len(result['missing_urls']) > 10:
                    f.write(f"    ... and {len(result['missing_urls']) - 10} more\n")
    
    logger.info(f"Report saved to: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Find URLs missing from decompiled source code')
    parser.add_argument('--url-dir', '-u', required=True, help='Directory containing URL files')
    parser.add_argument('--permission-dir', '-p', required=True, help='Directory containing permission files')
    parser.add_argument('--decompiled-dir', '-d', required=True, help='Directory containing decompiled APKs')
    parser.add_argument('--output', '-o', default='missing_urls_report.txt', help='Output file')
    parser.add_argument('--workers', '-w', type=int, default=4, help='Number of parallel workers')
    
    args = parser.parse_args()
    
    summary = analyze_missing_urls(
        args.url_dir,
        args.permission_dir,
        args.decompiled_dir,
        args.output,
        args.workers
    )
    
    print(f"\nAnalysis complete:")
    print(f"  Total apps: {summary.get('total_apps', 0)}")
    print(f"  Apps with missing URLs: {summary.get('apps_with_missing_urls', 0)}")
    print(f"  Total missing URLs: {summary.get('total_missing_urls', 0)}")


if __name__ == "__main__":
    main()
