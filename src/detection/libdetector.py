#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Library Detector Module

Searches for specific native library files in decompiled APKs.
Part of the Profit2Pitfall toolkit.
"""

import os
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def find_lib_files(jadx_dirs: List[str], search_files: List[str], output_file: str = None) -> Dict[str, Any]:
    """
    Search for specific library files in JADX output directories.
    
    Args:
        jadx_dirs: List of JADX output directories
        search_files: List of library filenames to search for
        output_file: Output file path (optional)
        
    Returns:
        Dictionary with search results
    """
    results = []
    
    for jadx_dir in jadx_dirs:
        if not os.path.exists(jadx_dir):
            logger.warning(f"Directory not found: {jadx_dir}")
            continue

        logger.info(f"Searching in: {jadx_dir}")
        hash_dirs = [d for d in os.listdir(jadx_dir) if os.path.isdir(os.path.join(jadx_dir, d))]

        for hash_dir in hash_dirs:
            resources_lib_path = os.path.join(jadx_dir, hash_dir, "resources", "lib")

            if not os.path.exists(resources_lib_path):
                continue

            arch_dirs = [d for d in os.listdir(resources_lib_path) if os.path.isdir(os.path.join(resources_lib_path, d))]

            for arch_dir in arch_dirs:
                arch_path = os.path.join(resources_lib_path, arch_dir)

                for lib_file in search_files:
                    lib_path = os.path.join(arch_path, lib_file)
                    if os.path.exists(lib_path):
                        results.append({
                            'library': lib_file,
                            'hash': hash_dir,
                            'arch': arch_dir,
                            'path': lib_path
                        })
                        logger.info(f"Found: {lib_file} in {hash_dir}")

    summary = {
        'total_found': len(results),
        'libraries_found': list(set(r['library'] for r in results)),
        'results': results
    }

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("Library Search Results\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Search terms: {search_files}\n")
            f.write(f"Total found: {len(results)}\n\n")
            for r in results:
                f.write(f"Library: {r['library']}, Hash: {r['hash']}, Arch: {r['arch']}\n")
        logger.info(f"Results saved to: {output_file}")

    return summary


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Search for specific libraries in decompiled APKs')
    parser.add_argument('--jadx-dirs', '-j', nargs='+', required=True, help='JADX output directories')
    parser.add_argument('--libraries', '-l', nargs='+', required=True, help='Library files to search for')
    parser.add_argument('--output', '-o', default='lib_search_results.txt', help='Output file path')
    args = parser.parse_args()

    results = find_lib_files(args.jadx_dirs, args.libraries, args.output)
    print(f"\nSearch complete: Found {results['total_found']} matches")


if __name__ == "__main__":
    main()
