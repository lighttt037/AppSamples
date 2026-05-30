#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Duplicate Merge Module

Identifies and merges duplicate APK samples based on hash values.
Part of the Profit2Pitfall toolkit.
"""

import os
import hashlib
import shutil
import argparse
import logging
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def compute_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Compute hash of a file.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hex digest of hash
    """
    hash_func = getattr(hashlib, algorithm)()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_func.update(chunk)
            
    return hash_func.hexdigest()


def find_duplicates(
    directory: str,
    file_pattern: str = "*.apk"
) -> Dict[str, List[str]]:
    """
    Find duplicate files in a directory based on hash.
    
    Args:
        directory: Directory to scan
        file_pattern: File pattern to match
        
    Returns:
        Dictionary mapping hash to list of file paths
    """
    dir_path = Path(directory)
    if not dir_path.exists():
        logger.error(f"Directory not found: {directory}")
        return {}
        
    files = list(dir_path.glob(file_pattern))
    logger.info(f"Found {len(files)} files matching {file_pattern}")
    
    hash_map: Dict[str, List[str]] = defaultdict(list)
    
    for file_path in files:
        try:
            file_hash = compute_file_hash(str(file_path))
            hash_map[file_hash].append(str(file_path))
        except Exception as e:
            logger.error(f"Error hashing {file_path}: {e}")
            
    # Filter to only duplicates
    duplicates = {h: paths for h, paths in hash_map.items() if len(paths) > 1}
    
    logger.info(f"Found {len(duplicates)} groups of duplicates")
    return duplicates


def merge_duplicates(
    duplicates: Dict[str, List[str]],
    output_dir: str,
    keep_strategy: str = "first"
) -> Dict[str, Any]:
    """
    Merge duplicate files.
    
    Args:
        duplicates: Dictionary of hash -> file paths
        output_dir: Directory for merged files
        keep_strategy: Which file to keep (first, largest, smallest)
        
    Returns:
        Statistics about merge operation
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    stats = {
        'total_duplicates': sum(len(p) for p in duplicates.values()),
        'unique_files': len(duplicates),
        'space_saved': 0,
        'files_removed': 0
    }
    
    for file_hash, paths in duplicates.items():
        # Sort paths based on strategy
        if keep_strategy == "largest":
            paths.sort(key=lambda p: os.path.getsize(p), reverse=True)
        elif keep_strategy == "smallest":
            paths.sort(key=lambda p: os.path.getsize(p))
        # else: keep first (default order)
        
        keep_path = paths[0]
        
        # Copy the file to keep to output
        dest_path = output_path / Path(keep_path).name
        if not dest_path.exists():
            shutil.copy2(keep_path, dest_path)
            
        # Calculate space saved from duplicates
        for dup_path in paths[1:]:
            stats['space_saved'] += os.path.getsize(dup_path)
            stats['files_removed'] += 1
            
    return stats


def deduplicate_directory(
    input_dir: str,
    output_dir: str = None,
    remove_duplicates: bool = False,
    report_file: str = None
) -> Dict[str, Any]:
    """
    Deduplicate a directory of files.
    
    Args:
        input_dir: Input directory
        output_dir: Output directory for unique files
        remove_duplicates: Whether to remove duplicate files
        report_file: Path to save report
        
    Returns:
        Deduplication results
    """
    duplicates = find_duplicates(input_dir)
    
    results = {
        'input_dir': input_dir,
        'duplicate_groups': len(duplicates),
        'duplicate_files': sum(len(p) - 1 for p in duplicates.values()),
        'duplicates': duplicates
    }
    
    if output_dir:
        # Get all unique files (including non-duplicates)
        all_files = list(Path(input_dir).glob("*.apk"))
        hash_to_file = {}
        
        for file_path in all_files:
            file_hash = compute_file_hash(str(file_path))
            if file_hash not in hash_to_file:
                hash_to_file[file_hash] = str(file_path)
                
        # Copy unique files
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for file_path in hash_to_file.values():
            dest = output_path / Path(file_path).name
            if not dest.exists():
                shutil.copy2(file_path, dest)
                
        results['unique_files_copied'] = len(hash_to_file)
        
    if report_file:
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("Duplicate Detection Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Input directory: {input_dir}\n")
            f.write(f"Duplicate groups: {results['duplicate_groups']}\n")
            f.write(f"Duplicate files: {results['duplicate_files']}\n\n")
            
            if duplicates:
                f.write("Duplicate Groups:\n")
                f.write("-" * 40 + "\n")
                for file_hash, paths in duplicates.items():
                    f.write(f"\nHash: {file_hash[:32]}...\n")
                    for path in paths:
                        f.write(f"  - {Path(path).name}\n")
                        
        logger.info(f"Report saved to: {report_file}")
        
    return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Find and merge duplicate files')
    parser.add_argument('--input-dir', '-i', required=True, help='Input directory')
    parser.add_argument('--output-dir', '-o', help='Output directory for unique files')
    parser.add_argument('--report', '-r', default='duplicates_report.txt', help='Report file')
    parser.add_argument('--pattern', '-p', default='*.apk', help='File pattern')
    
    args = parser.parse_args()
    
    results = deduplicate_directory(
        args.input_dir,
        args.output_dir,
        report_file=args.report
    )
    
    print(f"\nDeduplication complete:")
    print(f"  Duplicate groups: {results['duplicate_groups']}")
    print(f"  Duplicate files: {results['duplicate_files']}")
    if args.output_dir:
        print(f"  Unique files copied: {results.get('unique_files_copied', 0)}")


if __name__ == "__main__":
    main()
