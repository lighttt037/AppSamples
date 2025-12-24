#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK Hash Naming Module

Renames APK files based on their hash values for consistent naming.
Part of the Profit2Pitfall toolkit.
"""

import os
import hashlib
import shutil
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def compute_md5(file_path: str) -> str:
    """Compute MD5 hash of file."""
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def rename_by_hash(
    input_dir: str,
    output_dir: str = None,
    hash_type: str = "md5",
    keep_original: bool = True,
    file_pattern: str = "*.apk"
) -> Dict[str, Any]:
    """
    Rename files based on their hash values.
    
    Args:
        input_dir: Input directory containing files
        output_dir: Output directory (uses input_dir if not specified)
        hash_type: Hash algorithm to use (md5 or sha256)
        keep_original: Keep original files (copy vs move)
        file_pattern: File pattern to match
        
    Returns:
        Statistics about rename operation
    """
    input_path = Path(input_dir)
    if not input_path.exists():
        logger.error(f"Directory not found: {input_dir}")
        return {}
        
    output_path = Path(output_dir) if output_dir else input_path
    output_path.mkdir(parents=True, exist_ok=True)
    
    hash_func = compute_md5 if hash_type == "md5" else compute_sha256
    
    files = list(input_path.glob(file_pattern))
    logger.info(f"Found {len(files)} files to process")
    
    stats = {
        'total_files': len(files),
        'renamed': 0,
        'skipped': 0,
        'errors': 0,
        'mapping': {}
    }
    
    for file_path in files:
        try:
            file_hash = hash_func(str(file_path))
            new_name = f"{file_hash}.apk"
            new_path = output_path / new_name
            
            if new_path.exists() and new_path != file_path:
                logger.info(f"Skipping duplicate: {file_path.name}")
                stats['skipped'] += 1
                continue
                
            if keep_original or output_dir:
                shutil.copy2(file_path, new_path)
            else:
                shutil.move(file_path, new_path)
                
            stats['mapping'][str(file_path.name)] = new_name
            stats['renamed'] += 1
            logger.info(f"Renamed: {file_path.name} -> {new_name}")
            
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            stats['errors'] += 1
            
    return stats


def batch_rename(
    directories: List[str],
    output_dir: str,
    hash_type: str = "md5"
) -> Dict[str, Any]:
    """
    Batch rename files from multiple directories.
    
    Args:
        directories: List of input directories
        output_dir: Output directory
        hash_type: Hash algorithm to use
        
    Returns:
        Combined statistics
    """
    total_stats = {
        'total_files': 0,
        'renamed': 0,
        'skipped': 0,
        'errors': 0
    }
    
    for directory in directories:
        logger.info(f"Processing: {directory}")
        stats = rename_by_hash(
            directory,
            output_dir,
            hash_type=hash_type,
            keep_original=True
        )
        
        total_stats['total_files'] += stats.get('total_files', 0)
        total_stats['renamed'] += stats.get('renamed', 0)
        total_stats['skipped'] += stats.get('skipped', 0)
        total_stats['errors'] += stats.get('errors', 0)
        
    return total_stats


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Rename APK files by hash')
    parser.add_argument('--input-dir', '-i', help='Input directory')
    parser.add_argument('--input-dirs', '-I', nargs='+', help='Multiple input directories')
    parser.add_argument('--output-dir', '-o', help='Output directory')
    parser.add_argument('--hash', '-H', choices=['md5', 'sha256'], default='md5', help='Hash type')
    parser.add_argument('--move', '-m', action='store_true', help='Move instead of copy')
    
    args = parser.parse_args()
    
    if args.input_dirs:
        if not args.output_dir:
            parser.error("--output-dir required with --input-dirs")
        stats = batch_rename(args.input_dirs, args.output_dir, args.hash)
    elif args.input_dir:
        stats = rename_by_hash(
            args.input_dir,
            args.output_dir,
            hash_type=args.hash,
            keep_original=not args.move
        )
    else:
        parser.error("Either --input-dir or --input-dirs required")
        return
        
    print(f"\nRename complete:")
    print(f"  Total files: {stats['total_files']}")
    print(f"  Renamed: {stats['renamed']}")
    print(f"  Skipped: {stats['skipped']}")
    print(f"  Errors: {stats['errors']}")


if __name__ == "__main__":
    main()
