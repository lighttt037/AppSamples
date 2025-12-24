#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto JADX Decompiler Module

Automates batch decompilation of APK files using JADX.
Part of the Profit2Pitfall toolkit.
"""

import os
import subprocess
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class JadxDecompiler:
    """Wrapper for JADX decompilation tool."""
    
    def __init__(
        self,
        jadx_path: str = "jadx",
        output_dir: str = "./jadx_output",
        threads: int = 4
    ):
        """
        Initialize JADX decompiler.
        
        Args:
            jadx_path: Path to JADX executable (default: assumes in PATH)
            output_dir: Base directory for decompiled output
            threads: Number of JADX threads to use
        """
        self.jadx_path = jadx_path
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def verify_jadx(self) -> bool:
        """Verify JADX is available."""
        try:
            result = subprocess.run(
                [self.jadx_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            logger.info(f"JADX version: {result.stdout.strip()}")
            return True
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"JADX not found or error: {e}")
            return False
    
    def decompile_apk(self, apk_path: str, output_name: Optional[str] = None) -> bool:
        """
        Decompile a single APK file.
        
        Args:
            apk_path: Path to APK file
            output_name: Custom output directory name (default: APK filename)
            
        Returns:
            True if successful, False otherwise
        """
        apk_path = Path(apk_path)
        if not apk_path.exists():
            logger.error(f"APK not found: {apk_path}")
            return False
            
        if output_name is None:
            output_name = apk_path.stem
            
        output_path = self.output_dir / output_name
        
        if output_path.exists():
            logger.info(f"Already decompiled: {output_name}")
            return True
            
        cmd = [
            self.jadx_path,
            "-d", str(output_path),
            "-j", str(self.threads),
            "--no-res",  # Skip resources for faster decompilation
            str(apk_path)
        ]
        
        try:
            logger.info(f"Decompiling: {apk_path.name}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully decompiled: {apk_path.name}")
                return True
            else:
                logger.error(f"JADX error for {apk_path.name}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout decompiling: {apk_path.name}")
            return False
        except Exception as e:
            logger.error(f"Error decompiling {apk_path.name}: {e}")
            return False
    
    def batch_decompile(
        self,
        apk_dir: str,
        max_workers: int = 2
    ) -> dict:
        """
        Batch decompile all APKs in a directory.
        
        Args:
            apk_dir: Directory containing APK files
            max_workers: Number of parallel decompilation jobs
            
        Returns:
            Dictionary with success/failure counts
        """
        apk_dir = Path(apk_dir)
        if not apk_dir.exists():
            logger.error(f"APK directory not found: {apk_dir}")
            return {"success": 0, "failed": 0}
            
        apk_files = list(apk_dir.glob("*.apk"))
        logger.info(f"Found {len(apk_files)} APK files to decompile")
        
        results = {"success": 0, "failed": 0, "skipped": 0}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.decompile_apk, str(apk)): apk
                for apk in apk_files
            }
            
            for future in as_completed(futures):
                apk = futures[future]
                try:
                    if future.result():
                        results["success"] += 1
                    else:
                        results["failed"] += 1
                except Exception as e:
                    logger.error(f"Error processing {apk}: {e}")
                    results["failed"] += 1
                    
        return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Batch decompile APKs using JADX')
    parser.add_argument('--jadx-path', '-j', default='jadx', help='Path to JADX executable')
    parser.add_argument('--apk-dir', '-a', help='Directory containing APK files')
    parser.add_argument('--apk-file', '-f', help='Single APK file to decompile')
    parser.add_argument('--output-dir', '-o', default='./jadx_output', help='Output directory')
    parser.add_argument('--threads', '-t', type=int, default=4, help='JADX threads')
    parser.add_argument('--workers', '-w', type=int, default=2, help='Parallel workers')
    
    args = parser.parse_args()
    
    decompiler = JadxDecompiler(
        jadx_path=args.jadx_path,
        output_dir=args.output_dir,
        threads=args.threads
    )
    
    if not decompiler.verify_jadx():
        print("Error: JADX not found. Please install JADX or specify path with --jadx-path")
        return
    
    if args.apk_file:
        success = decompiler.decompile_apk(args.apk_file)
        print(f"Decompilation {'successful' if success else 'failed'}")
    elif args.apk_dir:
        results = decompiler.batch_decompile(args.apk_dir, args.workers)
        print(f"\nBatch decompilation complete:")
        print(f"  Success: {results['success']}")
        print(f"  Failed: {results['failed']}")
    else:
        parser.error("Either --apk-dir or --apk-file must be specified")


if __name__ == "__main__":
    main()
