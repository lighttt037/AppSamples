#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Certificate Analyzer Module

Analyzes APK signing certificates to identify certificate reuse patterns
and potential connections between malicious applications.

Part of the Profit2Pitfall toolkit.
"""

import os
import re
import argparse
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def extract_cert_info(file_path: str) -> Dict[str, str]:
    """
    Extract certificate information from a certificate analysis file.
    
    Args:
        file_path: Path to the certificate info file
        
    Returns:
        Dictionary containing certificate information
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        cert_info = {}

        # Extract application name
        app_name_match = re.search(r'应用名称：(.+)', content)
        if app_name_match:
            cert_info['app_name'] = app_name_match.group(1).strip()

        # Extract certificate DN (Distinguished Name)
        dn_match = re.search(r'certificate DN:\s*(.+)', content)
        if dn_match:
            cert_info['dn'] = dn_match.group(1).strip()

        # Extract SHA-256 fingerprint
        sha256_match = re.search(r'SHA-256 digest:\s*([a-fA-F0-9]+)', content)
        if sha256_match:
            cert_info['sha256'] = sha256_match.group(1).strip()

        # Extract SHA-1 fingerprint
        sha1_match = re.search(r'SHA-1 digest:\s*([a-fA-F0-9]+)', content)
        if sha1_match:
            cert_info['sha1'] = sha1_match.group(1).strip()

        # Extract MD5 fingerprint
        md5_match = re.search(r'MD5 digest:\s*([a-fA-F0-9]+)', content)
        if md5_match:
            cert_info['md5'] = md5_match.group(1).strip()

        return cert_info

    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return {}


def parse_filename(filename: str) -> Optional[str]:
    """Parse filename to extract hash value."""
    match = re.match(r'([a-fA-F0-9]+)_info\.txt$', filename)
    if match:
        return match.group(1)
    return None


def create_cert_signature(cert_info: Dict[str, str]) -> str:
    """Create a certificate signature for identifying identical certificates."""
    if 'sha1' in cert_info and cert_info['sha1']:
        return cert_info['sha1']
    elif 'md5' in cert_info and cert_info['md5']:
        return cert_info['md5']
    elif 'sha256' in cert_info and cert_info['sha256']:
        return cert_info['sha256']
    else:
        return cert_info.get('dn', 'unknown')


def extract_package_name_from_apkinfo(hash_value: str, apkinfo_dir: str) -> Optional[str]:
    """Extract package name from APK info file."""
    if not os.path.exists(apkinfo_dir):
        return None
    
    try:
        for filename in os.listdir(apkinfo_dir):
            if filename.endswith('.txt'):
                match = re.match(r'([a-fA-F0-9]+)\.apk_(.+)\.txt$', filename)
                if match and match.group(1) == hash_value:
                    return match.group(2)
        return None
    except Exception as e:
        logger.error(f"Error extracting package name: {e}")
        return None


def analyze_certificates(
    certs_dir: str,
    apkinfo_dir: str = None,
    output_file: str = None
) -> Dict[str, Any]:
    """
    Analyze certificates in a directory to find reuse patterns.
    
    Args:
        certs_dir: Directory containing certificate files
        apkinfo_dir: Directory containing APK info files (optional)
        output_file: Path to output file (optional)
        
    Returns:
        Dictionary with analysis results
    """
    if not os.path.exists(certs_dir):
        logger.error(f"Directory not found: {certs_dir}")
        return {}

    cert_groups = defaultdict(list)

    for filename in os.listdir(certs_dir):
        if not filename.endswith('.txt'):
            continue
            
        file_path = os.path.join(certs_dir, filename)
        hash_value = parse_filename(filename)
        
        if not hash_value:
            continue

        cert_info = extract_cert_info(file_path)
        if not cert_info:
            continue

        package_name = "unknown"
        if apkinfo_dir:
            package_name = extract_package_name_from_apkinfo(hash_value, apkinfo_dir) or "unknown"

        cert_signature = create_cert_signature(cert_info)

        app_info = {
            'filename': filename,
            'hash': hash_value,
            'package': package_name,
            'cert_info': cert_info,
            'cert_signature': cert_signature
        }

        cert_groups[cert_signature].append(app_info)

    results = {
        'total_apps': sum(len(apps) for apps in cert_groups.values()),
        'unique_certs': len(cert_groups),
        'cert_groups': dict(cert_groups),
        'shared_certs': {k: v for k, v in cert_groups.items() if len(v) > 1}
    }

    if output_file:
        _write_report(results, output_file)

    return results


def _write_report(results: Dict[str, Any], output_file: str):
    """Write analysis report to file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("Certificate Analysis Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total applications analyzed: {results['total_apps']}\n")
        f.write(f"Unique certificates found: {results['unique_certs']}\n")
        f.write(f"Shared certificates: {len(results['shared_certs'])}\n\n")

        if results['shared_certs']:
            f.write("Shared Certificate Details:\n")
            f.write("-" * 40 + "\n")
            
            for i, (cert_sig, apps) in enumerate(results['shared_certs'].items(), 1):
                f.write(f"\nCertificate Group {i} ({len(apps)} apps):\n")
                f.write(f"  Signature: {cert_sig[:32]}...\n")
                for app in apps:
                    f.write(f"  - {app['package']} ({app['hash'][:16]}...)\n")

    logger.info(f"Report saved to: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Analyze APK certificates for reuse patterns')
    parser.add_argument('--certs-dir', '-c', required=True, help='Directory containing certificate files')
    parser.add_argument('--apkinfo-dir', '-a', help='Directory containing APK info files')
    parser.add_argument('--output', '-o', default='certificate_analysis.txt', help='Output file path')
    
    args = parser.parse_args()
    
    results = analyze_certificates(args.certs_dir, args.apkinfo_dir, args.output)
    
    print(f"\nAnalysis complete:")
    print(f"  Total apps: {results.get('total_apps', 0)}")
    print(f"  Unique certs: {results.get('unique_certs', 0)}")
    print(f"  Shared certs: {len(results.get('shared_certs', {}))}")


if __name__ == "__main__":
    main()
