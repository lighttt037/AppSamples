#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Emulator Detection Module

Detects emulator-related artifacts and anti-emulation techniques in APKs.
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


# Common emulator detection patterns found in malicious apps
EMULATOR_DETECTION_PATTERNS = {
    'build_properties': [
        r'Build\.FINGERPRINT.*generic',
        r'Build\.MODEL.*sdk',
        r'Build\.MODEL.*Emulator',
        r'Build\.MODEL.*Android SDK',
        r'Build\.MANUFACTURER.*Genymotion',
        r'Build\.BRAND.*generic',
        r'Build\.DEVICE.*generic',
        r'Build\.PRODUCT.*sdk',
        r'Build\.HARDWARE.*goldfish',
        r'Build\.HARDWARE.*ranchu',
    ],
    'system_properties': [
        r'ro\.hardware.*goldfish',
        r'ro\.hardware.*ranchu',
        r'ro\.kernel\.qemu',
        r'ro\.product\.device.*generic',
        r'ro\.build\.characteristics.*emulator',
        r'init\.svc\.qemud',
        r'init\.svc\.qemu-props',
    ],
    'file_checks': [
        r'/dev/socket/qemud',
        r'/dev/qemu_pipe',
        r'/system/lib/libc_malloc_debug_qemu\.so',
        r'/sys/qemu_trace',
        r'/system/bin/qemu-props',
        r'ueventd\.android_x86\.rc',
        r'x86\.prop',
        r'ueventd\.ttVM_x86\.rc',
        r'fstab\.andy',
        r'ueventd\.andy\.rc',
    ],
    'telephony_checks': [
        r'getDeviceId.*000000000000000',
        r'getSubscriberId.*null',
        r'getLine1Number.*null',
        r'getNetworkOperatorName.*Android',
        r'getSimSerialNumber.*89014103211118510720',
    ],
    'sensor_checks': [
        r'getSensorList.*size.*==.*0',
        r'TYPE_ACCELEROMETER.*null',
        r'TYPE_GYROSCOPE.*null',
    ]
}


class EmulatorDetectionAnalyzer:
    """Analyzer for emulator detection code in APKs."""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.findings: Dict[str, List[Dict[str, Any]]] = {}
        
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze project for emulator detection patterns.
        
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Analyzing: {self.project_path}")
        
        sources_dir = self.project_path / "sources"
        if not sources_dir.exists():
            sources_dir = self.project_path
            
        java_files = list(sources_dir.rglob("*.java"))
        smali_files = list(sources_dir.rglob("*.smali"))
        
        all_files = java_files + smali_files
        logger.info(f"Found {len(all_files)} source files to analyze")
        
        for file_path in all_files:
            self._analyze_file(file_path)
            
        return self._generate_report()
        
    def _analyze_file(self, file_path: Path):
        """Analyze a single file for emulator detection patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.debug(f"Error reading {file_path}: {e}")
            return
            
        rel_path = str(file_path.relative_to(self.project_path))
        
        for category, patterns in EMULATOR_DETECTION_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    if category not in self.findings:
                        self.findings[category] = []
                    self.findings[category].append({
                        'file': rel_path,
                        'pattern': pattern,
                        'matches': matches[:5]  # Limit matches
                    })
                    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate analysis report."""
        total_findings = sum(len(v) for v in self.findings.values())
        
        report = {
            'project': str(self.project_path),
            'total_findings': total_findings,
            'categories_detected': list(self.findings.keys()),
            'has_emulator_detection': total_findings > 0,
            'risk_level': self._calculate_risk_level(total_findings),
            'details': self.findings
        }
        
        return report
        
    def _calculate_risk_level(self, total_findings: int) -> str:
        """Calculate risk level based on findings."""
        if total_findings == 0:
            return "none"
        elif total_findings <= 3:
            return "low"
        elif total_findings <= 10:
            return "medium"
        else:
            return "high"
            
    def export_report(self, output_path: str):
        """Export report to file."""
        report = self._generate_report()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("Emulator Detection Analysis Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Project: {report['project']}\n")
            f.write(f"Risk Level: {report['risk_level'].upper()}\n")
            f.write(f"Total Findings: {report['total_findings']}\n")
            f.write(f"Categories: {', '.join(report['categories_detected'])}\n\n")
            
            if report['has_emulator_detection']:
                f.write("Detailed Findings:\n")
                f.write("-" * 40 + "\n")
                
                for category, findings in report['details'].items():
                    f.write(f"\n{category}:\n")
                    for finding in findings[:10]:  # Limit output
                        f.write(f"  File: {finding['file']}\n")
                        f.write(f"  Pattern: {finding['pattern']}\n")
                        f.write("\n")
                        
        logger.info(f"Report saved to: {output_path}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Analyze APK for emulator detection code')
    parser.add_argument('--project', '-p', required=True, help='Decompiled project path')
    parser.add_argument('--output', '-o', default='emulator_detection_report.txt', help='Output file')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.project):
        print(f"Error: Path not found: {args.project}")
        return
        
    analyzer = EmulatorDetectionAnalyzer(args.project)
    report = analyzer.analyze()
    analyzer.export_report(args.output)
    
    print(f"\nAnalysis complete:")
    print(f"  Risk Level: {report['risk_level'].upper()}")
    print(f"  Total Findings: {report['total_findings']}")
    print(f"  Has Emulator Detection: {report['has_emulator_detection']}")


if __name__ == "__main__":
    main()
