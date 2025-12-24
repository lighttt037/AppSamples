#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Evasion Technique Detection Module

This module implements detection algorithms for network-level evasion techniques
used by task-oriented scam apps.

Techniques Detected:
    1. Time-Based Domain Rotation
    2. Remote Cloud Server Loading

This module serves as the main entry point and re-exports all public APIs
from the submodules: core, parsers, and detectors.

Author: Research Team
License: MIT

Example:
    Command-line usage::
    
        # Detect domain rotation
        python -m src.network rotation \\
            --dir-t1 /path/to/traffic/day1 \\
            --dir-t2 /path/to/traffic/day2 \\
            --output results.json
        
        # Detect cloud loading
        python -m src.network cloud \\
            --mitm-dir /path/to/mitm/output \\
            --output cloud_results.json
    
    Python API usage::
    
        from src.network import DomainRotationDetector, CloudConfigDetector
        
        # Domain rotation detection
        detector = DomainRotationDetector()
        result = detector.detect_from_files("day1.txt", "day2.txt")
        
        # Cloud loading detection
        detector = CloudConfigDetector()
        responses = MitmResponseParser().parse_mitm_file("mitm.txt")
        result = detector.detect(responses)
"""

import argparse
import sys

# Re-export public API from submodules
from .core import (
    DetectionConfig,
    TrafficCapture,
    HTTPResponse,
    DetectionResult,
    levenshtein_distance,
    extract_tld,
    is_same_tld,
    is_base64_encoded,
    is_randomized_string,
    extract_urls_from_text,
    is_static_resource,
    is_public_ip,
    LEVENSHTEIN_AVAILABLE,
)

from .parsers import (
    parse_tls_sni,
    parse_pcap_file,
    parse_traffic_result_file,
    MitmResponseParser,
    SCAPY_AVAILABLE,
)

from .detectors import (
    DomainRotationDetector,
    CloudConfigDetector,
    detect_domain_rotation_batch,
    detect_cloud_loading_batch,
    save_results,
)


__all__ = [
    # Configuration
    'DetectionConfig',
    
    # Data classes
    'TrafficCapture',
    'HTTPResponse',
    'DetectionResult',
    
    # Detectors
    'DomainRotationDetector',
    'CloudConfigDetector',
    
    # Parsers
    'MitmResponseParser',
    'parse_tls_sni',
    'parse_pcap_file',
    'parse_traffic_result_file',
    
    # Batch processing
    'detect_domain_rotation_batch',
    'detect_cloud_loading_batch',
    'save_results',
    
    # Utility functions
    'levenshtein_distance',
    'extract_tld',
    'is_same_tld',
    'is_base64_encoded',
    'is_randomized_string',
    'extract_urls_from_text',
    'is_static_resource',
    'is_public_ip',
    
    # Availability flags
    'LEVENSHTEIN_AVAILABLE',
    'SCAPY_AVAILABLE',
]


def main():
    """Main entry point for command line usage."""
    parser = argparse.ArgumentParser(
        description='Network Evasion Technique Detection for Task-Oriented Scam Apps',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Detect domain rotation:
    %(prog)s rotation --dir-t1 traffic/day1 --dir-t2 traffic/day2

  Detect cloud loading:
    %(prog)s cloud --mitm-dir mitm_output/

  Analyze single app:
    %(prog)s single --file-t1 app_day1.txt --file-t2 app_day2.txt
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Detection command')
    
    # Domain rotation detection
    rotation_parser = subparsers.add_parser(
        'rotation', 
        help='Detect time-based domain rotation'
    )
    rotation_parser.add_argument(
        '--dir-t1', 
        required=True,
        help='Directory with traffic results at time t'
    )
    rotation_parser.add_argument(
        '--dir-t2', 
        required=True,
        help='Directory with traffic results at time t+24h'
    )
    rotation_parser.add_argument(
        '--output', 
        default='domain_rotation_results.json',
        help='Output file for results (default: domain_rotation_results.json)'
    )
    rotation_parser.add_argument(
        '--threshold', 
        type=int, 
        default=6,
        help='Edit distance threshold τ (default: 6)'
    )
    
    # Cloud loading detection
    cloud_parser = subparsers.add_parser(
        'cloud', 
        help='Detect remote cloud server loading'
    )
    cloud_parser.add_argument(
        '--mitm-dir', 
        required=True,
        help='Directory with MITM proxy output files'
    )
    cloud_parser.add_argument(
        '--output', 
        default='cloud_loading_results.json',
        help='Output file for results (default: cloud_loading_results.json)'
    )
    
    # Single file analysis
    single_parser = subparsers.add_parser(
        'single', 
        help='Analyze single app traffic files'
    )
    single_parser.add_argument(
        '--file-t1', 
        help='Traffic file at time t (for rotation detection)'
    )
    single_parser.add_argument(
        '--file-t2', 
        help='Traffic file at time t+24h (for rotation detection)'
    )
    single_parser.add_argument(
        '--mitm-file', 
        help='MITM output file (for cloud loading detection)'
    )
    
    args = parser.parse_args()
    
    if args.command == 'rotation':
        config = DetectionConfig(edit_distance_threshold=args.threshold)
        results = detect_domain_rotation_batch(
            args.dir_t1, 
            args.dir_t2, 
            args.output,
            config
        )
        print(f"\n✓ Detected domain rotation in {len(results)} apps")
        print(f"  Results saved to: {args.output}")
        
    elif args.command == 'cloud':
        results = detect_cloud_loading_batch(
            args.mitm_dir, 
            args.output
        )
        print(f"\n✓ Detected cloud loading in {len(results)} apps")
        print(f"  Results saved to: {args.output}")
        
    elif args.command == 'single':
        config = DetectionConfig()
        
        if args.file_t1 and args.file_t2:
            detector = DomainRotationDetector(config)
            result = detector.detect_from_files(args.file_t1, args.file_t2)
            print(f"\n{'='*60}")
            print("Domain Rotation Detection")
            print('='*60)
            print(f"  Detected: {'Yes' if result.detected else 'No'}")
            print(f"  Confidence: {result.confidence:.2f}")
            if result.detected:
                print(f"  Rotating pairs found: {len(result.evidence['rotating_pairs'])}")
                for pair in result.evidence['rotating_pairs']:
                    print(f"    • {pair['domain_t1']} → {pair['domain_t2']}")
                    print(f"      (TLD: {pair['tld']}, Edit Distance: {pair['edit_distance']})")
        
        if args.mitm_file:
            mitm_parser = MitmResponseParser(config)
            detector = CloudConfigDetector(config)
            responses = mitm_parser.parse_mitm_file(args.mitm_file)
            result = detector.detect(responses)
            print(f"\n{'='*60}")
            print("Cloud Loading Detection")
            print('='*60)
            print(f"  Detected: {'Yes' if result.detected else 'No'}")
            print(f"  Confidence: {result.confidence:.2f}")
            if result.detected:
                print(f"  Suspicious responses: {len(result.evidence['suspicious_responses'])}")
                for resp in result.evidence['suspicious_responses'][:5]:
                    print(f"    • {resp['url']}")
                if len(result.evidence['suspicious_responses']) > 5:
                    print(f"    ... and {len(result.evidence['suspicious_responses']) - 5} more")
        
        if not args.file_t1 and not args.file_t2 and not args.mitm_file:
            single_parser.print_help()
    else:
        parser.print_help()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
