#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Evasion Detection Example

This example demonstrates how to use the network evasion detection module
to identify time-based domain rotation and cloud server loading techniques.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network import (
    DomainRotationDetector,
    CloudConfigDetector,
    DetectionConfig,
    TrafficCapture,
    HTTPResponse,
    MitmResponseParser
)


def example_domain_rotation():
    """
    Example: Detect time-based domain rotation
    
    This demonstrates how to detect apps that rotate their domain names
    algorithmically over time.
    """
    print("=" * 70)
    print("Example 1: Time-Based Domain Rotation Detection")
    print("=" * 70)
    print()
    
    # Configure detector with custom threshold
    config = DetectionConfig(edit_distance_threshold=6)
    detector = DomainRotationDetector(config)
    
    # Example: Create synthetic traffic captures for demonstration
    # In practice, these would come from actual network captures
    traffic_t1 = TrafficCapture(
        app_id="com.example.scamapp",
        capture_time="2024-01-01 12:00:00",
        domains={
            "abcdefg.example.com",
            "api.google.com",  # Legitimate domain (whitelisted)
            "cdn.cloudflare.com"  # Legitimate CDN
        }
    )
    
    traffic_t2 = TrafficCapture(
        app_id="com.example.scamapp",
        capture_time="2024-01-02 12:00:00",  # 24 hours later
        domains={
            "xyzvwxy.example.com",  # Rotated domain (same length, same TLD, high edit distance)
            "api.google.com",  # Still using Google API
            "cdn.cloudflare.com"  # Still using Cloudflare CDN
        }
    )
    
    # Detect rotation
    result = detector.detect(traffic_t1, traffic_t2)
    
    # Display results
    print(f"App ID: {traffic_t1.app_id}")
    print(f"Detected: {'Yes' if result.detected else 'No'}")
    print(f"Confidence: {result.confidence:.2f}")
    print()
    
    if result.detected:
        print("Rotating domain pairs found:")
        for pair in result.evidence['rotating_pairs']:
            print(f"  • {pair['domain_t1']} → {pair['domain_t2']}")
            print(f"    TLD: {pair['tld']}, Edit Distance: {pair['edit_distance']}")
        print()
        print("Analysis:")
        print("  ✓ Same top-level domain")
        print("  ✓ Same string length")
        print("  ✓ High edit distance (algorithmically rotated)")
        print("  ✓ Legitimate domains unchanged (whitelisted)")
    else:
        print("No domain rotation detected.")
    
    print()


def example_cloud_loading():
    """
    Example: Detect remote cloud server loading
    
    This demonstrates how to detect apps that retrieve C2 server addresses
    from cloud storage services.
    """
    print("=" * 70)
    print("Example 2: Remote Cloud Server Loading Detection")
    print("=" * 70)
    print()
    
    # Configure detector
    config = DetectionConfig()
    detector = CloudConfigDetector(config)
    
    # Example: Create synthetic HTTP responses
    # In practice, these would come from MITM proxy captures
    responses = [
        # Suspicious response from Alibaba Cloud OSS
        HTTPResponse(
            url="https://example-bucket.oss-cn-hangzhou.aliyuncs.com/config/server.json",
            host="example-bucket.oss-cn-hangzhou.aliyuncs.com",
            path="/config/server.json",
            status_code=200,
            body='{"server": "http://192.168.1.100:8080", "backup": "http://203.0.113.5:9090"}',
            headers={"Content-Type": "application/json"}
        ),
        
        # Normal CDN content (will be filtered)
        HTTPResponse(
            url="https://cdn.jsdelivr.net/npm/package@1.0.0/dist/bundle.js",
            host="cdn.jsdelivr.net",
            path="/npm/package@1.0.0/dist/bundle.js",
            status_code=200,
            body='function init() { console.log("Hello"); }',
            headers={"Content-Type": "application/javascript"}
        ),
        
        # Suspicious base64-encoded response
        HTTPResponse(
            url="https://scam-storage.cos.ap-beijing.myqcloud.com/dn.json",
            host="scam-storage.cos.ap-beijing.myqcloud.com",
            path="/dn.json",
            status_code=200,
            body="aHR0cDovLzEyMy40NS42Ny44OTo4MDgw",  # Base64 encoded IP
            headers={"Content-Type": "text/plain"}
        )
    ]
    
    # Detect cloud loading
    result = detector.detect(responses)
    
    # Display results
    print(f"Detected: {'Yes' if result.detected else 'No'}")
    print(f"Confidence: {result.confidence:.2f}")
    print()
    
    if result.detected:
        print(f"Suspicious responses found: {len(result.evidence['suspicious_responses'])}")
        print()
        for i, resp in enumerate(result.evidence['suspicious_responses'], 1):
            print(f"Response {i}:")
            print(f"  URL: {resp['url']}")
            print(f"  Status: {resp['status_code']}")
            if resp.get('external_urls'):
                print(f"  External URLs found: {', '.join(resp['external_urls'])}")
            if resp.get('is_obfuscated'):
                print(f"  Contains obfuscated content")
            if resp.get('is_config_file'):
                print(f"  Config file path detected")
            print()
        
        print("Analysis:")
        print("  ✓ Retrieves configuration from cloud storage")
        print("  ✓ Contains IP addresses or URLs in response")
        print("  ✓ Uses config-related path names")
        print("  ✓ May use encoding/obfuscation")
    else:
        print("No cloud server loading detected.")
    
    print()


def example_file_based_detection():
    """
    Example: Detect from actual traffic files
    
    This shows how to process real traffic capture files.
    """
    print("=" * 70)
    print("Example 3: File-Based Detection")
    print("=" * 70)
    print()
    
    # This example assumes you have traffic files
    # For demonstration, we'll show the code structure
    
    print("To detect domain rotation from actual files:")
    print()
    print("  from src.network import DomainRotationDetector, DetectionConfig")
    print()
    print("  config = DetectionConfig(edit_distance_threshold=6)")
    print("  detector = DomainRotationDetector(config)")
    print()
    print("  result = detector.detect_from_files(")
    print("      file_t1='traffic/app_day1.txt',")
    print("      file_t2='traffic/app_day2.txt'")
    print("  )")
    print()
    print("  if result.detected:")
    print("      print(f'Detected rotation in {result.app_id}')")
    print()
    print()
    print("To detect cloud loading from MITM captures:")
    print()
    print("  from src.network import CloudConfigDetector, MitmResponseParser")
    print()
    print("  parser = MitmResponseParser()")
    print("  detector = CloudConfigDetector()")
    print()
    print("  responses = parser.parse_mitm_file('mitm_output.txt')")
    print("  result = detector.detect(responses)")
    print()
    print("  if result.detected:")
    print("      print(f'Detected cloud loading')")
    print()


def main():
    """Run all examples"""
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "Network Evasion Detection Examples" + " " * 19 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    # Run examples
    example_domain_rotation()
    print("\n")
    
    example_cloud_loading()
    print("\n")
    
    example_file_based_detection()
    
    print()
    print("=" * 70)
    print("Examples completed!")
    print("=" * 70)
    print()
    print("For more information, see the documentation:")
    print("  • README.md")
    print("  • src/network/README.md (if available)")
    print()


if __name__ == "__main__":
    main()
