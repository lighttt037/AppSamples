#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network IP Testing Module

Tests and validates IP addresses extracted from network traffic.
Part of the Profit2Pitfall toolkit.
"""

import os
import re
import socket
import argparse
import logging
import concurrent.futures
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Optional requests import
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class IPTester:
    """Test connectivity and gather information about IP addresses."""
    
    def __init__(self, timeout: int = 5):
        """
        Initialize IP tester.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
        
    def test_port(self, ip: str, port: int) -> bool:
        """Test if a port is open on an IP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
            
    def test_common_ports(self, ip: str) -> Dict[int, bool]:
        """Test common ports on an IP."""
        common_ports = [80, 443, 8080, 8443, 22, 21, 3306, 5432, 6379, 27017]
        results = {}
        
        for port in common_ports:
            results[port] = self.test_port(ip, port)
            
        return results
        
    def get_http_info(self, ip: str, port: int = 80) -> Dict[str, Any]:
        """Get HTTP server information."""
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests library not available'}
            
        info = {
            'accessible': False,
            'server': None,
            'status_code': None,
            'content_length': None
        }
        
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            
            info['accessible'] = True
            info['status_code'] = response.status_code
            info['server'] = response.headers.get('Server')
            info['content_length'] = len(response.content)
            
        except Exception as e:
            info['error'] = str(e)
            
        return info
        
    def reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
            
    def full_test(self, ip: str) -> Dict[str, Any]:
        """Perform full test on an IP."""
        result = {
            'ip': ip,
            'reverse_dns': self.reverse_dns(ip),
            'open_ports': {},
            'http_info': None
        }
        
        port_results = self.test_common_ports(ip)
        result['open_ports'] = {p: s for p, s in port_results.items() if s}
        
        if port_results.get(80):
            result['http_info'] = self.get_http_info(ip, 80)
        elif port_results.get(8080):
            result['http_info'] = self.get_http_info(ip, 8080)
            
        return result


def extract_ips_from_file(file_path: str) -> List[str]:
    """Extract IP addresses from file."""
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return []
        
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    return list(set(re.findall(pattern, content)))


def batch_test(
    ips: List[str],
    tester: IPTester,
    max_workers: int = 10
) -> List[Dict[str, Any]]:
    """Batch test multiple IPs."""
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(tester.full_test, ip): ip for ip in ips}
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                ip = futures[future]
                results.append({'ip': ip, 'error': str(e)})
                
    return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Test IP addresses from network traffic')
    parser.add_argument('--ip', '-i', help='Single IP to test')
    parser.add_argument('--file', '-f', help='File containing IPs')
    parser.add_argument('--timeout', '-t', type=int, default=5, help='Connection timeout')
    parser.add_argument('--workers', '-w', type=int, default=10, help='Max parallel workers')
    parser.add_argument('--output', '-o', default='ip_test_results.txt', help='Output file')
    
    args = parser.parse_args()
    
    tester = IPTester(timeout=args.timeout)
    
    if args.ip:
        result = tester.full_test(args.ip)
        print(f"\nIP: {result['ip']}")
        print(f"Reverse DNS: {result.get('reverse_dns', 'N/A')}")
        print(f"Open ports: {list(result.get('open_ports', {}).keys())}")
        if result.get('http_info'):
            print(f"HTTP Server: {result['http_info'].get('server', 'N/A')}")
            
    elif args.file:
        ips = extract_ips_from_file(args.file)
        logger.info(f"Testing {len(ips)} IPs...")
        
        results = batch_test(ips, tester, args.workers)
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("IP Test Results\n")
            f.write("=" * 60 + "\n\n")
            
            for result in results:
                f.write(f"IP: {result['ip']}\n")
                if result.get('error'):
                    f.write(f"  Error: {result['error']}\n")
                else:
                    f.write(f"  Reverse DNS: {result.get('reverse_dns', 'N/A')}\n")
                    f.write(f"  Open ports: {list(result.get('open_ports', {}).keys())}\n")
                f.write("\n")
                
        print(f"\nResults saved to: {args.output}")
        
    else:
        parser.error("Either --ip or --file must be specified")


if __name__ == "__main__":
    main()
