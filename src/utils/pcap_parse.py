#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP Parser Module

Parses PCAP network capture files to extract network traffic information.
Part of the Profit2Pitfall toolkit.
"""

import os
import re
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Optional scapy import
try:
    from scapy.all import rdpcap, DNS, DNSQR, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Install with: pip install scapy")


class PcapParser:
    """Parser for PCAP network capture files."""
    
    def __init__(self):
        self.dns_queries: Set[str] = set()
        self.ip_addresses: Set[str] = set()
        self.http_hosts: Set[str] = set()
        self.connections: List[Dict[str, Any]] = []
        
    def parse_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        Parse a PCAP file and extract network information.
        
        Args:
            pcap_path: Path to PCAP file
            
        Returns:
            Dictionary with extracted network data
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for PCAP parsing")
            return {}
            
        if not os.path.exists(pcap_path):
            logger.error(f"PCAP file not found: {pcap_path}")
            return {}
            
        logger.info(f"Parsing PCAP: {pcap_path}")
        
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            logger.error(f"Error reading PCAP: {e}")
            return {}
            
        for pkt in packets:
            # Extract DNS queries
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    qname = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                    self.dns_queries.add(qname)
                except Exception:
                    pass
                    
            # Extract IP addresses
            if pkt.haslayer(IP):
                self.ip_addresses.add(pkt[IP].src)
                self.ip_addresses.add(pkt[IP].dst)
                
            # Extract HTTP Host headers
            if pkt.haslayer(TCP):
                try:
                    payload = bytes(pkt[TCP].payload)
                    if b'Host:' in payload:
                        match = re.search(rb'Host:\s*([^\r\n]+)', payload)
                        if match:
                            host = match.group(1).decode('utf-8').strip()
                            self.http_hosts.add(host)
                except Exception:
                    pass
                    
        return self.get_results()
        
    def get_results(self) -> Dict[str, Any]:
        """Get parsing results."""
        return {
            'dns_queries': sorted(self.dns_queries),
            'ip_addresses': sorted(self.ip_addresses),
            'http_hosts': sorted(self.http_hosts),
            'total_dns': len(self.dns_queries),
            'total_ips': len(self.ip_addresses),
            'total_hosts': len(self.http_hosts)
        }
        
    def export_results(self, output_path: str):
        """Export results to file."""
        results = self.get_results()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("PCAP Analysis Results\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"DNS Queries ({results['total_dns']}):\n")
            for query in results['dns_queries']:
                f.write(f"  {query}\n")
            f.write("\n")
            
            f.write(f"HTTP Hosts ({results['total_hosts']}):\n")
            for host in results['http_hosts']:
                f.write(f"  {host}\n")
            f.write("\n")
            
            f.write(f"IP Addresses ({results['total_ips']}):\n")
            for ip in results['ip_addresses'][:50]:  # Limit output
                f.write(f"  {ip}\n")
            if results['total_ips'] > 50:
                f.write(f"  ... and {results['total_ips'] - 50} more\n")
                
        logger.info(f"Results saved to: {output_path}")


def parse_text_result(result_file: str) -> Dict[str, Any]:
    """
    Parse a text-based traffic result file.
    
    Args:
        result_file: Path to result file
        
    Returns:
        Dictionary with parsed data
    """
    if not os.path.exists(result_file):
        logger.error(f"File not found: {result_file}")
        return {}
        
    with open(result_file, 'r', encoding='utf-8') as f:
        content = f.read()
        
    hosts = set()
    ips = set()
    
    # Extract hosts from common patterns
    host_patterns = [
        r'Host:\s*([^\s\r\n]+)',
        r'domain:\s*([^\s\r\n]+)',
        r'SNI:\s*([^\s\r\n]+)',
    ]
    
    for pattern in host_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        hosts.update(matches)
        
    # Extract IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips.update(re.findall(ip_pattern, content))
    
    return {
        'hosts': sorted(hosts),
        'ips': sorted(ips),
        'total_hosts': len(hosts),
        'total_ips': len(ips)
    }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Parse PCAP files for network analysis')
    parser.add_argument('--pcap', '-p', help='PCAP file to parse')
    parser.add_argument('--result-file', '-r', help='Text result file to parse')
    parser.add_argument('--output', '-o', default='pcap_analysis.txt', help='Output file')
    
    args = parser.parse_args()
    
    if args.pcap:
        if not SCAPY_AVAILABLE:
            print("Error: Scapy is required for PCAP parsing")
            print("Install with: pip install scapy")
            return
            
        pcap_parser = PcapParser()
        results = pcap_parser.parse_pcap(args.pcap)
        pcap_parser.export_results(args.output)
        
        print(f"\nPCAP Analysis complete:")
        print(f"  DNS queries: {results.get('total_dns', 0)}")
        print(f"  HTTP hosts: {results.get('total_hosts', 0)}")
        print(f"  IP addresses: {results.get('total_ips', 0)}")
        
    elif args.result_file:
        results = parse_text_result(args.result_file)
        print(f"\nResult file analysis:")
        print(f"  Hosts: {results.get('total_hosts', 0)}")
        print(f"  IPs: {results.get('total_ips', 0)}")
        
    else:
        parser.error("Either --pcap or --result-file must be specified")


if __name__ == "__main__":
    main()
