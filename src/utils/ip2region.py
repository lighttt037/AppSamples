#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP to Region Module

Maps IP addresses to geographic regions for network traffic analysis.
Part of the Profit2Pitfall toolkit.
"""

import os
import re
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Optional ip2region import
try:
    import ip2region
    IP2REGION_AVAILABLE = True
except ImportError:
    IP2REGION_AVAILABLE = False


class IPGeoLocator:
    """IP address geolocation service."""
    
    def __init__(self, database_path: Optional[str] = None):
        """
        Initialize IP geolocator.
        
        Args:
            database_path: Path to ip2region database file (optional)
        """
        self.database_path = database_path
        self.searcher = None
        self._init_searcher()
        
    def _init_searcher(self):
        """Initialize the IP searcher."""
        if not IP2REGION_AVAILABLE:
            logger.warning("ip2region not available. Install with: pip install ip2region")
            return
            
        if self.database_path and os.path.exists(self.database_path):
            try:
                self.searcher = ip2region.Ip2Region(self.database_path)
                logger.info("ip2region database loaded")
            except Exception as e:
                logger.error(f"Failed to load database: {e}")
                
    def lookup(self, ip: str) -> Dict[str, Any]:
        """
        Look up geographic information for an IP address.
        
        Args:
            ip: IP address to look up
            
        Returns:
            Dictionary with location information
        """
        result = {
            'ip': ip,
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown'
        }
        
        if not self._is_valid_ip(ip):
            result['error'] = 'Invalid IP address'
            return result
            
        if self._is_private_ip(ip):
            result['country'] = 'Private'
            result['region'] = 'Private Network'
            return result
            
        if self.searcher:
            try:
                data = self.searcher.search(ip)
                if data:
                    # Parse ip2region response
                    parts = data.get('region', '').split('|')
                    if len(parts) >= 5:
                        result['country'] = parts[0] if parts[0] != '0' else 'Unknown'
                        result['region'] = parts[2] if parts[2] != '0' else 'Unknown'
                        result['city'] = parts[3] if parts[3] != '0' else 'Unknown'
                        result['isp'] = parts[4] if parts[4] != '0' else 'Unknown'
            except Exception as e:
                logger.debug(f"Lookup error for {ip}: {e}")
                
        return result
        
    def batch_lookup(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Batch lookup for multiple IPs."""
        return [self.lookup(ip) for ip in ips]
        
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address format."""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))
        
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in private range."""
        parts = [int(p) for p in ip.split('.')]
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 127.0.0.0/8 (loopback)
        if parts[0] == 127:
            return True
            
        return False


def extract_ips_from_file(file_path: str) -> List[str]:
    """Extract IP addresses from a text file."""
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return []
        
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ips = list(set(re.findall(ip_pattern, content)))
    
    return ips


def analyze_ip_distribution(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze geographic distribution of IPs."""
    countries = {}
    regions = {}
    isps = {}
    
    for result in results:
        country = result.get('country', 'Unknown')
        region = result.get('region', 'Unknown')
        isp = result.get('isp', 'Unknown')
        
        countries[country] = countries.get(country, 0) + 1
        regions[region] = regions.get(region, 0) + 1
        isps[isp] = isps.get(isp, 0) + 1
        
    return {
        'total_ips': len(results),
        'countries': dict(sorted(countries.items(), key=lambda x: x[1], reverse=True)),
        'regions': dict(sorted(regions.items(), key=lambda x: x[1], reverse=True)[:20]),
        'isps': dict(sorted(isps.items(), key=lambda x: x[1], reverse=True)[:20])
    }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Map IP addresses to geographic regions')
    parser.add_argument('--ip', '-i', help='Single IP to lookup')
    parser.add_argument('--file', '-f', help='File containing IPs')
    parser.add_argument('--database', '-d', help='Path to ip2region database')
    parser.add_argument('--output', '-o', default='ip_analysis.txt', help='Output file')
    
    args = parser.parse_args()
    
    locator = IPGeoLocator(args.database)
    
    if args.ip:
        result = locator.lookup(args.ip)
        print(f"\nIP: {result['ip']}")
        print(f"Country: {result['country']}")
        print(f"Region: {result['region']}")
        print(f"City: {result['city']}")
        print(f"ISP: {result['isp']}")
        
    elif args.file:
        ips = extract_ips_from_file(args.file)
        logger.info(f"Found {len(ips)} unique IPs")
        
        results = locator.batch_lookup(ips)
        analysis = analyze_ip_distribution(results)
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("IP Geographic Analysis\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Total IPs: {analysis['total_ips']}\n\n")
            f.write("Country Distribution:\n")
            for country, count in analysis['countries'].items():
                f.write(f"  {country}: {count}\n")
                
        print(f"\nAnalysis complete. Results saved to: {args.output}")
        
    else:
        parser.error("Either --ip or --file must be specified")


if __name__ == "__main__":
    main()
