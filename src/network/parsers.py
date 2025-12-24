#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Evasion Detection - Traffic Parsers Module

This module provides parsers for extracting network traffic information
from various sources including PCAP files, traffic analysis results,
and MITM proxy captures.

Part of the Profit2Pitfall toolkit.

License: MIT
"""

import re
import struct
import logging
from typing import List, Optional
from pathlib import Path

from .core import (
    DetectionConfig,
    TrafficCapture,
    HTTPResponse,
    is_public_ip,
    logger
)

# Third-party imports for PCAP parsing
try:
    from scapy.all import rdpcap, TCP, UDP, Raw, DNS, DNSQR, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. PCAP parsing will be disabled.")


# ============================================================================
# TLS/SSL Parsing Functions
# ============================================================================

def parse_tls_sni(payload: bytes) -> Optional[str]:
    """
    Parse TLS Client Hello to extract SNI (Server Name Indication).
    
    This function parses the raw TCP payload of a TLS Client Hello
    message to extract the server name the client is connecting to.
    
    Args:
        payload: Raw TCP payload bytes
        
    Returns:
        Server name if found, None otherwise
    
    Note:
        SNI extraction is essential for analyzing HTTPS traffic
        without decryption, as it reveals the target domain.
    """
    try:
        if len(payload) < 5:
            return None
        
        # TLS Record Header
        content_type = payload[0]
        if content_type != 22:  # Handshake
            return None
        
        record_length = struct.unpack('!H', payload[3:5])[0]
        if len(payload) < 5 + record_length:
            return None
        
        # Handshake header
        handshake_type = payload[5]
        if handshake_type != 1:  # ClientHello
            return None
        
        pos = 9  # Start of ClientHello body
        
        # Skip version (2) + random (32)
        pos += 34
        
        # Skip session ID
        if pos >= len(payload):
            return None
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        
        # Skip cipher suites
        if pos + 2 > len(payload):
            return None
        cipher_suites_len = struct.unpack('!H', payload[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len
        
        # Skip compression methods
        if pos >= len(payload):
            return None
        compression_len = payload[pos]
        pos += 1 + compression_len
        
        # Extensions length
        if pos + 2 > len(payload):
            return None
        extensions_len = struct.unpack('!H', payload[pos:pos + 2])[0]
        pos += 2
        end_extensions = pos + extensions_len
        
        # Parse extensions
        while pos + 4 <= end_extensions:
            ext_type = struct.unpack('!H', payload[pos:pos + 2])[0]
            ext_length = struct.unpack('!H', payload[pos + 2:pos + 4])[0]
            pos += 4
            
            if ext_type == 0:  # SNI extension
                if pos + 2 > end_extensions:
                    return None
                    
                sni_list_len = struct.unpack('!H', payload[pos:pos + 2])[0]
                pos += 2
                list_end = pos + sni_list_len
                
                while pos + 3 <= list_end:
                    name_type = payload[pos]
                    name_len = struct.unpack('!H', payload[pos + 1:pos + 3])[0]
                    pos += 3
                    
                    if pos + name_len > list_end:
                        return None
                    
                    if name_type == 0:  # host_name
                        return payload[pos:pos + name_len].decode('utf-8', errors='ignore')
                    pos += name_len
                return None
            else:
                pos += ext_length
        
        return None
    except Exception:
        return None


# ============================================================================
# PCAP Parsing Functions
# ============================================================================

def parse_pcap_file(pcap_path: str, config: DetectionConfig = None) -> TrafficCapture:
    """
    Parse a PCAP file and extract network information.
    
    This function processes a PCAP file to extract DNS queries,
    TLS SNI values, HTTP requests, and public IP addresses.
    
    Args:
        pcap_path: Path to PCAP file
        config: Detection configuration (optional)
        
    Returns:
        TrafficCapture object with extracted data
        
    Raises:
        RuntimeError: If Scapy is not available
        
    Example:
        >>> capture = parse_pcap_file("traffic.pcap")
        >>> print(capture.domains)
        {'example.com', 'api.example.com'}
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is required for PCAP parsing. Install with: pip install scapy")
    
    config = config or DetectionConfig()
    app_id = Path(pcap_path).stem
    capture = TrafficCapture(app_id=app_id, capture_time="")
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        logger.error(f"Failed to read PCAP file {pcap_path}: {e}")
        return capture
    
    for pkt in packets:
        # Extract TLS SNI
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_payload = bytes(pkt[Raw].load)
            sni = parse_tls_sni(raw_payload)
            if sni:
                capture.tls_sni.add(sni)
                capture.domains.add(sni)
        
        # Extract DNS queries
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors='ignore')
            qname = qname.rstrip('.')
            if qname:
                capture.dns_queries.add(qname)
                capture.domains.add(qname)
        
        # Extract HTTP requests
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                if any(payload.startswith(m) for m in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE']):
                    lines = payload.splitlines()
                    if lines:
                        parts = lines[0].split()
                        if len(parts) >= 2:
                            method, path = parts[0], parts[1]
                            host = None
                            for line in lines[1:]:
                                if line.lower().startswith('host:'):
                                    host = line.split(':', 1)[1].strip()
                                    break
                            if host:
                                capture.http_requests.append({
                                    'method': method,
                                    'path': path,
                                    'host': host,
                                    'url': f"http://{host}{path}"
                                })
                                capture.domains.add(host)
            except Exception:
                pass
        
        # Extract public IPs
        if pkt.haslayer(IP):
            for ip_str in (pkt[IP].src, pkt[IP].dst):
                if is_public_ip(ip_str):
                    capture.public_ips.add(ip_str)
    
    # Filter out whitelisted domains
    capture.domains = {d for d in capture.domains 
                       if not any(w in d.lower() for w in config.domain_whitelist)}
    
    return capture


# ============================================================================
# Traffic Result File Parser
# ============================================================================

def parse_traffic_result_file(file_path: str, config: DetectionConfig = None) -> TrafficCapture:
    """
    Parse a traffic analysis result file (txt format from pcap_parse.py output).
    
    This function parses the structured text output from traffic analysis
    tools to extract domain and IP information.
    
    Args:
        file_path: Path to traffic result file
        config: Detection configuration (optional)
        
    Returns:
        TrafficCapture object with extracted data
        
    Example:
        >>> capture = parse_traffic_result_file("app_traffic.txt")
        >>> print(len(capture.domains))
        15
    """
    config = config or DetectionConfig()
    app_id = Path(file_path).stem
    capture = TrafficCapture(app_id=app_id, capture_time="")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Failed to read file {file_path}: {e}")
        return capture
    
    # Extract domains from "All Host Network Information" section
    pattern = r"======== All Host Network Information \(Union\) ========\s*([\s\S]*?)(?=\n=|$)"
    match = re.search(pattern, content)
    
    if match:
        lines = match.group(1).strip().splitlines()
        for line in lines:
            line = line.strip()
            if line and line.lower() != 'none':
                # Filter out whitelisted domains
                if not any(w in line.lower() for w in config.domain_whitelist):
                    capture.domains.add(line)
    
    # Extract TLS SNI
    sni_pattern = r"======== TLS SNI Names ========\s*([\s\S]*?)(?=\n=|$)"
    sni_match = re.search(sni_pattern, content)
    if sni_match:
        lines = sni_match.group(1).strip().splitlines()
        for line in lines:
            line = line.strip()
            if line and line.lower() != 'none':
                capture.tls_sni.add(line)
    
    # Extract DNS queries
    dns_pattern = r"======== DNS Query Names ========\s*([\s\S]*?)(?=\n=|$)"
    dns_match = re.search(dns_pattern, content)
    if dns_match:
        lines = dns_match.group(1).strip().splitlines()
        for line in lines:
            line = line.strip()
            if line and line.lower() != 'none':
                capture.dns_queries.add(line)
    
    # Extract public IPs
    ip_pattern = r"======== Public IP Addresses ========\s*([\s\S]*?)(?=\n=|$)"
    ip_match = re.search(ip_pattern, content)
    if ip_match:
        lines = ip_match.group(1).strip().splitlines()
        for line in lines:
            line = line.strip()
            if line and line.lower() != 'none':
                capture.public_ips.add(line)
    
    return capture


# ============================================================================
# MITM Proxy Response Parser
# ============================================================================

class MitmResponseParser:
    """
    Parser for MITM proxy captured traffic files.
    
    This class parses output from MITM proxy tools (like mitmproxy)
    to extract HTTP request/response pairs for analysis.
    
    Attributes:
        config: Detection configuration
        
    Example:
        >>> parser = MitmResponseParser()
        >>> responses = parser.parse_mitm_file("mitm_output.txt")
        >>> for resp in responses:
        ...     print(f"{resp.url}: {resp.status_code}")
    """
    
    def __init__(self, config: DetectionConfig = None):
        """
        Initialize the MITM response parser.
        
        Args:
            config: Detection configuration (optional)
        """
        self.config = config or DetectionConfig()
    
    def parse_mitm_file(self, file_path: str) -> List[HTTPResponse]:
        """
        Parse MITM proxy output file.
        
        Args:
            file_path: Path to MITM output file
            
        Returns:
            List of HTTPResponse objects
        """
        responses = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Failed to read MITM file {file_path}: {e}")
            return responses
        
        # Parse REQUEST and RESPONSE blocks
        pattern = r"=== (REQUEST|RESPONSE) ===\s*([\s\S]*?)(?==== REQUEST ===|=== RESPONSE ===|$)"
        blocks = re.findall(pattern, content)
        
        current_request = None
        cloud_requests_without_response = []
        
        for block_type, block_content in blocks:
            if block_type == 'REQUEST':
                # Extract URL from request
                url_match = re.search(r"URL:\s*(.+)", block_content)
                if url_match:
                    url = url_match.group(1).strip()
                    # Parse host and path from URL
                    host_match = re.match(r'https?://([^/:]+)(.*)', url)
                    if host_match:
                        current_request = {
                            'url': url,
                            'host': host_match.group(1),
                            'path': host_match.group(2) or '/'
                        }
                        
                        # Track cloud requests for later
                        if self._is_cloud_request(current_request['host']):
                            cloud_requests_without_response.append(current_request)
                        
            elif block_type == 'RESPONSE' and current_request:
                # Extract status code
                status_match = re.search(r"Status.*?:\s*(\d+)", block_content)
                status_code = int(status_match.group(1)) if status_match else 200
                
                # Extract body
                body_match = re.search(r"Body:\s*([\s\S]*?)(?:=+\n|$)", block_content)
                body = body_match.group(1).strip() if body_match else ""
                
                responses.append(HTTPResponse(
                    url=current_request['url'],
                    host=current_request['host'],
                    path=current_request['path'],
                    status_code=status_code,
                    body=body
                ))
                
                # Remove from pending list if it was a cloud request
                cloud_requests_without_response = [
                    r for r in cloud_requests_without_response 
                    if r['url'] != current_request['url']
                ]
                current_request = None
        
        # Add cloud requests without responses (failed/timeout requests)
        # These are also suspicious - attempted config loading that failed
        for req in cloud_requests_without_response:
            responses.append(HTTPResponse(
                url=req['url'],
                host=req['host'],
                path=req['path'],
                status_code=0,  # No response received
                body=""
            ))
        
        return responses
    
    def _is_cloud_request(self, host: str) -> bool:
        """Check if a host is a cloud provider."""
        host_lower = host.lower()
        return any(pattern in host_lower for pattern in self.config.cloud_provider_patterns)
