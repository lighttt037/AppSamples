#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Evasion Detection - Detection Algorithms Module

This module implements the core detection algorithms for network-level
evasion techniques used by task-oriented scam applications:

1. Time-Based Domain Rotation Detection
2. Remote Cloud Server Loading Detection

Part of the Profit2Pitfall toolkit.

License: MIT
"""

import os
import re
import json
import base64
import math
import logging
from typing import List, Dict, Any
from collections import Counter
from pathlib import Path

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
    logger
)
from .parsers import parse_traffic_result_file, MitmResponseParser


# ============================================================================
# Time-Based Domain Rotation Detection
# ============================================================================

class DomainRotationDetector:
    """
    Detector for time-based domain rotation technique.
    
    This detector identifies apps that generate algorithmically rotating 
    domain names based on time. It compares network traffic captures taken 
    24 hours apart to identify domains that change while maintaining similar structure.
    
    Algorithm Overview:
        1. Extract domains from traffic at time t and t+24h
        2. Compute set differences (domains unique to each time point)
        3. Check pairs for rotation patterns:
           - Same TLD
           - Same string length  
           - Edit distance >= threshold τ
    
    Attributes:
        config: Detection configuration parameters
        
    Example:
        >>> detector = DomainRotationDetector()
        >>> result = detector.detect_from_files("day1.txt", "day2.txt")
        >>> if result.detected:
        ...     print(f"Found {len(result.evidence['rotating_pairs'])} rotating pairs")
    """
    
    def __init__(self, config: DetectionConfig = None):
        """
        Initialize detector.
        
        Args:
            config: Detection configuration (optional)
        """
        self.config = config or DetectionConfig()
    
    def detect(self, 
               traffic_t1: TrafficCapture, 
               traffic_t2: TrafficCapture) -> DetectionResult:
        """
        Detect time-based domain rotation by comparing traffic captures
        taken 24 hours apart.
        
        Args:
            traffic_t1: Traffic capture at time t
            traffic_t2: Traffic capture at time t+24h
            
        Returns:
            DetectionResult with rotation evidence
        """
        app_id = traffic_t1.app_id
        
        # Get domains from both captures, excluding whitelist
        D1 = traffic_t1.domains - self.config.domain_whitelist
        D2 = traffic_t2.domains - self.config.domain_whitelist
        
        # Compute set differences
        delta_1 = D1 - D2  # Domains only in first capture
        delta_2 = D2 - D1  # Domains only in second capture
        
        rotating_pairs = []
        
        # Check all pairs for rotation patterns
        for d1 in delta_1:
            for d2 in delta_2:
                if self._is_rotating_pair(d1, d2):
                    rotating_pairs.append({
                        'domain_t1': d1,
                        'domain_t2': d2,
                        'tld': extract_tld(d1),
                        'edit_distance': levenshtein_distance(d1, d2)
                    })
        
        detected = len(rotating_pairs) > 0
        confidence = min(1.0, len(rotating_pairs) * 0.3) if detected else 0.0
        
        return DetectionResult(
            app_id=app_id,
            technique='time_based_domain_rotation',
            detected=detected,
            evidence={
                'rotating_pairs': rotating_pairs,
                'domains_t1': list(D1),
                'domains_t2': list(D2),
                'delta_1': list(delta_1),
                'delta_2': list(delta_2)
            },
            confidence=confidence
        )
    
    def _is_rotating_pair(self, d1: str, d2: str) -> bool:
        """
        Check if two domains form a rotating pair.
        
        Criteria:
        1. Same TLD (top-level domain)
        2. Same string length
        3. Edit distance >= threshold (τ = 6)
        
        Args:
            d1: First domain
            d2: Second domain
            
        Returns:
            True if domains appear to be algorithmically rotated
        """
        # Check same TLD
        if not is_same_tld(d1, d2):
            return False
        
        # Check same length
        if len(d1) != len(d2):
            return False
        
        # Check edit distance >= threshold
        edit_dist = levenshtein_distance(d1, d2)
        if edit_dist < self.config.edit_distance_threshold:
            return False
        
        return True
    
    def detect_from_files(self, 
                          file_t1: str, 
                          file_t2: str) -> DetectionResult:
        """
        Detect domain rotation from traffic result files.
        
        Args:
            file_t1: Path to traffic result file at time t
            file_t2: Path to traffic result file at time t+24h
            
        Returns:
            DetectionResult
        """
        traffic_t1 = parse_traffic_result_file(file_t1, self.config)
        traffic_t2 = parse_traffic_result_file(file_t2, self.config)
        
        return self.detect(traffic_t1, traffic_t2)


# ============================================================================
# Remote Cloud Server Loading Detection
# ============================================================================

class CloudConfigDetector:
    """
    Detector for remote cloud server loading technique.
    
    This detector identifies apps that retrieve server addresses from 
    cloud storage services. It analyzes HTTP responses from cloud 
    providers to detect config loading.
    
    Detection Criteria:
        (a) Content-based: Response contains external IPs/URLs
        (b) Encoding-based: Base64 or obfuscated content
        (c) Failure-based: Error responses indicating config retrieval
    
    Attributes:
        config: Detection configuration parameters
        
    Example:
        >>> detector = CloudConfigDetector()
        >>> parser = MitmResponseParser()
        >>> responses = parser.parse_mitm_file("mitm.txt")
        >>> result = detector.detect(responses)
    """
    
    def __init__(self, config: DetectionConfig = None):
        """
        Initialize detector.
        
        Args:
            config: Detection configuration (optional)
        """
        self.config = config or DetectionConfig()
    
    def detect(self, responses: List[HTTPResponse]) -> DetectionResult:
        """
        Detect remote cloud server loading from HTTP responses.
        
        Args:
            responses: List of HTTP responses from decrypted traffic
            
        Returns:
            DetectionResult with cloud loading evidence
        """
        suspicious_responses = []
        
        for response in responses:
            # Skip if host is in whitelist
            host_lower = response.host.lower()
            if any(pattern in host_lower for pattern in self.config.domain_whitelist):
                continue
            
            # Skip legitimate content
            if self._is_legitimate_content(response):
                continue
            
            # Check if request is to cloud provider, suspicious source, or direct IP
            is_cloud = self._is_cloud_provider(response.host)
            is_ip_host = self._is_ip_address(response.host)
            
            # Check path/body for config signals
            is_config_file = self._is_config_file_request(response.path)
            is_config_body = self._has_config_body(response.body)
            is_suspicious_path = self._is_suspicious_path(response.path)
            has_oss_headers = self._has_oss_headers(response)
            
            # Skip if not cloud/IP and doesn't have strong config signals
            if not (is_cloud or is_ip_host or (is_config_file and is_config_body)):
                continue
            
            # Parse response body for external URLs
            extracted_urls = extract_urls_from_text(response.body)
            external_urls = {
                u for u in extracted_urls 
                if not self._is_same_host(u, response.host) 
                and not is_static_resource(u, self.config)
            }
            
            # Detection criteria
            is_external = len(external_urls) > 0
            is_obfuscated = self._is_obfuscated_content(response.body)
            is_anomalous = self._is_anomalous_response(response)
            is_short_response = len(response.body.strip()) < 500 if response.body else False
            
            # Enhanced detection logic
            if (is_config_file or is_config_body or 
                (is_suspicious_path and (is_external or is_obfuscated or is_anomalous)) or 
                (is_ip_host and (is_config_file or is_suspicious_path)) or
                (is_config_file and is_config_body) or
                (has_oss_headers and is_config_file and is_short_response)):
                suspicious_responses.append({
                    'url': response.url,
                    'host': response.host,
                    'path': response.path,
                    'status_code': response.status_code,
                    'external_urls': list(external_urls),
                    'is_external': is_external,
                    'is_obfuscated': is_obfuscated,
                    'is_anomalous': is_anomalous,
                    'is_suspicious_path': is_suspicious_path,
                    'is_config_file': is_config_file,
                    'is_config_body': is_config_body,
                    'is_ip_host': is_ip_host,
                    'has_oss_headers': has_oss_headers,
                    'is_short_response': is_short_response
                })
        
        detected = len(suspicious_responses) > 0
        confidence = min(1.0, len(suspicious_responses) * 0.25) if detected else 0.0
        
        return DetectionResult(
            app_id="",  # Set by caller
            technique='remote_cloud_server_loading',
            detected=detected,
            evidence={
                'suspicious_responses': suspicious_responses,
                'total_cloud_requests': sum(1 for r in responses if self._is_cloud_provider(r.host))
            },
            confidence=confidence
        )
    
    def _is_cloud_provider(self, host: str) -> bool:
        """Check if host belongs to a cloud provider."""
        host_lower = host.lower()
        return any(pattern in host_lower for pattern in self.config.cloud_provider_patterns)
    
    def _is_same_host(self, url: str, host: str) -> bool:
        """Check if URL points to the same host."""
        try:
            match = re.match(r'https?://([^/:]+)', url)
            if match:
                url_host = match.group(1).lower()
                return url_host == host.lower()
        except:
            pass
        return False
    
    def _is_ip_address(self, host: str) -> bool:
        """Check if host is an IP address (IPv4)."""
        parts = host.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
        return False
    
    def _is_obfuscated_content(self, body: str) -> bool:
        """Check if response body is obfuscated."""
        if not body or len(body.strip()) == 0:
            return False
        
        body_stripped = body.strip()
        
        # Check for Base64 encoding
        if is_base64_encoded(body_stripped):
            return True
        
        # Check for randomized content
        if is_randomized_string(body_stripped):
            return True
        
        # Check if content is mostly non-printable
        printable_ratio = sum(1 for c in body_stripped if c.isprintable()) / len(body_stripped)
        if printable_ratio < 0.5:
            return True
        
        return False
    
    def _is_anomalous_response(self, response: HTTPResponse) -> bool:
        """Check if response is anomalous (failed or empty)."""
        if response.status_code >= 400:
            return True
        if not response.body or len(response.body.strip()) == 0:
            return True
        return False
    
    def _is_suspicious_path(self, path: str) -> bool:
        """Check if URL path contains config-related keywords."""
        path_lower = path.lower()
        path_without_query = path_lower.split('?')[0]
        
        # Exclude static resources first
        for ext in self.config.static_resource_extensions:
            if path_without_query.endswith(ext):
                return False
        
        # Check for config-related keywords
        for keyword in self.config.config_path_keywords:
            if keyword in path_lower:
                return True
        
        # Check for common config file extensions
        config_extensions = ['.txt', '.json', '.xml', '.conf', '.cfg', '.ini', '.dat']
        if any(path_without_query.endswith(ext) for ext in config_extensions):
            return True
        
        # Check if filename appears randomized (MD5/SHA hash-like)
        filename = path.split('/')[-1].split('?')[0]
        if filename:
            name_part = filename.rsplit('.', 1)[0] if '.' in filename else filename
            # Check for hex strings
            if len(name_part) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in name_part):
                return True
            if len(name_part) >= 10 and is_randomized_string(name_part, min_length=10):
                return True
        
        return False
    
    def _is_config_file_request(self, path: str) -> bool:
        """Check if the path explicitly looks like a config file request."""
        path_lower = path.lower()
        path_without_query = path_lower.split('?')[0]
        
        # Exclude static resources
        for ext in self.config.static_resource_extensions:
            if path_without_query.endswith(ext):
                return False
        
        # Config file extensions
        config_extensions = ['.txt', '.json', '.xml', '.html', '.conf', '.cfg', '.ini', '.dat', '.yaml', '.yml']
        
        for ext in config_extensions:
            if path_without_query.endswith(ext):
                exclude_patterns = ['readme', 'license', 'changelog', 'version', 'manifest']
                filename_lower = path_without_query.split('/')[-1].lower()
                
                if any(pattern in filename_lower for pattern in exclude_patterns):
                    return False
                return True
        
        # Check for suspicious path keywords
        suspicious_keywords = [
            'config', 'domain', 'server', 'api', 'endpoint', 
            'url', 'host', 'address', 'link', 'path',
            'domainname', 'servername', 'apiurl', 'configurl'
        ]
        if any(keyword in path_lower for keyword in suspicious_keywords):
            return True
        
        # Check if filename is a hash without extension
        filename = path.split('/')[-1].split('?')[0]
        if filename and '.' not in filename:
            if len(filename) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in filename):
                return True
        
        return False

    def _has_config_body(self, body: str) -> bool:
        """Check if response body contains config data."""
        if not body or len(body.strip()) < 10:
            return False
        
        body_stripped = body.strip()
        body_lower = body.lower()
        
        # Check for config error messages
        if any(err in body_lower for err in ['no such domain', 'domain not found', 'nosuchbucket', 'bucket does not exist']):
            return True
        
        # Check for config keywords
        keyword_count = sum(1 for keyword in self.config.config_body_keywords if keyword in body_lower)
        if keyword_count >= 2:
            return True
        
        # Check for multiple URLs
        url_count = len(re.findall(r'https?://[^\s\'"]+', body))
        if url_count >= 2:
            return True
        
        # Check for WebSocket URLs
        if 'wss://' in body_lower or 'ws://' in body_lower:
            return True
        
        # Check for IP:port format
        ip_port_count = len(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', body))
        if ip_port_count >= 1:
            return True
        
        # Check for short encoded responses
        if '\n' not in body_stripped and len(body_stripped) < 500:
            if len(body_stripped) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', body_stripped):
                try:
                    decoded = base64.b64decode(body_stripped).decode('utf-8', errors='ignore')
                    if any(pattern in decoded.lower() for pattern in ['http', 'url', '{', 'domain', 'server']):
                        return True
                except:
                    pass
            
            # Check entropy
            if len(body_stripped) > 30:
                entropy = self._calculate_entropy(body_stripped)
                if entropy > 4.5:
                    return True
        
        # Check for domain/link arrays in JSON
        if any(pattern in body_lower for pattern in ['"domain":', '"url":', '"link":', '"server":', '"host":', '"data":']):
            try:
                data = json.loads(body)
                
                if isinstance(data, list):
                    if len(data) > 0 and all(isinstance(item, str) for item in data):
                        if any('http' in item.lower() or '.' in item for item in data):
                            return True
                
                if isinstance(data, dict):
                    for key in ['list', 'data', 'domain', 'url', 'link', 'server', 'host', 'httpdns', 'nos']:
                        if key in data:
                            value = data[key]
                            if isinstance(value, list) and len(value) > 0:
                                if any(isinstance(item, str) and ('http' in item or '://' in item or ':' in item) for item in value):
                                    return True
                                if any(isinstance(item, dict) and ('url' in item or 'domain' in item) for item in value):
                                    return True
                    if any(key in data for key in ['appPath', 'file_cdn_domain', 'downloadUrl', 'routeType', 'ws_url', 'service_url']):
                        return True
            except:
                pass
        
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _has_oss_headers(self, response: HTTPResponse) -> bool:
        """Check if response has OSS/CDN related headers."""
        if not hasattr(response, 'headers') or not response.headers:
            return False
        
        headers_str = str(response.headers).lower()
        
        oss_indicators = [
            'x-oss-',     # Alibaba Cloud OSS
            'x-cos-',     # Tencent Cloud COS
            'x-amz-',     # AWS S3
            'x-qiniu-',   # Qiniu Cloud
            'x-upyun-',   # Upyun Cloud
        ]
        
        return any(indicator in headers_str for indicator in oss_indicators)
    
    def _is_legitimate_content(self, response: HTTPResponse) -> bool:
        """Check if this is legitimate content from known providers."""
        host_lower = response.host.lower()
        path_lower = response.path.lower()
        url_lower = response.url.lower()
        
        for domain in self.config.legitimate_content_domains:
            if domain in host_lower:
                for pattern in self.config.content_path_patterns:
                    if pattern in url_lower or pattern in path_lower:
                        return True
                path_without_query = path_lower.split('?')[0]
                for ext in self.config.static_resource_extensions:
                    if path_without_query.endswith(ext):
                        return True
        
        return False


# ============================================================================
# Batch Processing Functions
# ============================================================================

def detect_domain_rotation_batch(
    traffic_dir_t1: str,
    traffic_dir_t2: str,
    output_file: str = None,
    config: DetectionConfig = None
) -> List[DetectionResult]:
    """
    Detect domain rotation across all apps in traffic directories.
    
    Args:
        traffic_dir_t1: Directory with traffic results at time t
        traffic_dir_t2: Directory with traffic results at time t+24h
        output_file: Optional output file for results
        config: Detection configuration
        
    Returns:
        List of DetectionResults for apps with detected rotation
    """
    config = config or DetectionConfig()
    detector = DomainRotationDetector(config)
    results = []
    
    if not os.path.isdir(traffic_dir_t1) or not os.path.isdir(traffic_dir_t2):
        logger.error("Traffic directories not found")
        return results
    
    # Get all traffic files
    t1_files = {f for f in os.listdir(traffic_dir_t1) if f.endswith('.txt')}
    t2_files = {f for f in os.listdir(traffic_dir_t2) if f.endswith('.txt')}
    common_files = t1_files & t2_files
    
    logger.info(f"Processing {len(common_files)} apps for domain rotation detection")
    
    for filename in common_files:
        file_t1 = os.path.join(traffic_dir_t1, filename)
        file_t2 = os.path.join(traffic_dir_t2, filename)
        
        try:
            result = detector.detect_from_files(file_t1, file_t2)
            if result.detected:
                results.append(result)
                logger.info(f"Domain rotation detected in {filename}")
        except Exception as e:
            logger.error(f"Error processing {filename}: {e}")
    
    if output_file:
        save_results(results, output_file)
    
    if common_files:
        logger.info(f"Detected domain rotation in {len(results)}/{len(common_files)} apps "
                    f"({100*len(results)/len(common_files):.2f}%)")
    
    return results


def detect_cloud_loading_batch(
    mitm_dir: str,
    output_file: str = None,
    config: DetectionConfig = None
) -> List[DetectionResult]:
    """
    Detect cloud server loading across all apps in MITM directory.
    
    Args:
        mitm_dir: Directory with MITM proxy output files
        output_file: Optional output file for results
        config: Detection configuration
        
    Returns:
        List of DetectionResults for apps with detected cloud loading
    """
    config = config or DetectionConfig()
    detector = CloudConfigDetector(config)
    parser = MitmResponseParser(config)
    results = []
    
    if not os.path.isdir(mitm_dir):
        logger.error("MITM directory not found")
        return results
    
    mitm_files = [f for f in os.listdir(mitm_dir) if f.endswith('.txt')]
    
    logger.info(f"Processing {len(mitm_files)} apps for cloud loading detection")
    
    for filename in mitm_files:
        file_path = os.path.join(mitm_dir, filename)
        
        try:
            responses = parser.parse_mitm_file(file_path)
            result = detector.detect(responses)
            result.app_id = Path(filename).stem
            
            if result.detected:
                results.append(result)
                logger.info(f"Cloud loading detected in {filename}")
        except Exception as e:
            logger.error(f"Error processing {filename}: {e}")
    
    if output_file:
        save_results(results, output_file)
    
    if mitm_files:
        logger.info(f"Detected cloud loading in {len(results)}/{len(mitm_files)} apps "
                    f"({100*len(results)/len(mitm_files):.2f}%)")
    
    return results


def save_results(results: List[DetectionResult], output_file: str):
    """Save detection results to JSON file."""
    output_data = []
    for result in results:
        output_data.append({
            'app_id': result.app_id,
            'technique': result.technique,
            'detected': result.detected,
            'confidence': result.confidence,
            'evidence': result.evidence
        })
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Results saved to {output_file}")
