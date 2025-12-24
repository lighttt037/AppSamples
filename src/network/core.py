#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Evasion Detection - Core Module

This module provides core data structures and configuration classes
for network evasion detection in task-oriented scam applications.

Part of the Profit2Pitfall toolkit.

License: MIT
"""

import re
import base64
import logging
import ipaddress
from typing import Set, List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict

# Third-party imports
try:
    import Levenshtein
    LEVENSHTEIN_AVAILABLE = True
except ImportError:
    LEVENSHTEIN_AVAILABLE = False
    logging.warning("python-Levenshtein not available. Using fallback implementation.")


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Configuration and Constants
# ============================================================================

@dataclass
class DetectionConfig:
    """
    Configuration for network evasion detection algorithms.
    
    This class encapsulates all configurable parameters used in the detection
    of network-level evasion techniques employed by task-oriented scam apps.
    
    Attributes:
        edit_distance_threshold: Threshold τ for edit distance in domain rotation detection
        domain_whitelist: Set of legitimate third-party domains to exclude
        cloud_provider_patterns: Patterns identifying cloud storage providers
        config_path_keywords: Keywords indicating config file paths
        config_body_keywords: Keywords indicating config content in response body
    """
    
    # Threshold for edit distance in domain rotation detection
    edit_distance_threshold: int = 6
    
    # Whitelist of legitimate third-party domains to exclude
    domain_whitelist: Set[str] = field(default_factory=lambda: {
        # Analytics & Advertising
        'google-analytics.com', 'googleadservices.com', 'doubleclick.net',
        'facebook.com', 'facebook.net', 'fbcdn.net',
        'umeng.com', 'umengcloud.com',
        'cnzz.com',
        
        # Cloud Services (legitimate CDN/Storage for content)
        'googleapis.com', 'gstatic.com',
        'cloudflare.com', 'akamai.net', 'fastly.net',
        
        # System/Device noise & Enterprise services
        'mumu.163.com', 'mumu',
        'netease.com', 'netease.im', 'netease',
        'android.bugly.qq.com', 'snowflake.qq.com',
        'feishu.cn', 'feishu.com', 'larkoffice.com',
        'sentry.io',
        'vscode-cdn.net', 'vscode-cdn', 'microsoft.com', 'microsoft',
        'apple.com', 'icloud.com',
        '127.0.0.1',
        '.ms',
        
        # API testing/mock platforms
        'apifoxmock.com', 'apifox.cn', 'postman-echo.com',
    })
    
    # Legitimate service domains (content providers, not config sources)
    legitimate_content_domains: Set[str] = field(default_factory=lambda: {
        # Major content providers
        'qq.com', 'gtimg.com', 'qpic.cn',
        'baidu.com', 'bdimg.com', 'bdstatic.com',
        'taobao.com', 'tmall.com', 'alicdn.com',
        'sina.com', 'sinaimg.cn', 'weibo.com',
        'sohu.com', 'bilibili.com', 'iqiyi.com',
        'netease.com', 'netease.im', '163.com',
    })
    
    # Cloud provider patterns for detecting remote config loading
    cloud_provider_patterns: Set[str] = field(default_factory=lambda: {
        # Alibaba Cloud
        'aliyuncs.com', 'oss-cn-', 'oss-accelerate', 'oss-rg-', 'oss-ap-', 'aliyun.com',
        # Tencent Cloud  
        'myqcloud.com', 'cos.ap-', 'cos-ap-', 'tencent-cloud.com',
        # Huawei Cloud
        'myhuaweicloud.com', 'obs.cn-',
        # AWS
        's3.amazonaws.com', 'cloudfront.net', 'amazonaws.com',
        # Azure
        'blob.core.windows.net', 'azureedge.net',
        # Qiniu Cloud
        'clouddn.com', 'qiniucdn.com', 'qiniudn.com', 'qbox.me',
        # Code hosting platforms (HIGHLY SUSPICIOUS for config loading)
        'gitee.com',
        'github.io', 'githubusercontent.com',
        'coding.net', 'gitcode.net',
        # Google Cloud
        'storage.googleapis.com', 'googleusercontent.com',
        # Other CDNs
        'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
    })
    
    # Config-related path keywords
    config_path_keywords: Set[str] = field(default_factory=lambda: {
        'config', 'conf', 'cfg',
        'domain', 'server', 'host',
        'ip', 'addr', 'address',
        'api', 'endpoint', 'url',
        'setting', 'settings',
        'init', 'bootstrap',
        'dn.json', 'domain.json', 'server.json', 'url.json',
        'apppath', 'cdn', 'route', 'link',
        'Config',
    })
    
    # Keywords in response body that suggest config content
    config_body_keywords: Set[str] = field(default_factory=lambda: {
        'domain', 'url', 'link', 'server', 'host', 'address',
        'appPath', 'file_cdn_domain', 'downloadUrl',
        'httpdns', 'nos', 'lbs', 'weblink', 'routeType',
    })
    
    # Paths that indicate news/content (not config)
    content_path_patterns: Set[str] = field(default_factory=lambda: {
        '/news/', '/article/', '/view/', '/content/',
        '/thumb', '/img/', '/image/', '/pic/',
        'inews.', 'news_', 'article_', 'snpimg.',
        'big_img', 'small_img', 'thumb_img',
    })
    
    # Static resource extensions to exclude
    static_resource_extensions: Set[str] = field(default_factory=lambda: {
        '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg',
        '.mp3', '.mp4', '.wav', '.avi', '.mov', '.webm',
        '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    })


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class TrafficCapture:
    """
    Represents traffic capture data for an application.
    
    This class stores network traffic information extracted from PCAP files
    or traffic analysis results for a specific app.
    
    Attributes:
        app_id: Unique identifier for the application
        capture_time: Timestamp of traffic capture
        domains: Set of all domains observed in traffic
        http_requests: List of HTTP request details
        dns_queries: Set of DNS query names
        tls_sni: Set of TLS SNI values
        public_ips: Set of public IP addresses contacted
    """
    app_id: str
    capture_time: str
    domains: Set[str] = field(default_factory=set)
    http_requests: List[Dict[str, Any]] = field(default_factory=list)
    dns_queries: Set[str] = field(default_factory=set)
    tls_sni: Set[str] = field(default_factory=set)
    public_ips: Set[str] = field(default_factory=set)


@dataclass
class HTTPResponse:
    """
    Represents an HTTP response for analysis.
    
    This class encapsulates HTTP response data extracted from MITM
    proxy captures for cloud config detection.
    
    Attributes:
        url: Full request URL
        host: Host/domain of the request
        path: URL path component
        status_code: HTTP status code
        body: Response body content
        headers: Response headers
    """
    url: str
    host: str
    path: str
    status_code: int
    body: str
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass 
class DetectionResult:
    """
    Result of network evasion detection.
    
    This class represents the output of detection algorithms, containing
    information about whether evasion was detected and supporting evidence.
    
    Attributes:
        app_id: Unique identifier for the analyzed application
        technique: Name of the detection technique applied
        detected: Whether the evasion technique was detected
        evidence: Dictionary containing supporting evidence
        confidence: Confidence score (0.0 to 1.0)
    """
    app_id: str
    technique: str
    detected: bool
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


# ============================================================================
# Utility Functions
# ============================================================================

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate the Levenshtein (edit) distance between two strings.
    
    The edit distance is the minimum number of single-character edits
    (insertions, deletions, or substitutions) required to transform
    one string into the other.
    
    Args:
        s1: First string
        s2: Second string
        
    Returns:
        Edit distance between the two strings
    
    Example:
        >>> levenshtein_distance("abc", "abd")
        1
        >>> levenshtein_distance("abc", "xyz")
        3
    """
    if LEVENSHTEIN_AVAILABLE:
        return Levenshtein.distance(s1, s2)
    
    # Fallback implementation using dynamic programming
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def extract_tld(domain: str) -> str:
    """
    Extract the top-level domain from a domain name.
    
    Handles common multi-part TLDs like .co.uk, .com.cn, etc.
    
    Args:
        domain: Full domain name (e.g., 'sub.example.com')
        
    Returns:
        Top-level domain (e.g., 'example.com')
    
    Example:
        >>> extract_tld('api.example.com')
        'example.com'
        >>> extract_tld('www.example.co.uk')
        'example.co.uk'
    """
    parts = domain.lower().strip().split('.')
    if len(parts) >= 2:
        # Handle common multi-part TLDs
        multi_tlds = {'co.uk', 'com.cn', 'net.cn', 'org.cn', 'com.hk', 'co.jp'}
        if len(parts) >= 3:
            potential_tld = '.'.join(parts[-2:])
            if potential_tld in multi_tlds:
                return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return domain


def is_same_tld(domain1: str, domain2: str) -> bool:
    """
    Check if two domains share the same top-level domain.
    
    Args:
        domain1: First domain name
        domain2: Second domain name
        
    Returns:
        True if domains share the same TLD
    """
    return extract_tld(domain1) == extract_tld(domain2)


def is_base64_encoded(text: str) -> bool:
    """
    Check if text appears to be Base64 encoded.
    
    Args:
        text: Text to check
        
    Returns:
        True if text appears to be Base64 encoded
    """
    if not text or len(text) < 4:
        return False
    
    # Check for Base64 character set
    base64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
    
    # Remove whitespace
    clean_text = text.strip().replace('\n', '').replace('\r', '')
    
    if not base64_pattern.match(clean_text):
        return False
    
    # Try to decode
    try:
        decoded = base64.b64decode(clean_text, validate=True)
        # Check if decoded content is printable or valid UTF-8
        try:
            decoded.decode('utf-8')
            return True
        except:
            # Could be binary data, still valid Base64
            return len(decoded) > 0
    except:
        return False


def is_randomized_string(text: str, min_length: int = 8) -> bool:
    """
    Check if a string appears to be randomly generated.
    
    Analyzes character distribution and vowel/consonant ratios
    to determine if a string is algorithmically generated.
    
    Args:
        text: String to check
        min_length: Minimum length to consider
        
    Returns:
        True if string appears randomized
    """
    if len(text) < min_length:
        return False
    
    # Check consonant/vowel ratio
    vowels = set('aeiouAEIOU')
    consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
    
    vowel_count = sum(1 for c in text if c in vowels)
    consonant_count = sum(1 for c in text if c in consonants)
    
    if consonant_count == 0:
        return False
    
    ratio = vowel_count / consonant_count if consonant_count > 0 else 0
    
    # Natural language typically has ratio around 0.3-0.5
    if ratio < 0.1 or ratio > 0.8:
        return True
    
    # Check character frequency distribution
    char_freq = defaultdict(int)
    for c in text.lower():
        if c.isalpha():
            char_freq[c] += 1
    
    if len(char_freq) > 0:
        avg_freq = len(text) / len(char_freq)
        variance = sum((f - avg_freq) ** 2 for f in char_freq.values()) / len(char_freq)
        # Random strings tend to have more uniform distribution (lower variance)
        if variance < 2 and len(text) >= 12:
            return True
    
    return False


def extract_urls_from_text(text: str) -> Set[str]:
    """
    Extract URLs, IPs, and domains from text content.
    
    Args:
        text: Text content to parse
        
    Returns:
        Set of extracted network identifiers (URLs, IPs, domains)
    """
    results = set()
    
    # URL pattern
    url_pattern = r'https?://[^\s<>"\']+|ftp://[^\s<>"\']+|wss?://[^\s<>"\']+'
    results.update(re.findall(url_pattern, text, re.IGNORECASE))
    
    # IP address pattern (IPv4)
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    results.update(re.findall(ip_pattern, text))
    
    # Domain pattern
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    results.update(re.findall(domain_pattern, text))
    
    return results


def is_static_resource(url: str, config: DetectionConfig) -> bool:
    """
    Check if URL points to a static resource.
    
    Args:
        url: URL to check
        config: Detection configuration
        
    Returns:
        True if URL points to a static resource (image, CSS, JS, etc.)
    """
    url_lower = url.lower()
    return any(url_lower.endswith(ext) for ext in config.static_resource_extensions)


def is_public_ip(ip_str: str) -> bool:
    """
    Check if an IP address is public (not private/loopback/reserved).
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if IP is a public address
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved)
    except ValueError:
        return False
