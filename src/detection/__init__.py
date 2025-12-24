#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detection Module

Static and dynamic analysis tools for Android APK detection:
- Network evasion techniques (domain rotation, cloud loading)
- Certificate analysis
- Permission analysis
- Code similarity analysis
- Third-party library detection
"""

from .certificate_analyzer import analyze_certificates, extract_cert_info
from .permission_analyzer import analyze_permissions, load_dangerous_permissions
from .analysis_similarity import analyze_similarity, APKAnalyzer
from .searchurl import find_urls_in_project, find_urls_from_pcap_result
from .extractwebview import WebViewAnalyzer
from .compareapk import ApkVariantAnalyzer
from .libdetector import find_lib_files
from .analysis_lib import analyze_lib_files

__all__ = [
    'analyze_certificates',
    'extract_cert_info',
    'analyze_permissions',
    'load_dangerous_permissions',
    'analyze_similarity',
    'APKAnalyzer',
    'find_urls_in_project',
    'find_urls_from_pcap_result',
    'WebViewAnalyzer',
    'ApkVariantAnalyzer',
    'find_lib_files',
    'analyze_lib_files',
]
