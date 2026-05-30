#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebView URL Analyzer Module

Extracts and analyzes WebView-related URLs from decompiled APK source code.
Part of the Profit2Pitfall toolkit.
"""

import os
import re
import json
import argparse
import logging
from urllib.parse import urlparse
from typing import Dict, List, Set, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


CLOUD_PROVIDERS = {
    "Alibaba Cloud": {
        "domains": ["aliyun.com", "alicdn.com", "alipay.com", "taobao.com", "tmall.com"]
    },
    "Tencent Cloud": {
        "domains": ["tencent.com", "qq.com", "qcloud.com", "myqcloud.com", "gtimg.com"]
    },
    "Huawei Cloud": {
        "domains": ["huaweicloud.com", "hwclouds.com", "hicloud.com"]
    },
    "Baidu Cloud": {
        "domains": ["baidu.com", "bcebos.com", "bdstatic.com"]
    },
    "AWS": {
        "domains": ["amazonaws.com", "aws.com", "cloudfront.net"]
    },
    "Google Cloud": {
        "domains": ["googleapis.com", "google.com", "gstatic.com"]
    }
}


class WebViewAnalyzer:
    """Analyzer for WebView URLs in decompiled APK code."""
    
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.url_results: Set[str] = set()
        self.provider_results: Dict[str, Any] = {}

    def extract_webview_urls(self) -> List[str]:
        """Extract WebView-related URLs from project."""
        logger.info("Extracting WebView-related URLs...")

        webview_patterns = [
            r'loadUrl\("([^"]+)"\)',
            r'loadDataWithBaseURL\("([^"]+)"',
            r'loadData\("([^"]+)"'
        ]

        for root, _, files in os.walk(self.project_path):
            for file in files:
                if file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            for pattern in webview_patterns:
                                matches = re.findall(pattern, content)
                                self.url_results.update(matches)
                    except Exception as e:
                        logger.debug(f"Error reading file: {file_path}: {e}")

        return list(self.url_results)

    def analyze_url_providers(self) -> Dict[str, Any]:
        """Analyze URL service providers."""
        logger.info("Analyzing URL service providers...")

        if not self.url_results:
            self.extract_webview_urls()

        providers = {}

        for url in self.url_results:
            try:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                
                if not domain:
                    continue

                provider_info = {
                    "URL": url,
                    "domain": domain,
                    "provider": "Unknown"
                }

                for provider, info in CLOUD_PROVIDERS.items():
                    for pattern in info["domains"]:
                        if pattern in domain:
                            provider_info["provider"] = provider
                            break

                providers[url] = provider_info

            except Exception as e:
                logger.debug(f"Error analyzing URL {url}: {e}")

        self.provider_results = providers
        return providers

    def generate_report(self) -> Dict[str, Any]:
        """Generate analysis report."""
        return {
            "webview_urls": list(self.url_results),
            "url_providers": self.provider_results or self.analyze_url_providers()
        }

    def export_to_json(self, output_path: str) -> str:
        """Export report to JSON file."""
        report = self.generate_report()
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        logger.info(f"Report saved to: {output_path}")
        return output_path


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Analyze WebView URLs in decompiled APK')
    parser.add_argument('--project-path', '-p', required=True, help='Decompiled project path')
    parser.add_argument('--output', '-o', default='webview_analysis.json', help='Output file path')
    args = parser.parse_args()

    if not os.path.exists(args.project_path):
        logger.error(f"Path not found: {args.project_path}")
        return

    analyzer = WebViewAnalyzer(args.project_path)
    analyzer.extract_webview_urls()
    analyzer.analyze_url_providers()
    analyzer.export_to_json(args.output)

    print(f"\nAnalysis complete: {len(analyzer.url_results)} URLs found")


if __name__ == "__main__":
    main()
