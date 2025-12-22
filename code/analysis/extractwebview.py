#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import dns.resolver
import ipaddress
from urllib.parse import urlparse


class WebViewAnalyzer:
    def __init__(self, project_path):
        self.project_path = project_path
        self.url_results = set()
        self.service_provider_results = {}

        # 云服务提供商的IP段和域名信息
        self.cloud_providers = {
            "阿里云": {
                "domains": ["aliyun.com", "alicdn.com", "alipay.com", "taobao.com", "tmall.com", "alibaba"],
                "ip_ranges": ["47.92.0.0/14", "47.96.0.0/14", "47.100.0.0/14", "39.96.0.0/14", "42.120.0.0/16"]
            },
            "腾讯云": {
                "domains": ["tencent.com", "qq.com", "qcloud.com", "myqcloud.com", "gtimg.com", "weixin"],
                "ip_ranges": ["119.28.0.0/15", "182.254.0.0/16", "101.32.0.0/14", "101.226.0.0/15"]
            },
            "华为云": {
                "domains": ["huaweicloud.com", "hwclouds.com", "hicloud.com", "huawei"],
                "ip_ranges": ["114.116.0.0/16", "121.36.0.0/15", "122.112.128.0/17", "49.4.0.0/16"]
            },
            "百度云": {
                "domains": ["baidu.com", "bcebos.com", "bdstatic.com", "baiduyun"],
                "ip_ranges": ["180.76.0.0/16", "111.230.0.0/16", "111.235.0.0/16", "110.242.0.0/16"]
            },
            "AWS": {
                "domains": ["amazonaws.com", "aws.com", "amazon.com", "cloudfront.net"],
                "ip_ranges": ["52.0.0.0/8", "54.0.0.0/8", "13.32.0.0/12", "18.32.0.0/12"]
            },
            "Microsoft Azure": {
                "domains": ["azure.com", "microsoft.com", "windowsazure.com", "msecnd.net"],
                "ip_ranges": ["13.64.0.0/12", "52.224.0.0/14", "65.52.0.0/14", "104.208.0.0/14"]
            },
            "Google Cloud": {
                "domains": ["googleapis.com", "google.com", "gstatic.com", "googleusercontent.com"],
                "ip_ranges": ["34.64.0.0/11", "35.184.0.0/13", "104.154.0.0/15", "108.59.80.0/20"]
            }
        }

    def extract_webview_urls(self):
        """递归遍历项目目录，提取与WebView相关的URL"""
        print("[*] 提取WebView相关的URL...")

        webview_patterns = [
            r'loadUrl\("([^"]+)"\)',  # 匹配 loadUrl("http://example.com")
            r'loadDataWithBaseURL\("([^"]+)"',  # 匹配 loadDataWithBaseURL("http://example.com")
        ]

        # 递归遍历项目目录
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
                        print(f"[!] 读取文件时出错: {file_path}, 错误: {str(e)}")

        return list(self.url_results)

    def analyze_url_providers(self):
        """分析URL所属的服务提供商"""
        print("[*] 分析URL服务提供商...")

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
                    "域名": domain,
                    "IP": None,
                    "服务提供商": "未知"
                }

                # 使用DNS解析获取IP
                try:
                    answers = dns.resolver.resolve(domain, 'A')
                    ips = [answer.address for answer in answers]
                    provider_info["IP"] = ips[0] if ips else None
                except Exception:
                    pass

                # 尝试确定云服务提供商
                provider_identified = False

                # 根据域名确定提供商
                for provider, info in self.cloud_providers.items():
                    for pattern in info["domains"]:
                        if pattern in domain:
                            provider_info["服务提供商"] = provider
                            provider_identified = True
                            break
                    if provider_identified:
                        break

                # 如果有IP但未确定提供商，尝试根据IP段确定
                if provider_info["IP"] and not provider_identified:
                    ip_obj = ipaddress.ip_address(provider_info["IP"])
                    for provider, info in self.cloud_providers.items():
                        for ip_range in info["ip_ranges"]:
                            if ip_obj in ipaddress.ip_network(ip_range):
                                provider_info["服务提供商"] = provider
                                provider_identified = True
                                break
                        if provider_identified:
                            break

                providers[url] = provider_info

            except Exception as e:
                print(f"[!] 分析URL时出错 {url}: {str(e)}")

        self.service_provider_results = providers
        return providers

    def generate_report(self):
        """生成分析报告"""
        print("[*] 生成分析报告...")

        report = {
            "WebView相关URL": list(self.url_results),
            "URL服务提供商": self.service_provider_results if self.service_provider_results else self.analyze_url_providers()
        }

        return report

    def export_to_json(self, output_path="webview_analysis.json"):
        """将报告导出为JSON文件"""
        report = self.generate_report()

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=4)

        print(f"[*] 报告已保存至: {output_path}")
        return output_path


def main():

    project_path = "/Users/gyc/Desktop/all/com.example.app"

    if not os.path.exists(project_path):
        print(f"[!] 路径不存在: {project_path}")
        return

    analyzer = WebViewAnalyzer(project_path)
    analyzer.extract_webview_urls()
    analyzer.analyze_url_providers()

    # 导出报告
    analyzer.export_to_json()


if __name__ == "__main__":
    main()