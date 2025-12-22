import os
import re
import xml.etree.ElementTree as ET
from collections import defaultdict


class WebViewDetector:
    def __init__(self, apk_folder_path):
        self.apk_folder = apk_folder_path
        self.webview_indicators = defaultdict(int)

    def analyze_manifest(self):
        """分析AndroidManifest.xml"""
        manifest_path = os.path.join(self.apk_folder, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # 检查网络权限
            for uses_permission in root.findall('.//uses-permission'):
                permission = uses_permission.get('{http://schemas.android.com/apk/res/android}name', '')
                if 'INTERNET' in permission:
                    self.webview_indicators['internet_permission'] += 1
                if 'ACCESS_NETWORK_STATE' in permission:
                    self.webview_indicators['network_state_permission'] += 1

            # 检查WebView相关的activity配置
            for activity in root.findall('.//activity'):
                activity_name = activity.get('{http://schemas.android.com/apk/res/android}name', '')
                if 'webview' in activity_name.lower():
                    self.webview_indicators['webview_activity'] += 1

        except ET.ParseError:
            pass

    def analyze_java_files(self):
        """分析Java源码文件"""
        java_files = []
        for root, dirs, files in os.walk(self.apk_folder):
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))

        webview_imports = 0
        webview_usage = 0
        javascript_enabled = 0
        url_loading = 0
        main_activity_webview = 0

        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # 检查WebView相关导入
                if re.search(r'import.*WebView', content):
                    webview_imports += 1

                # 检查WebView实例化和使用
                if re.search(r'new\s+WebView|WebView\s+\w+|findViewById.*WebView', content):
                    webview_usage += 1

                # 检查JavaScript启用
                if re.search(r'setJavaScriptEnabled\s*\(\s*true\s*\)', content):
                    javascript_enabled += 1

                # 检查URL加载模式
                if re.search(r'loadUrl\s*\(\s*["\']https?://', content):
                    url_loading += 1

                # 检查主Activity中的WebView使用
                if 'MainActivity' in java_file or 'Main' in java_file:
                    if re.search(r'WebView|loadUrl', content):
                        main_activity_webview += 1

            except Exception:
                continue

        self.webview_indicators['webview_imports'] = webview_imports
        self.webview_indicators['webview_usage'] = webview_usage
        self.webview_indicators['javascript_enabled'] = javascript_enabled
        self.webview_indicators['url_loading'] = url_loading
        self.webview_indicators['main_activity_webview'] = main_activity_webview

    def analyze_resources(self):
        """分析资源文件"""
        res_folder = os.path.join(self.apk_folder, "res")
        if not os.path.exists(res_folder):
            return

        layout_webviews = 0

        # 检查布局文件中的WebView
        layout_folders = [d for d in os.listdir(res_folder) if d.startswith('layout')]

        for layout_folder in layout_folders:
            layout_path = os.path.join(res_folder, layout_folder)
            if not os.path.isdir(layout_path):
                continue

            for layout_file in os.listdir(layout_path):
                if layout_file.endswith('.xml'):
                    try:
                        with open(os.path.join(layout_path, layout_file), 'r',
                                  encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if '<WebView' in content or 'android.webkit.WebView' in content:
                                layout_webviews += 1
                    except Exception:
                        continue

        self.webview_indicators['layout_webviews'] = layout_webviews

    def analyze_strings(self):
        """分析字符串资源"""
        strings_path = os.path.join(self.apk_folder, "res", "values", "strings.xml")
        if not os.path.exists(strings_path):
            return

        try:
            with open(strings_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # 检查URL相关字符串
            url_patterns = [
                r'https?://[^\s"<>]+',
                r'file:///android_asset/',
                r'javascript:',
            ]

            url_strings = 0
            for pattern in url_patterns:
                url_strings += len(re.findall(pattern, content))

            self.webview_indicators['url_strings'] = url_strings

        except Exception:
            pass

    def calculate_score(self):
        """计算WebView架构可能性评分"""
        weights = {
            'internet_permission': 10,
            'network_state_permission': 5,
            'webview_activity': 15,
            'webview_imports': 20,
            'webview_usage': 25,
            'javascript_enabled': 20,
            'url_loading': 30,
            'main_activity_webview': 35,
            'layout_webviews': 25,
            'url_strings': 10,
        }

        total_score = 0
        max_possible_score = 0

        for indicator, count in self.webview_indicators.items():
            if indicator in weights:
                if count > 0:
                    total_score += weights[indicator]
                max_possible_score += weights[indicator]

        # 计算百分比得分
        if max_possible_score > 0:
            percentage = (total_score / max_possible_score) * 100
        else:
            percentage = 0

        return percentage, total_score

    def detect(self):
        """执行检测"""
        print(f"正在分析应用: {self.apk_folder}")

        # 执行各项分析
        self.analyze_manifest()
        self.analyze_java_files()
        self.analyze_resources()
        self.analyze_strings()

        # 计算得分
        percentage, total_score = self.calculate_score()

        # 输出结果
        print("\n=== WebView架构检测结果 ===")
        print(f"检测得分: {percentage:.1f}%")

        print("\n详细指标:")
        for indicator, count in self.webview_indicators.items():
            if count > 0:
                print(f"  {indicator}: {count}")

        # 判断结果
        if percentage >= 70:
            result = "高度可能"
            confidence = "高"
        elif percentage >= 40:
            result = "可能"
            confidence = "中"
        elif percentage >= 20:
            result = "较少可能"
            confidence = "低"
        else:
            result = "不太可能"
            confidence = "很低"

        print(f"\n结论: 该应用{result}使用WebView架构 (置信度: {confidence})")

        return {
            'is_webview_app': percentage >= 40,
            'confidence_percentage': percentage,
            'confidence_level': confidence,
            'indicators': dict(self.webview_indicators)
        }


def main():
    """主函数"""
    import sys

    base_dirs = [f"C:\\must\\jadx_output{i}" for i in range(1, 5)]
    output_file = os.path.join(os.path.dirname(__file__), "webview_result.txt")
    bare_output_file = os.path.join(os.path.dirname(__file__), "webview_bare_data.txt")
    print(f"输出结果将保存到: {output_file}")
    with open(output_file, "w", encoding="utf-8") as out_f, \
         open(bare_output_file, "w", encoding="utf-8") as bare_f:
        for base_dir in base_dirs:
            if not os.path.exists(base_dir):
                continue
            for folder in os.listdir(base_dir):
                print(f"正在检测: {folder}")
                apk_folder = os.path.join(base_dir, folder)
                if os.path.isdir(apk_folder):
                    detector = WebViewDetector(apk_folder)
                    result = detector.detect()
                    out_f.write(f"检测文件夹: {apk_folder}\n")
                    out_f.write(f"检测得分: {result['confidence_percentage']:.1f}%\n")
                    out_f.write(f"置信度: {result['confidence_level']}\n")
                    out_f.write(f"是否WebView应用: {'是' if result['is_webview_app'] else '否'}\n")
                    out_f.write("详细指标:\n")
                    for indicator, count in result['indicators'].items():
                        if count > 0:
                            out_f.write(f"  {indicator}: {count}\n")
                    out_f.write("\n")
                    # 写入原始result数据
                    bare_f.write(f"{apk_folder}\t{repr(result)}\n")

    # apk_folder = "C:\\Users\gyc\Desktop\\aaaaaa\\aaa"

    # if not os.path.exists(apk_folder):
    #     print(f"错误: 文件夹 {apk_folder} 不存在")
    #     sys.exit(1)

    # detector = WebViewDetector(apk_folder)
    # result = detector.detect()

    # return result


if __name__ == "__main__":
    main()