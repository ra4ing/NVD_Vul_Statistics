from parse_html import AnalysisType, WebDataAnalyzer, WebDataExtractor

def get_data():
    vul_keywords = [
        'buffer overflow',
        'injection vulnerability',  # 合并SQL注入、命令注入等为更广泛的注入漏洞
        'cross-site scripting',  # 保留XSS，它是Web安全中的一个重要漏洞
        'code execution',  # 合并远程代码执行、命令执行等为代码执行漏洞
        'denial of service',  # 保留DoS漏洞
        'cross-site request forgery',  # 保留CSRF，它在Web应用中也是常见的安全问题
        'information disclosure',  # 保留信息泄露类型，因为它覆盖了广泛的漏洞
        'authentication issue'  # 合并认证绕过、会话管理问题等为认证问题
    ]
    for keyword in vul_keywords:
        extractor = WebDataExtractor(keyword)
        extractor.fetch_and_save_html()
        df = extractor.extract_table_data()
        extractor.analyze_and_plot(df)


def analysis():
    analyzer = WebDataAnalyzer("data")
    analyzer.load_data()
    analyzer.analyze_and_plot(AnalysisType.TREND)
    analyzer.analyze_and_plot(AnalysisType.PROPORTIONAL)


if __name__ == '__main__':
    get_data()
    analysis()