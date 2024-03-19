from parse_html import AnalysisType, WebDataAnalyzer, WebDataExtractor

def get_data():
    vul_keywords = [
        'buffer overflow',
        'injection vulnerability',  # Merging SQL Injection, Command Injection, etc. into Broader Injection Vulnerabilities
        'cross-site scripting',  # XSS
        'code execution',  # Combining Remote Code Execution, Command Execution, etc. for Code Execution Vulnerabilities
        'denial of service',  # DoS vulnerability
        'cross-site request forgery',  # Preserve CSRF, which is also a common security issue in web applications
        'information disclosure',  # Retain the type of information leakage as it covers a wide range of vulnerabilities
        'authentication issue'  # Merge authentication bypass, session management issues, etc. into authentication issues
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