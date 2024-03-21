from enum import Enum
import os
import requests
from bs4 import BeautifulSoup
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


class SecurityScoreType:
    ANY = "ANY"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    MEDIUM_HIGH = "MEDIUM_HIGH"
    HIGH = "HIGH"
    


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

scores = [
    SecurityScoreType.ANY, 
    SecurityScoreType.LOW, 
    SecurityScoreType.MEDIUM, 
    SecurityScoreType.MEDIUM_HIGH,
    SecurityScoreType.HIGH, 
]


class WebDataExtractor:
    """
    A class for extracting vulnerability data from the web, saving it locally,
    and performing data analysis and visualization.
    """
        
    def __init__(self, vul_name, security_score: SecurityScoreType):
        """
        Initialize the WebDataExtractor with the given vulnerability name.
        """
        if security_score == "ANY":
            self.url = f"https://nvd.nist.gov/vuln/search/statistics?form_type=Basic&results_type=statistics&query={vul_name.replace(' ', '+')}&search_type=all&isCpeNameSearch=false"
            
        else:
            self.url = f"https://nvd.nist.gov/vuln/search/statistics?form_type=Advanced&results_type=statistics&query={vul_name.replace(' ', '+')}&search_type=all&isCpeNameSearch=false&cvss_version=2&cvss_v2_severity={security_score}"
        self.html_filename_with_score = f"{vul_name.replace(' ', '_')}-{security_score}.html"
        self.html_dir_name = "html"
    
    def fetch_and_save_html(self):
        """
        Fetch the HTML content from the specified URL and save it to a local file.
        """
        response = requests.get(self.url)
        html_content = response.text
        with open(self.html_dir_name + '/'+ self.html_filename_with_score, 'w', encoding='utf-8') as file:
            file.write(html_content)


class WebDataAnalyzer:
    def __init__(self, vul_name):
        """
        Initialize the WebDataExtractor with the given vulnerability name.
        """

        self.html_filename_without_score = f"{vul_name.replace(' ', '_')}"
        self.html_dir_name = "html"
        self.csv_filename = f"data/{vul_name.replace(' ', '_')}.csv"
        self.vul_name = f"{vul_name.title()}"


    def extract_table_data(self):
        aggregated_data = {}
        security_levels = [ 
            SecurityScoreType.ANY, 
            SecurityScoreType.LOW, 
            SecurityScoreType.MEDIUM, 
            SecurityScoreType.MEDIUM_HIGH,
            SecurityScoreType.HIGH
        ]
        columns = ['Year', 'Total', 'Percentage'] + security_levels

        for filename in os.listdir(self.html_dir_name):

            if filename.startswith(self.html_filename_without_score) and filename.endswith('.html'):
                security_level = filename.split('-')[-1].replace('.html', '').strip().upper()

                if security_level in security_levels:
                    with open(os.path.join(self.html_dir_name, filename), 'r', encoding='utf-8') as file:
                        soup = BeautifulSoup(file, 'html.parser')

                    rows = soup.find_all('tr')[1:]  # Skip the title row
                    for row in rows:
                        cols = row.find_all(['th', 'td'])
                        year, matches, total, percentage = int(cols[0].text), int(cols[1].text), int(cols[2].text), float(cols[3].text.strip('%'))

                        if year not in aggregated_data:
                            aggregated_data[year] = {col: 0 for col in columns}
                        if security_level == "ANY":
                            aggregated_data[year]['Year'] = year
                            aggregated_data[year]['Total'] = total
                            aggregated_data[year]['Percentage'] = percentage
                        aggregated_data[year][security_level] = matches

        df = pd.DataFrame(list(aggregated_data.values()), columns=columns)
        df.to_csv(self.csv_filename, index=False)
        print(f"Saved data to {self.csv_filename}")


class WebDataPloter():
    """
    A class for analyzing vulnerability data from multiple CSV files and generating visualizations.
    """
    
    def __init__(self, data_dir):
        """
        Initialize the WebDataAnalyzer with the directory containing the CSV data files.
        """
        self.data_dir = data_dir
        self.data = {}
        self.__load_data__()
        


    def __load_data__(self):
        """
        Load data from CSV files in the specified directory into a single DataFrame.
        """
        for filename in os.listdir(self.data_dir):
            if filename.endswith(".csv"):
                file_path = os.path.join(self.data_dir, filename)
                vul_name = filename[:-4].replace("_", " ")
                df = pd.read_csv(file_path)
                df.fillna(0, inplace = True)
                df.sort_values(by='Year', ascending=True, inplace=True)
                df.reset_index(drop=True, inplace=True)
                self.data[vul_name] = df


    def plot_csv(self):
        """
        Perform data analysis and create visualizations.
        """

        for vul_name in vul_keywords:
            df = self.data[vul_name]
            fig, ax1 = plt.subplots(figsize=(10, 6))
            ax2 = ax1.twinx()

            # 创建堆叠柱状图
            bars = df.plot(kind='bar', x='Year', stacked=True, 
                    y=['LOW', 'MEDIUM', 'HIGH'], 
                    ax=ax1, width=0.8, alpha=0.75, colormap='viridis')
            
            

            # # 创建趋势线图
            df.plot(y='Total', kind='line', ax=ax2, color='cornflowerblue', marker='x', linestyle='-', linewidth=2, label='Total Trend', zorder=9)

            # 设置比例注释
            for i, total in enumerate(df['Total']):
                ax2.annotate(f'{total}', (i, total), textcoords="offset points", xytext=(0,10), ha='center', fontsize=6, zorder=10)

            # 在堆叠柱状图的顶部添加数量和比例注释
            for i, (rect, year, any, low, medium_high, pct) in enumerate(zip(bars.patches, df['Year'], df['ANY'], df["LOW"], df["MEDIUM_HIGH"], df['Percentage'])):
                if pct > 0:
                    height = any
                    ax1.annotate(f'{any}\n{pct}%', (rect.get_x() + rect.get_width() / 2, height),
                                textcoords="offset points", xytext=(0,30), ha='center', fontsize=6, arrowprops=dict(arrowstyle="<->", connectionstyle="arc3", color='lightgray'), zorder=10)
                    if low + medium_high <= 10:
                        ax1.bar(i, any, width=0.8, color='gray', alpha=0.75, zorder=10)

            # 添加图例
            ax1.legend(loc='upper left')
            ax2.legend(loc='upper right')

            # 设置标题和轴标签
            ax1.set_title(f"{vul_name.title()}")
            ax1.set_xlabel('Year')
            ax1.set_ylabel('Count')
            ax2.set_ylabel('Total Count / Percentage')

            # 调整X轴标签
            ax1.set_xticks(range(len(df['Year'])))
            ax1.set_xticklabels(df['Year'], rotation=45)

            # 显示图表
            plt.tight_layout()
            plt_filename = f"plot/{vul_name.replace(' ', '_')}.png"
            plt.savefig(plt_filename, dpi=1080)


    def plot_pie(self):
        for vul_name in vul_keywords:
            df = self.data[vul_name]
            # 直接使用df，因为已经假定df只包含2022年的数据
            df_2022 = df[df["Year"] == 2022]
            df_2022_other = df_2022[SecurityScoreType.ANY] \
                        - df_2022[SecurityScoreType.LOW] \
                        - df_2022[SecurityScoreType.MEDIUM] \
                        - df_2022[SecurityScoreType.HIGH]

            # # 数据准备
            labels = ["Low", 
                    "Medium", 
                    "High",
                    "Other"
            ]
            sizes = [df_2022['LOW'].iloc[0],
                    df_2022['MEDIUM'].iloc[0],
                    df_2022['HIGH'].iloc[0],
                    df_2022_other.iloc[0]
            ]

            colors = [
                '#77DD77', # green
                '#FDFD96', # yellow
                '#FF6961', # red
                '#CFCFC4'] # gray

            explode = (0, 0, 0.1, 0)  # 突出显示'ANY'或'HIGH'

            # # 绘制饼图
            fig, ax = plt.subplots(figsize=(8, 8))
            
            wedges, texts, autotexts = ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
                                    shadow=False, startangle=180, textprops={'fontsize': 14})
            # 美化图例
            ax.legend(wedges, labels,
                    title="Security Levels",
                    loc="center left",
                    bbox_to_anchor=(1, 0, 0.5, 1))

            plt.title(f'{vul_name} Security Level Proportions in 2022', fontsize=16, fontweight='bold')

            plt.tight_layout()
            plt_filename = f"plot/{vul_name.replace(' ', '_')}_Security_Level_Proportions_in_2022.png"
            plt.savefig(plt_filename, dpi=1080)

    def plot_analysis(self):

        any_sums = {}
        total = 0
        for vul_name in vul_keywords:
            if vul_name == "code execution":
                continue
            df = self.data[vul_name]
            df_2023 = df[df['Year'] == 2023]  # 筛选2023年的记录
            any_sum = df_2023['ANY'].sum()  # 计算ANY字段的总和
            any_sums[vul_name] = any_sum  # 存储结果
            total = df_2023['Total'].sum()

        # 将结果转换为适用于饼状图的结构
        labels = list(any_sums.keys()) + ["other"]
        sizes = list(any_sums.values())
        sizes = sizes + [total - sum(sizes)]

        # print(labels, sizes)

        color_scheme = {
            'buffer overflow': '#ff6666', # 亮红色, 突出显示
            'injection vulnerability': '#3498db', # 蓝色
            'cross-site scripting': '#2ecc71', # 绿色
            'denial of service': '#f1c40f', # 黄色
            'cross-site request forgery': '#9b59b6', # 紫色
            'information disclosure': '#34495e', # 深蓝色
            'authentication issue': '#95a5a6', # 灰色
            'other': '#7f8c8d', # 暗灰色
        }

        colors = [color_scheme[label] for label in labels]

        explode = (0.1, 0, 0, 0, 0, 0, 0, 0)  # 突出显示'ANY'或'HIGH'

        # # 绘制饼图
        fig, ax = plt.subplots(figsize=(16, 9))
        
        wedges, texts, autotexts = ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
                                shadow=False, startangle=180, textprops={'fontsize': 14})
        # 美化图例
        ax.legend(wedges, labels,
                title="Security Levels",
                loc="center left",
                bbox_to_anchor=(1, 0, 0.5, 1))

        plt.title(f'Vulnerable Type Proportions in 2023', fontsize=16, fontweight='bold')

        plt.tight_layout()
        plt_filename = f"plot/Vulnerable_Type_Proportions_in_2023.png"
        plt.savefig(plt_filename, dpi=1080)