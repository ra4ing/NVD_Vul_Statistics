from enum import Enum
import os
import requests
from bs4 import BeautifulSoup
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

class WebDataExtractor:
    """
    A class for extracting vulnerability data from the web, saving it locally,
    and performing data analysis and visualization.
    """
        
    def __init__(self, vul_name):
        """
        Initialize the WebDataExtractor with the given vulnerability name.
        """
        self.url = f"https://nvd.nist.gov/vuln/search/statistics?form_type=Basic&results_type=statistics&query={vul_name.replace(' ', '+')}&search_type=all&isCpeNameSearch=false"
        self.html_filename = f"html/{vul_name.replace(' ', '_')}.html"
        self.csv_filename = f"data/{vul_name.replace(' ', '_')}.csv"
        self.plt_filename = f"plot/{vul_name.replace(' ', '_')}.png"
        self.vul_name = f"{vul_name.title()} Vulnerability"
    
    def fetch_and_save_html(self):
        """
        Fetch the HTML content from the specified URL and save it to a local file.
        """
        response = requests.get(self.url)
        html_content = response.text
        with open(self.html_filename, 'w', encoding='utf-8') as file:
            file.write(html_content)
    
    def extract_table_data(self):
        """
        Parse the HTML file and extract the table data.
        """
        with open(self.html_filename, 'r', encoding='utf-8') as file:
            soup = BeautifulSoup(file, 'html.parser')

        # 提取表格数据
        data = []
        rows = soup.find_all('tr')[1:]  # 跳过标题行
        for row in rows:
            cols = row.find_all(['th', 'td'])
            year = int(cols[0].text)
            matches = int(cols[1].text)
            total = int(cols[2].text)
            percentage = float(cols[3].text.strip('%'))
            data.append([year, matches, total, percentage])

        # 转换为DataFrame
        df = pd.DataFrame(data, columns=['Year', 'Matches', 'Total', 'Percentage'])
        self.save_table(df)
        return df
    
    def save_table(self, df):
        """
        Save the extracted table data to a CSV file.
        """
        df.to_csv(self.csv_filename, index=False)

    def analyze_and_plot(self, df):
        """
        Perform data analysis and create visualizations.
        """
        fig, ax1 = plt.subplots(figsize=(14, 8))

        ax1.bar(df['Year'], df['Matches'], color='skyblue', label='Matches', width=0.4, align='center')
        ax1.bar(df['Year']+0.4, df['Total'], color='lightgreen', label='Total', width=0.4, align='center')
        ax1.set_xlabel('Year', fontsize=14)
        ax1.set_ylabel('Count', fontsize=14)
        ax1.tick_params(axis='y')
        ax1.set_xticks(np.arange(min(df['Year']), max(df['Year'])+1, 5))
        ax1.set_xticklabels(np.arange(min(df['Year']), max(df['Year'])+1, 5), rotation=45)

        ax2 = ax1.twinx()
        ax2.plot(df['Year'], df['Percentage'], color='red', marker='o', label='Percentage')
        ax2.set_ylabel('Percentage', fontsize=14)
        ax2.tick_params(axis='y')

        lines, labels = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax2.legend(lines + lines2, labels + labels2, loc='upper left')

        plt.title(self.vul_name, fontsize=16)
        plt.grid(True, which='both', linestyle='--', linewidth=0.5)
        plt.tight_layout()
        self.save_plt()
    
    def save_plt(self):
        plt.savefig(self.plt_filename)
        plt.close()


class WebDataAnalyzer:
    """
    A class for analyzing vulnerability data from multiple CSV files and generating visualizations.
    """
    
    def __init__(self, data_dir):
        """
        Initialize the WebDataAnalyzer with the directory containing the CSV data files.
        """
        self.data_dir = data_dir
        self.data = None
    
    def load_data(self):
        """
        Load data from CSV files in the specified directory into a single DataFrame.
        """
        data_frames = []
        for filename in os.listdir(self.data_dir):
            if filename.endswith(".csv"):
                file_path = os.path.join(self.data_dir, filename)
                vul_name = filename[:-4].replace("_", " ").title()
                df = pd.read_csv(file_path)
                df['Vulnerability'] = vul_name
                data_frames.append(df)
        
        self.data = pd.concat(data_frames, ignore_index=True)
        print(self.data)


    def plot_line_graph(self):
        plt.figure(figsize=(14, 8))
    
        # 绘制每种漏洞随时间变化的Total
        for vul_name in self.data['Vulnerability'].unique():
            subset = self.data[self.data['Vulnerability'] == vul_name]
            if vul_name.lower() == 'buffer overflow':
                plt.plot(subset['Year'], subset['Matches'], label=vul_name, color='red', linewidth=2)  # 红色实线
            else:
                plt.plot(subset['Year'], subset['Matches'], label=vul_name, linestyle='--')  # 浅色虚线

        plt.xlabel('Year')
        plt.ylabel('Total Vulnerabilities')
        plt.title('Vulnerability Trends Over Time')
        plt.legend()
        plt.show()

    def plot_stacked_bar_chart(self):
        plt.figure(figsize=(14, 8))

        # 获取所有数据中出现的年份，并排序
        all_years = sorted(self.data['Year'].unique())
        unique_vulnerabilities = self.data['Vulnerability'].unique()

        bottom = np.zeros(len(all_years))

        # 准备颜色，确保buffer overflow使用红色，其他使用不同颜色
        colors = ['red' if vul.lower() == 'buffer overflow' else 'lightblue' for vul in unique_vulnerabilities]

        for i, vul_name in enumerate(unique_vulnerabilities):
            vul_data = self.data[self.data['Vulnerability'] == vul_name]
            
            # 对于当前漏洞类型，确保覆盖所有年份，缺失的用0填充
            totals = []
            for year in all_years:
                if year in vul_data['Year'].values:
                    totals.append(vul_data[vul_data['Year'] == year]['Total'].sum())
                else:
                    totals.append(0)
            
            plt.bar(all_years, totals, bottom=bottom, color=colors[i], label=vul_name)
            bottom += np.array(totals)

        # 绘制所有漏洞的总和趋势线
        total_by_year = self.data.groupby('Year')['Total'].sum().reindex(all_years, fill_value=0)
        plt.plot(all_years, total_by_year, color='black', linewidth=2, label='Total Trend')

        plt.xlabel('Year')
        plt.ylabel('Total Vulnerabilities')
        plt.title('Stacked Vulnerability Count Over Time')
        plt.xticks(all_years, rotation=45)
        plt.legend()
        plt.tight_layout()
        plt.show()




    def analyze_and_plot(self):
        # self.plot_stacked_bar_chart()
        self.plot_line_graph()
#         grouped_data = self.data.groupby(['Year', 'Vulnerability']).sum().reset_index()
#         years = np.sort(self.data['Year'].unique())

#         fig, ax1 = plt.subplots(figsize=(16, 9))

#         # 分配颜色：Buffer Overflow为红色，其他漏洞为不同的浅色
#         other_vuls = [vul for vul in self.data['Vulnerability'].unique() if vul != 'Buffer Overflow']
#         colors = plt.cm.Pastel1(np.linspace(0, 1, len(other_vuls)))
#         vul_colors = {vul: colors[i] for i, vul in enumerate(other_vuls)}
#         vul_colors['Buffer Overflow'] = 'red'  # 确保与数据中的Buffer Overflow对应

#         filename = ""
#         if analysis_type == AnalysisType.PROPORTIONAL:
#             filename = "plot/Proportional_Analysis.png"
#             # 首先绘制Buffer Overflow的柱状图
#             bo_data = grouped_data[grouped_data['Vulnerability'] == 'Buffer Overflow']
#             bo_matches_by_year = bo_data.set_index('Year')['Matches'].reindex(years, fill_value=0)
#             ax1.bar(years, bo_matches_by_year, color='red', label='Buffer Overflow', width=0.4, alpha=1.0)
#             bottom_array = bo_matches_by_year.values

#             # 绘制其他漏洞的堆叠柱状图
#             for vul in other_vuls:
#                 vul_data = grouped_data[grouped_data['Vulnerability'] == vul]
#                 matches_by_year = vul_data.set_index('Year')['Matches'].reindex(years, fill_value=0)
#                 ax1.bar(years, matches_by_year, bottom=bottom_array, color=vul_colors[vul], label=vul, width=0.4, alpha=0.7)
#                 bottom_array += matches_by_year.values
#         elif analysis_type == AnalysisType.TREND:
#             filename = "plot/Trend_Analysis.png"
#             # 为每种漏洞类型绘制折线图
#             for vul in self.data['Vulnerability'].unique():
#                 vul_data = grouped_data[grouped_data['Vulnerability'] == vul]
#                 matches_by_year = vul_data.set_index('Year')['Matches'].reindex(years, fill_value=0)
#                 ax1.plot(years, matches_by_year, color=vul_colors[vul], linestyle='-' if vul == 'Buffer Overflow' else "--", marker='o', linewidth=2 if vul == 'Buffer Overflow' else 1)

#         ax2 = ax1.twinx()
#         # 假设Buffer Overflow存在于数据中，我们可以用它来获取每年的Total值
#         # 如果Buffer Overflow可能不存在，应该选择一个确保存在的漏洞类型
#         bo_data = grouped_data[grouped_data['Vulnerability'] == 'Buffer Overflow']
#         total_by_year = bo_data.set_index('Year')['Total'].reindex(years, fill_value=0)
#         ax2.plot(years, total_by_year, color='black', linestyle='-', linewidth=2, label='Total')

#         ax1.set_xlabel('Year', fontsize=14)
#         ax1.set_ylabel('Matches', fontsize=14)
#         ax2.set_ylabel('Total', fontsize=14)
#         ax1.set_xticks(years)
#         ax1.set_xticklabels(years, rotation=45)

#         # 处理图例
#         handles1, labels1 = ax1.get_legend_handles_labels()
#         handle2, label2 = ax2.get_legend_handles_labels()[0], ax2.get_legend_handles_labels()[1][0]
#         ax1.legend(handles1 + [handle2], labels1 + [label2], loc='upper left', title='Vulnerability')

#         plt.title("Vulnerability Trends Including Buffer Overflow", fontsize=16)
#         plt.tight_layout()
#         plt.grid(True, linestyle='--', linewidth=0.5)
#         plt.savefig(filename)
#         plt.close()

