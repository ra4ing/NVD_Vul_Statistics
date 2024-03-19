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

        # Extract table data
        data = []
        rows = soup.find_all('tr')[1:]  # skip title row
        for row in rows:
            cols = row.find_all(['th', 'td'])
            year = int(cols[0].text)
            matches = int(cols[1].text)
            total = int(cols[2].text)
            percentage = float(cols[3].text.strip('%'))
            data.append([year, matches, total, percentage])

        # Convert to DataFrame
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


class AnalysisType(Enum):
    PROPORTIONAL = "Proportional"
    TREND = "Trend"


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


    def analyze_and_plot(self, analysis_type):
        grouped_data = self.data.groupby(['Year', 'Vulnerability']).sum().reset_index()
        years = np.sort(self.data['Year'].unique())

        fig, ax1 = plt.subplots(figsize=(16, 9))

        # Distribution colour: Buffer Overflow is red, other vulnerabilities are different light colours.
        other_vuls = [vul for vul in self.data['Vulnerability'].unique() if vul != 'Buffer Overflow']
        colors = plt.cm.Pastel1(np.linspace(0, 1, len(other_vuls)))
        vul_colors = {vul: colors[i] for i, vul in enumerate(other_vuls)}
        vul_colors['Buffer Overflow'] = 'red'

        filename = ""
        bottom_array = []
        if analysis_type == AnalysisType.PROPORTIONAL:
            filename = "plot/Proportional_Analysis.png"
            bo_data = grouped_data[grouped_data['Vulnerability'] == 'Buffer Overflow']
            bo_matches_by_year = bo_data.set_index('Year')['Matches'].reindex(years, fill_value=0)
            bottom_array = [0 for i in range(len(bo_matches_by_year))]
            # print(len(bottom_array))
            ax1.bar(years, bo_matches_by_year, color='red', label='Buffer Overflow', width=0.4, alpha=1.0)
            bo_percentage_by_year = bo_data.set_index('Year')['Percentage'].reindex(years, fill_value=0)

            for year, percentage, match in zip(years, bo_percentage_by_year, bo_matches_by_year):
                ax1.annotate(f"{percentage:.1f}%", (year, bottom_array[year - years[0]] + match), color='red', xytext=(0, 3), textcoords='offset points', ha='center', va='bottom', fontsize=8)

            bottom_array = bo_matches_by_year.values
            
            # print(len(bottom_array))
            for vul in other_vuls:
                vul_data = grouped_data[grouped_data['Vulnerability'] == vul]
                matches_by_year = vul_data.set_index('Year')['Matches'].reindex(years, fill_value=0)
                ax1.bar(years, matches_by_year, bottom=bottom_array, color=vul_colors[vul], label=vul, width=0.4, alpha=0.7)

                percentage_by_year = vul_data.set_index('Year')['Percentage'].reindex(years, fill_value=0)
                for year, percentage, match in zip(years, percentage_by_year, matches_by_year):
                    ax1.annotate(f"{percentage:.1f}%", (year, bottom_array[year - years[0]] + match), color=vul_colors[vul], xytext=(0, 3), textcoords='offset points', ha='center', va='bottom', fontsize=8)

                bottom_array += matches_by_year.values

        elif analysis_type == AnalysisType.TREND:
            filename = "plot/Trend_Analysis.png"

            for vul in self.data['Vulnerability'].unique():
                vul_data = grouped_data[grouped_data['Vulnerability'] == vul]
                linestyle = '-' if vul == 'Buffer Overflow' else "--"
                linewidth = 2 if vul == 'Buffer Overflow' else 1
                label = f"{vul} ({linestyle})"

                matches_by_year = vul_data.set_index('Year')['Matches'].reindex(years, fill_value=0)
                ax1.plot(years, matches_by_year, color=vul_colors[vul], linestyle=linestyle, marker='o', linewidth=linewidth, label=label)
                # Scale figures on line graphs
                percentage_by_year = vul_data.set_index('Year')['Percentage'].reindex(years, fill_value=0)
                for year, percentage in zip(years, percentage_by_year):
                    ax1.annotate(f"{percentage:.1f}%", (year, matches_by_year[year]), color=vul_colors[vul], xytext=(0, 5), textcoords='offset points', ha='center', va='bottom', fontsize=8)

        ax1.set_xlabel('Year')
        ax1.set_ylabel('Number of Matches')
        ax1.set_xticks(years)
        ax1.set_xticklabels(years, rotation=45)
        ax1.legend()
        plt.tight_layout()
        plt.savefig(filename)