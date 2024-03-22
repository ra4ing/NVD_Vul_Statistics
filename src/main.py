from parse_html import *



def get_data():
    for keyword in vul_keywords:
        for score in scores:
            extractor = WebDataExtractor(keyword, score)
            extractor.fetch_and_save_html()


def extract_csv():
    for keyword in vul_keywords:
        analyser = WebDataAnalyzer(keyword)
        analyser.extract_table_data()

def plot_csv():
    ploter = WebDataPloter("data")
    ploter.plot_csv()

def plot_pie():
    ploter = WebDataPloter("data")
    ploter.plot_pie()


def plot_analysis():
    ploter = WebDataPloter("data")
    ploter.plot_analysis()

def analysis():
    analyzer = WebDataAnalyzer("data")
    analyzer.load_data()

if __name__ == '__main__':
    # get_data()
    # extract_csv()
    # plot_csv()
    plot_pie()
    # plot_analysis()
