import os
import argparse
from requests.auth import HTTPBasicAuth
import requests
import json
import sys

from bs4 import BeautifulSoup
import pandas as pd
'''
def collect_cve_inform(url):

    response = requests.get(url)
    if response.status_code == 200:
        html = response.content
        soup = BeautifulSoup(html, 'html.parser')
        print(soup)

    else:
        print(response.status_code)
'''
def search_cpe22(keyword):
    '''
    driver = webdriver.Chrome(executable_path='./chromedriver.exe')
    driver.get('https://nvd.nist.gov/products/cpe/search//results?namingFormat=2.3&keyword='+keyword)
    try:
        element = driver.find_element(By.CLASS_NAME,'col-lg-12')
        element2 = element.find_element(By.TAG_NAME, 'a')
        print(element2.text)
    except NoSuchElementException:
        print("%s : 검색 결과 없음 " %keyword)
        return NoSuchElementException
    '''
    url = 'https://nvd.nist.gov/products/cpe/search//results?namingFormat=2.2&keyword= '+keyword+' '
    response = requests.get(url)
    print(keyword)
    if len(keyword)<3:
        return
    if response.status_code == 200:
        html = response.content
        soup = BeautifulSoup(html, 'html.parser')
        soup.find('input',{'id' : 'Keywords'})['value'] =keyword

        results_count = soup.find('strong',attrs ={'data-testid':'cpe-matching-records-count'}).getText()
        #print(results_count)
        print('{0} : cve 검색결과 수 {1}'.format(keyword, results_count))
        if results_count == '0':
            return
        else:
            if results_count != '1':
                print("예외처리")
            results = soup.find('div', attrs={'class': 'searchResults'})
            result = results.find('div', attrs={'class': 'col-lg-12'}).find('strong').find('a')
            print(keyword+' : '+ result.getText())
            return result.getText()
    else:
        print(response.status_code)
        return
def lookup_cpe(word):
    #runPath = os.path.dirname(os.path.realpath(__file__))
    #sys.path.append(os.path.join(runPath, ".."))
    #from cpeguesser import CPEGuesser
    '''
    parser = argparse.ArgumentParser(
        description='Find potential CPE names from a list of keyword(s) and return a JSON of the results'
    )
    parser.add_argument(
        'word',
        metavar='WORD',
        type=str,
        nargs='+',
        help='One or more keyword(s) to lookup',
    )
    args = parser.parse_args()
    '''
    #cpeGuesser = CPEGuesser()
    #print(json.dumps(cpeGuesser.guessCpe(word)))
    return
def search_cve(keyword):
    #수정필요
    url = r'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query= '+keyword+' &search_type=all&isCpeNameSearch='
    #url = r'https://nvd.nist.gov/vuln/search'

    response = requests.get(url)
    if response.status_code == 200:
        html = response.content
        soup = BeautifulSoup(html, 'html.parser')
        results_count = soup.find('strong', attrs={'data-testid': 'vuln-matching-records-count'}).getText()
        #print(results_count)
        print('{0} : cve 검색결과 수 {1}'.format(keyword, results_count))
        if results_count == '0':
            return
        else:
            table = soup.find('table', attrs={'data-testid': 'vuln-results-table'})
            table_html =str(table)
            table_df_list = pd.read_html(table_html)
            print(table_df_list)
            ###
            #result = results.find('div', attrs={'class': 'col-lg-12'}).find('strong').find('a')
            #print(keyword + ' : ' + result.getText())
            return
    else:
        print(response.status_code)
        return

if __name__ == "__main__":
    url = r"https://www.opencve.io/cve?cvss=&search=libavformat"
    #search_cpe22('libavformat')
    search_cve(search_cpe22('libavformat'))
    #lookup_cpe('libavformat')
    #collect_cve_inform(url)