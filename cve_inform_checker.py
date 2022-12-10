import os
import argparse
from requests.auth import HTTPBasicAuth
import requests
import datetime
import json
import sys
import cpeguesser

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
def search_cpe22(keywords):
    result = {}
    text = []
    num = 0

    url = 'https://nvd.nist.gov/products/cpe/search//results?namingFormat=2.2&keyword= ' + k + ' '
    response = requests.get(url)
    if response.status_code == 200:
        for k in keywords:
            print(k)
            if len(k) < 3:
                return

                html = response.content
                soup = BeautifulSoup(html, 'html.parser')
                results_count = soup.find('strong', attrs={'data-testid': 'cpe-matching-records-count'}).getText()
                # print(results_count)
                print('{0} : cve 검색결과 수 {1}'.format(k, results_count))
                text.append(str('{0} : cve 검색결과 수 {1}'.format(k, results_count)) + '\n')
                if results_count != '1':
                    print("예외처리")
                    results = soup.find('div', attrs={'class': 'searchResults'})
                    result = results.find('div', attrs={'class': 'col-lg-12'}).find('strong').find('a')
                    print(k + ' : ' + result.getText())
                    text.append(str(k + ' : ' + result.getText()) + '\n')

        result['text'] = text
        result['num'] = num
        return result
    else:
        result['text'] = str(response.status_code)
        return result

def search_cve(keyword):
    result = {}
    text = []
    num = 0


    #nvd api를 이용
    base_url = r'https://services.nvd.nist.gov/cves/2.0'
    url = r'https://nvd.nist.gov/vuln/search'
    #url = base_url+'pubStartDate=2020-01-01T00:00:00.000&pubEndDate='+str(datetime.date.today())+'T00:00:00.000'
    headers = {'Accept': 'application/json'}
    #개인 키
    auth = HTTPBasicAuth('apikey', '3a199e6c-3c95-4e84-b4fa-9061f296b6b5 ')
    #https://nvd.nist.gov/developers/vulnerabilities 참고

    payload = {'keywordSearch' : keyword,}
    response = requests.get(url, headers=headers, auth=auth, params =payload)
    #url = r'https://nvd.nist.gov/vuln/search'
    print(response.url)
    text.append(str("search {0} from {1} .".format(keyword,response.url)) + '\n')
    if response.status_code == 200:
        html = response.content

        soup = BeautifulSoup(html, 'html.parser')
        '''
        results_count = soup.find('strong', attrs={'data-testid': 'vuln-matching-records-count'}).getText()
        #print(results_count)
        print('{0} : cve 검색결과 수 {1}'.format(keyword, results_count))
        if results_count == '0':
            return
        '''
        table = soup.find('table', attrs={'id': 'cves'})
        table_html = str(table)
        table_df_list = pd.read_html(table_html)
        print(table_df_list)
        text.append(str(table_df_list) + '\n')
        print(text)
        ###
        # result = results.find('div', attrs={'class': 'col-lg-12'}).find('strong').find('a')
        # print(keyword + ' : ' + result.getText())
        result['text'] = text
        result['num'] = num
        return result
    else:
        print(response.status_code)
        result['text'] = str(response.status_code)
        return result

if __name__ == "__main__":
    url = r"https://www.opencve.io/cve?cvss=&search=libavformat"

    #search_cve(search_cpe22('libavformat'))
    #search_cve('libavformat')
    #cpe_guesser = cpeguesser.CPEGuesser()
    #result = cpe_guesser.guessCpe('libavformat')
    #print(result)
    #lookup_cpe('libavformat')
    #collect_cve_inform(url)