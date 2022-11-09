import os
import argparse
from requests.auth import HTTPBasicAuth
import requests
import datetime
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
def search_cve(keyword):

    #nvd api를 이용
    base_url = r'https://services.nvd.nist.gov/rest/json/cves/2.0'
    #url = base_url+'pubStartDate=2020-01-01T00:00:00.000&pubEndDate='+str(datetime.date.today())+'T00:00:00.000'
    headers = {'Accept': 'application/json'}
    #개인 키
    auth = HTTPBasicAuth('apikey', '3a199e6c-3c95-4e84-b4fa-9061f296b6b5 ')
    #https://nvd.nist.gov/developers/vulnerabilities 참고

    payload = {'pubStartDate' : '2020-01-01T00:00:00.000','pubEndDate': str(datetime.date.today())+ 'T00:00:00.000','keywordSearch' : keyword,}
    response = requests.get(base_url, headers=headers, auth=auth, params =payload)
    #url = r'https://nvd.nist.gov/vuln/search'
    print(response.url)
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
        ###
        # result = results.find('div', attrs={'class': 'col-lg-12'}).find('strong').find('a')
        # print(keyword + ' : ' + result.getText())
        return
    else:
        print(response.status_code)
        return

if __name__ == "__main__":
    url = r"https://www.opencve.io/cve?cvss=&search=libavformat"

    #search_cpe22('libavformat')
    #search_cve(search_cpe22('libavformat'))
    search_cve('libavformat')
    #lookup_cpe('libavformat')
    #collect_cve_inform(url)