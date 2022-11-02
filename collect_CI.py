import re
import requests
import json
from selenium.common import NoSuchElementException
from selenium import webdriver
from selenium.webdriver.common.by import By
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
                pprint("예외처리")
            results = soup.find('div', attrs={'class': 'searchResults'})
            result = results.find('div', attrs={'class': 'col-lg-12'}).find('strong').find('a')
            print(keyword+' : '+ result.getText())
            return
    else:
        print(response.status_code)
        return
def search_cve(keyword):
    #수정필요
    url = r'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query= '+keyword+' &search_type=all&isCpeNameSearch=false'
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
    #search_cpe23(';!!@!@#@!!#@122')
    search_cve('libavformat')
    #collect_cve_inform(url)