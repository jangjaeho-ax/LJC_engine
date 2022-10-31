import re
import requests
import json
from selenium.common import NoSuchElementException
from selenium import webdriver
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
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
def get_cpe23_from_nvd(keyword):
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
    url = 'https://nvd.nist.gov/products/cpe/search//results?namingFormat=2.3&keyword='+keyword
    response = requests.get(url)
    if response.status_code == 200:
        html = response.content
        soup = BeautifulSoup(html, 'html.parser')
        results_count = int(soup.find('strong',attrs ={'data-testid':'cpe-matching-records-count'}).getText())
        print(results_count)
        if results_count == 0:
            print('%s : cpe 검색결과 없음' %keyword)
            return
        else:
            if results_count != 1:
                print('%s : cpe 검색결과가 1 이상' % keyword)
            results = soup.find('div', attrs={'class': 'searchResults'})
            result = results.find('div', attrs={'class': 'col-lg-12'}).find('strong').find('a')
            print(result.getText())
            return


    else:
        print(response.status_code)
        return

def collect_cve_inform(url):
    driver = webdriver.Chrome(executable_path = './chromedriver.exe')
    driver.get(url)
    element = driver.find_element(By.CLASS_NAME,"cve")

if __name__ == "__main__":
    url = r"https://www.opencve.io/cve?cvss=&search=libavformat"
    get_cpe23_from_nvd(';!!@!@#@!!#@122')
    #collect_cve_inform(url)