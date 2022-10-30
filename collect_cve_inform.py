import re
import requests
import json
from selenium.webdriver import Chrome
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
def collect_cve_inform(url):
    driver = Chrome(executable_path = './chromedriver.exe')
    driver.get(url)

if __name__ == "__main__":
    url = r"https://www.opencve.io/cve?cvss=&search=libavformat"
    collect_cve_inform(url)