import re

import requests
from bs4 import BeautifulSoup

import mapping as m


def get_malware_bazaar():
    url = 'https://mb-api.abuse.ch/api/v1/'
    query = {'query': 'get_recent', 'selector': '100'}
    response = requests.post(url, data=query)
    if response.status_code == 200:
        data = response.json()
        return data['data']
    else:
        return None


def get_apt_etda(malware_family):
    if malware_family is None:
        return None
    url = f"https://apt.etda.or.th/cgi-bin/listtools.cgi?c=&t=&x={malware_family}"
    response = requests.get(url)
    page = BeautifulSoup(response.text, 'lxml')
    malware_family_pattern = malware_family.replace(" ", "").lower()
    links = page.find_all('a')

    for link in links:
        href = link.get('href')
        cleaned_url = re.sub(r"[^a-zA-Z]", '', link.text)
        cleaned_url_lower = cleaned_url.lower()
        if malware_family_pattern in cleaned_url_lower:
            url = f"https://apt.etda.or.th{href}"
            break

    response = requests.get(url)
    if response.status_code == 200:
        bs = BeautifulSoup(response.text, "lxml")
        pattern = re.compile('/cgi-bin/listtools.cgi\?t')
        malware_classes = [name.text for name in bs.findAll('a', class_="inlink", href=pattern)]
        for i in range(len(malware_classes)):
            malware_classes[i] = m.ETDA[malware_classes[i]]
        return malware_classes
    else:
        return None


def get_virus_total(md5):
    api_key = "6a4008aee40403e369363d35234e1b175ae0914f39af94ff97a4ec5dcc3be734"
    url = f"https://www.virustotal.com/api/v3/files/{md5}"
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        av_detects = [scan['result'] for scan in data['data']['attributes']['last_analysis_results'].values() if
                      scan['result'] is not None]

        return av_detects
    else:
        return None


def get_virus_total_family(md5):
    api_key = "6a4008aee40403e369363d35234e1b175ae0914f39af94ff97a4ec5dcc3be734"
    url = f"https://www.virustotal.com/api/v3/files/{md5}"
    headers = {'x-apikey': api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        try:
            malware_family = [scan['value'] for scan in
                              data['data']['attributes']['popular_threat_classification']['popular_threat_name']]
            return malware_family
        except KeyError:
            pass
    except requests.exceptions.RequestException:
        pass
    return None


def get_virus_total_class(md5):
    api_key = "6a4008aee40403e369363d35234e1b175ae0914f39af94ff97a4ec5dcc3be734"
    url = f"https://www.virustotal.com/api/v3/files/{md5}"
    headers = {'x-apikey': api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        try:
            malware_classes = [scan['value'] for scan in
                               data['data']['attributes']['popular_threat_classification'][
                                   'popular_threat_category']]
            for i in range(len(malware_classes)):
                malware_classes[i] = m.VT[malware_classes[i]]
            return malware_classes
        except KeyError:
            pass
    except requests.exceptions.RequestException:
        pass
    return None
