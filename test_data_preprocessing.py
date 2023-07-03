from googlesearch import search
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import ssl
import socket
from urllib.parse import urlparse
import requests
import re
import numpy as np


def main(url):
    # Creating an empty list
    data = []

    # 1st Value []
    match = re.search(r'https?://([^/]+)', url)
    if match:
        domain = match.group(1)
        match = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain)
        if match:
            result = 1
        else:
            result = -1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 2nd Value []
    if len(url) < 54:
        result = 1
    elif 54 <= len(url) <= 75:
        result = 0
    elif len(url) > 75:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 3rd Value []
    response = requests.get(url)
    if response.history:
        result = 1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 4th Value []
    if "@" in response.url:
        result = 1
    else:
        result = -1
    data.append(result)

    # 5th Value []
    if "//" in response.url:
        result = 1
    else:
        result = -1
    data.append(result)

    # 6th Value []
    tlds = ['com', 'org', 'net', 'edu']
    match = re.search(r'https?://(.+)\.(%s)/' % '|'.join(tlds), url)
    if match:
        domain = match.group(1)
        if '-' in domain or '_' in domain:
            result = 1
        else:
            result = -1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 7th Value []
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc
    netloc_parts = netloc.split(".")
    if len(netloc_parts) > 2:
        subdomain = netloc_parts[0]
    else:
        subdomain = ""
    if subdomain:
        result = 1
    elif subdomain == "":
        result = 0
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 8th Value []
    def check_ssl(website):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((website, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=website) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        if cert['subjectAltName'][0][1] == website:
                            return 1
                        else:
                            return -1
                    else:
                        return 0
        except Exception:
            return -1

    result = check_ssl(url)
    # Adding the value to the list
    data.append(result)

    # 9th Value []
    def get_domain_name(website):
        domain_present = re.findall(
            r'(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/?)(?:[^\s()<>]+|\((['
            r'^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))',
            website)
        if domain_present:
            return domain_present[0][1:-1]
        return None

    def is_phishing_website(website):
        domain_present = get_domain_name(website)
        if domain_present:
            try:
                domain_info = whois.whois(domain_present)
                if domain_info.expiration_date:
                    expiration_date = domain_info.expiration_date
                    if isinstance(expiration_date, list):
                        expiration_date = expiration_date[0]
                    if (expiration_date - datetime.now()).days <= 365:
                        return True
                return False
            except Exception:
                pass
        return None

    if is_phishing_website(url):
        result = -1
    else:
        result = 1
    # Adding the value to the list
    data.append(result)

    # 10th Value []
    soup = BeautifulSoup(response.content, 'html.parser')
    favicon_link = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
    if favicon_link is not None:
        result = 1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 11th Value []
    if ":" in parsed_url.netloc:
        result = 1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 12th Value []
    if re.search(r'https://', url):
        https_token = 1
    else:
        https_token = -1
    # Adding the value to the list
    data.append(https_token)

    # 13th Value []
    html = response.content
    soup = BeautifulSoup(html, 'html.parser')
    external_urls = []
    for tag in soup.find_all(['img', 'video', 'audio']):
        if tag.has_attr('src'):
            external_urls.append(tag['src'])
    for tag in soup.find_all('a'):
        if tag.has_attr('href'):
            href = tag['href']
            if href.startswith('http') or href.startswith('//'):
                external_urls.append(href)
    if not external_urls:
        result = -1
    else:
        num_external_urls = len([url for url in external_urls if not url.startswith(url)])
        percent_external_urls = (num_external_urls / len(external_urls)) * 100
        if percent_external_urls < 40:
            result = -1
        else:
            result = 1
    # Adding the value to the list
    data.append(result)

    # 14th Value []
    anchor_tags = soup.find_all('a')
    if len(anchor_tags) == 0:
        result = 1
    else:
        num_different_domains = sum(1 for a in anchor_tags if 'http' in a.get('href', '') and url not in a.get('href'))
        percent_different_domains = (num_different_domains / len(anchor_tags)) * 100
        if percent_different_domains < 31:
            result = 1
        elif 31 <= percent_different_domains <= 67:
            result = 0
        else:
            result = -1
    # Adding the value to the list
    data.append(result)

    # 15th Value []
    meta_links = soup.select(
        'head meta[http-equiv="refresh"], head meta[http-equiv="Content-Type"], head meta['
        'http-equiv="Content-Language"], head meta[http-equiv="Pragma"], head meta[http-equiv="Cache-Control"], '
        'head meta[charset]')
    script_links = soup.select('head script[src], body script[src]')
    other_links = soup.select(
        'head link[href], body link[href], img[src], iframe[src], embed[src], object[data], video[src], audio[src], '
        'source[src], track[src], input[src], form[action], frame[src]')
    total_links = len(meta_links) + len(script_links) + len(other_links)
    if total_links == 0:
        result = -1
    else:
        meta_percentage = len(meta_links) / total_links * 100
        script_percentage = len(script_links) / total_links * 100
        other_percentage = len(other_links) / total_links * 100

        if meta_percentage < 17 or script_percentage < 17 or other_percentage < 17:
            result = 1
        elif 17 <= meta_percentage <= 81 and 17 <= script_percentage <= 81 and 17 <= other_percentage <= 81:
            result = 0
        else:
            result = -1
    # Adding the value to the list
    data.append(result)

    # 16th Value []
    sfh = parsed_url.fragment
    domain = parsed_url.netloc.split(':')[0]

    if sfh == "" or sfh.lower() == "about:blank":
        result = -1
    elif domain not in sfh:
        result = 0
    else:
        result = 1
    # Adding the value to the list
    data.append(result)

    # 17th Value []
    if 'mail(' in url or 'mailto:' in url:
        result = -1
    else:
        result = 1
    # Adding the value to the list
    data.append(result)

    # 18th Value []
    domain = url.split('/')[2]
    w = whois.whois(domain)
    if w.domain_name:
        result = 1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 19th Value []
    response_redirect = requests.get(url, allow_redirects=False)

    if response_redirect.status_code == 301 or response_redirect.status_code == 302:
        result = 1
    else:
        result = 0
    # Adding the value to the list
    data.append(result)

    # 20th Value []
    html_content = response.text
    soup = BeautifulSoup(html_content, "html.parser")
    onmouseover_event = soup.find(attrs={"onMouseOver": True})
    if onmouseover_event is not None and "window.status" in onmouseover_event["onMouseOver"]:
        result = -1
    else:
        result = 1
    # Adding the value to the list
    data.append(result)

    # 21st Value []
    page_source = response.text
    if re.search(r"event\.button\s*==\s*2", page_source):
        result = 1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 22nd Value []
    def has_text_fields(website):
        response_website = requests.get(website)
        soup_website = BeautifulSoup(response_website.text, "html.parser")
        for pop_up in soup_website.find_all("div", {"class": "pop-up"}):
            for form in pop_up.find_all("form"):
                if form.find_all("input", {"type": "text"}):
                    return True
        return False

    if has_text_fields(url):
        result = 1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 23rd Value []
    iframes = soup.find_all('iframe')
    uses_iframe = len(iframes) > 0
    has_border = False
    for iframe in iframes:
        if 'frameborder' in iframe.attrs:
            border_value = iframe.attrs['frameborder']
            if border_value == '0':
                has_border = True
                break
    if uses_iframe and not has_border:
        result = 1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 24th Value []
    domain = whois.whois(urlparse(url).netloc)
    reg_date = domain.creation_date
    if isinstance(reg_date, list):
        reg_date = reg_date[0]

    if reg_date is not None:
        age_days = (datetime.now() - reg_date).days
    else:
        age_days = -1
    if age_days >= 180:
        result = 1
    else:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 25th Value []
    try:
        domain = url.split("//")[-1].split("/")[0]
        w = whois.whois(domain)
        if not w.name_servers:
            result = -1
        else:
            result = 1
    except Exception:
        result = -1
    # Adding the value to the list
    data.append(result)

    # 26th Value []
    def get_website_rank(website):
        try:
            response_website = requests.get(f'https://www.alexa.com/siteinfo/{website}')
            soup_website = BeautifulSoup(response_website.content, 'html.parser')
            rank = soup_website.find('div', {'class': 'rank-global'}).find('strong').text
            rank = int(rank.replace(',', ''))
            if rank:
                if rank < 100000:
                    result_website = 1
                elif rank > 100000:
                    result_website = 0
                else:
                    result_website = -1
            else:
                result_website = -1
            return result_website
        except:
            return -1

    result = get_website_rank(url)
    # Adding the value to the list
    data.append(result)

    # 27th Value []
    def get_page_rank(website):
        try:
            search_results = list(search("info:" + website, num_results=1))
            if len(search_results) > 0:
                response_website = requests.get(search_results[0])
                soup_website = BeautifulSoup(response_website.content, 'html.parser')
                page_rank_tag = soup_website.find('div', {'id': 'result-stats'})
                if page_rank_tag is not None:
                    page_rank = float(page_rank_tag.text.split()[1][:-1])
                else:
                    page_rank = 0
                if page_rank < 0.2:
                    result_website = -1
                else:
                    result_website = 1
            else:
                result_website = -1
        except Exception as e:
            print("Error getting PageRank for {}: {}".format(url, str(e)))
            result_website = -1
        return result_website

    result = get_page_rank(url)
    # Adding the value to the list
    data.append(result)

    # 28th Value []
    def links_pointing_to_page_rule(links):
        if links == 0:
            return -1
        elif 0 < links <= 2:
            return 0
        else:
            return 1

    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    a_tags = soup.find_all('a')
    num_external_links = sum(1 for a in a_tags if a.has_attr('href') and not a['href'].startswith(url))
    result = links_pointing_to_page_rule(num_external_links)
    # Adding the value to the list
    data.append(result)

    # returning the processed test data for the model to evaluate
    return np.array(data)
