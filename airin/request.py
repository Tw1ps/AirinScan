import json
import random
import urllib3
from threading import Thread
from queue import Queue

import tqdm
import requests
from bs4 import BeautifulSoup

from airin.config import settings
from airin.config.log import logger


# 以下代码来自OneForAll，内容有删改

def req_thread_count():
    count = settings.request.thread_count
    if isinstance(count, int):
        count = max(16, count)
    else:
        count = 32
    logger.log('DEBUG', f'Number of request threads {count}')
    return count


def get_html_title(markup):
    """
    获取标题

    :param markup: html标签
    :return: 标题
    """
    soup = BeautifulSoup(markup, 'html.parser')

    title = soup.title
    if title:
        return title.text

    h1 = soup.h1
    if h1:
        return h1.text

    h2 = soup.h2
    if h2:
        return h2.text

    h3 = soup.h3
    if h3:
        return h3.text

    desc = soup.find('meta', attrs={'name': 'description'})
    if desc:
        return desc['content']

    word = soup.find('meta', attrs={'name': 'keywords'})
    if word:
        return word['content']

    text = soup.text
    if len(text) <= 200:
        return repr(text)

    return 'None'


def get_progress_bar(total):
    bar = tqdm.tqdm()
    bar.total = total
    bar.desc = 'Request Progress'
    bar.ncols = 80
    return bar


def get_resp(url, session):
    timeout = settings.request.timeout_second
    redirect = settings.request.allow_redirect
    proxy = None
    if settings.request.enable_proxy:
        proxy = random.choice(settings.proxy_pool)
    try:
        resp = session.get(url, timeout=timeout,
                           allow_redirects=redirect, proxies=proxy)
    except Exception as e:
        logger.log('DEBUG', e.args)
        resp = e
    return resp


def request(urls_queue, resp_queue, session):
    while not urls_queue.empty():
        index, url, cidr, ip, port = urls_queue.get()
        resp = get_resp(url, session)
        resp_queue.put((index, resp, cidr, ip, port))
        urls_queue.task_done()


def progress(bar, total, urls_queue):
    while True:
        remaining = urls_queue.qsize()
        done = total - remaining
        bar.n = done
        bar.update()
        if remaining == 0:
            break


def get_session():
    header = settings.request.default_headers
    verify = settings.request.ssl_verify
    redirect_limit = settings.request.redirect_limit
    session = requests.Session()
    session.trust_env = False
    session.headers = header
    session.verify = verify
    session.max_redirects = redirect_limit
    return session


def decode_resp_text(resp):
    content = resp.content
    if not content:
        return str('')
    try:
        # 先尝试用utf-8严格解码
        content = str(content, encoding='utf-8', errors='strict')
    except (LookupError, TypeError, UnicodeError):
        try:
            # 再尝试用gb18030严格解码
            content = str(content, encoding='gb18030', errors='strict')
        except (LookupError, TypeError, UnicodeError):
            # 最后尝试自动解码
            content = str(content, errors='replace')
    return content


def get_html_info(resp_queue):
    results = list()
    while not resp_queue.empty():
        index, resp, cidr, ip, port = resp_queue.get()

        if isinstance(resp, Exception):
            title = str(resp.args)
            status_code = None
        else:
            title = get_html_title(decode_resp_text(resp))
            status_code = resp.status_code

        results.append({
            "cidr": cidr,
            "ip": ip,
            "port": port,
            "title": title,
            "status": status_code
        })
    return results


def bulk_request(targets: list):
    logger.log('INFOR', 'Requesting urls in bulk')
    resp_queue = Queue()
    urls_queue = Queue()
    task_count = len(targets)
    for index, itm in enumerate(targets):
        url = itm.get('url')
        cidr = itm.get('cidr')
        ip = itm.get('ip')
        port = itm.get('port')
        urls_queue.put((index, url, cidr, ip, port))
    session = get_session()
    thread_count = req_thread_count()
    if task_count <= thread_count:
        # 如果请求任务数很小不用创建很多线程了
        thread_count = task_count
    bar = get_progress_bar(task_count)

    progress_thread = Thread(target=progress, name='ProgressThread',
                             args=(bar, task_count, urls_queue), daemon=True)
    progress_thread.start()

    for i in range(thread_count):
        request_thread = Thread(target=request, name=f'RequestThread-{i}',
                                args=(urls_queue, resp_queue, session), daemon=True)
        request_thread.start()

    urls_queue.join()
    return resp_queue


def run_request(targets: list):
    """
    HTTP request entrance

    :param  str domain: domain to be requested
    :param  list data: subdomains data to be requested
    :param  any port: range of ports to be requested
    :return list: result
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logger.log('INFOR', f'Start requesting HTTP service')
    resp_queue = bulk_request(targets)
    results = get_html_info(resp_queue)
    logger.log('INFOR', f'Finish requesting HTTP service')
    return results
