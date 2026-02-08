from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlencode, urlparse

import os, re, ssl, math, time, json, secrets, asyncio, aiohttp, hashlib, requests

# user: https://www.goofish.com/personal?userId=391299371
# item: https://www.goofish.com/item?id=1006651726943
# main: https://www.goofish.com

ITEMLIST_API = 'mtop.idle.web.xyh.item.list'
DETAIL_API   = 'mtop.taobao.idle.pc.detail'
USER_API     = 'mtop.idle.web.user.page.head'
COOKIE_API   = 'mtop.taobao.widgetservice.getjsoncomponent'
TEST_URL     = 'https://www.goofish.com/item?id=1006651726943' 
TIMEOUT      = 5  # hard fail fast
ASHERROR     = -123

def log(text):
    if 0 == 1: print(f"LOG: {text}")

def get_decimal(text):
    return int(re.findall(r'\d+', text)[0])

def get_float(text):
    return float(re.findall(r'\d+', text)[0])

def load_proxies(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def headers(url=TEST_URL):
    return {
        'Referer': f'{url}',
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
    }

def params(ts, sign, api, cnt, data):
    return {
        'jsv': '2.7.2',
        'appKey': '34839810',
        't': ts,
        'sign': sign,
        'v': '1.0',
        'type': 'originaljson',
        'accountSite': 'xianyu',
        'dataType': 'json',
        'timeout': '20000',
        'api': api,
        'sessionOption': 'AutoLoginOnly',
        'spm_cnt': cnt,
        'data': data
    }

def getProxyCookies(proxy):
    driver = None
    try:
        options = Options()
        options.page_load_strategy = "none"
        
        if proxy:
            options.add_argument(f'--proxy-server={proxy}')

        driver = webdriver.Chrome(options=options)
        driver.minimize_window()
        
        print(f"Loading placeholder page: {TEST_URL}\n")
        driver.get(TEST_URL)

        title = driver.title.lower()
        page = driver.page_source.lower()
        
        if (
            "privacy error" in title or
            "your connection is not private" in title or
            "net::err_cert" in page or
            "main-frame-error" in page
        ):
            raise RuntimeError("Privacy / SSL error detected (bad proxy)")

        cookies = [WebDriverWait(driver, 30).until(lambda d: d.get_cookie(name)) for name in ['_m_h5_tk', '_m_h5_tk_enc']]

        return {c['name']: c['value'] for c in cookies}

    except Exception as e:
        log(e)
        if driver:
            driver.quit()
        if "Privacy / SSL error detected (bad proxy)" in str(e):
            return ASHERROR
        return None
    finally:
        if driver:
            driver.quit()

async def fetch_single_item(session, item_id, cookies, proxy):
    data_json = json.dumps({"itemId": str(item_id)}, separators=(',', ':'))
    ts = str(int(time.time() * 1000))
    token = cookies['_m_h5_tk'].split('_')[0]
    sign = hashlib.md5(f"{token}&{ts}&34839810&{data_json}".encode()).hexdigest()
    try:
        async with session.get(f"https://h5api.m.goofish.com/h5/{DETAIL_API}/1.0/", params=params(ts, sign, DETAIL_API, 'a21ybx.item.0.0', data_json), 
                               headers=headers(f"https://www.goofish.com/item?id={item_id}"), cookies=cookies, proxy=proxy, timeout=60) as resp:
            return await resp.json()
    except Exception as e:
        return None

async def fetch_item_detail_async(item_ids, cookies, proxy):
    if not isinstance(item_ids, list):
        item_ids = [item_ids]
    results = []
    connector = aiohttp.TCPConnector(limit=len(item_ids))  # limit concurrent connections
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_single_item(session, item_id, cookies, proxy) for item_id in item_ids]
        results = await asyncio.gather(*tasks)
    return results

def print_item_info(data):
    if not data: return print("No data found")
    if data.get('ret', ['SUCCESS::调用成功'])[0] != 'SUCCESS::调用成功':
        print(f"API Error: {data.get('ret')}\nFull response: {json.dumps(data, ensure_ascii=False, indent=2)}")
        return
    item = data.get('data', {}).get('itemDO')
    if not item:
        print(f"No itemDO found. Keys: {list(data.get('data', {}).keys())}\nResponse snippet: {json.dumps(data, ensure_ascii=False, indent=2)[:500]}...")
        return
    print("\n" + "="*60)
    print(f"Title: {item.get('title', 'N/A')}\nPrice: ¥{item.get('soldPrice', 'N/A')}\nItem ID: {item.get('itemId', 'N/A')}")
    print("="*60)
    print(f"\nDescription:\n{item.get('desc', 'N/A')}")
    print(f"\nLabels:")
    for label in item.get('itemLabelExtList', []):
        print(f"  • {label.get('text', '')}")
    print("\nStats:")
    print(f"  Views: {item.get('browseCnt',0)}  Wants: {item.get('wantCnt',0)}  Collects: {item.get('collectCnt',0)}")
    print(f"\nCreated: {item.get('GMT_CREATE_DATE_KEY','N/A')}")
    print(f"URL: https://www.goofish.com/item?id={item.get('itemId','')}")
    print("="*60 + "\n")

async def check_proxy(session, proxy):
    start = time.time()
    try:
        # Ensure proxy has a scheme
        proxy = str(proxy)
        if not proxy.startswith(("http://", "https://", "socks4://", "socks5://")):
            proxy = f"http://{proxy}"
            
        async with session.get(
            TEST_URL,
            proxy=proxy,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            headers=headers(),
            allow_redirects=False,
        ) as resp:
            if resp.status in (200, 302):
                latency = time.time() - start
                log(f"✅ {proxy} | {resp.status} | {latency:.2f}s")
                return proxy, True, latency
            else:
                log(f"⚠️ {proxy} | {resp.status}")
    except aiohttp.ClientSSLError as e:
        log(f"❌ {proxy} | SSL / Privacy error: {e}")
    except ssl.SSLError as e:
        log(f"❌ {proxy} | SSL / Privacy error: {e}")
    except aiohttp.ClientProxyConnectionError:
        log(f"❌ {proxy} | Proxy connection error")
    except aiohttp.ClientHttpProxyError:
        log(f"❌ {proxy} | Bad request / unsupported proxy")
    except aiohttp.ServerDisconnectedError:
        log(f"❌ {proxy} | Server disconnected")
    except Exception as e:
        log(f"❌ {proxy} | {type(e).__name__}: {e}")
    
    return proxy, False, None

async def test_proxies_concurrently(proxies, concurrency=200):
    connector = aiohttp.TCPConnector(
        limit=concurrency,
        ssl=False,            # faster, we only care if CONNECT works
        ttl_dns_cache=300
    )
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    results = []
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout
    ) as session:
        tasks = [
            check_proxy(session, p)
            for p in proxies
        ]
        for coro in asyncio.as_completed(tasks):
            proxy, ok, latency = await coro
            if ok:
                # print(f"✅ {proxy} | {latency:.2f}s")
                results.append((proxy, ok, latency))
    return results

def getIndividualInfo(item_ids, cookies, proxy, show_info):
    unfiltered_results = asyncio.run(fetch_item_detail_async(item_ids, cookies, proxy))
    filtered_results = [result for result in unfiltered_results if result and result.get('ret') == ['SUCCESS::调用成功']]
    results = {}
    total = len(filtered_results)
    print(f"Awaited: {len(item_ids)} Got: {total}\n")
    if total > 0 and len(item_ids) == total:
        for index, result in enumerate(filtered_results):
            if show_info:
                print_item_info(result)
            if 'data' in result and 'itemDO' in result['data']:
                id = result['data']['itemDO'].get('itemId', 'N/A')
                title = result['data']['itemDO'].get('title', 'N/A')
                labels = [l['text'] for l in result['data']['itemDO'].get('itemLabelExtList', [])]
                results.update({str(id): {"title": title, "labels": labels}})
    else:
        print("Failed to fetch items\n")
        return ASHERROR, results
    return 1, results

def getCookies(user_id):
    start = time.time()
    options = Options()
    options.page_load_strategy = "none"
    driver = webdriver.Chrome(options=options)
    driver.minimize_window()
    try:
        driver.get(f"https://www.goofish.com/personal?userId={user_id}")
        cookies = [WebDriverWait(driver, 30).until(lambda d: d.get_cookie(name)) for name in ['_m_h5_tk', '_m_h5_tk_enc']]
        # for cookie in cookies:
        #     name = cookie['name']
        #     expiry = datetime.fromtimestamp(cookie['expiry'])
        #     delta = expiry - datetime.now()
        #     h, rem = divmod(int(delta.total_seconds()), 3600)
        #     m, s = divmod(rem, 60)
        #     formatted = f"{h:02d}:{m:02d}:{s:02d}"
        #     print(f"{name} {formatted}")
        print(f"GetCookies took {(time.time() - start):.2f} seconds\n")
        return {c['name']: c['value'] for c in cookies}
    except Exception as e:
        print(f"Error getting cookies: {e}")
        raise
    finally:
        driver.quit()

def genFakeCookies(proxy): # we use fake/empty cookies to get the real
    ts = str(int(time.time() * 1000))
    url = f"https://h5api.m.goofish.com/h5/{COOKIE_API}/1.0/"
    cookies = {'_m_h5_tk':'','_m_h5_tk_enc':''}
    with requests.get(url=url, params=params(ts, None, COOKIE_API, None, None), headers=headers(url), cookies=cookies, proxies={"http":proxy}) as resp: 
        if len(resp.cookies) > 0 and resp.cookies['_m_h5_tk_enc'] and resp.cookies['_m_h5_tk']: 
            cookies['_m_h5_tk_enc'] = resp.cookies['_m_h5_tk_enc']
            cookies['_m_h5_tk']     = resp.cookies['_m_h5_tk']
    return cookies

async def fetch_single_page(session, user_id, page_number, page_size, cookies):
    data_dict = {
        "needGroupInfo": True,
        "pageNumber": page_number,
        "userId": user_id,
        "pageSize": page_size
    }
    data_json = json.dumps(data_dict, separators=(',', ':'), ensure_ascii=False)
    ts = str(int(time.time() * 1000))
    token = cookies['_m_h5_tk'].split('_')[0]
    sign = hashlib.md5(f"{token}&{ts}&34839810&{data_json}".encode()).hexdigest()

    try:
        async with session.post(f"https://h5api.m.goofish.com/h5/{ITEMLIST_API}/1.0/", params=params(ts, sign, ITEMLIST_API, 'a21ybx.personal.0.0', data_json),
                                headers=headers(), cookies=cookies, timeout=60) as resp:
            return await resp.json()
    except Exception as e:
        return None

async def fetch_all_pages_async(user_id, pages_total, page_size, cookies_dict):
    all_items = []
    connector = aiohttp.TCPConnector(limit=20)  # limit concurrent connections
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_single_page(session, user_id, page, page_size, cookies_dict) for page in range(1, pages_total + 1)]
        results = await asyncio.gather(*tasks)
        for page, result in enumerate(results, 1):
            if not result or result.get('ret') != ['SUCCESS::调用成功']:
                log(f"✗ Failed on page {page}/{pages_total}")
                if page == 1:
                    print(result)
                    exit(1)
                continue

            items = result.get('data', {}).get('cardList', [])
            log(f"✓ Retrieved {len(items)} items on page {page}/{pages_total}")
            all_items.extend(items)
    return all_items

async def fisrt_response(user_id, cookies):
    async with aiohttp.ClientSession() as session:
        res = await fetch_single_page(session, user_id, 1, 0, cookies)
        groups = {g['groupName']: g for g in res['data']['itemGroupList']}
        return groups.get('全部', {}).get('itemNumber', 0), groups.get('在售', {}).get('itemNumber', 0)

def getMultipleItems(user_id, cookies, page_size=20):
    total, items = asyncio.run(fisrt_response(user_id, cookies))
    print(f"A total of {items}/{total} itens are for sale from seller ({user_id})\n")
    pages_total = math.ceil(items / page_size)
    results = asyncio.run(fetch_all_pages_async(user_id=user_id, pages_total=pages_total, page_size=page_size, cookies_dict=cookies))
    return sorted(results, key=lambda x: (get_float(x["cardData"]["priceInfo"]["price"])*10000.0) if '万' in x["cardData"]["priceInfo"]["price"] else float(x["cardData"]["priceInfo"]["price"]))

def getFastestProxy(proxies):
    results = asyncio.run(test_proxies_concurrently(proxies, concurrency=200))
    working = [(p, l) for p, ok, l in results if ok]
    if not working:
        log("No proxies available\n")
        return False, None
    working.sort(key=lambda x: x[1])
    fastestProxy = working[0][0]
    # Remove the fastest proxy from the original list
    if fastestProxy[7:] in proxies:
        proxies.remove(fastestProxy[7:])
    log(f"Fastest proxy: {fastestProxy} | Latency: {working[0][1]:.2f}s\n")
    return True, fastestProxy

class Goofish():
    def __init__(self, users, yuanBase, yuanTax):
        self.yuanMaximum  = None
        self.yuanBase     = yuanBase
        self.yuanTax      = yuanTax
        self.users        = users
        self.cookies      = None
        self.interest     = []
        self.fastestProxy = None
        self.proxies      = []

    def proxy(self, path):
        if len(self.proxies) <= 0 and path is not None:
            self.proxies = load_proxies(path)
        hasProxy, fastestProxy = getFastestProxy(self.proxies)
        self.fastestProxy = fastestProxy
        print(f"Got proxy {self.fastestProxy}\n")
        return self

    def cookie(self):
        self.cookies = genFakeCookies(self.fastestProxy)
        print(f"_m_h5_tk:     {self.cookies['_m_h5_tk']}")
        print(f"_m_h5_tk_enc: {self.cookies['_m_h5_tk_enc']}\n")
        return self

    def interested(self, yuanMaximum):
        self.yuanMaximum = yuanMaximum
        for user in self.users:
            vendor = getMultipleItems(user, self.cookies)
            for item in vendor:
                card            =  item['cardData']
                itemStatus      =  card['itemStatus']
                priceInfo       =  card['priceInfo'] 
                if itemStatus   == 1: continue # ignore non sellable itens
                title           =  card['title']
                categoryId      =  card['categoryId']
                id              =  card['detailParams']['itemId']
                pricePreText    =  priceInfo['preText']
                price           = (get_float(priceInfo['price'])*10000.0) if '万' in priceInfo['price'] else float(priceInfo['price'])
                priceCalculated = (price*yuanBase*yuanTax)
                if (price <= self.yuanMaximum): 
                    self.interest.append({
                        "title": title,
                        "categoryId": categoryId,
                        "id": id,
                        "pricePreText": pricePreText,
                        "price": price,
                        "priceCalculated": priceCalculated,
                    })
        return self
    
    def details(self):
        error, results = getIndividualInfo([g['id'] for g in self.interest], self.cookies, self.fastestProxy, False)
        if error != ASHERROR:
            for g in self.interest:
                g['detail'] = results[g['id']]
        else:
            if len(self.proxies) > 0: 
                self.proxy(None)
                self.cookie()
                self.details()
        return self
    
    def filter(self):
        for g in self.interest[:]:
            if g.get('detail') is None: continue
            title = g['detail']['title']
            labels = g['detail']['labels']
            if '海外有锁' in labels:
                log(f"{title} | {g['id']} | Bloqueado no exterior")
                self.interest.remove(g)
            elif '海外无锁' in labels:
                log(f"{title} | {g['id']} | Sem bloqueio no exterior")
            else:
                log(f"{title} | {g['id']} | Labels {labels}")
        return self

    def by(self, fn):
        self.interest.sort(key=fn)
        return self

if __name__ == "__main__":
    users = {
        "triste":     "3300819188",    # personal
        "precinho":   "391299371",     # perfect
        "generoso":   "2206724161961", # good
        "simon":      "625270896",     # bad
        "dandan":     "2218106941844", # ipone
        "placavideo": "2219652125665", # test
    }

    yuanMaximum = 3000.0
    yuanBase    = 0.76
    yuanTax     = 1.08
    start       = time.time()
    
    urs = [users["triste"], users["precinho"], users['generoso']]

    g = (Goofish(urs, yuanBase, yuanTax)
        # .proxy(r"C:\Users\Administrator\Downloads\http_proxies.txt")
        .cookie()
        .interested(yuanMaximum)
        .details()
        .filter()
        .by(lambda item: item['priceCalculated'])
    )

    for item in g.interest: # ({', '.join(map(str, item['detail']['labels']))}) |
        print(f'({item['title']}) | R${item['priceCalculated']:.2f} | https://www.goofish.com/item?id={item['id']}')
    print()

    print(f"Everything took {(time.time() - start):.2f} seconds\n")