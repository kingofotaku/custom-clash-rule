import requests, yaml, re
url = 'https://dwauhiaoawdibga.bikamanhua.top/sha/bi/gfw?token=833741abb097e5d4c2e40080d52c57b1'
headers = {'User-Agent': 'ClashforWindows/0.19.0'}
resp = requests.get(url, headers=headers)
resp.encoding = 'utf-8'
config = yaml.safe_load(resp.text)
proxies = config.get('proxies', [])
print(f'Total proxies: {len(proxies)}')
if proxies:
    print(f'First proxy name: {proxies[0].get("name")}')
    
exclude_pattern = re.compile(r'(?i)(剩余|套餐|直连|meta|永久网址|到期)')
servers = set()
for proxy in proxies:
    name = proxy.get('name', '')
    if exclude_pattern.search(name):
        continue
    server = proxy.get('server')
    if server:
        servers.add(server)
print(f'Extracted servers: {len(servers)}')
print(servers)
