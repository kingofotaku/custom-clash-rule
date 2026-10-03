import os
import sys
import time
import json
import yaml
import socket
import requests
import base64
import urllib.parse
import ipaddress
import re
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

def is_valid_ip(ip_str):
    """过滤掉机场用于提示节点的无效 IP 或公共 DNS"""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            return False
        # 排除经常被用作 dummy 节点的 DNS IP
        dummy_ips = {'1.1.1.1', '8.8.8.8', '8.8.4.4', '1.0.0.1', '255.255.255.255', '0.0.0.0'}
        if str(ip) in dummy_ips:
            return False
        return True
    except ValueError:
        return False

def get_ips_from_domain(domain):
    """解析域名获取 IP 列表 (结合 socket 原生解析与 dnspython 公共 DNS 解析，最大化提取 IP，支持 v4/v6)"""
    ips = set()
    
    try:
        if is_valid_ip(domain):
            ips.add(domain)
            return ips
    except Exception:
        pass
        
    success = False
    max_retries = 3
    
    # 方法 1：原生 Socket 解析 (利用系统 DNS 获取最优 CDN 节点)
    for attempt in range(max_retries):
        try:
            results = socket.getaddrinfo(domain, None, family=socket.AF_UNSPEC)
            for result in results:
                ip = result[4][0]
                if is_valid_ip(ip):
                    ips.add(ip)
            if ips:
                success = True
                break
        except Exception:
            pass

    # 方法 2：dnspython 指定公共 DNS 解析 (获取全局 Anycast 节点)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '223.5.5.5']
    resolver.timeout = 2
    resolver.lifetime = 3
    
    for attempt in range(max_retries):
        try:
            dns_success = False
            # IPv4 解析
            try:
                ans_a = resolver.resolve(domain, 'A')
                for rdata in ans_a:
                    ip = rdata.to_text()
                    if is_valid_ip(ip):
                        ips.add(ip)
                dns_success = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
            # IPv6 解析
            try:
                ans_aaaa = resolver.resolve(domain, 'AAAA')
                for rdata in ans_aaaa:
                    ip = rdata.to_text()
                    if is_valid_ip(ip):
                        ips.add(ip)
                dns_success = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
            if dns_success:
                success = True
                break
                
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"dnspython failed to resolve {domain}: {e}")
                
    if not success and not ips:
        # 两种方法都失败，回退保留原始域名 (IP 字面量除外，DOMAIN 规则匹配不了 IP)
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            ips.add(f"DOMAIN:{domain}")
        
    return ips

def parse_clash_yaml(content):
    """解析 Clash YAML 提取 server"""
    servers = set()
    exclude_pattern = re.compile(r"(?i)(剩余|套餐|直连|meta|永久网址|到期)")
    try:
        config = yaml.safe_load(content)
        if config and 'proxies' in config:
            for proxy in config['proxies']:
                name = proxy.get('name', '')
                if exclude_pattern.search(name):
                    continue
                server = proxy.get('server')
                if server:
                    servers.add(server)
    except Exception as e:
        print(f"YAML parsing error: {e}")
    return servers

def parse_node_uris(content):
    """从 base64 解码后的分享链接中提取 server (支持 ss / vmess / trojan / vless / hysteria2 / tuic)"""
    servers = set()
    for line in content.splitlines():
        line = line.strip()
        if '://' not in line:
            continue
        scheme, _, body = line.partition('://')
        scheme = scheme.lower()
        try:
            if scheme == 'vmess':
                # vmess://base64(JSON)，host 在 add 字段
                body = body.split('#', 1)[0]
                info = json.loads(base64.b64decode(body + '=' * (-len(body) % 4)))
                host = info.get('add') or ''
            elif scheme == 'ss':
                # 两种形式: ss://base64(method:pass)@host:port 或 ss://base64(method:pass@host:port)
                body = body.split('#', 1)[0]
                if '@' not in body:
                    body = base64.b64decode(body + '=' * (-len(body) % 4)).decode('utf-8')
                host = urllib.parse.urlsplit('//' + body).hostname or ''
            else:
                # trojan / vless / hysteria2 / tuic 等标准 URL 形式
                host = urllib.parse.urlsplit(line).hostname or ''
            host = str(host).strip()
            if re.fullmatch(r'[0-9A-Za-z._:\[\]-]+', host):
                servers.add(host)
        except Exception:
            continue
    return servers

def decode_base64_text(content):
    """尝试把订阅内容按 Base64 解码为文本 (容忍换行与缺失 padding)"""
    text = re.sub(r'\s+', '', content)
    if not text:
        return None
    text += '=' * (-len(text) % 4)
    for candidate in (text, text.replace('-', '+').replace('_', '/')):
        try:
            return base64.b64decode(candidate).decode('utf-8')
        except Exception:
            continue
    return None

def process_subscription(url):
    """处理单个订阅链接"""
    servers = set()
    headers = {
        # 伪装成 Clash Meta 客户端，触发机场下发完整节点配置
        'User-Agent': 'clash.meta'
    }
    print(f"Fetching: {url}")
    # 抓取失败时重试（含首次共 4 次），退避 5/10/15 秒，吸收瞬时网络抖动
    attempts = 4
    content = None
    for attempt in range(1, attempts + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            resp.encoding = 'utf-8'
            content = resp.text
            break
        except Exception as e:
            print(f"Fetch attempt {attempt}/{attempts} failed for {url}: {e}")
            if attempt < attempts:
                time.sleep(attempt * 5)

    if content is None:
        print(f"Giving up on {url} after {attempts} attempts.")
        return servers

    # 尝试作为 YAML 解析
    parsed_servers = parse_clash_yaml(content)
    if parsed_servers:
        print(f"Parsed {len(parsed_servers)} unique server domains as YAML.")
        servers.update(parsed_servers)
    else:
        print("Content is not valid Clash YAML or contains 0 proxies. Attempting Base64 decode...")
        # 部分机场对非 Clash 客户端下发 base64 内容，解码后可能是 YAML 或节点分享链接
        decoded = decode_base64_text(content)
        if decoded is None:
            print(f"Not Base64 either. First 100 chars of response: {content[:100]}")
        else:
            parsed_servers = parse_clash_yaml(decoded) or parse_node_uris(decoded)
            if parsed_servers:
                print(f"Parsed {len(parsed_servers)} unique servers from Base64 content.")
                servers.update(parsed_servers)
            else:
                print("Base64 decoded, but no servers found inside.")

    return servers

def main():
    urls = []
    for i in range(1, 10):
        url = os.environ.get(f'AIRPORT{i}', '').strip()
        if url:
            urls.append(url)

    if not urls:
        print("No AIRPORT1-AIRPORT9 found in environment variables.")
        return
    
    all_servers = set()
    failed = 0
    for url in urls:
        servers = process_subscription(url)
        if not servers:
            failed += 1
        all_servers.update(servers)

    if failed:
        # 任一订阅失败或为空则不更新白名单（保留上一版），并让 CI 失败以便察觉
        print(f"{failed}/{len(urls)} subscriptions failed or empty, aborting without updating the whitelist.")
        sys.exit(1)
    
    print(f"Total unique servers extracted: {len(all_servers)}")
    
    all_ips = set()
    # 使用线程池并发解析 DNS
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(get_ips_from_domain, all_servers)
        for ips in results:
            all_ips.update(ips)
            
    print(f"Total unique IPs resolved: {len(all_ips)}")
    
    # 写入 Rule-Provider 文件
    output_file = 'custom_routes.yaml'
    
    masked_items = set()
    for item in all_ips:
        if item.startswith("DOMAIN:"):
            masked_items.add(f"DOMAIN,{item.split(':', 1)[1]}")
        else:
            try:
                # 模糊化 IP (IPv4 -> /24, IPv6 -> /64) 以保护隐私
                if ':' in item:
                    net = ipaddress.IPv6Interface(f"{item}/64").network.with_prefixlen
                    masked_items.add(f"IP-CIDR6,{net}")
                else:
                    net = ipaddress.IPv4Interface(f"{item}/24").network.with_prefixlen
                    masked_items.add(f"IP-CIDR,{net}")
            except Exception:
                pass
                
    # 原始域名也加入白名单 (部分代理工具直接把域名交给路由器，此时没有 IP 可匹配)
    for server in all_servers:
        try:
            ipaddress.ip_address(server)
        except ValueError:
            masked_items.add(f"DOMAIN,{server}")

    # 按照规则排序输出
    sorted_masked = sorted(list(masked_items))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for item in sorted_masked:
            f.write(f"  - {item}\n")
                
    print(f"Successfully wrote {len(sorted_masked)} rules to {output_file}")

if __name__ == '__main__':
    main()
