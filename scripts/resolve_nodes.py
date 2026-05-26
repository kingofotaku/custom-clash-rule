import os
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
    """解析域名获取 IP 列表 (支持 v4/v6，带重试和回退机制)"""
    ips = set()
    
    # 如果本身已经是合法的 IP，则直接返回
    try:
        if is_valid_ip(domain):
            ips.add(domain)
            return ips
    except Exception:
        pass
        
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '223.5.5.5']
    resolver.timeout = 2
    resolver.lifetime = 3
    
    max_retries = 3
    success = False
    
    for attempt in range(max_retries):
        try:
            # IPv4 解析
            try:
                ans_a = resolver.resolve(domain, 'A')
                for rdata in ans_a:
                    ip = rdata.to_text()
                    if is_valid_ip(ip):
                        ips.add(ip)
                success = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
            # IPv6 解析
            try:
                ans_aaaa = resolver.resolve(domain, 'AAAA')
                for rdata in ans_aaaa:
                    ip = rdata.to_text()
                    if is_valid_ip(ip):
                        ips.add(ip)
                success = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
            if success:
                break
                
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"Failed to resolve {domain} after {max_retries} attempts.")
                
    if not success and not ips:
        # 重试结束后仍无 IP，则回退保留原始域名
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

def process_subscription(url):
    """处理单个订阅链接"""
    servers = set()
    headers = {
        # 伪装成 Clash Meta 客户端，触发机场下发完整节点配置
        'User-Agent': 'clash.meta'
    }
    print(f"Fetching: {url}")
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        resp.encoding = 'utf-8'
        content = resp.text
        
        # 尝试作为 YAML 解析
        parsed_servers = parse_clash_yaml(content)
        if parsed_servers:
            print(f"Parsed {len(parsed_servers)} unique server domains as YAML.")
            servers.update(parsed_servers)
        else:
            print("Content is not valid Clash YAML or contains 0 proxies. Attempting Base64 decode...")
            # 补齐 base64 padding
            padding_needed = len(content) % 4
            if padding_needed:
                content += '=' * (4 - padding_needed)
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                print(f"Successfully decoded Base64, found {len(decoded.splitlines())} lines. Base64 parsing not fully implemented yet, only YAML is supported.")
            except Exception as e:
                print(f"Not Base64 either. First 100 chars of response: {content[:100]}")
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
    
    return servers

def main():
    airport1 = os.environ.get('AIRPORT1', '').strip()
    airport2 = os.environ.get('AIRPORT2', '').strip()
    
    urls = []
    if airport1:
        urls.append(airport1)
    if airport2:
        urls.append(airport2)
        
    if not urls:
        print("No AIRPORT1 or AIRPORT2 found in environment variables.")
        return
    
    all_servers = set()
    for url in urls:
        all_servers.update(process_subscription(url))
    
    print(f"Total unique servers extracted: {len(all_servers)}")
    
    all_ips = set()
    # 使用线程池并发解析 DNS
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(get_ips_from_domain, all_servers)
        for ips in results:
            all_ips.update(ips)
            
    print(f"Total unique IPs resolved: {len(all_ips)}")
    
    # 写入 Rule-Provider 文件
    output_file = 'airport_nodes.yaml'
    
    # 按照 IP 排序输出
    sorted_ips = sorted(list(all_ips))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for item in sorted_ips:
            if item.startswith("DOMAIN:"):
                f.write(f"  - DOMAIN,{item.split(':', 1)[1]}\n")
            elif ':' in item:
                f.write(f"  - IP-CIDR6,{item}/128\n")
            else:
                f.write(f"  - IP-CIDR,{item}/32\n")
                
    print(f"Successfully wrote {len(sorted_ips)} IPs to {output_file}")

if __name__ == '__main__':
    main()
