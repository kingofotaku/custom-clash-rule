import os
import yaml
import socket
import requests
import base64
import urllib.parse
import ipaddress
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
    """解析域名获取 IP 列表"""
    ips = set()
    try:
        # socket.getaddrinfo returns a list of 5-tuples
        # (family, type, proto, canonname, sockaddr)
        # sockaddr is (IP, port) for IPv4
        results = socket.getaddrinfo(domain, None)
        for result in results:
            ip = result[4][0]
            if is_valid_ip(ip):
                ips.add(ip)
    except Exception as e:
        print(f"Failed to resolve {domain}: {e}")
    return ips

def parse_clash_yaml(content):
    """解析 Clash YAML 提取 server"""
    servers = set()
    try:
        config = yaml.safe_load(content)
        if config and 'proxies' in config:
            for proxy in config['proxies']:
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
        # 伪装成 Clash 客户端，触发机场下发 Clash 格式配置
        'User-Agent': 'ClashforWindows/0.19.0'
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
            print(f"Parsed {len(parsed_servers)} servers as YAML.")
            servers.update(parsed_servers)
        else:
            # 如果不是 YAML，可能是 Base64 编码的 vmess/ss 链接，简单做后备处理
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                # 简单粗暴正则或者分行提取 (这只是一个简单的 fallback)
                print("Content might be base64. Base64 processing not fully implemented. Please ensure airport supports Clash UA.")
            except:
                pass
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
        for ip in sorted_ips:
            # 简单判断 IPv6
            if ':' in ip:
                f.write(f"  - IP-CIDR6,{ip}/128\n")
            else:
                f.write(f"  - IP-CIDR,{ip}/32\n")
                
    print(f"Successfully wrote {len(sorted_ips)} IPs to {output_file}")

if __name__ == '__main__':
    main()
