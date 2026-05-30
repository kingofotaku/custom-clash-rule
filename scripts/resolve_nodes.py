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
    """杩囨护鎺夋満鍦虹敤浜庢彁绀鸿妭鐐圭殑鏃犳晥 IP 鎴栧叕鍏?DNS"""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            return False
        # 鎺掗櫎缁忓父琚敤浣?dummy 鑺傜偣鐨?DNS IP
        dummy_ips = {'1.1.1.1', '8.8.8.8', '8.8.4.4', '1.0.0.1', '255.255.255.255', '0.0.0.0'}
        if str(ip) in dummy_ips:
            return False
        return True
    except ValueError:
        return False

def get_ips_from_domain(domain):
    """瑙ｆ瀽鍩熷悕鑾峰彇 IP 鍒楄〃 (缁撳悎 socket 鍘熺敓瑙ｆ瀽涓?dnspython 鍏叡 DNS 瑙ｆ瀽锛屾渶澶у寲鎻愬彇 IP锛屾敮鎸?v4/v6)"""
    ips = set()
    
    try:
        if is_valid_ip(domain):
            ips.add(domain)
            return ips
    except Exception:
        pass
        
    success = False
    max_retries = 3
    
    # 鏂规硶 1锛氬師鐢?Socket 瑙ｆ瀽 (鍒╃敤绯荤粺 DNS 鑾峰彇鏈€浼?CDN 鑺傜偣)
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

    # 鏂规硶 2锛歞nspython 鎸囧畾鍏叡 DNS 瑙ｆ瀽 (鑾峰彇鍏ㄥ眬 Anycast 鑺傜偣)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '223.5.5.5']
    resolver.timeout = 2
    resolver.lifetime = 3
    
    for attempt in range(max_retries):
        try:
            dns_success = False
            # IPv4 瑙ｆ瀽
            try:
                ans_a = resolver.resolve(domain, 'A')
                for rdata in ans_a:
                    ip = rdata.to_text()
                    if is_valid_ip(ip):
                        ips.add(ip)
                dns_success = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
            # IPv6 瑙ｆ瀽
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
        # 涓ょ鏂规硶閮藉け璐ワ紝鍥為€€淇濈暀鍘熷鍩熷悕
        ips.add(f"DOMAIN:{domain}")
        
    return ips

def parse_clash_yaml(content):
    """瑙ｆ瀽 Clash YAML 鎻愬彇 server"""
    servers = set()
    exclude_pattern = re.compile(r"(?i)(鍓╀綑|濂楅|鐩磋繛|meta|姘镐箙缃戝潃|鍒版湡)")
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
    """澶勭悊鍗曚釜璁㈤槄閾炬帴"""
    servers = set()
    headers = {
        # 浼鎴?Clash Meta 瀹㈡埛绔紝瑙﹀彂鏈哄満涓嬪彂瀹屾暣鑺傜偣閰嶇疆
        'User-Agent': 'clash.meta'
    }
    print(f"Fetching: {url}")
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        resp.encoding = 'utf-8'
        content = resp.text
        
        # 灏濊瘯浣滀负 YAML 瑙ｆ瀽
        parsed_servers = parse_clash_yaml(content)
        if parsed_servers:
            print(f"Parsed {len(parsed_servers)} unique server domains as YAML.")
            servers.update(parsed_servers)
        else:
            print("Content is not valid Clash YAML or contains 0 proxies. Attempting Base64 decode...")
            # 琛ラ綈 base64 padding
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
    # 浣跨敤绾跨▼姹犲苟鍙戣В鏋?DNS
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(get_ips_from_domain, all_servers)
        for ips in results:
            all_ips.update(ips)
            
    print(f"Total unique IPs resolved: {len(all_ips)}")
    
    # 鍐欏叆 Rule-Provider 鏂囦欢
    output_file = 'custom_routes.yaml'
    
    masked_items = set()
    for item in all_ips:
        if item.startswith("DOMAIN:"):
            masked_items.add(f"DOMAIN,{item.split(':', 1)[1]}")
        else:
            try:
                # 妯＄硦鍖?IP (IPv4 -> /24, IPv6 -> /64) 浠ヤ繚鎶ら殣绉?
                if ':' in item:
                    net = ipaddress.IPv6Interface(f"{item}/64").network.with_prefixlen
                    masked_items.add(f"IP-CIDR6,{net}")
                else:
                    net = ipaddress.IPv4Interface(f"{item}/24").network.with_prefixlen
                    masked_items.add(f"IP-CIDR,{net}")
            except Exception:
                pass
                
    # 鎸夌収瑙勫垯鎺掑簭杈撳嚭
    sorted_masked = sorted(list(masked_items))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for item in sorted_masked:
            f.write(f"  - {item}\n")
                
    print(f"Successfully wrote {len(sorted_masked)} IPs to {output_file}")

if __name__ == '__main__':
    main()

