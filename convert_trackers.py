import requests
import re
from urllib.parse import urlparse
import ipaddress

# 源地址
URL = "https://raw.githubusercontent.com/adysec/tracker/main/trackers_all.txt"

# 输出文件名
FILE_DOMAIN = "trackers_domain.yaml"
FILE_IP = "trackers_ip.yaml"

def get_trackers(url):
    try:
        print(f"正在下载 Tracker 列表: {url} ...")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        # 按行分割，去重，去空
        lines = set(line.strip() for line in response.text.split('\n') if line.strip())
        return lines
    except Exception as e:
        print(f"下载失败: {e}")
        return []

def is_ip(host):
    """判断是否为IP地址 (IPv4 或 IPv6)"""
    try:
        # 移除可能存在的 IPv6 方括号
        clean_host = host.strip("[]")
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False

def parse_trackers(lines):
    domains = set()
    ips = set()

    for line in lines:
        try:
            # 简单修复一些不规范的写法，确保 urlparse 能解析
            if not re.match(r'^[a-zA-Z]+://', line):
                line = 'udp://' + line

            parsed = urlparse(line)
            host = parsed.hostname
            
            if not host:
                continue

            if is_ip(host):
                # 处理 IP
                clean_ip = host.strip("[]")
                try:
                    # 验证是否为有效 IP
                    ip_obj = ipaddress.ip_address(clean_ip)
                    if isinstance(ip_obj, ipaddress.IPv4Address):
                        ips.add(f"  - IP-CIDR,{clean_ip}/32")
                    elif isinstance(ip_obj, ipaddress.IPv6Address):
                        ips.add(f"  - IP-CIDR6,{clean_ip}/128")
                except ValueError:
                    pass
            else:
                # 处理域名
                # 排除无效域名（如 localhost 等）
                if '.' in host:
                    domains.add(f"  - DOMAIN,{host}")
        except Exception:
            continue
            
    return sorted(list(domains)), sorted(list(ips))

def save_to_yaml(filename, rules, type_name):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"payload:\n")
        f.write(f"  # {type_name} Trackers List\n")
        f.write(f"  # Count: {len(rules)}\n")
        for rule in rules:
            f.write(f"{rule}\n")
    print(f"已生成 {filename}，包含 {len(rules)} 条规则。")

if __name__ == "__main__":
    lines = get_trackers(URL)
    if lines:
        print(f"获取到 {len(lines)} 行原始数据，开始处理...")
        domain_rules, ip_rules = parse_trackers(lines)
        
        save_to_yaml(FILE_DOMAIN, domain_rules, "Domain")
        save_to_yaml(FILE_IP, ip_rules, "IP")
        print("处理完成！")
