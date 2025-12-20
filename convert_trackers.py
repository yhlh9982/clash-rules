import requests
import re
from urllib.parse import urlparse
import ipaddress

# =========================
# 配置区
# =========================

URL = "https://raw.githubusercontent.com/adysec/tracker/main/trackers_all.txt"

# 原始数据输出
FILE_DOMAIN_RAW = "trackers_domain_raw.txt"
FILE_IP_RAW = "trackers_ip_raw.txt"

# Clash 规则输出
FILE_DOMAIN_CLASH = "trackers_domain.yaml"
FILE_IP_CLASH = "trackers_ip.yaml"


# =========================
# 工具函数
# =========================

def get_trackers(url):
    try:
        print(f"正在下载 Tracker 列表: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        lines = set(
            line.strip()
            for line in response.text.splitlines()
            if line.strip()
        )
        return lines
    except Exception as e:
        print(f"下载失败: {e}")
        return set()


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# =========================
# 解析逻辑
# =========================

def parse_trackers(lines):
    domains = set()
    ips = set()

    for line in lines:
        try:
            # 修复无 scheme 的 tracker
            if not re.match(r'^[a-zA-Z]+://', line):
                line = 'udp://' + line

            parsed = urlparse(line)
            host = parsed.hostname

            if not host:
                continue

            host = host.strip("[]")

            if is_ip(host):
                ips.add(host)
            else:
                if '.' in host:
                    domains.add(host)

        except Exception:
            continue

    return sorted(domains), sorted(ips)


# =========================
# 保存原始数据
# =========================

def save_raw_list(filename, items, title):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"# {title}\n")
        f.write(f"# Count: {len(items)}\n\n")
        for item in items:
            f.write(f"{item}\n")
    print(f"已生成 {filename}（{len(items)} 条）")


# =========================
# 生成 Clash 规则
# =========================

def generate_clash_domain_rules(domains):
    return [f"  - DOMAIN,{d}" for d in domains]


def generate_clash_ip_rules(ips):
    rules = []
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                rules.append(f"  - IP-CIDR,{ip}/32")
            else:
                rules.append(f"  - IP-CIDR6,{ip}/128")
        except ValueError:
            continue
    return rules


def save_clash_yaml(filename, rules, title):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        f.write(f"  # {title}\n")
        f.write(f"  # Count: {len(rules)}\n")
        for rule in rules:
            f.write(f"{rule}\n")
    print(f"已生成 {filename}（{len(rules)} 条）")


# =========================
# 主流程
# =========================

if __name__ == "__main__":
    lines = get_trackers(URL)

    if not lines:
        print("未获取到任何数据，终止执行")
        exit(1)

    print(f"获取到 {len(lines)} 行原始 Tracker，开始解析...")

    domains, ips = parse_trackers(lines)

    # 1️⃣ 输出原始情报
    save_raw_list(FILE_DOMAIN_RAW, domains, "Tracker Domains (raw)")
    save_raw_list(FILE_IP_RAW, ips, "Tracker IPs (IPv4 + IPv6 raw)")

    # 2️⃣ 生成 Clash 规则
    domain_rules = generate_clash_domain_rules(domains)
    ip_rules = generate_clash_ip_rules(ips)

    save_clash_yaml(FILE_DOMAIN_CLASH, domain_rules, "Tracker Domains (Clash)")
    save_clash_yaml(FILE_IP_CLASH, ip_rules, "Tracker IPs (Clash)")

    print("全部处理完成 ✔")
