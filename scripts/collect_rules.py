import ipaddress
import re
import shutil
import sys
import tarfile
from pathlib import Path
from urllib.parse import urlparse

import requests


# =========================
# 路径配置
# =========================

DATA_DIR = Path("data")
SOURCE_DIR = DATA_DIR / "source"
PRODUCT_DIR = Path("product")

CUSTOM_RULES = [
    {
        "name": "Jcdn",
        "source_file": DATA_DIR / "Jcdn.txt",
        "product_file": PRODUCT_DIR / "Jcdn.txt",
    },
    {
        "name": "Jweb",
        "source_file": DATA_DIR / "Jweb.txt",
        "product_file": PRODUCT_DIR / "Jweb.txt",
    },
]

TRACKER_URL = "https://raw.githubusercontent.com/adysec/tracker/main/trackers_all.txt"
TRACKER_RAW_FILE = SOURCE_DIR / "trackers_all.txt"
TRACKER_DOMAIN_PRODUCT = PRODUCT_DIR / "trackers_domain.txt"
TRACKER_IP_PRODUCT = PRODUCT_DIR / "trackers_ip.txt"

LOYALSOLDIER_RULES = [
    {
        "name": "proxy",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
        "source_file": SOURCE_DIR / "proxy.yaml",
        "product_file": PRODUCT_DIR / "proxy.yaml",
    },
    {
        "name": "direct",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
        "source_file": SOURCE_DIR / "direct.yaml",
        "product_file": PRODUCT_DIR / "direct.yaml",
    },
    {
        "name": "reject",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
        "source_file": SOURCE_DIR / "reject.yaml",
        "product_file": PRODUCT_DIR / "reject.yaml",
    },
    {
        "name": "cncidr",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt",
        "source_file": SOURCE_DIR / "cncidr.yaml",
        "product_file": PRODUCT_DIR / "cncidr.yaml",
    },
]

CNLITE_CATEGORY_FILE = DATA_DIR / "cnlite_geosite.txt"
CNLITE_PRODUCT_FILE = PRODUCT_DIR / "cnlite.txt"

DOMAIN_LIST_ARCHIVE_URL = "https://github.com/v2fly/domain-list-community/archive/refs/heads/master.tar.gz"
DOMAIN_LIST_ARCHIVE_FILE = SOURCE_DIR / "domain-list-community.tar.gz"
DOMAIN_LIST_EXTRACT_DIR = SOURCE_DIR / "domain-list-community"
DOMAIN_LIST_DATA_DIR = DOMAIN_LIST_EXTRACT_DIR / "data"


# =========================
# 基础工具
# =========================

def prepare_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    PRODUCT_DIR.mkdir(parents=True, exist_ok=True)


def download_text(url):
    try:
        print(f"正在下载：{url}")
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        return response.text
    except Exception as error:
        print(f"下载失败：{url}")
        print(f"错误信息：{error}")
        return None


def download_binary(url, output_path):
    try:
        print(f"正在下载压缩包：{url}")
        response = requests.get(url, timeout=120, stream=True)
        response.raise_for_status()

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)

        print(f"已保存到：{output_path}")
        return True
    except Exception as error:
        print(f"下载失败：{url}")
        print(f"错误信息：{error}")
        return False


def download_file(url, output_path):
    text = download_text(url)
    if text is None:
        return False

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8", newline="\n")
    print(f"已保存到：{output_path}")
    return True


def read_clean_lines(path):
    if not path.exists():
        print(f"文件不存在：{path}")
        return []

    lines = []
    with open(path, "r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
    return lines


def save_plain_txt(path, items):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as file:
        for item in items:
            file.write(f"{item}\n")
    print(f"已生成：{path}，共 {len(items)} 条")


# =========================
# 自定义规则
# =========================

def process_custom_rules():
    print("")
    print("========== 处理自定义规则 ==========")

    for rule in CUSTOM_RULES:
        name = rule["name"]
        source_file = rule["source_file"]
        product_file = rule["product_file"]

        print("")
        print(f"正在处理自定义规则：{name}")

        if not source_file.exists():
            print(f"自定义规则文件不存在：{source_file}")
            sys.exit(1)

        lines = sorted(set(read_clean_lines(source_file)))
        save_plain_txt(product_file, lines)


# =========================
# Tracker 处理
# =========================

def is_ip(value):
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_domain(domain):
    domain = domain.strip().lower().strip(".")

    if not domain:
        return None

    if domain.startswith("*."):
        domain = domain[2:]

    if domain.startswith("."):
        domain = domain[1:]

    if not domain or "." not in domain or " " in domain:
        return None

    return domain


def ip_to_cidr(ip):
    try:
        ip_obj = ipaddress.ip_address(ip.strip("[]"))
        if ip_obj.version == 4:
            return f"{ip_obj.compressed}/32"
        return f"{ip_obj.compressed}/128"
    except ValueError:
        return None


def parse_trackers(lines):
    domains = set()
    ip_cidrs = set()

    for raw_line in lines:
        try:
            line = raw_line.strip()
            if not line:
                continue

            if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", line):
                line = "udp://" + line

            parsed = urlparse(line)
            host = parsed.hostname
            if not host:
                continue

            host = host.strip("[]").lower()

            if is_ip(host):
                cidr = ip_to_cidr(host)
                if cidr:
                    ip_cidrs.add(cidr)
            else:
                domain = normalize_domain(host)
                if domain:
                    domains.add(domain)
        except Exception:
            continue

    return sorted(domains), sorted(ip_cidrs)


def process_trackers():
    print("")
    print("========== 处理 Tracker 规则 ==========")

    text = download_text(TRACKER_URL)
    if text is None:
        print("Tracker 下载失败，终止。")
        sys.exit(1)

    TRACKER_RAW_FILE.parent.mkdir(parents=True, exist_ok=True)
    TRACKER_RAW_FILE.write_text(text, encoding="utf-8", newline="\n")
    print(f"Tracker 原始文件已保存到：{TRACKER_RAW_FILE}")

    raw_lines = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        raw_lines.append(line)

    domains, ip_cidrs = parse_trackers(raw_lines)

    print(f"解析到 Tracker 域名数量：{len(domains)}")
    print(f"解析到 Tracker IP/CIDR 数量：{len(ip_cidrs)}")

    save_plain_txt(TRACKER_DOMAIN_PRODUCT, domains)
    save_plain_txt(TRACKER_IP_PRODUCT, ip_cidrs)


# =========================
# Loyalsoldier 处理
# =========================

def process_loyalsoldier_rules():
    print("")
    print("========== 处理 Loyalsoldier 规则 ==========")

    for rule in LOYALSOLDIER_RULES:
        name = rule["name"]
        url = rule["url"]
        source_file = rule["source_file"]
        product_file = rule["product_file"]

        print("")
        print(f"正在处理规则：{name}")

        if not download_file(url, source_file):
            print(f"规则下载失败，终止：{name}")
            sys.exit(1)

        product_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, product_file)
        print(f"已输出到：{product_file}")


# =========================
# Geosite 聚合
# =========================

def prepare_domain_list_source():
    if DOMAIN_LIST_EXTRACT_DIR.exists():
        shutil.rmtree(DOMAIN_LIST_EXTRACT_DIR)

    if not download_binary(DOMAIN_LIST_ARCHIVE_URL, DOMAIN_LIST_ARCHIVE_FILE):
        sys.exit(1)

    with tarfile.open(DOMAIN_LIST_ARCHIVE_FILE, "r:gz") as archive:
        archive.extractall(path=SOURCE_DIR)

    extracted_root = SOURCE_DIR / "domain-list-community-master"
    if not extracted_root.exists():
        print("解压后的 domain-list-community 目录不存在。")
        sys.exit(1)

    extracted_root.rename(DOMAIN_LIST_EXTRACT_DIR)

    if not DOMAIN_LIST_DATA_DIR.exists():
        print(f"未找到 geosite 数据目录：{DOMAIN_LIST_DATA_DIR}")
        sys.exit(1)

    print(f"geosite 数据已准备完成：{DOMAIN_LIST_DATA_DIR}")


def normalize_domain_rule(value):
    domain = value.strip().lower().strip()
    if not domain:
        return None
    if domain.startswith("."):
        domain = domain[1:]
    if domain.startswith("*."):
        domain = domain[2:]
    if not domain or "." not in domain or " " in domain:
        return None
    return f"+.{domain}"


def normalize_full_rule(value):
    domain = value.strip().lower().strip()
    if not domain:
        return None
    if domain.startswith("."):
        domain = domain[1:]
    if not domain or "." not in domain or " " in domain:
        return None
    return domain


def parse_geosite_entry(raw_line):
    line = raw_line.split("#", 1)[0].strip()
    if not line:
        return None, None

    if " @" in line:
        line = line.split(" @", 1)[0].strip()

    if ":" not in line:
        return "domain", line

    entry_type, entry_value = line.split(":", 1)
    return entry_type.strip(), entry_value.strip()


def collect_geosite_category(category, seen_categories):
    if category in seen_categories:
        return set()

    seen_categories.add(category)

    category_file = DOMAIN_LIST_DATA_DIR / category
    if not category_file.exists():
        print(f"未找到 geosite 类目文件：{category}")
        sys.exit(1)

    results = set()

    with open(category_file, "r", encoding="utf-8") as file:
        for raw_line in file:
            entry_type, entry_value = parse_geosite_entry(raw_line)
            if not entry_type or not entry_value:
                continue

            if entry_type == "include":
                results.update(collect_geosite_category(entry_value, seen_categories))
                continue

            if entry_type == "domain":
                rule = normalize_domain_rule(entry_value)
                if rule:
                    results.add(rule)
                continue

            if entry_type == "full":
                rule = normalize_full_rule(entry_value)
                if rule:
                    results.add(rule)
                continue

            if entry_type == "regexp":
                continue

            if entry_type == "keyword":
                continue

            if entry_type == "attr":
                continue

            if entry_type == "domain-regexp":
                continue

            if entry_type == "full-regexp":
                continue

            rule = normalize_domain_rule(entry_value)
            if rule:
                results.add(rule)

    return results


def process_cnlite():
    print("")
    print("========== 处理 cnlite geosite 聚合 ==========")

    if not CNLITE_CATEGORY_FILE.exists():
        print(f"缺少类目文件：{CNLITE_CATEGORY_FILE}")
        sys.exit(1)

    prepare_domain_list_source()

    categories = read_clean_lines(CNLITE_CATEGORY_FILE)
    if not categories:
        print("cnlite_geosite.txt 为空，终止。")
        sys.exit(1)

    merged_rules = set()
    for category in categories:
        print(f"提取 geosite 类目：{category}")
        merged_rules.update(collect_geosite_category(category, set()))

    sorted_rules = sorted(merged_rules)
    save_plain_txt(CNLITE_PRODUCT_FILE, sorted_rules)


# =========================
# 主流程
# =========================

def main():
    prepare_dirs()
    process_custom_rules()
    process_trackers()
    process_loyalsoldier_rules()
    process_cnlite()

    print("")
    print("全部资料收集和整理完成。")
    print(f"可读产物目录：{PRODUCT_DIR}")


if __name__ == "__main__":
    main()
