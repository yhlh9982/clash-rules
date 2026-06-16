import requests
import re
from urllib.parse import urlparse
from pathlib import Path
import ipaddress
import shutil
import sys


# =========================
# 路径配置
# =========================

DATA_DIR = Path("data")
SOURCE_DIR = DATA_DIR / "source"
PRODUCT_DIR = Path("product")

# 你自己维护的规则
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

# Tracker 原始列表
TRACKER_URL = "https://raw.githubusercontent.com/adysec/tracker/main/trackers_all.txt"
TRACKER_RAW_FILE = SOURCE_DIR / "trackers_all.txt"
TRACKER_DOMAIN_PRODUCT = PRODUCT_DIR / "trackers_domain.txt"
TRACKER_IP_PRODUCT = PRODUCT_DIR / "trackers_ip.txt"

# Loyalsoldier 规则源
# 注意：这些 .txt 实际内容是 YAML payload 格式
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


# =========================
# 目录准备
# =========================

def prepare_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    PRODUCT_DIR.mkdir(parents=True, exist_ok=True)


# =========================
# 下载函数
# =========================

def download_text(url):
    try:
        print(f"正在下载：{url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"下载失败：{url}")
        print(f"错误信息：{e}")
        return None


def download_file(url, output_path):
    text = download_text(url)

    if text is None:
        return False

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8", newline="\n")

    print(f"已保存到：{output_path}")
    return True


# =========================
# 通用文本处理
# =========================

def read_clean_lines(path):
    """
    读取文本，去掉空行和注释行。
    """
    if not path.exists():
        print(f"文件不存在：{path}")
        return []

    result = []

    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            result.append(line)

    return result


def save_plain_txt(path, items):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for item in items:
            f.write(f"{item}\n")

    print(f"已生成：{path}，共 {len(items)} 条")


# =========================
# Tracker 解析
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

    if not domain:
        return None

    if "." not in domain:
        return None

    if " " in domain:
        return None

    return domain


def ip_to_cidr(ip):
    try:
        ip_obj = ipaddress.ip_address(ip.strip("[]"))

        if ip_obj.version == 4:
            return f"{ip_obj.compressed}/32"
        else:
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

            if line.startswith("#"):
                continue

            # 没有协议头时，补 udp://，方便 urlparse 提取 hostname
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

        if not line:
            continue

        if line.startswith("#"):
            continue

        raw_lines.append(line)

    print(f"获取到 Tracker 原始行数：{len(raw_lines)}")

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

        print(f"已输出到 product：{product_file}")


# =========================
# 自定义规则处理
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
            print("请先创建该文件。")
            sys.exit(1)

        lines = read_clean_lines(source_file)

        # 去重排序，保持 product 内容干净
        lines = sorted(set(lines))

        save_plain_txt(product_file, lines)


# =========================
# 主流程
# =========================

def main():
    prepare_dirs()

    process_custom_rules()
    process_trackers()
    process_loyalsoldier_rules()

    print("")
    print("全部资料收集和整理完成。")
    print("")
    print("输出目录：")
    print(f"  data/source/：下载的原始资料")
    print(f"  product/：   最终用于生成 .mrs 的可读文本")


if __name__ == "__main__":
    main()
