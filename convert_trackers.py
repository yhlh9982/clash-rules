import requests
import re
import shutil
import subprocess
from urllib.parse import urlparse
from pathlib import Path
import ipaddress
import os
import sys


# =========================
# 配置区
# =========================

# Tracker 原始列表
URL = "https://raw.githubusercontent.com/adysec/tracker/main/trackers_all.txt"

# 规则集名称
RULESET_NAME = "trackers"

# 输出目录
DIST_DIR = Path("dist")

# TXT 输出目录
TXT_GEOSITE_DIR = DIST_DIR / "txt" / "geosite"
TXT_GEOIP_DIR = DIST_DIR / "txt" / "geoip"

# MRS 输出目录
MRS_GEOSITE_DIR = DIST_DIR / "mrs" / "geosite"
MRS_GEOIP_DIR = DIST_DIR / "mrs" / "geoip"

# TXT 输出文件
DOMAIN_TXT = TXT_GEOSITE_DIR / f"{RULESET_NAME}.txt"
IP_TXT = TXT_GEOIP_DIR / f"{RULESET_NAME}.txt"

# MRS 输出文件
DOMAIN_MRS = MRS_GEOSITE_DIR / f"{RULESET_NAME}.mrs"
IP_MRS = MRS_GEOIP_DIR / f"{RULESET_NAME}.mrs"

# mihomo 命令
# 如果 mihomo 不在 PATH 中，可以用环境变量指定：
# MIHOMO_BIN=/path/to/mihomo python3 build_trackers_ruleset.py
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")


# =========================
# 目录准备
# =========================

def prepare_dirs():
    TXT_GEOSITE_DIR.mkdir(parents=True, exist_ok=True)
    TXT_GEOIP_DIR.mkdir(parents=True, exist_ok=True)
    MRS_GEOSITE_DIR.mkdir(parents=True, exist_ok=True)
    MRS_GEOIP_DIR.mkdir(parents=True, exist_ok=True)


# =========================
# 下载 Tracker
# =========================

def download_trackers(url):
    try:
        print(f"正在下载 Tracker 列表：{url}")

        response = requests.get(url, timeout=20)
        response.raise_for_status()

        lines = set()

        for raw_line in response.text.splitlines():
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            lines.add(line)

        return lines

    except Exception as e:
        print(f"下载失败：{e}")
        return set()


# =========================
# 判断和规范化
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

    # 域名中至少应包含一个点
    if "." not in domain:
        return None

    # 过滤明显异常内容
    if " " in domain:
        return None

    # 过滤通配符前缀，保持纯域名
    if domain.startswith("*."):
        domain = domain[2:]

    if domain.startswith("."):
        domain = domain[1:]

    if not domain:
        return None

    return domain


def ip_to_cidr(ip):
    """
    将单个 IP 转换为 Mihomo ipcidr rule-set 更适合的 CIDR 表示。

    IPv4:
      1.2.3.4 -> 1.2.3.4/32

    IPv6:
      2001:db8::1 -> 2001:db8::1/128

    注意：
      这里不是 Clash 规则。
      不会生成 IP-CIDR,1.2.3.4/32。
      只会生成 1.2.3.4/32。
    """
    try:
        ip_obj = ipaddress.ip_address(ip.strip("[]"))

        if ip_obj.version == 4:
            return f"{ip_obj.compressed}/32"
        else:
            return f"{ip_obj.compressed}/128"

    except ValueError:
        return None


# =========================
# 解析 Tracker
# =========================

def parse_trackers(lines):
    domains = set()
    ip_cidrs = set()

    for raw_line in lines:
        try:
            line = raw_line.strip()

            if not line:
                continue

            # 如果没有协议头，补 udp://，方便 urlparse 提取 hostname
            #
            # 例如：
            # tracker.example.com:6969/announce
            #
            # 补成：
            # udp://tracker.example.com:6969/announce
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


# =========================
# 保存纯 TXT
# =========================

def save_plain_txt(path, items):
    """
    保存纯文本规则集。

    域名文件示例：
      tracker.example.com
      tracker.opentrackr.org

    IP 文件示例：
      1.2.3.4/32
      2001:db8::1/128

    不写入：
      payload:
      DOMAIN,
      IP-CIDR,
      rules:
      注释
      统计信息
    """
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for item in items:
            f.write(f"{item}\n")

    print(f"已生成 TXT：{path}，共 {len(items)} 条")


# =========================
# Mihomo 检查
# =========================

def check_mihomo():
    if shutil.which(MIHOMO_BIN):
        return True

    if Path(MIHOMO_BIN).exists():
        return True

    print("")
    print("错误：未找到 mihomo，无法生成 .mrs 文件。")
    print("")
    print("请先安装 mihomo，或者通过 MIHOMO_BIN 指定路径。")
    print("")
    print("示例：")
    print("  MIHOMO_BIN=/usr/local/bin/mihomo python3 build_trackers_ruleset.py")
    print("")
    return False


# =========================
# 生成 MRS
# =========================

def convert_to_mrs(input_txt, output_mrs, behavior):
    """
    使用 mihomo convert-ruleset 生成 .mrs。

    behavior:
      domain  -> 域名规则集
      ipcidr  -> IP CIDR 规则集
    """
    cmd = [
        MIHOMO_BIN,
        "convert-ruleset",
        behavior,
        "text",
        str(input_txt),
        str(output_mrs),
    ]

    print(f"正在生成 MRS：{' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True)
        print(f"已生成 MRS：{output_mrs}")

    except subprocess.CalledProcessError as e:
        print(f"生成 MRS 失败：{output_mrs}")
        print(f"错误信息：{e}")
        sys.exit(1)


# =========================
# 主流程
# =========================

def main():
    prepare_dirs()

    lines = download_trackers(URL)

    if not lines:
        print("未获取到任何 Tracker 数据，终止执行。")
        sys.exit(1)

    print(f"获取到 {len(lines)} 行原始 Tracker，开始分类。")

    domains, ip_cidrs = parse_trackers(lines)

    print(f"解析到域名数量：{len(domains)}")
    print(f"解析到 IP/CIDR 数量：{len(ip_cidrs)}")

    # 1. 输出纯 TXT
    save_plain_txt(DOMAIN_TXT, domains)
    save_plain_txt(IP_TXT, ip_cidrs)

    # 2. 检查 mihomo
    if not check_mihomo():
        sys.exit(1)

    # 3. 生成 Mihomo 可用的 .mrs
    convert_to_mrs(DOMAIN_TXT, DOMAIN_MRS, "domain")
    convert_to_mrs(IP_TXT, IP_MRS, "ipcidr")

    print("")
    print("全部处理完成。")
    print("")
    print("输出文件：")
    print(f"  域名 TXT：{DOMAIN_TXT}")
    print(f"  IP TXT：  {IP_TXT}")
    print(f"  域名 MRS：{DOMAIN_MRS}")
    print(f"  IP MRS：  {IP_MRS}")


if __name__ == "__main__":
    main()
