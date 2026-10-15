import ipaddress
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests


DATA_DIR = Path("data")
SOURCE_DIR = DATA_DIR / "source"
PRODUCT_DIR = Path("product")


# 自定义规则源文件。
# product 中统一输出可读的 TXT 文件。
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


# Tracker 规则。
TRACKER_URL = "https://raw.githubusercontent.com/adysec/tracker/main/trackers_all.txt"
TRACKER_RAW_FILE = SOURCE_DIR / "trackers_all.txt"
TRACKER_DOMAIN_PRODUCT = PRODUCT_DIR / "trackers_domain.txt"
TRACKER_IP_PRODUCT = PRODUCT_DIR / "trackers_ip.txt"


# Loyalsoldier 上游文件虽然使用 .txt 后缀，
# 但文件内容是带 payload: 的 YAML rule-set。
#
# product 中继续保留 .txt 后缀，方便查看。
LOYALSOLDIER_RULES = [
    {
        "name": "proxy",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
        "source_file": SOURCE_DIR / "proxy.txt",
        "product_file": PRODUCT_DIR / "proxy.txt",
    },
    {
        "name": "direct",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
        "source_file": SOURCE_DIR / "direct.txt",
        "product_file": PRODUCT_DIR / "direct.txt",
    },
    {
        "name": "reject",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
        "source_file": SOURCE_DIR / "reject.txt",
        "product_file": PRODUCT_DIR / "reject.txt",
    },
    {
        "name": "cncidr",
        "url": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt",
        "source_file": SOURCE_DIR / "cncidr.txt",
        "product_file": PRODUCT_DIR / "cncidr.txt",
    },
]


# cnlite 聚合规则。
CNLITE_CATEGORY_FILE = DATA_DIR / "cnlite_geosite.txt"
CNLITE_PRODUCT_FILE = PRODUCT_DIR / "cnlite.txt"
CNLITE_SOURCE_DIR = SOURCE_DIR / "meta_geosite"

META_RULES_GEOSITE_BASE_URL = (
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite"
)


def prepare_dirs():
    """
    创建需要使用的目录，并删除旧版遗留的 product YAML 文件。
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    PRODUCT_DIR.mkdir(parents=True, exist_ok=True)
    CNLITE_SOURCE_DIR.mkdir(parents=True, exist_ok=True)

    legacy_yaml_files = [
        PRODUCT_DIR / "Jcdn.yaml",
        PRODUCT_DIR / "Jweb.yaml",
        PRODUCT_DIR / "cnlite.yaml",
        PRODUCT_DIR / "trackers_domain.yaml",
        PRODUCT_DIR / "trackers_ip.yaml",
        PRODUCT_DIR / "proxy.yaml",
        PRODUCT_DIR / "direct.yaml",
        PRODUCT_DIR / "reject.yaml",
        PRODUCT_DIR / "cncidr.yaml",
    ]

    for path in legacy_yaml_files:
        if path.exists():
            path.unlink()
            print(f"已删除旧版 YAML 产物：{path}")


def download_text(url):
    """
    下载文本内容。
    """
    try:
        print(f"正在下载：{url}")

        response = requests.get(
            url,
            timeout=60,
        )
        response.raise_for_status()

        return response.text

    except Exception as error:
        print(f"下载失败：{url}")
        print(f"错误信息：{error}")
        return None


def download_file(url, output_path):
    """
    下载文本文件并保存到指定路径。
    """
    text = download_text(url)

    if text is None:
        return False

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        text,
        encoding="utf-8",
        newline="\n",
    )

    print(f"已保存到：{output_path}")
    return True


def read_clean_lines(path):
    """
    读取非空、非注释行。
    """
    if not path.exists():
        print(f"文件不存在：{path}")
        return []

    lines = []

    with path.open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        for raw_line in file:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            lines.append(line)

    return lines


def normalize_custom_rule_line(line):
    """
    兼容普通 TXT 和 YAML 列表片段。

    支持：
        +.example.com
        api.example.com
        - +.example.com
        - api.example.com

    不修改 +.domain 和完整域名的原始语义。
    """
    value = line.strip()

    if not value:
        return None

    if value == "payload:":
        return None

    if value.startswith("#"):
        return None

    if value.startswith("- "):
        value = value[2:].strip()

    if len(value) >= 2:
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]

    value = value.strip()

    if not value:
        return None

    return value


def save_plain_txt(path, items):
    """
    每行保存一条可读规则。
    """
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        for item in items:
            file.write(f"{item}\n")

    print(f"已生成：{path}，共 {len(items)} 条")


def process_custom_rules():
    """
    处理 Jcdn 和 Jweb。
    """
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

        normalized_rules = set()

        for line in read_clean_lines(source_file):
            normalized = normalize_custom_rule_line(line)

            if normalized:
                normalized_rules.add(normalized)

        sorted_rules = sorted(normalized_rules)

        save_plain_txt(
            product_file,
            sorted_rules,
        )


def is_ip(value):
    """
    判断字符串是否为 IPv4 或 IPv6。
    """
    try:
        ipaddress.ip_address(
            value.strip("[]")
        )
        return True

    except ValueError:
        return False


def normalize_domain(domain):
    """
    规范化从 Tracker URL 中取得的主机名。

    Tracker 规则表示明确的 Tracker 主机，
    因此不自动增加 +.。
    """
    value = domain.strip().lower().rstrip(".")

    if not value:
        return None

    if value.startswith("*."):
        value = value[2:]

    if value.startswith("."):
        value = value[1:]

    if not value:
        return None

    if "." not in value:
        return None

    if any(character.isspace() for character in value):
        return None

    return value


def ip_to_cidr(ip):
    """
    将单个 IP 转换为 CIDR。
    """
    try:
        ip_obj = ipaddress.ip_address(
            ip.strip("[]")
        )

        if ip_obj.version == 4:
            return f"{ip_obj.compressed}/32"

        return f"{ip_obj.compressed}/128"

    except ValueError:
        return None


def parse_tracker_line(raw_line):
    """
    从一条 Tracker 地址中提取主机。

    返回：
        ("domain", "tracker.example.com")
        ("ipcidr", "1.2.3.4/32")
        (None, None)
    """
    line = raw_line.strip()

    if not line:
        return None, None

    try:
        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            line,
        ):
            line = "udp://" + line

        parsed = urlparse(line)
        host = parsed.hostname

        if not host:
            return None, None

        host = host.strip("[]").lower()

        if is_ip(host):
            cidr = ip_to_cidr(host)

            if cidr:
                return "ipcidr", cidr

            return None, None

        domain = normalize_domain(host)

        if domain:
            return "domain", domain

        return None, None

    except Exception:
        return None, None


def parse_trackers(lines):
    """
    解析 Tracker 地址并统计合并情况。

    注意：
    多个协议、端口或路径不同但主机相同的 Tracker，
    在 domain/ipcidr 规则中只能形成一条主机规则。
    """
    domains = set()
    ip_cidrs = set()

    parsed_domain_occurrences = 0
    parsed_ip_occurrences = 0
    failed_lines = []

    for raw_line in lines:
        rule_type, value = parse_tracker_line(raw_line)

        if rule_type == "domain":
            parsed_domain_occurrences += 1
            domains.add(value)

        elif rule_type == "ipcidr":
            parsed_ip_occurrences += 1
            ip_cidrs.add(value)

        else:
            failed_lines.append(raw_line)

    stats = {
        "source_lines": len(lines),
        "parsed_lines": (
            parsed_domain_occurrences
            + parsed_ip_occurrences
        ),
        "failed_lines": len(failed_lines),
        "domain_occurrences": parsed_domain_occurrences,
        "ip_occurrences": parsed_ip_occurrences,
        "unique_domains": len(domains),
        "unique_ip_cidrs": len(ip_cidrs),
        "merged_domain_duplicates": (
            parsed_domain_occurrences
            - len(domains)
        ),
        "merged_ip_duplicates": (
            parsed_ip_occurrences
            - len(ip_cidrs)
        ),
        "unique_rules": (
            len(domains)
            + len(ip_cidrs)
        ),
    }

    return (
        sorted(domains),
        sorted(ip_cidrs),
        failed_lines,
        stats,
    )


def print_tracker_stats(stats, failed_lines):
    """
    输出 Tracker 数量检查结果。
    """
    print("")
    print("========== Tracker 数量核对 ==========")
    print(
        f"源文件有效行数："
        f"{stats['source_lines']}"
    )
    print(
        f"成功解析行数："
        f"{stats['parsed_lines']}"
    )
    print(
        f"解析失败行数："
        f"{stats['failed_lines']}"
    )
    print(
        f"域名出现次数："
        f"{stats['domain_occurrences']}"
    )
    print(
        f"IP 出现次数："
        f"{stats['ip_occurrences']}"
    )
    print(
        f"唯一域名规则数："
        f"{stats['unique_domains']}"
    )
    print(
        f"唯一 IP/CIDR 规则数："
        f"{stats['unique_ip_cidrs']}"
    )
    print(
        f"相同域名被合并数量："
        f"{stats['merged_domain_duplicates']}"
    )
    print(
        f"相同 IP 被合并数量："
        f"{stats['merged_ip_duplicates']}"
    )
    print(
        f"最终唯一规则总数："
        f"{stats['unique_rules']}"
    )

    expected_parsed = (
        stats["source_lines"]
        - stats["failed_lines"]
    )

    if stats["parsed_lines"] != expected_parsed:
        print(
            "警告：成功解析统计与预期数量不一致。"
        )

    if stats["unique_rules"] != stats["source_lines"]:
        difference = (
            stats["source_lines"]
            - stats["unique_rules"]
        )

        print(
            "说明：最终唯一规则数与源文件行数不同。"
        )
        print(
            f"差值：{difference}"
        )
        print(
            "原因是相同主机使用不同协议、端口或路径时，"
            "domain/ipcidr 规则只能保留一个唯一主机。"
        )

    if failed_lines:
        print("")
        print("解析失败示例（最多显示 20 条）：")

        for line in failed_lines[:20]:
            print(f"  - {line}")


def process_trackers():
    """
    下载、解析并输出 Tracker 域名和 IP 规则。
    """
    print("")
    print("========== 处理 Tracker 规则 ==========")

    text = download_text(TRACKER_URL)

    if text is None:
        print("Tracker 下载失败，终止。")
        sys.exit(1)

    TRACKER_RAW_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    TRACKER_RAW_FILE.write_text(
        text,
        encoding="utf-8",
        newline="\n",
    )

    print(
        f"Tracker 原始文件已保存到："
        f"{TRACKER_RAW_FILE}"
    )

    raw_lines = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        raw_lines.append(line)

    (
        domains,
        ip_cidrs,
        failed_lines,
        stats,
    ) = parse_trackers(raw_lines)

    print_tracker_stats(
        stats,
        failed_lines,
    )

    save_plain_txt(
        TRACKER_DOMAIN_PRODUCT,
        domains,
    )

    save_plain_txt(
        TRACKER_IP_PRODUCT,
        ip_cidrs,
    )

    written_total = len(domains) + len(ip_cidrs)

    if written_total != stats["unique_rules"]:
        print("错误：写入规则数量与统计数量不一致。")
        sys.exit(1)

    print(
        f"Tracker 最终输出规则总数："
        f"{written_total}"
    )


def process_loyalsoldier_rules():
    """
    下载 Loyalsoldier 标准 payload rule-set。

    文件在 product 中使用 .txt 后缀，
    内容保持上游原样。
    """
    print("")
    print("========== 处理 Loyalsoldier 规则 ==========")

    for rule in LOYALSOLDIER_RULES:
        name = rule["name"]
        url = rule["url"]
        source_file = rule["source_file"]
        product_file = rule["product_file"]

        print("")
        print(f"正在处理规则：{name}")

        if not download_file(
            url,
            source_file,
        ):
            print(f"规则下载失败，终止：{name}")
            sys.exit(1)

        product_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copyfile(
            source_file,
            product_file,
        )

        print(f"已输出到：{product_file}")


def normalize_geosite_line(line):
    """
    转换 MetaCubeX geosite list。

    full:example.com
        -> example.com

    domain:example.com
        -> +.example.com

    example.com
        -> +.example.com
    """
    value = line.strip()

    if not value:
        return None

    if value.startswith("full:"):
        domain = value[5:].strip().lower()

        if not domain:
            return None

        if "." not in domain:
            return None

        if any(
            character.isspace()
            for character in domain
        ):
            return None

        return domain

    if value.startswith("domain:"):
        domain = (
            value[7:]
            .strip()
            .lower()
            .strip(".")
        )

        if not domain:
            return None

        if "." not in domain:
            return None

        if any(
            character.isspace()
            for character in domain
        ):
            return None

        return f"+.{domain}"

    # regexp: 和 keyword: 不能直接放入 domain behavior。
    if ":" in value:
        return None

    value = value.lower().strip()

    if not value:
        return None

    if "." not in value:
        return None

    if any(
        character.isspace()
        for character in value
    ):
        return None

    if value.startswith("+."):
        return value

    if value.startswith("."):
        return f"+{value}"

    return f"+.{value}"


def process_cnlite():
    """
    聚合 cnlite 类目。
    """
    print("")
    print("========== 处理 cnlite 聚合规则 ==========")

    if not CNLITE_CATEGORY_FILE.exists():
        print(
            f"缺少类目文件："
            f"{CNLITE_CATEGORY_FILE}"
        )
        sys.exit(1)

    categories = read_clean_lines(
        CNLITE_CATEGORY_FILE
    )

    if not categories:
        print("cnlite_geosite.txt 为空，终止。")
        sys.exit(1)

    merged_rules = set()

    for category in categories:
        url = (
            f"{META_RULES_GEOSITE_BASE_URL}/"
            f"{category}.list"
        )

        source_file = (
            CNLITE_SOURCE_DIR
            / f"{category}.list"
        )

        print(f"下载 geosite 类目：{category}")

        if not download_file(
            url,
            source_file,
        ):
            print(
                f"下载 geosite 类目失败："
                f"{category}"
            )
            sys.exit(1)

        for line in read_clean_lines(source_file):
            normalized = normalize_geosite_line(line)

            if normalized:
                merged_rules.add(normalized)

    sorted_rules = sorted(merged_rules)

    save_plain_txt(
        CNLITE_PRODUCT_FILE,
        sorted_rules,
    )


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
