import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


PRODUCT_DIR = Path("product")
RELEASE_DIR = Path("release")
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")


# 保留原有 9 个规则集。
#
# source_format 表示 product 中的原始文件格式：
# - text：product 中为可读 TXT，构建时转换为 release/*.yaml
# - yaml：product 中已经是 YAML，直接复制到 release/*.yaml
#
# convert_behavior 表示 Mihomo 转换规则类型：
# - domain
# - ipcidr
RULESETS = [
    {
        "name": "Jcdn",
        "behavior": "domain",
        "source_format": "text",
        "input_file": PRODUCT_DIR / "Jcdn.txt",
        "yaml_file": RELEASE_DIR / "Jcdn.yaml",
        "output_file": RELEASE_DIR / "Jcdn.mrs",
    },
    {
        "name": "Jweb",
        "behavior": "domain",
        "source_format": "text",
        "input_file": PRODUCT_DIR / "Jweb.txt",
        "yaml_file": RELEASE_DIR / "Jweb.yaml",
        "output_file": RELEASE_DIR / "Jweb.mrs",
    },
    {
        "name": "cnlite",
        "behavior": "domain",
        "source_format": "text",
        "input_file": PRODUCT_DIR / "cnlite.txt",
        "yaml_file": RELEASE_DIR / "cnlite.yaml",
        "output_file": RELEASE_DIR / "cnlite.mrs",
    },
    {
        "name": "trackers_domain",
        "behavior": "domain",
        "source_format": "text",
        "input_file": PRODUCT_DIR / "trackers_domain.txt",
        "yaml_file": RELEASE_DIR / "trackers_domain.yaml",
        "output_file": RELEASE_DIR / "trackers_domain.mrs",
    },
    {
        "name": "trackers_ip",
        "behavior": "ipcidr",
        "source_format": "text",
        "input_file": PRODUCT_DIR / "trackers_ip.txt",
        "yaml_file": RELEASE_DIR / "trackers_ip.yaml",
        "output_file": RELEASE_DIR / "trackers_ip.mrs",
    },
    {
        "name": "proxy",
        "behavior": "domain",
        "source_format": "yaml",
        "input_file": PRODUCT_DIR / "proxy.yaml",
        "yaml_file": RELEASE_DIR / "proxy.yaml",
        "output_file": RELEASE_DIR / "proxy.mrs",
    },
    {
        "name": "direct",
        "behavior": "domain",
        "source_format": "yaml",
        "input_file": PRODUCT_DIR / "direct.yaml",
        "yaml_file": RELEASE_DIR / "direct.yaml",
        "output_file": RELEASE_DIR / "direct.mrs",
    },
    {
        "name": "reject",
        "behavior": "domain",
        "source_format": "yaml",
        "input_file": PRODUCT_DIR / "reject.yaml",
        "yaml_file": RELEASE_DIR / "reject.yaml",
        "output_file": RELEASE_DIR / "reject.mrs",
    },
    {
        "name": "cncidr",
        "behavior": "ipcidr",
        "source_format": "yaml",
        "input_file": PRODUCT_DIR / "cncidr.yaml",
        "yaml_file": RELEASE_DIR / "cncidr.yaml",
        "output_file": RELEASE_DIR / "cncidr.mrs",
    },
]


def check_mihomo():
    """
    检查 Mihomo 是否存在。
    """
    if shutil.which(MIHOMO_BIN):
        return True

    if Path(MIHOMO_BIN).is_file():
        return True

    print(f"错误：未找到 mihomo：{MIHOMO_BIN}")
    print("示例：")
    print("MIHOMO_BIN=/usr/local/bin/mihomo python3 scripts/build_mrs.py")
    return False


def read_clean_lines(input_file):
    """
    读取 TXT 规则。

    只删除空行和以 # 开头的注释行。
    不修改规则本身，特别保留：
    +.example.com
    api.example.com
    IP/CIDR
    """
    lines = []

    with input_file.open("r", encoding="utf-8-sig") as file:
        for raw_line in file:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            lines.append(line)

    return lines


def write_text_ruleset_yaml(input_file, yaml_file):
    """
    将 product/*.txt 转换成可供 Mihomo 使用的 YAML：

    payload:
      - "+.example.com"
      - "api.example.com"

    使用 JSON 字符串写法，JSON 字符串同时也是合法 YAML 字符串，
    可以安全保留 +.、特殊字符以及 Unicode 内容。
    """
    lines = read_clean_lines(input_file)

    yaml_file.parent.mkdir(parents=True, exist_ok=True)

    with yaml_file.open("w", encoding="utf-8", newline="\n") as file:
        if not lines:
            file.write("payload: []\n")
        else:
            file.write("payload:\n")

            for line in lines:
                encoded_line = json.dumps(
                    line,
                    ensure_ascii=False,
                )
                file.write(f"  - {encoded_line}\n")

    return len(lines)


def prepare_yaml_file(ruleset):
    """
    准备 release/*.yaml。

    text：
        product/*.txt -> release/*.yaml

    yaml：
        product/*.yaml -> release/*.yaml
    """
    input_file = ruleset["input_file"]
    yaml_file = ruleset["yaml_file"]
    source_format = ruleset["source_format"]

    if not input_file.exists():
        print(f"错误：输入文件不存在：{input_file}")
        return False, 0

    if input_file.stat().st_size == 0:
        print(f"错误：输入文件为空：{input_file}")
        return False, 0

    yaml_file.parent.mkdir(parents=True, exist_ok=True)

    if yaml_file.exists():
        yaml_file.unlink()

    if source_format == "text":
        count = write_text_ruleset_yaml(input_file, yaml_file)

    elif source_format == "yaml":
        shutil.copyfile(input_file, yaml_file)
        count = -1

    else:
        print(f"错误：未知 source_format：{source_format}")
        return False, 0

    if not yaml_file.exists():
        print(f"错误：YAML 文件未生成：{yaml_file}")
        return False, 0

    if yaml_file.stat().st_size == 0:
        print(f"错误：YAML 文件为空：{yaml_file}")
        return False, 0

    return True, count


def convert_to_mrs(ruleset):
    """
    使用 release/*.yaml 作为唯一转换输入，生成 release/*.mrs。
    """
    input_file = ruleset["input_file"]
    yaml_file = ruleset["yaml_file"]
    output_file = ruleset["output_file"]
    behavior = ruleset["behavior"]

    prepared, source_count = prepare_yaml_file(ruleset)

    if not prepared:
        return False

    if output_file.exists():
        output_file.unlink()

    command = [
        MIHOMO_BIN,
        "convert-ruleset",
        behavior,
        "yaml",
        str(yaml_file),
        str(output_file),
    ]

    print("")
    print(f"========== 构建规则集：{ruleset['name']} ==========")
    print(f"原始输入：{input_file}")
    print(f"YAML 文件：{yaml_file}")
    print(f"转换行为：{behavior}")
    print("转换格式：yaml")
    print(f"MRS 文件：{output_file}")

    if source_count >= 0:
        print(f"TXT 有效行数：{source_count}")

    print(f"执行命令：{' '.join(command)}")

    try:
        result = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
        )
    except OSError as error:
        print(f"执行 Mihomo 失败：{error}")
        return False

    if result.stdout:
        print(result.stdout.rstrip())

    if result.returncode != 0:
        print(f"生成失败：{output_file}")

        if result.stderr:
            print(result.stderr.rstrip())

        return False

    if not output_file.exists():
        print(f"生成失败：Mihomo 未生成输出文件：{output_file}")
        return False

    if output_file.stat().st_size == 0:
        print(f"生成失败：MRS 文件为空：{output_file}")
        return False

    print(f"生成成功：{output_file}")
    print(f"YAML 文件大小：{yaml_file.stat().st_size} bytes")
    print(f"MRS 文件大小：{output_file.stat().st_size} bytes")

    return True


def main():
    if not check_mihomo():
        sys.exit(1)

    RELEASE_DIR.mkdir(parents=True, exist_ok=True)

    failed = []

    for ruleset in RULESETS:
        success = convert_to_mrs(ruleset)

        if not success:
            failed.append(ruleset["name"])

    print("")
    print("========== 构建结果 ==========")

    if failed:
        print("以下规则集生成失败：")

        for name in failed:
            print(f"  - {name}")

        sys.exit(1)

    print(f"全部 YAML/MRS 文件生成完成，共 {len(RULESETS)} 组：")

    for ruleset in RULESETS:
        yaml_file = ruleset["yaml_file"]
        output_file = ruleset["output_file"]

        print(f"  - {yaml_file}")
        print(f"  - {output_file}")


if __name__ == "__main__":
    main()
