import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PRODUCT_DIR = Path("product")
RELEASE_DIR = Path("release")
MIHOMO_BIN = os.environ.get(
    "MIHOMO_BIN",
    "mihomo",
)


# 保持原来的 9 个规则集。
#
# source_type:
#
# plain:
#   每行一条规则的普通 TXT。
#   在系统临时目录包装为 payload YAML 后转换。
#
# yaml_text:
#   文件后缀为 TXT，但内容本身是标准 payload YAML。
#   直接作为 yaml 输入转换。
RULESETS = [
    {
        "name": "Jcdn",
        "behavior": "domain",
        "source_type": "plain",
        "input_file": PRODUCT_DIR / "Jcdn.txt",
        "output_file": RELEASE_DIR / "Jcdn.mrs",
    },
    {
        "name": "Jweb",
        "behavior": "domain",
        "source_type": "plain",
        "input_file": PRODUCT_DIR / "Jweb.txt",
        "output_file": RELEASE_DIR / "Jweb.mrs",
    },
    {
        "name": "cnlite",
        "behavior": "domain",
        "source_type": "plain",
        "input_file": PRODUCT_DIR / "cnlite.txt",
        "output_file": RELEASE_DIR / "cnlite.mrs",
    },
    {
        "name": "trackers_domain",
        "behavior": "domain",
        "source_type": "plain",
        "input_file": PRODUCT_DIR / "trackers_domain.txt",
        "output_file": RELEASE_DIR / "trackers_domain.mrs",
    },
    {
        "name": "trackers_ip",
        "behavior": "ipcidr",
        "source_type": "plain",
        "input_file": PRODUCT_DIR / "trackers_ip.txt",
        "output_file": RELEASE_DIR / "trackers_ip.mrs",
    },
    {
        "name": "proxy",
        "behavior": "domain",
        "source_type": "yaml_text",
        "input_file": PRODUCT_DIR / "proxy.txt",
        "output_file": RELEASE_DIR / "proxy.mrs",
    },
    {
        "name": "direct",
        "behavior": "domain",
        "source_type": "yaml_text",
        "input_file": PRODUCT_DIR / "direct.txt",
        "output_file": RELEASE_DIR / "direct.mrs",
    },
    {
        "name": "reject",
        "behavior": "domain",
        "source_type": "yaml_text",
        "input_file": PRODUCT_DIR / "reject.txt",
        "output_file": RELEASE_DIR / "reject.mrs",
    },
    {
        "name": "cncidr",
        "behavior": "ipcidr",
        "source_type": "yaml_text",
        "input_file": PRODUCT_DIR / "cncidr.txt",
        "output_file": RELEASE_DIR / "cncidr.mrs",
    },
]


def check_mihomo():
    """
    检查 Mihomo 是否存在。
    """
    if shutil.which(MIHOMO_BIN):
        return True

    mihomo_path = Path(MIHOMO_BIN)

    if (
        mihomo_path.exists()
        and mihomo_path.is_file()
    ):
        return True

    print(f"错误：未找到 mihomo：{MIHOMO_BIN}")
    print("示例：")
    print(
        "MIHOMO_BIN=/usr/local/bin/mihomo "
        "python3 scripts/build_mrs.py"
    )

    return False


def read_plain_rules(input_file):
    """
    读取每行一条规则的普通 TXT。
    """
    rules = []

    with input_file.open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        for raw_line in file:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            rules.append(line)

    return rules


def write_temporary_payload_yaml(
    input_file,
    temporary_yaml,
):
    """
    将普通 TXT 包装成临时 YAML payload。

    临时文件仅用于 Mihomo 转换，
    构建结束后自动删除。
    """
    rules = read_plain_rules(input_file)

    with temporary_yaml.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        if not rules:
            file.write("payload: []\n")
        else:
            file.write("payload:\n")

            for rule in rules:
                encoded_rule = json.dumps(
                    rule,
                    ensure_ascii=False,
                )

                file.write(
                    f"  - {encoded_rule}\n"
                )

    return len(rules)


def validate_yaml_text_file(path):
    """
    检查 TXT 内容是否具有 payload YAML 结构。

    实际语法解析由 Mihomo 完成。
    """
    try:
        content = path.read_text(
            encoding="utf-8-sig"
        )

    except UnicodeDecodeError as error:
        print(f"错误：无法读取文件：{path}")
        print(f"错误信息：{error}")
        return False

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line == "payload:":
            return True

        if line.startswith("payload:"):
            return True

    print(
        f"错误：文件不是标准 payload rule-set："
        f"{path}"
    )

    return False


def run_mihomo_convert(
    name,
    behavior,
    input_file,
    output_file,
):
    """
    调用 Mihomo 转换规则集。
    """
    if output_file.exists():
        output_file.unlink()

    command = [
        MIHOMO_BIN,
        "convert-ruleset",
        behavior,
        "yaml",
        str(input_file),
        str(output_file),
    ]

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

    if result.stderr:
        print(result.stderr.rstrip())

    if result.returncode != 0:
        print(f"生成失败：{name}")
        return False

    if not output_file.exists():
        print(
            f"生成失败：Mihomo 未生成文件："
            f"{output_file}"
        )
        return False

    if output_file.stat().st_size == 0:
        print(
            f"生成失败：MRS 文件为空："
            f"{output_file}"
        )
        return False

    print(f"生成成功：{output_file}")
    print(
        f"MRS 文件大小："
        f"{output_file.stat().st_size} bytes"
    )

    return True


def convert_ruleset(ruleset, temporary_dir):
    """
    转换单个规则集。
    """
    name = ruleset["name"]
    behavior = ruleset["behavior"]
    source_type = ruleset["source_type"]
    input_file = ruleset["input_file"]
    output_file = ruleset["output_file"]

    print("")
    print(f"========== 构建规则集：{name} ==========")
    print(f"输入文件：{input_file}")
    print(f"规则行为：{behavior}")
    print(f"输出文件：{output_file}")

    if not input_file.exists():
        print(f"错误：输入文件不存在：{input_file}")
        return False

    if input_file.stat().st_size == 0:
        print(f"错误：输入文件为空：{input_file}")
        return False

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if source_type == "plain":
        temporary_yaml = (
            temporary_dir
            / f"{name}.yaml"
        )

        rule_count = write_temporary_payload_yaml(
            input_file,
            temporary_yaml,
        )

        print(f"TXT 有效规则数量：{rule_count}")
        print(f"临时转换输入：{temporary_yaml}")

        return run_mihomo_convert(
            name=name,
            behavior=behavior,
            input_file=temporary_yaml,
            output_file=output_file,
        )

    if source_type == "yaml_text":
        if not validate_yaml_text_file(input_file):
            return False

        print(
            "输入文件内容为 payload YAML，"
            "直接使用 yaml 格式转换。"
        )

        return run_mihomo_convert(
            name=name,
            behavior=behavior,
            input_file=input_file,
            output_file=output_file,
        )

    print(f"错误：未知 source_type：{source_type}")
    return False


def remove_old_release_yaml():
    """
    删除旧版本可能遗留在 release 目录中的 YAML 文件。
    """
    old_yaml_files = [
        RELEASE_DIR / "Jcdn.yaml",
        RELEASE_DIR / "Jweb.yaml",
        RELEASE_DIR / "cnlite.yaml",
        RELEASE_DIR / "trackers_domain.yaml",
        RELEASE_DIR / "trackers_ip.yaml",
        RELEASE_DIR / "proxy.yaml",
        RELEASE_DIR / "direct.yaml",
        RELEASE_DIR / "reject.yaml",
        RELEASE_DIR / "cncidr.yaml",
    ]

    for path in old_yaml_files:
        if path.exists():
            path.unlink()
            print(f"已删除旧版 Release YAML：{path}")


def main():
    if not check_mihomo():
        sys.exit(1)

    RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    remove_old_release_yaml()

    failed = []

    with tempfile.TemporaryDirectory(
        prefix="mihomo-rules-"
    ) as temporary_path:
        temporary_dir = Path(temporary_path)

        for ruleset in RULESETS:
            success = convert_ruleset(
                ruleset,
                temporary_dir,
            )

            if not success:
                failed.append(ruleset["name"])

    print("")
    print("========== 构建结果 ==========")

    if failed:
        print("以下规则集生成失败：")

        for name in failed:
            print(f"  - {name}")

        sys.exit(1)

    print(
        f"全部 MRS 文件生成完成，"
        f"共 {len(RULESETS)} 个："
    )

    for ruleset in RULESETS:
        output_file = ruleset["output_file"]

        print(
            f"  - {output_file} "
            f"({output_file.stat().st_size} bytes)"
        )


if __name__ == "__main__":
    main()
