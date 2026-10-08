import os
import shutil
import subprocess
import sys
from pathlib import Path


PRODUCT_DIR = Path("product")
RELEASE_DIR = Path("release")
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")


# 保持原文件设定，不增加或删除规则集
RULESETS = [
    {
        "name": "Jcdn",
        "behavior": "domain",
        "input_format": "yaml",
        "input_file": PRODUCT_DIR / "Jcdn.yaml",
        "output_file": RELEASE_DIR / "Jcdn.mrs",
    },
    {
        "name": "Jweb",
        "behavior": "domain",
        "input_format": "yaml",
        "input_file": PRODUCT_DIR / "Jweb.yaml",
        "output_file": RELEASE_DIR / "Jweb.mrs",
    },
    {
        "name": "cnlite",
        "behavior": "domain",
        "input_format": "yaml",
        "input_file": PRODUCT_DIR / "cnlite.yaml",
        "output_file": RELEASE_DIR / "cnlite.mrs",
    },
    {
        "name": "trackers_domain",
        "behavior": "domain",
        "input_format": "yaml",
        "input_file": PRODUCT_DIR / "trackers_domain.yaml",
        "output_file": RELEASE_DIR / "trackers_domain.mrs",
    },
    {
        "name": "trackers_ip",
        "behavior": "ipcidr",
        "input_format": "yaml",
        "input_file": PRODUCT_DIR / "trackers_ip.yaml",
        "output_file": RELEASE_DIR / "trackers_ip.mrs",
    },
    {
        "name": "proxy",
        "behavior": "domain",
        "input_format": "yaml",
        "input_file": PRODUCT_DIR / "proxy.yaml",
        "output_file": RELEASE_DIR / "proxy.mrs",
    },
    {
        "name": "direct",
        "behavior": "domain",
        "input_format": "yaml",
        "input_file": PRODUCT_DIR / "direct.yaml",
        "output_file": RELEASE_DIR / "direct.mrs",
    },
    {
        "name": "reject",
        "behavior": "domain",
        "input_format": "yaml",
        "input_file": PRODUCT_DIR / "reject.yaml",
        "output_file": RELEASE_DIR / "reject.mrs",
    },
    {
        "name": "cncidr",
        "behavior": "ipcidr",
        "input_format": "yaml",
        "input_file": PRODUCT_DIR / "cncidr.yaml",
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


def convert_to_mrs(input_file, output_file, behavior, input_format):
    """
    使用 Mihomo 将规则集转换为 MRS。
    """
    if not input_file.exists():
        print(f"错误：输入文件不存在：{input_file}")
        return False

    if input_file.stat().st_size == 0:
        print(f"错误：输入文件为空：{input_file}")
        return False

    output_file.parent.mkdir(parents=True, exist_ok=True)

    # 删除本次输出对应的旧文件，避免将旧 MRS 误认为新结果
    if output_file.exists():
        output_file.unlink()

    command = [
        MIHOMO_BIN,
        "convert-ruleset",
        behavior,
        input_format,
        str(input_file),
        str(output_file),
    ]

    print()
    print(f"========== 构建规则集：{input_file.stem} ==========")
    print(f"输入文件：{input_file}")
    print(f"输入格式：{input_format}")
    print(f"行为类型：{behavior}")
    print(f"输出文件：{output_file}")
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
        print(f"生成失败：未找到输出文件：{output_file}")
        return False

    output_size = output_file.stat().st_size

    if output_size == 0:
        print(f"生成失败：输出文件为空：{output_file}")
        return False

    print(f"生成成功：{output_file}")
    print(f"文件大小：{output_size} bytes")

    return True


def main():
    if not check_mihomo():
        sys.exit(1)

    RELEASE_DIR.mkdir(parents=True, exist_ok=True)

    failed = []

    for ruleset in RULESETS:
        success = convert_to_mrs(
            input_file=ruleset["input_file"],
            output_file=ruleset["output_file"],
            behavior=ruleset["behavior"],
            input_format=ruleset["input_format"],
        )

        if not success:
            failed.append(ruleset["name"])

    print()
    print("========== 构建结果 ==========")

    if failed:
        print("以下规则集生成失败：")
        for name in failed:
            print(f"  - {name}")
        sys.exit(1)

    print(f"全部 MRS 文件生成完成，共 {len(RULESETS)} 个：")

    for ruleset in RULESETS:
        output_file = ruleset["output_file"]
        print(f"  - {output_file}")


if __name__ == "__main__":
    main()
