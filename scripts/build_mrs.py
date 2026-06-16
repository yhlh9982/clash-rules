import shutil
import subprocess
from pathlib import Path
import os
import sys


# =========================
# 路径配置
# =========================

PRODUCT_DIR = Path("product")
RELEASE_DIR = Path("release")

MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")


# =========================
# 规则转换配置
# =========================

RULESETS = [
    # 自定义规则
    {
        "name": "Jcdn",
        "behavior": "domain",
        "input_format": "text",
        "input_file": PRODUCT_DIR / "Jcdn.txt",
        "output_file": RELEASE_DIR / "Jcdn.mrs",
    },
    {
        "name": "Jweb",
        "behavior": "domain",
        "input_format": "text",
        "input_file": PRODUCT_DIR / "Jweb.txt",
        "output_file": RELEASE_DIR / "Jweb.mrs",
    },

    # Tracker 规则
    {
        "name": "trackers_domain",
        "behavior": "domain",
        "input_format": "text",
        "input_file": PRODUCT_DIR / "trackers_domain.txt",
        "output_file": RELEASE_DIR / "trackers_domain.mrs",
    },
    {
        "name": "trackers_ip",
        "behavior": "ipcidr",
        "input_format": "text",
        "input_file": PRODUCT_DIR / "trackers_ip.txt",
        "output_file": RELEASE_DIR / "trackers_ip.mrs",
    },

    # Loyalsoldier 规则
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


# =========================
# 检查 mihomo
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
    print("  MIHOMO_BIN=/usr/local/bin/mihomo python3 scripts/build_mrs.py")
    print("")
    return False


# =========================
# 生成 MRS
# =========================

def convert_to_mrs(input_file, output_file, behavior, input_format):
    if not input_file.exists():
        print(f"输入文件不存在：{input_file}")
        sys.exit(1)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        MIHOMO_BIN,
        "convert-ruleset",
        behavior,
        input_format,
        str(input_file),
        str(output_file),
    ]

    print("")
    print(f"正在生成 MRS：{' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True)
        print(f"已生成：{output_file}")

    except subprocess.CalledProcessError as e:
        print(f"生成 MRS 失败：{output_file}")
        print(f"错误信息：{e}")
        sys.exit(1)


# =========================
# 主流程
# =========================

def main():
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)

    if not check_mihomo():
        sys.exit(1)

    for ruleset in RULESETS:
        name = ruleset["name"]
        behavior = ruleset["behavior"]
        input_format = ruleset["input_format"]
        input_file = ruleset["input_file"]
        output_file = ruleset["output_file"]

        print("")
        print(f"========== 构建规则集：{name} ==========")

        convert_to_mrs(
            input_file=input_file,
            output_file=output_file,
            behavior=behavior,
            input_format=input_format,
        )

    print("")
    print("全部 MRS 文件生成完成。")
    print("")
    print("输出目录：")
    print(f"  {RELEASE_DIR}")


if __name__ == "__main__":
    main()

