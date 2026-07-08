"""输出文件路径规则。"""

from pathlib import Path


OUTPUT_DIR = "outputs"


def _input_stem(input_file: str) -> str:
    return Path(input_file).stem


def build_report_output_path(input_file: str) -> str:
    return str(Path(OUTPUT_DIR) / f"{_input_stem(input_file)}_processed.csv")


def build_blocklist_output_path(input_file: str) -> str:
    return str(Path(OUTPUT_DIR) / f"{_input_stem(input_file)}_blocklist_recommendations.csv")


def build_firewall_blacklist_output_path(output_dir: str = OUTPUT_DIR) -> Path:
    return Path(output_dir) / "sangfor_firewall_blacklists.csv"
