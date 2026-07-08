from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
FIREWALL_DIR = PROJECT_ROOT / "firewall"
if str(FIREWALL_DIR) not in sys.path:
    sys.path.insert(0, str(FIREWALL_DIR))

from modules.output_paths import build_report_output_path, build_blocklist_output_path
from sangfor_firewall_blocklist import parse_args


def test_report_csv_defaults_to_outputs_with_input_stem():
    assert build_report_output_path("/tmp/sangfor-sip-report-KsearchLog-20260703180201.xlsx") == str(
        Path("outputs") / "sangfor-sip-report-KsearchLog-20260703180201_processed.csv"
    )


def test_blocklist_csv_defaults_to_outputs_with_input_stem():
    assert build_blocklist_output_path("/tmp/report.xlsx") == str(
        Path("outputs") / "report_blocklist_recommendations.csv"
    )


def test_firewall_export_defaults_to_outputs_dir():
    args = parse_args(["--export"])

    assert args.output_dir == "outputs"


if __name__ == "__main__":
    test_report_csv_defaults_to_outputs_with_input_stem()
    test_blocklist_csv_defaults_to_outputs_with_input_stem()
    test_firewall_export_defaults_to_outputs_dir()
    print("plain python output path tests passed")
