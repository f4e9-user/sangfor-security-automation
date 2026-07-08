from pathlib import Path
import contextlib
import io
import sqlite3
import sys
import tempfile

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules import main_app
from modules.blocklist_advisor import BlocklistAdvisor
from modules.database_manager import DatabaseManager


def make_cli_attack_df():
    return pd.DataFrame({
        "时间": pd.date_range("2026-06-01 10:00:00", periods=6, freq="30min"),
        "攻击类型": ["SQL注入", "代码执行", "SQL注入", "WebShell上传", "SQL注入", "目录遍历"],
        "源IP": ["203.0.113.10"] * 6,
        "请求URL": [
            "/login?id=1 union select password",
            "/cgi-bin/../../../bin/sh",
            "/index.php?id=1 sleep(5)",
            "/upload/shell.jsp",
            "/admin/config.php",
            "/../../etc/passwd",
        ],
        "严重等级": ["高危"] * 6,
        "描述": ["CLI 持久化回归样本"] * 6,
    })


def _read_ip_observations(db_path, source_ip):
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        "SELECT execution_id, source_ip, attack_count, threat_types, severity_dist "
        "FROM ip_observations WHERE source_ip = ?",
        (source_ip,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def _read_top_attacker_execution_ids(db_path, source_ip):
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        "SELECT execution_id FROM top_attackers WHERE source_ip = ? ORDER BY id",
        (source_ip,),
    )
    rows = [row[0] for row in cursor.fetchall()]
    conn.close()
    return rows


def test_process_xlsx_persists_blocklist_scores_and_observations():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db_path = temp_dir / "attackers.db"
        output_csv = temp_dir / "processed.csv"
        blocklist_csv = temp_dir / "blocklist.csv"

        original_detect_report_type = main_app.detect_report_type
        original_read_excel_file = main_app.read_excel_file
        original_save_to_csv = main_app.save_to_csv
        original_export_csv = BlocklistAdvisor.export_csv

        def fake_save_to_csv(df, path):
            Path(path).write_text("ok\n", encoding="utf-8")

        def fake_export_csv(self, blocklist, path=None):
            return original_export_csv(self, blocklist, path=str(blocklist_csv))

        try:
            main_app.detect_report_type = lambda input_file: ("SIP", 0)
            main_app.read_excel_file = lambda input_file, skiprows: make_cli_attack_df()
            main_app.save_to_csv = fake_save_to_csv
            BlocklistAdvisor.export_csv = fake_export_csv

            captured_stdout = io.StringIO()
            captured_stderr = io.StringIO()
            with contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(captured_stderr):
                main_app.process_xlsx(
                    input_file="fake.xlsx",
                    output_csv=str(output_csv),
                    db_path=str(db_path),
                    enable_db_logging=True,
                    enable_blocklist=True,
                    enable_ai_analysis=False,
                    enable_local_analysis=False,
                )
        finally:
            main_app.detect_report_type = original_detect_report_type
            main_app.read_excel_file = original_read_excel_file
            main_app.save_to_csv = original_save_to_csv
            BlocklistAdvisor.export_csv = original_export_csv

        db = DatabaseManager(str(db_path))
        score_history = db.get_ip_score_history("203.0.113.10")
        assert score_history, "CLI blocklist path should persist ip_scores rows"

        row = score_history[-1]
        assert row["base_score"] > 0
        assert row["history_score"] == 0
        assert row["final_score"] >= row["base_score"]
        assert row["evidence_json"] and row["evidence_json"] != "{}"
        assert row["history_details_json"] and row["history_details_json"] != "{}"
        assert row["is_recommended"] is True

        observations = _read_ip_observations(db_path, "203.0.113.10")
        assert len(observations) == 1
        assert observations[0][2] == 6
        assert "SQL注入" in observations[0][3]
        assert "高危" in observations[0][4]

        top_attacker_execution_ids = _read_top_attacker_execution_ids(db_path, "203.0.113.10")
        assert len(top_attacker_execution_ids) == 1
        assert row["execution_id"] == observations[0][0] == top_attacker_execution_ids[0]

        combined_output = captured_stdout.getvalue() + captured_stderr.getvalue()
        assert "黑名单文件时出错" not in combined_output
        assert "None" not in combined_output


def test_process_xlsx_uses_default_outputs_dir_for_csv_artifacts():
    original_detect_report_type = main_app.detect_report_type
    original_read_excel_file = main_app.read_excel_file
    original_save_to_csv = main_app.save_to_csv
    original_export_csv = BlocklistAdvisor.export_csv
    captured = {}

    def fake_save_to_csv(df, path):
        captured["processed_csv"] = path

    def fake_export_csv(self, blocklist, path=None, input_file=None):
        captured["blocklist_csv"] = path
        return path

    try:
        main_app.detect_report_type = lambda input_file: ("SIP", 0)
        main_app.read_excel_file = lambda input_file, skiprows: make_cli_attack_df()
        main_app.save_to_csv = fake_save_to_csv
        BlocklistAdvisor.export_csv = fake_export_csv

        main_app.process_xlsx(
            input_file="/tmp/report.xlsx",
            output_csv=None,
            enable_db_logging=False,
            enable_blocklist=True,
            enable_ai_analysis=False,
            enable_local_analysis=False,
        )
    finally:
        main_app.detect_report_type = original_detect_report_type
        main_app.read_excel_file = original_read_excel_file
        main_app.save_to_csv = original_save_to_csv
        BlocklistAdvisor.export_csv = original_export_csv

    assert captured["processed_csv"] == str(Path("outputs") / "report_processed.csv")
    assert captured["blocklist_csv"] == str(Path("outputs") / "report_blocklist_recommendations.csv")


if __name__ == "__main__":
    test_process_xlsx_persists_blocklist_scores_and_observations()
    test_process_xlsx_uses_default_outputs_dir_for_csv_artifacts()
    print("plain python main_app blocklist persistence test passed")
