from pathlib import Path
import sys
import tempfile

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules.blocklist_advisor import BlocklistAdvisor


def make_attack_df(ip="203.0.113.10", rows=6):
    return pd.DataFrame({
        "时间": pd.date_range("2026-06-01 10:00:00", periods=rows, freq="30min"),
        "攻击类型": ["SQL注入", "代码执行", "SQL注入", "WebShell上传", "SQL注入", "目录遍历"][:rows],
        "源IP": [ip] * rows,
        "目的IP": ["10.0.0.5"] * rows,
        "目的端口": ["80"] * rows,
        "请求URL": [
            "/login?id=1 union select password",
            "/cgi-bin/../../../bin/sh",
            "/index.php?id=1 sleep(5)",
            "/upload/shell.jsp",
            "/admin/config.php",
            "/../../etc/passwd",
        ][:rows],
        "严重等级": ["高危"] * rows,
        "描述": ["攻击样本"] * rows,
    })


def test_score_without_history_uses_base_score_only():
    advisor = BlocklistAdvisor(make_attack_df(), db_manager=None)

    scored = advisor.score_all_ips(min_attacks=1)

    assert len(scored) == 1
    item = scored[0]
    assert item["base_score"] > 0
    assert item["history_score"] == 0
    assert item["final_score"] == item["base_score"]
    assert item["score"] == item["final_score"]
    assert item["score_details"]["history"]["score"] == 0


class FakeHistoryDB:
    def get_ip_history_summary(self, ip, before_execution_id=None):
        return {
            "seen_before": True,
            "historical_occurrences": 9,
            "prior_execution_count": 9,
            "prior_total_attacks": 300,
            "prior_days_seen": 5,
            "recent_execution_count": 3,
            "first_seen": "2026-05-20T08:00:00",
            "last_seen": "2026-06-01T08:00:00",
            "last_seen_days": 1.0,
            "prior_max_recommendation": "建议封禁",
            "prior_max_score": 88,
            "previous_recommendation_count": 2,
            "recent_recommendation": "建议封禁",
            "note": "历史出现 9 次，累计攻击 300 次",
        }


def test_history_score_is_capped_at_15_and_reasons_are_generated():
    advisor = BlocklistAdvisor(make_attack_df(), db_manager=FakeHistoryDB(), current_execution_id="run-new")

    item = advisor.score_all_ips(min_attacks=1)[0]

    assert item["history_score"] == 15
    assert item["final_score"] == min(100, round(item["base_score"] + 15, 1))
    assert item["history"]["previous_recommendation_count"] == 2
    assert item["recommendation_reasons"]
    assert any("历史" in reason for reason in item["recommendation_reasons"])
    assert 2 <= len(item["recommendation_reasons"]) <= 4


class FailingHistoryDB:
    def get_ip_history_summaries(self, ips, before_execution_id=None):
        raise RuntimeError("database locked")


def test_history_query_failure_falls_back_to_base_score():
    advisor = BlocklistAdvisor(make_attack_df(), db_manager=FailingHistoryDB(), current_execution_id="run-new")

    item = advisor.score_all_ips(min_attacks=1)[0]

    assert item["history_score"] == 0
    assert item["final_score"] == item["base_score"]
    assert item["history"]["seen_before"] is False
    assert "查询失败" in item["history"]["note"]


def make_low_risk_df():
    return pd.DataFrame({
        "时间": pd.date_range("2026-06-01", periods=3, freq="1h"),
        "攻击类型": ["扫描", "扫描", "扫描"],
        "源IP": ["198.51.100.23"] * 3,
        "请求URL": ["/", "/index", "/health"],
        "严重等级": ["低危", "低危", "低危"],
        "描述": ["低风险扫描"] * 3,
    })


class StrongHistoryDB:
    def get_ip_history_summaries(self, ips, before_execution_id=None):
        return {ip: {
            "seen_before": True,
            "historical_occurrences": 20,
            "prior_execution_count": 20,
            "prior_total_attacks": 1000,
            "prior_days_seen": 10,
            "recent_execution_count": 5,
            "last_seen_days": 1,
            "previous_recommendation_count": 5,
            "recent_recommendation": "立即封禁",
            "prior_max_recommendation": "立即封禁",
            "prior_max_score": 95,
            "max_historical_score": 95,
            "note": "历史出现 20 次",
        } for ip in ips}


def test_low_base_score_is_not_recommended_only_because_of_history():
    advisor = BlocklistAdvisor(make_low_risk_df(), db_manager=StrongHistoryDB())

    blocklist = advisor.generate_blocklist(min_attacks=3, min_score=15)

    assert blocklist == []


def test_current_risk_below_min_score_is_not_recommended():
    advisor = BlocklistAdvisor(make_attack_df(rows=3), db_manager=None)

    blocklist = advisor.generate_blocklist(min_attacks=3, min_score=80)

    assert blocklist == []


def test_export_csv_contains_history_loop_fields():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        advisor = BlocklistAdvisor(make_attack_df(), db_manager=FakeHistoryDB())

        blocklist = advisor.generate_blocklist(min_attacks=3)
        output = temp_dir / "blocklist.csv"
        advisor.export_csv(blocklist, path=str(output))
        exported = pd.read_csv(output)

        for column in [
            "base_score",
            "history_score",
            "final_score",
            "historical_occurrences",
            "previous_recommendation_count",
            "first_seen",
            "last_seen",
            "recommendation_reasons",
        ]:
            assert column in exported.columns
        assert exported.loc[0, "previous_recommendation_count"] == 2
        assert "历史" in exported.loc[0, "recommendation_reasons"]


if __name__ == "__main__":
    test_score_without_history_uses_base_score_only()
    test_history_score_is_capped_at_15_and_reasons_are_generated()
    test_history_query_failure_falls_back_to_base_score()
    test_low_base_score_is_not_recommended_only_because_of_history()
    test_current_risk_below_min_score_is_not_recommended()
    test_export_csv_contains_history_loop_fields()
    print("plain python blocklist history test passed")
