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


def test_volume_score_is_stable_when_an_extreme_ip_is_added_to_batch():
    target = make_attack_df(ip="203.0.113.50", rows=6)
    target = pd.concat([target] * 9, ignore_index=True).iloc[:50]
    baseline = BlocklistAdvisor(target).score_all_ips(min_attacks=1)
    baseline_item = next(item for item in baseline if item["ip"] == "203.0.113.50")

    extreme = pd.concat([make_attack_df(ip="198.51.100.200", rows=6)] * 742, ignore_index=True).iloc[:4449]
    mixed = BlocklistAdvisor(pd.concat([target, extreme], ignore_index=True)).score_all_ips(min_attacks=1)
    mixed_item = next(item for item in mixed if item["ip"] == "203.0.113.50")

    assert baseline_item["score_details"]["volume"]["score"] == mixed_item["score_details"]["volume"]["score"]


def test_fatal_severity_counts_as_critical_risk():
    df = make_attack_df(rows=3)
    df["严重等级"] = "致命"

    item = BlocklistAdvisor(df).score_all_ips(min_attacks=1)[0]

    assert item["score_details"]["severity"]["critical_ratio"] == 1.0
    assert item["score_details"]["severity"]["score"] > 0


def make_behavior_df(*, ip="203.0.113.80", rows=240, high_risk=False, positive=False):
    threat = "反序列化远程代码执行" if high_risk else "网站扫描"
    return pd.DataFrame({
        "时间": pd.date_range("2026-07-01", periods=rows, freq="1min"),
        "攻击类型": [threat] * rows,
        "源IP": [ip] * rows,
        "目的IP": [f"10.0.0.{(index % 8) + 1}" for index in range(rows)],
        "请求URL": ["/api/deserialize?cmd=/bin/sh" if high_risk else f"/missing/{index}" for index in range(rows)],
        "严重等级": ["致命" if high_risk else "中危"] * rows,
        "描述": ["反序列化命令执行" if high_risk else "扫描探测"] * rows,
        "动作": ["允许" if positive else "拒绝"] * rows,
        "攻击结果": ["尝试" if positive else "失败"] * rows,
        "状态码": ["200" if positive else "404"] * rows,
    })


def test_behavior_confidence_rewards_allowed_effective_multi_target_activity():
    positive = BlocklistAdvisor(make_behavior_df(rows=20, positive=True)).score_all_ips(min_attacks=1)[0]
    negative = BlocklistAdvisor(make_behavior_df(rows=20, positive=False)).score_all_ips(min_attacks=1)[0]

    positive_behavior = positive["score_details"]["behavior_confidence"]
    negative_behavior = negative["score_details"]["behavior_confidence"]
    assert positive_behavior["score"] > negative_behavior["score"]
    assert positive_behavior["allowed_rate"] == 1.0
    assert negative_behavior["blocked_rate"] == 1.0
    assert negative_behavior["failed_rate"] == 1.0
    assert negative_behavior["not_found_rate"] == 1.0
    assert positive_behavior["target_count"] == 8


def test_behavior_confidence_degrades_cleanly_when_optional_columns_are_missing():
    item = BlocklistAdvisor(make_low_risk_df()).score_all_ips(min_attacks=1)[0]

    behavior = item["score_details"]["behavior_confidence"]
    assert behavior["score"] == 0
    assert behavior["allowed_rate"] is None
    assert behavior["blocked_rate"] is None
    assert behavior["failed_rate"] is None
    assert behavior["not_found_rate"] is None


def test_high_volume_failed_scan_is_recommended_but_never_immediate():
    item = BlocklistAdvisor(make_behavior_df()).score_all_ips(min_attacks=3)[0]
    blocklist = BlocklistAdvisor(make_behavior_df()).generate_blocklist(min_attacks=3)

    assert item["recommendation"] == "建议封禁"
    assert blocklist[0]["recommendation"] == "建议封禁"
    assert item["score_details"]["high_risk_intent"]["detected"] is False
    assert any("高频" in reason for reason in item["recommendation_reasons"])


def test_failed_high_risk_attack_retains_high_risk_intent():
    item = BlocklistAdvisor(make_behavior_df(rows=12, high_risk=True, positive=False)).score_all_ips(min_attacks=3)[0]

    assert item["score_details"]["high_risk_intent"]["detected"] is True
    assert item["recommendation"] in {"建议封禁", "立即封禁"}


def test_high_risk_attack_with_allowed_2xx_signal_can_be_immediate():
    item = BlocklistAdvisor(make_behavior_df(rows=240, high_risk=True, positive=True)).score_all_ips(min_attacks=3)[0]

    assert item["recommendation"] == "立即封禁"
    assert item["score_details"]["behavior_confidence"]["allowed_rate"] == 1.0
    assert item["score_details"]["behavior_confidence"]["effective_response_rate"] == 1.0


def test_multi_stage_labels_with_overwhelming_failures_and_404s_are_not_immediate():
    df = make_behavior_df(rows=1000, high_risk=True, positive=False)
    df.loc[::3, "攻击类型"] = "信息泄露"
    df.loc[1::3, "攻击类型"] = "WebShell上传"
    df.loc[2::3, "攻击类型"] = "远程代码执行"

    item = BlocklistAdvisor(df).score_all_ips(min_attacks=3)[0]

    assert len(item["score_details"]["attack_chain"]["stages"]) >= 3
    assert item["final_score"] >= 70
    assert item["score_details"]["behavior_confidence"]["failed_rate"] == 1.0
    assert item["score_details"]["behavior_confidence"]["not_found_rate"] == 1.0
    assert item["recommendation"] == "建议封禁"


def test_rce_token_does_not_match_force_text():
    df = make_behavior_df(rows=240, positive=True)
    df["攻击类型"] = "Brute Force Attack"
    df["描述"] = "Brute Force Attack"
    df["请求URL"] = "/login"

    item = BlocklistAdvisor(df).score_all_ips(min_attacks=3)[0]

    assert item["score_details"]["high_risk_intent"]["detected"] is False
    assert item["recommendation"] != "立即封禁"


def test_sparse_status_codes_use_all_attacks_as_response_rate_denominator():
    df = make_behavior_df(rows=1000, high_risk=True, positive=True)
    df["状态码"] = None
    df.loc[0, "状态码"] = "200"

    item = BlocklistAdvisor(df).score_all_ips(min_attacks=3)[0]
    behavior = item["score_details"]["behavior_confidence"]

    assert behavior["effective_response_rate"] == 0.001
    assert behavior["status_coverage_rate"] == 0.001
    assert item["recommendation"] != "立即封禁"


def test_negative_action_and_result_text_do_not_count_as_positive():
    df = make_behavior_df(rows=20, high_risk=True, positive=False)
    df["动作"] = "不允许"
    df["攻击结果"] = "unsuccessful"

    behavior = BlocklistAdvisor(df).score_all_ips(min_attacks=3)[0]["score_details"]["behavior_confidence"]

    assert behavior["allowed_rate"] == 0.0
    assert behavior["effective_response_rate"] == 0.0


def test_high_risk_intent_is_detected_after_first_500_rows():
    df = make_behavior_df(rows=600, high_risk=False, positive=False)
    df.loc[599, "攻击类型"] = "远程代码执行"
    df.loc[599, "描述"] = "反序列化命令执行"

    item = BlocklistAdvisor(df).score_all_ips(min_attacks=3)[0]

    assert item["score_details"]["high_risk_intent"]["detected"] is True


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
            "behavior_confidence_score",
            "allowed_rate",
            "blocked_rate",
            "failed_rate",
            "not_found_rate",
            "effective_response_rate",
            "target_count",
            "high_risk_intent",
            "calibration_reasons",
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
