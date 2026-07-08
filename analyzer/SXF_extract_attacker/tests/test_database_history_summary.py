from pathlib import Path
import sqlite3
import sys
import tempfile

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules.database_manager import DatabaseManager


def test_get_ip_history_summaries_returns_required_fields():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db = DatabaseManager(str(temp_dir / "attackers.db"))

        db.save_ip_observations("run-1", [{
            "source_ip": "203.0.113.10",
            "attack_count": 12,
            "threat_types": {"代码执行": 12},
            "severity_dist": {"高危": 12},
        }])
        db.save_ip_observations("run-2", [{
            "source_ip": "203.0.113.10",
            "attack_count": 18,
            "threat_types": {"代码执行": 18},
            "severity_dist": {"高危": 18},
        }])
        db.save_ip_scores("run-2", [{
            "ip": "203.0.113.10",
            "score": 72,
            "base_score": 60,
            "history_score": 12,
            "final_score": 72,
            "attack_count": 18,
            "score_details": {"history": {"score": 12, "reasons": ["历史出现 1 次"]}},
            "evidence": {"unique_threats": 1, "threat_types": {"代码执行": 18}},
            "recommendation": "建议封禁",
            "is_recommended": True,
        }])

        summaries = db.get_ip_history_summaries(
            ["203.0.113.10", "198.51.100.1"],
            before_execution_id="run-new",
        )

        seen = summaries["203.0.113.10"]
        assert seen["seen_before"] is True
        assert seen["historical_occurrences"] == 2
        assert seen["previous_recommendation_count"] == 1
        assert seen["max_historical_score"] == 72
        assert seen["prior_max_score"] == 72
        assert seen["recent_recommendation"] == "建议封禁"
        assert seen["first_seen"]
        assert seen["last_seen"]

        unseen = summaries["198.51.100.1"]
        assert unseen["seen_before"] is False
        assert unseen["historical_occurrences"] == 0
        assert unseen["previous_recommendation_count"] == 0



def _set_created_at(db_path, table, execution_id, created_at):
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        f"UPDATE {table} SET created_at = ? WHERE execution_id = ?",
        (created_at, execution_id),
    )
    conn.commit()
    conn.close()


def test_before_execution_excludes_current_and_future_history_by_timestamp():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db_path = temp_dir / "attackers.db"
        db = DatabaseManager(str(db_path))

        ip = "203.0.113.20"
        for execution_id, attack_count, score, recommendation in [
            ("run-prior", 7, 48, "持续监控"),
            ("run-current", 11, 88, "立即封禁"),
            ("run-future", 13, 99, "立即封禁"),
        ]:
            db.save_ip_observations(execution_id, [{"source_ip": ip, "attack_count": attack_count}])
            db.save_ip_scores(execution_id, [{
                "source_ip": ip,
                "final_score": score,
                "recommendation": recommendation,
                "is_recommended": True,
            }])

        for table in ("ip_observations", "ip_scores"):
            _set_created_at(db_path, table, "run-prior", "2026-01-01T00:00:00")
            _set_created_at(db_path, table, "run-current", "2026-01-02T00:00:00")
            _set_created_at(db_path, table, "run-future", "2026-01-03T00:00:00")

        summary = db.get_ip_history_summary(ip, before_execution_id="run-current")

        assert summary["historical_occurrences"] == 1
        assert summary["prior_execution_count"] == 1
        assert summary["prior_total_attacks"] == 7
        assert summary["prior_max_score"] == 48
        assert summary["previous_recommendation_count"] == 1
        assert summary["recent_recommendation"] == "持续监控"


def test_before_execution_uses_current_score_timestamp_when_observation_missing():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db_path = temp_dir / "attackers.db"
        db = DatabaseManager(str(db_path))

        ip = "203.0.113.10"
        db.save_ip_observations("run-prior", [{"source_ip": ip, "attack_count": 6}])
        db.save_ip_scores("run-prior", [{
            "source_ip": ip,
            "final_score": 42,
            "recommendation": "持续监控",
            "is_recommended": True,
        }])
        db.save_ip_scores("run-current", [{
            "source_ip": ip,
            "final_score": 80,
            "recommendation": "建议封禁",
            "is_recommended": True,
        }])
        db.save_ip_observations("run-future", [{"source_ip": ip, "attack_count": 30}])
        db.save_ip_scores("run-future", [{
            "source_ip": ip,
            "final_score": 99,
            "recommendation": "立即封禁",
            "is_recommended": True,
        }])

        for table in ("ip_observations", "ip_scores"):
            _set_created_at(db_path, table, "run-prior", "2026-01-01T00:00:00")
            _set_created_at(db_path, table, "run-current", "2026-01-02T00:00:00")
            _set_created_at(db_path, table, "run-future", "2026-01-03T00:00:00")

        summary = db.get_ip_history_summary(ip, before_execution_id="run-current")

        assert summary["historical_occurrences"] == 1
        assert summary["previous_recommendation_count"] == 1
        assert summary["prior_max_score"] == 42
        assert summary["max_historical_score"] == 42
        assert summary["recent_recommendation"] == "持续监控"
        assert summary["prior_max_recommendation"] == "持续监控"



def test_save_ip_scores_counts_recommended_recommendation_without_flag():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db = DatabaseManager(str(temp_dir / "attackers.db"))

        ip = "203.0.113.30"
        db.save_ip_observations("run-1", [{"source_ip": ip, "attack_count": 5}])
        db.save_ip_scores("run-1", [{
            "source_ip": ip,
            "final_score": 70,
            "recommendation": "建议封禁",
        }])

        summary = db.get_ip_history_summary(ip, before_execution_id="run-new")

        assert summary["previous_recommendation_count"] == 1


def test_prior_max_recommendation_matches_max_score_not_most_recent():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db_path = temp_dir / "attackers.db"
        db = DatabaseManager(str(db_path))

        ip = "203.0.113.40"
        db.save_ip_observations("run-high", [{"source_ip": ip, "attack_count": 20}])
        db.save_ip_scores("run-high", [{
            "source_ip": ip,
            "final_score": 95,
            "recommendation": "立即封禁",
            "is_recommended": True,
        }])
        db.save_ip_observations("run-recent", [{"source_ip": ip, "attack_count": 8}])
        db.save_ip_scores("run-recent", [{
            "source_ip": ip,
            "final_score": 55,
            "recommendation": "持续监控",
            "is_recommended": True,
        }])

        for table in ("ip_observations", "ip_scores"):
            _set_created_at(db_path, table, "run-high", "2026-01-01T00:00:00")
            _set_created_at(db_path, table, "run-recent", "2026-01-02T00:00:00")

        summary = db.get_ip_history_summary(ip, before_execution_id="run-new")

        assert summary["prior_max_score"] == 95
        assert summary["prior_max_recommendation"] == "立即封禁"
        assert summary["recent_recommendation"] == "持续监控"


def test_prior_max_recommendation_is_none_when_max_score_row_has_no_recommendation():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db_path = temp_dir / "attackers.db"
        db = DatabaseManager(str(db_path))

        ip = "203.0.113.45"
        db.save_ip_observations("run-high", [{"source_ip": ip, "attack_count": 20}])
        db.save_ip_scores("run-high", [{
            "source_ip": ip,
            "final_score": 95,
            "recommendation": "",
            "is_recommended": False,
        }])
        db.save_ip_observations("run-lower", [{"source_ip": ip, "attack_count": 8}])
        db.save_ip_scores("run-lower", [{
            "source_ip": ip,
            "final_score": 55,
            "recommendation": "持续监控",
            "is_recommended": True,
        }])

        for table in ("ip_observations", "ip_scores"):
            _set_created_at(db_path, table, "run-high", "2026-01-01T00:00:00")
            _set_created_at(db_path, table, "run-lower", "2026-01-02T00:00:00")

        summary = db.get_ip_history_summary(ip, before_execution_id="run-new")

        assert summary["prior_max_score"] == 95
        assert summary["max_historical_score"] == 95
        assert summary["prior_max_recommendation"] is None
        assert summary["recent_recommendation"] == "持续监控"


def test_before_execution_uses_executions_timestamp_when_current_rows_lack_created_at():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db_path = temp_dir / "attackers.db"
        db = DatabaseManager(str(db_path))

        ip = "203.0.113.60"
        for execution_id, attack_count, score, recommendation in [
            ("run-prior", 5, 40, "持续监控"),
            ("run-current", 9, 75, "建议封禁"),
            ("run-future", 30, 99, "立即封禁"),
        ]:
            db.save_ip_observations(execution_id, [{"source_ip": ip, "attack_count": attack_count}])
            db.save_ip_scores(execution_id, [{
                "source_ip": ip,
                "final_score": score,
                "recommendation": recommendation,
                "is_recommended": True,
            }])

        for table in ("ip_observations", "ip_scores"):
            _set_created_at(db_path, table, "run-prior", "2026-01-01T00:00:00")
            _set_created_at(db_path, table, "run-current", None)
            _set_created_at(db_path, table, "run-future", "2026-01-03T00:00:00")

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE executions (
                execution_id TEXT PRIMARY KEY,
                execution_time TIMESTAMP
            )
        ''')
        cursor.execute(
            "INSERT INTO executions (execution_id, execution_time) VALUES (?, ?)",
            ("run-current", "2026-01-02T00:00:00"),
        )
        conn.commit()
        conn.close()

        summary = db.get_ip_history_summary(ip, before_execution_id="run-current")

        assert summary["historical_occurrences"] == 1
        assert summary["prior_execution_count"] == 1
        assert summary["prior_total_attacks"] == 5
        assert summary["prior_max_score"] == 40
        assert summary["max_historical_score"] == 40
        assert summary["previous_recommendation_count"] == 1
        assert summary["recent_recommendation"] == "持续监控"


def test_recent_execution_count_uses_real_seven_day_window():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db_path = temp_dir / "attackers.db"
        db = DatabaseManager(str(db_path))

        ip = "203.0.113.50"
        runs = [
            ("run-stale", "2026-01-01T00:00:00"),
            ("run-recent-1", "2026-01-08T00:00:00"),
            ("run-recent-2", "2026-01-09T00:00:00"),
            ("run-current", "2026-01-10T00:00:00"),
        ]
        for execution_id, created_at in runs:
            db.save_ip_observations(execution_id, [{"source_ip": ip, "attack_count": 3}])
            _set_created_at(db_path, "ip_observations", execution_id, created_at)

        summary = db.get_ip_history_summary(ip, before_execution_id="run-current")

        assert summary["prior_execution_count"] == 3
        assert summary["recent_execution_count"] == 2

def test_existing_observation_table_is_migrated_before_save():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db_path = temp_dir / "attackers.db"
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE ip_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                source_file TEXT,
                report_type TEXT,
                attack_count INTEGER NOT NULL,
                first_event_time TEXT,
                last_event_time TEXT,
                main_threat_type TEXT,
                unique_threat_types INTEGER,
                threat_types_json TEXT,
                severity_dist_json TEXT,
                dst_ips_json TEXT,
                dst_ports_json TEXT,
                top_urls_json TEXT,
                sample_descriptions_json TEXT,
                packet_evidence_json TEXT,
                evidence_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

        db = DatabaseManager(str(db_path))
        db.save_ip_observations("run-legacy", [{
            "source_ip": "203.0.113.70",
            "attack_count": 4,
            "threat_types": {"SQL注入": 4},
            "severity_dist": {"高危": 4},
        }])
        db.save_top_attackers(
            {"203.0.113.70": 4},
            source_file="legacy.xlsx",
            execution_id="run-legacy",
        )

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(ip_observations)")
        columns = {row[1] for row in cursor.fetchall()}
        cursor.execute("SELECT threat_types, severity_dist FROM ip_observations WHERE source_ip = ?", ("203.0.113.70",))
        row = cursor.fetchone()
        conn.close()

        assert "threat_types" in columns
        assert "severity_dist" in columns
        assert "SQL注入" in row[0]
        assert "高危" in row[1]

def test_existing_ip_scores_table_is_migrated_before_save():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db_path = temp_dir / "attackers.db"
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE ip_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                total_score REAL DEFAULT 0
            )
        ''')
        conn.commit()
        conn.close()

        db = DatabaseManager(str(db_path))
        db.save_ip_scores("run-legacy", [{
            "ip": "203.0.113.80",
            "score": 77,
            "score_details": {"volume": {"score": 25}},
            "evidence": {"unique_threats": 2},
            "recommendation": "建议封禁",
        }])

        rows = db.get_ip_score_history("203.0.113.80")

        assert len(rows) == 1
        assert rows[0]["total_score"] == 77
        assert "volume" in rows[0]["score_details"]
        assert rows[0]["recommendation"] == "建议封禁"

def test_save_ip_scores_persists_score_breakdown_and_history_snapshot():
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        db = DatabaseManager(str(temp_dir / "attackers.db"))

        db.save_ip_scores("run-1", [{
            "ip": "203.0.113.10",
            "score": 80,
            "base_score": 65,
            "history_score": 15,
            "final_score": 80,
            "attack_count": 10,
            "score_details": {
                "volume": {"score": 10},
                "history": {
                    "score": 15,
                    "previous_recommendation_count": 2,
                    "reasons": ["历史出现 9 次"],
                },
            },
            "evidence": {
                "unique_threats": 2,
                "threat_types": {"SQL注入": 7},
            },
            "history": {"historical_occurrences": 9},
            "recommendation": "建议封禁",
            "is_recommended": True,
        }])

        rows = db.get_ip_score_history("203.0.113.10")

        assert len(rows) == 1
        row = rows[0]
        assert row["base_score"] == 65
        assert row["history_score"] == 15
        assert row["final_score"] == 80
        assert "历史出现 9 次" in row["history_details_json"]
        assert row["historical_occurrences"] == 9


if __name__ == "__main__":
    test_get_ip_history_summaries_returns_required_fields()
    test_before_execution_excludes_current_and_future_history_by_timestamp()
    test_before_execution_uses_current_score_timestamp_when_observation_missing()
    test_save_ip_scores_counts_recommended_recommendation_without_flag()
    test_prior_max_recommendation_matches_max_score_not_most_recent()
    test_prior_max_recommendation_is_none_when_max_score_row_has_no_recommendation()
    test_before_execution_uses_executions_timestamp_when_current_rows_lack_created_at()
    test_recent_execution_count_uses_real_seven_day_window()
    test_existing_observation_table_is_migrated_before_save()
    test_existing_ip_scores_table_is_migrated_before_save()
    test_save_ip_scores_persists_score_breakdown_and_history_snapshot()
    print("plain python database history summary test passed")
