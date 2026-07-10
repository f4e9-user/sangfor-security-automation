#!/usr/bin/env python3
"""测试数据库功能"""

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules.database_manager import DatabaseManager


def test_database_functionality():
    """测试数据库功能：保存 top10 IP 并验证可读回。"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
        temp_db_path = tmp_file.name
    try:
        db_manager = DatabaseManager(temp_db_path)
        test_top_ips = {
            "192.168.1.100": 150,
            "10.0.0.50": 120,
            "198.51.100.25": 95,
            "8.8.8.8": 88,
            "1.1.1.1": 75,
            "202.108.22.5": 65,
            "114.114.114.114": 60,
            "223.5.5.5": 55,
            "119.29.29.29": 50,
            "180.76.76.76": 45,
        }
        db_manager.save_top_attackers(test_top_ips, "test_input.xlsx", "test_execution_001")

        recent_executions = db_manager.get_recent_executions(5)
        assert len(recent_executions) >= 1
        assert any(e["execution_id"] == "test_execution_001" for e in recent_executions)

        top_attackers = db_manager.get_top_attackers_by_execution("test_execution_001")
        assert len(top_attackers) == 10
        assert any(a["source_ip"] == "192.168.1.100" for a in top_attackers)

        all_top = db_manager.get_all_top_attackers(10)
        assert len(all_top) > 0
    finally:
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)


def test_with_sample_data():
    """使用示例数据测试：保存 3 条 mock IP 并验证可读回。"""
    class MockSeries:
        def __init__(self, data):
            self.data = data

        def to_dict(self):
            return self.data

    mock_top_ips = MockSeries({
        "192.168.1.1": 100,
        "10.0.0.1": 80,
        "198.51.100.1": 70,
    })

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
        temp_db_path = tmp_file.name
    try:
        db_manager = DatabaseManager(temp_db_path)
        db_manager.save_top_attackers(mock_top_ips.to_dict(), "sample.xlsx", "sample_exec_001")
        top_attackers = db_manager.get_top_attackers_by_execution("sample_exec_001")
        assert len(top_attackers) == 3
    finally:
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)


if __name__ == "__main__":
    print("🚀 开始数据库功能测试...")
    test_database_functionality()
    test_with_sample_data()
    print("\n🎉 所有测试通过！数据库功能正常工作。")
    sys.exit(0)