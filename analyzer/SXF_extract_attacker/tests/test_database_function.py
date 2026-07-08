#!/usr/bin/env python3
"""测试数据库功能的脚本"""

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules.database_manager import DatabaseManager

def test_database_functionality():
    """测试数据库功能"""
    print("🧪 开始测试数据库功能...")
    
    # 创建临时数据库文件用于测试
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_file:
        temp_db_path = tmp_file.name
    
    try:
        # 创建数据库管理器实例
        print(f"📁 创建数据库: {temp_db_path}")
        db_manager = DatabaseManager(temp_db_path)
        
        # 测试数据
        test_top_ips = {
            "192.168.1.100": 150,
            "10.0.0.50": 120,
            "172.16.0.25": 95,
            "8.8.8.8": 88,
            "1.1.1.1": 75,
            "202.108.22.5": 65,
            "114.114.114.114": 60,
            "223.5.5.5": 55,
            "119.29.29.29": 50,
            "180.76.76.76": 45
        }
        
        print("💾 测试保存top10 IP数据到数据库...")
        db_manager.save_top_attackers(test_top_ips, "test_input.xlsx", "test_execution_001")
        
        # 验证数据是否正确保存
        print("🔍 验证保存的数据...")
        recent_executions = db_manager.get_recent_executions(5)
        print(f"最近执行记录: {len(recent_executions)} 条")
        for exec_info in recent_executions:
            print(f"  - 执行ID: {exec_info['execution_id']}, 时间: {exec_info['execution_time']}, 文件: {exec_info['source_file']}")
        
        # 查询特定执行的top攻击源
        top_attackers = db_manager.get_top_attackers_by_execution("test_execution_001")
        print(f"\n📋 特定执行的top攻击源: {len(top_attackers)} 条")
        for attacker in top_attackers:
            print(f"  - IP: {attacker['source_ip']}, 次数: {attacker['ip_count']}, 排名: {attacker['rank_in_execution']}")
        
        # 查询总体top攻击源
        all_top = db_manager.get_all_top_attackers(10)
        print(f"\n📊 总体top攻击源: {len(all_top)} 条")
        for i, attacker in enumerate(all_top, 1):
            print(f"  {i}. IP: {attacker['source_ip']}, 总次数: {attacker['total_count']}, 执行次数: {attacker['execution_count']}")
        
        print("\n✅ 数据库功能测试通过！")
        
    except Exception as e:
        print(f"❌ 数据库功能测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # 清理临时数据库文件
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)
            print(f"🗑️ 清理临时数据库文件: {temp_db_path}")
    
    return True

def test_with_sample_data():
    """使用示例数据测试功能"""
    print("\n🧪 测试与现有代码集成...")
    
    # 模拟从pandas Series获取的数据
    class MockSeries:
        def __init__(self, data):
            self.data = data
        
        def to_dict(self):
            return self.data
    
    mock_top_ips = MockSeries({
        "192.168.1.1": 100,
        "10.0.0.1": 80,
        "172.16.0.1": 70
    })
    
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_file:
        temp_db_path = tmp_file.name
    
    try:
        db_manager = DatabaseManager(temp_db_path)
        # 测试保存模拟的pandas Series数据
        db_manager.save_top_attackers(mock_top_ips.to_dict(), "sample.xlsx", "sample_exec_001")
        
        # 验证数据
        top_attackers = db_manager.get_top_attackers_by_execution("sample_exec_001")
        print(f"✅ 集成测试通过，保存了 {len(top_attackers)} 条记录")
        
        for attacker in top_attackers:
            print(f"  - IP: {attacker['source_ip']}, 次数: {attacker['ip_count']}")
        
    except Exception as e:
        print(f"❌ 集成测试失败: {e}")
        return False
    finally:
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)
    
    return True

if __name__ == "__main__":
    print("🚀 开始数据库功能测试...")
    
    success1 = test_database_functionality()
    success2 = test_with_sample_data()
    
    if success1 and success2:
        print("\n🎉 所有测试通过！数据库功能正常工作。")
        sys.exit(0)
    else:
        print("\n💥 测试失败！")
        sys.exit(1)
