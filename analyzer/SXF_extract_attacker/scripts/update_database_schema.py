#!/usr/bin/env python3
"""数据库模式更新脚本"""

import argparse
import sqlite3
import os
from pathlib import Path


DEFAULT_DB_PATH = str(Path(__file__).resolve().parents[1] / "data" / "attackers.db")


def _ensure_columns(cursor, table_name, columns):
    cursor.execute(f"PRAGMA table_info({table_name})")
    existing = {column[1] for column in cursor.fetchall()}
    for name, definition in columns.items():
        if name not in existing:
            print(f"正在为 {table_name} 添加字段: {name}")
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {name} {definition}")


def update_database_schema(db_path=DEFAULT_DB_PATH):
    """幂等更新数据库模式"""
    print(f"正在更新数据库模式: {db_path}")

    if not os.path.exists(db_path):
        print(f"数据库文件不存在: {db_path}")
        print("创建新的数据库文件...")

    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute('PRAGMA busy_timeout = 30000')
    cursor = conn.cursor()

    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS top_attackers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                ip_count INTEGER NOT NULL,
                threat_type TEXT,
                source_file TEXT,
                rank_in_execution INTEGER,
                execution_id TEXT,
                real_block BOOLEAN DEFAULT FALSE
            )
        ''')
        _ensure_columns(cursor, 'top_attackers', {
            'real_block': 'BOOLEAN DEFAULT FALSE',
        })
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_execution_time ON top_attackers(execution_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON top_attackers(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_execution_id ON top_attackers(execution_id)')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT UNIQUE NOT NULL,
                execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_file TEXT,
                report_type TEXT,
                total_events INTEGER,
                excluded_ips_count INTEGER,
                top_ip_count INTEGER,
                processing_duration_seconds REAL,
                flags TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                threat_type TEXT,
                threat_subtype TEXT,
                dst_ip TEXT,
                dst_port TEXT,
                request_url TEXT,
                severity TEXT,
                attack_result TEXT,
                description TEXT,
                event_time TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_execution ON attack_events(execution_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_ip ON attack_events(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_threat ON attack_events(threat_type)')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                total_score REAL DEFAULT 0,
                base_score REAL DEFAULT 0,
                history_score REAL DEFAULT 0,
                final_score REAL DEFAULT 0,
                attack_count INTEGER DEFAULT 0,
                score_details TEXT,
                evidence TEXT,
                history_details_json TEXT,
                evidence_json TEXT,
                historical_occurrences INTEGER DEFAULT 0,
                recommendation TEXT,
                is_recommended BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        _ensure_columns(cursor, 'ip_scores', {
            'total_score': 'REAL DEFAULT 0',
            'base_score': 'REAL DEFAULT 0',
            'history_score': 'REAL DEFAULT 0',
            'final_score': 'REAL DEFAULT 0',
            'attack_count': 'INTEGER DEFAULT 0',
            'score_details': 'TEXT',
            'evidence': 'TEXT',
            'history_details_json': 'TEXT',
            'evidence_json': 'TEXT',
            'historical_occurrences': 'INTEGER DEFAULT 0',
            'recommendation': 'TEXT',
            'is_recommended': 'BOOLEAN DEFAULT FALSE',
            'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
        })
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scores_execution ON ip_scores(execution_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scores_ip ON ip_scores(source_ip)')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attack_count INTEGER DEFAULT 0,
                threat_types TEXT,
                severity_dist TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        _ensure_columns(cursor, 'ip_observations', {
            'attack_count': 'INTEGER DEFAULT 0',
            'threat_types': 'TEXT',
            'severity_dist': 'TEXT',
            'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
        })
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_observations_ip ON ip_observations(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_observations_execution ON ip_observations(execution_id)')

        conn.commit()
        print(f"✅ 数据库模式更新完成: {db_path}")
        return True
    except Exception as e:
        print(f"❌ 更新数据库模式时出错: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


def verify_schema(db_path=DEFAULT_DB_PATH):
    """验证数据库模式"""
    print(f"\n验证数据库模式: {db_path}")

    if not os.path.exists(db_path):
        print(f"数据库文件不存在: {db_path}")
        return False

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        required_tables = ['top_attackers', 'executions', 'attack_events', 'ip_scores', 'ip_observations']
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        ok = True
        for table in required_tables:
            if table not in tables:
                print(f"❌ 缺少表: {table}")
                ok = False
                continue
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in cursor.fetchall()]
            print(f"✅ {table}: {len(columns)} 个字段")

        for table in required_tables:
            if table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                print(f"  {table}: {cursor.fetchone()[0]} 条记录")

        return ok
    except Exception as e:
        print(f"❌ 验证数据库模式时出错: {e}")
        return False
    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="幂等更新 attackers SQLite 数据库表结构")
    parser.add_argument("db_path", nargs="?", default=DEFAULT_DB_PATH, help=f"数据库路径，默认 {DEFAULT_DB_PATH}")
    args = parser.parse_args()
    db_path = args.db_path

    print("=" * 60)
    print("数据库模式更新工具")
    print("=" * 60)

    success = update_database_schema(db_path)
    if success:
        verify_schema(db_path)

    print("=" * 60)
    print("任务完成")
