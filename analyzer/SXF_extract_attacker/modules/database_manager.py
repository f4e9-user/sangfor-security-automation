"""数据库管理模块 - 处理攻击源IP数据的SQLite存储"""

import sqlite3
import os
import csv
import json
from datetime import datetime
from typing import List, Tuple, Dict, Any


class DatabaseManager:
    """SQLite数据库管理器，用于存储和查询攻击源IP数据"""
    
    def __init__(self, db_path: str = "data/attackers.db"):
        """
        初始化数据库管理器
        
        Args:
            db_path: SQLite数据库文件路径
        """
        self.db_path = db_path
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self.init_database()
    
    def load_real_block_data(self, blacklist_file: str = "../blacklist.csv") -> set:
        """从CSV文件加载真实封堵IP列表"""
        real_block_ips = set()
        try:
            with open(blacklist_file, 'r', encoding='utf-8-sig') as csvfile:
                # Read the file as text first to handle special formatting
                content = csvfile.read()
                lines = content.split('\n')
                
                for line in lines[2:]:  # Skip first 2 header rows
                    if line.strip() and line.startswith("'"):
                        # Remove leading quote and extract IP
                        clean_line = line.strip()[1:]  # Remove leading '
                        
                        # Simple parsing: split by commas and get the first field
                        if '","' in clean_line:
                            ip_field = clean_line.split('","')[0]
                            ip_field = ip_field.strip("'\"")
                            
                            # Check if it's an IP address (contains digits and dots)
                            if '.' in ip_field and all(c.isdigit() or c == '.' for c in ip_field.replace('.', '')):
                                real_block_ips.add(ip_field)
        except FileNotFoundError:
            print(f"⚠️ 黑名单文件未找到: {blacklist_file}")
        except Exception as e:
            print(f"⚠️ 加载黑名单文件时出错: {e}")
        
        return real_block_ips
    
    def init_database(self):
        """初始化数据库表结构"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 创建攻击源IP记录表
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
        
        # 创建索引以提高查询性能
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_execution_time ON top_attackers(execution_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON top_attackers(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_execution_id ON top_attackers(execution_id)')

        # 保存每次运行中每个 IP 的观测摘要，用于后续历史评分
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
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_observations_ip ON ip_observations(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_observations_execution ON ip_observations(execution_id)')
        self._ensure_columns(cursor, 'ip_observations', {
            'attack_count': 'INTEGER DEFAULT 0',
            'threat_types': 'TEXT',
            'severity_dist': 'TEXT',
            'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
        })

        # 保存评分和推荐结果，用于统计历史最高分与历史推荐次数
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
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_scores_ip ON ip_scores(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_scores_execution ON ip_scores(execution_id)')
        self._ensure_columns(cursor, 'ip_scores', {
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
        
        
        conn.commit()
        conn.close()
    
    def _ensure_columns(self, cursor, table: str, columns: Dict[str, str]):
        """为已存在表补齐新增列。"""
        cursor.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cursor.fetchall()}
        for column, definition in columns.items():
            if column not in existing:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def save_top_attackers(self, top_ips: Dict[str, int], source_file: str = None, execution_id: str = None, blacklist_file: str = "../blacklist.csv"):
        """
        保存top攻击源IP到数据库
        
        Args:
            top_ips: Top IP字典，格式为 {ip: count}
            source_file: 源文件名
            execution_id: 执行ID，用于标识同一次执行
            blacklist_file: 黑名单文件路径，用于标记真实封堵IP
        """
        if not top_ips:
            return
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 加载真实封堵IP列表
        real_block_ips = self.load_real_block_data(blacklist_file)
        
        # 如果没有提供执行ID，则使用当前时间戳
        if not execution_id:
            execution_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        # 先删除本次执行的相同记录，避免重复
        cursor.execute("DELETE FROM top_attackers WHERE execution_id = ?", (execution_id,))
        
        # 准备插入数据
        records = []
        for rank, (ip, count) in enumerate(top_ips.items(), 1):
            is_real_block = ip in real_block_ips
            records.append((
                datetime.now().isoformat(),
                ip,
                count,
                None,  # threat_type暂时为None，后续可扩展
                source_file,
                rank,
                execution_id,
                is_real_block
            ))
        
        # 插入新数据
        cursor.executemany('''
            INSERT INTO top_attackers
            (execution_time, source_ip, ip_count, threat_type, source_file, rank_in_execution, execution_id, real_block)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', records)
        
        # 确保所有在黑名单中的IP都被正确标记（包括之前已存在的记录）
        for ip in real_block_ips:
            cursor.execute('''
                UPDATE top_attackers
                SET real_block = TRUE
                WHERE source_ip = ?
            ''', (ip,))
        
        conn.commit()
        conn.close()
        
        print(f"✅ 数据库记录已保存: {len(records)} 条top攻击源IP记录已插入数据库 {self.db_path}")
    
    def get_recent_executions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取最近的执行记录
        
        Args:
            limit: 返回记录数量限制
            
        Returns:
            执行记录列表
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT execution_id, execution_time, source_file
            FROM top_attackers
            ORDER BY execution_time DESC
            LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'execution_id': row[0],
                'execution_time': row[1],
                'source_file': row[2]
            })
        
        conn.close()
        return results
    
    def get_top_attackers_by_execution(self, execution_id: str) -> List[Dict[str, Any]]:
        """
        根据执行ID获取该次执行的top攻击源IP
        
        Args:
            execution_id: 执行ID
            
        Returns:
            该次执行的top攻击源IP列表
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, ip_count, rank_in_execution, execution_time
            FROM top_attackers
            WHERE execution_id = ?
            ORDER BY rank_in_execution
        ''', (execution_id,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'source_ip': row[0],
                'ip_count': row[1],
                'rank_in_execution': row[2],
                'execution_time': row[3]
            })
        
        conn.close()
        return results
    
    def get_all_top_attackers(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        获取所有记录中的top攻击源IP（按总出现次数排序）
        
        Args:
            limit: 返回记录数量限制
            
        Returns:
            按总出现次数排序的攻击源IP列表
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, SUM(ip_count) as total_count, COUNT(*) as execution_count
            FROM top_attackers
            GROUP BY source_ip
            ORDER BY total_count DESC
            LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'source_ip': row[0],
                'total_count': row[1],
                'execution_count': row[2]
            })
        
        conn.close()
        return results
    
    def get_all_top_attackers_with_real_block_status(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        获取所有记录中的top攻击源IP（按总出现次数排序），包含真实封堵状态
        
        Args:
            limit: 返回记录数量限制
            
        Returns:
            按总出现次数排序的攻击源IP列表，包含真实封堵状态
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, SUM(ip_count) as total_count, COUNT(*) as execution_count,
                   MAX(CASE WHEN real_block THEN 1 ELSE 0 END) as real_block
            FROM top_attackers
            GROUP BY source_ip
            ORDER BY total_count DESC
            LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'source_ip': row[0],
                'total_count': row[1],
                'execution_count': row[2],
                'real_block': bool(row[3])
            })
        
        conn.close()
        return results
    
    def save_ip_observations(self, execution_id: str, observations: List[Dict[str, Any]]):
        """保存每次执行的 IP 观测摘要。"""
        if not observations:
            return

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute("DELETE FROM ip_observations WHERE execution_id = ?", (execution_id,))
            now = datetime.now().isoformat()
            records = []
            for item in observations:
                source_ip = item.get('source_ip') or item.get('ip')
                if not source_ip:
                    continue
                records.append((
                    execution_id,
                    source_ip,
                    int(item.get('attack_count') or item.get('ip_count') or 0),
                    json.dumps(item.get('threat_types') or {}, ensure_ascii=False),
                    json.dumps(item.get('severity_dist') or {}, ensure_ascii=False),
                    now,
                ))

            if records:
                cursor.executemany('''
                    INSERT INTO ip_observations
                    (execution_id, source_ip, attack_count, threat_types, severity_dist, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', records)

            conn.commit()
        finally:
            conn.close()

    def save_ip_scores(self, execution_id: str, scores: List[Dict[str, Any]]):
        """保存每次执行的 IP 评分与推荐结果。"""
        if not scores:
            return

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute("DELETE FROM ip_scores WHERE execution_id = ?", (execution_id,))
            now = datetime.now().isoformat()
            records = []
            for item in scores:
                source_ip = item.get('source_ip') or item.get('ip')
                if not source_ip:
                    continue
                total_score = item.get('score')
                final_score = item.get('final_score')
                if final_score is None:
                    final_score = total_score
                recommendation = item.get('recommendation')
                explicit_recommended = item.get('is_recommended')
                if explicit_recommended is False or explicit_recommended == 0:
                    is_recommended = False
                else:
                    is_recommended = bool(explicit_recommended) or recommendation in (
                        '持续监控',
                        '建议封禁',
                        '立即封禁',
                    )
                score_details = item.get('score_details') or {}
                evidence = item.get('evidence') or {}
                history_details = {
                    **(score_details.get('history') or {}),
                    **(item.get('history') or {}),
                }
                records.append((
                    execution_id,
                    source_ip,
                    total_score or 0,
                    item.get('base_score') or 0,
                    item.get('history_score') or 0,
                    final_score or 0,
                    int(item.get('attack_count') or 0),
                    json.dumps(score_details, ensure_ascii=False),
                    json.dumps(evidence, ensure_ascii=False),
                    json.dumps(history_details, ensure_ascii=False),
                    json.dumps(evidence, ensure_ascii=False),
                    int(history_details.get('historical_occurrences') or 0),
                    recommendation,
                    is_recommended,
                    now,
                ))

            if records:
                cursor.executemany('''
                    INSERT INTO ip_scores
                    (execution_id, source_ip, total_score, base_score, history_score, final_score,
                     attack_count, score_details, evidence, history_details_json, evidence_json,
                     historical_occurrences, recommendation, is_recommended, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', records)

            conn.commit()
        finally:
            conn.close()

    def get_ip_score_history(self, source_ip: str) -> List[Dict[str, Any]]:
        """获取单个 IP 的评分历史明细。"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT execution_id, source_ip, total_score, base_score, history_score, final_score,
                   attack_count, score_details, evidence, history_details_json, evidence_json,
                   historical_occurrences, recommendation, is_recommended, created_at
            FROM ip_scores
            WHERE source_ip = ?
            ORDER BY created_at ASC, id ASC
        """, (source_ip,))

        rows = []
        for row in cursor.fetchall():
            rows.append({
                'execution_id': row[0],
                'source_ip': row[1],
                'total_score': row[2],
                'base_score': row[3],
                'history_score': row[4],
                'final_score': row[5],
                'attack_count': row[6],
                'score_details': row[7],
                'evidence': row[8],
                'history_details_json': row[9],
                'evidence_json': row[10],
                'historical_occurrences': row[11],
                'recommendation': row[12],
                'is_recommended': bool(row[13]),
                'created_at': row[14],
            })

        conn.close()
        return rows

    def _empty_ip_history_summary(self, source_ip: str) -> Dict[str, Any]:
        """返回首次出现 IP 的完整历史摘要字段。"""
        return {
            'source_ip': source_ip,
            'seen_before': False,
            'historical_occurrences': 0,
            'prior_execution_count': 0,
            'prior_total_attacks': 0,
            'prior_max_attacks': 0,
            'prior_days_seen': 0,
            'recent_execution_count': 0,
            'first_seen': None,
            'last_seen': None,
            'last_seen_days': None,
            'prior_max_recommendation': None,
            'prior_max_score': None,
            'max_historical_score': None,
            'previous_recommendation_count': 0,
            'recent_recommendation': None,
            'note': '首次出现',
        }

    def get_ip_history_summaries(self, source_ips: List[str], before_execution_id: str = None) -> Dict[str, Dict[str, Any]]:
        """批量获取 IP 历史摘要；当前实现复用单 IP 查询并补齐未见 IP。"""
        return {
            source_ip: self.get_ip_history_summary(source_ip, before_execution_id)
            for source_ip in source_ips
        }

    def _get_execution_timestamp(self, cursor, execution_id: str):
        """获取执行时间戳；不存在或无时间戳时返回 None。"""
        if not execution_id:
            return None

        cursor.execute('''
            SELECT MIN(created_at)
            FROM ip_observations
            WHERE execution_id = ? AND created_at IS NOT NULL AND created_at != ''
        ''', (execution_id,))
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]

        cursor.execute('''
            SELECT MIN(created_at)
            FROM ip_scores
            WHERE execution_id = ? AND created_at IS NOT NULL AND created_at != ''
        ''', (execution_id,))
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]

        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'executions'")
        if not cursor.fetchone():
            return None

        cursor.execute("PRAGMA table_info(executions)")
        columns = [column[1] for column in cursor.fetchall()]
        id_column = 'execution_id' if 'execution_id' in columns else None
        timestamp_column = next((
            column for column in (
                'execution_time',
                'created_at',
                'started_at',
                'timestamp',
                'run_at',
            )
            if column in columns
        ), None)
        if not id_column or not timestamp_column:
            return None

        cursor.execute(f'''
            SELECT MIN({timestamp_column})
            FROM executions
            WHERE {id_column} = ?
              AND {timestamp_column} IS NOT NULL
              AND {timestamp_column} != ''
        ''', (execution_id,))
        row = cursor.fetchone()
        return row[0] if row and row[0] else None

    def get_ip_history_summary(self, source_ip: str, before_execution_id: str = None) -> Dict[str, Any]:
        """获取单个 IP 在指定执行前的历史观测、评分与推荐摘要。"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        before_timestamp = self._get_execution_timestamp(cursor, before_execution_id)

        observation_params = [source_ip]
        observation_filter = "source_ip = ?"
        if before_execution_id:
            observation_filter += " AND execution_id != ?"
            observation_params.append(before_execution_id)
        if before_timestamp:
            observation_filter += " AND datetime(created_at) < datetime(?)"
            observation_params.append(before_timestamp)

        cursor.execute(f'''
            SELECT
                COUNT(*) AS historical_occurrences,
                COUNT(DISTINCT execution_id) AS prior_execution_count,
                COALESCE(SUM(attack_count), 0) AS prior_total_attacks,
                COALESCE(MAX(attack_count), 0) AS prior_max_attacks,
                COUNT(DISTINCT DATE(created_at)) AS prior_days_seen,
                MIN(created_at) AS first_seen,
                MAX(created_at) AS last_seen
            FROM ip_observations
            WHERE {observation_filter}
        ''', observation_params)
        row = cursor.fetchone()

        if not row or row[0] == 0:
            conn.close()
            return self._empty_ip_history_summary(source_ip)

        historical_occurrences = row[0]
        prior_total_attacks = row[2] or 0
        last_seen = row[6]

        score_params = [source_ip]
        score_filter = "source_ip = ?"
        if before_execution_id:
            score_filter += " AND execution_id != ?"
            score_params.append(before_execution_id)
        if before_timestamp:
            score_filter += " AND datetime(created_at) < datetime(?)"
            score_params.append(before_timestamp)

        cursor.execute(f'''
            SELECT MAX(COALESCE(final_score, total_score, 0))
            FROM ip_scores
            WHERE {score_filter}
        ''', score_params)
        max_score = cursor.fetchone()[0]

        cursor.execute(f'''
            SELECT recommendation
            FROM ip_scores
            WHERE {score_filter}
            ORDER BY COALESCE(final_score, total_score, 0) DESC, created_at DESC, id DESC
            LIMIT 1
        ''', score_params)
        max_recommendation_row = cursor.fetchone()
        prior_max_recommendation = None
        if max_recommendation_row and max_recommendation_row[0]:
            prior_max_recommendation = max_recommendation_row[0]

        cursor.execute(f'''
            SELECT COALESCE(SUM(CASE WHEN is_recommended THEN 1 ELSE 0 END), 0)
            FROM ip_scores
            WHERE {score_filter}
        ''', score_params)
        previous_recommendation_count = cursor.fetchone()[0] or 0

        cursor.execute(f'''
            SELECT recommendation
            FROM ip_scores
            WHERE {score_filter}
              AND recommendation IS NOT NULL
              AND recommendation != ''
            ORDER BY created_at DESC, id DESC
            LIMIT 1
        ''', score_params)
        recommendation_row = cursor.fetchone()
        recent_recommendation = recommendation_row[0] if recommendation_row else None

        recent_reference_time = before_timestamp or datetime.now().isoformat()
        cursor.execute(f'''
            SELECT COUNT(DISTINCT execution_id)
            FROM ip_observations
            WHERE {observation_filter}
              AND datetime(created_at) >= datetime(?, '-7 days')
        ''', observation_params + [recent_reference_time])
        recent_execution_count = cursor.fetchone()[0] or 0

        conn.close()

        last_seen_days = None
        if last_seen:
            try:
                last_seen_dt = datetime.fromisoformat(str(last_seen))
                last_seen_days = round((datetime.now() - last_seen_dt).total_seconds() / 86400, 1)
            except ValueError:
                last_seen_days = None

        return {
            'source_ip': source_ip,
            'seen_before': True,
            'historical_occurrences': historical_occurrences,
            'prior_execution_count': row[1] or 0,
            'prior_total_attacks': prior_total_attacks,
            'prior_max_attacks': row[3] or 0,
            'prior_days_seen': row[4] or 0,
            'recent_execution_count': recent_execution_count,
            'first_seen': row[5],
            'last_seen': last_seen,
            'last_seen_days': last_seen_days,
            'prior_max_recommendation': prior_max_recommendation,
            'prior_max_score': max_score,
            'max_historical_score': max_score,
            'previous_recommendation_count': previous_recommendation_count,
            'recent_recommendation': recent_recommendation,
            'note': f'历史出现 {historical_occurrences} 次，累计攻击 {prior_total_attacks} 次',
        }

    def update_real_block_status(self, blacklist_file: str = "../blacklist.csv") -> int:
        """
        根据黑名单文件更新现有记录的真实封堵状态
        
        Args:
            blacklist_file: 黑名单文件路径
            
        Returns:
            更新的记录数量
        """
        real_block_ips = self.load_real_block_data(blacklist_file)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 更新所有在黑名单中的IP记录的real_block状态
        updated_count = 0
        for ip in real_block_ips:
            cursor.execute('''
                UPDATE top_attackers
                SET real_block = TRUE
                WHERE source_ip = ?
            ''', (ip,))
            updated_count += cursor.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"✅ 已更新 {updated_count} 条记录的真实封堵状态")
        return updated_count
    
    def clear_old_records(self, days: int = 30) -> int:
        """
        清理指定天数前的旧记录
        
        Args:
            days: 保留天数
            
        Returns:
            删除的记录数量
        """
        from datetime import datetime, timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM top_attackers 
            WHERE execution_time < ?
        ''', (cutoff_date.isoformat(),))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted_count


def test_database():
    """测试数据库功能"""
    db = DatabaseManager("test_attackers.db")
    
    # 模拟top10数据
    test_data = {
        "192.168.1.1": 150,
        "10.0.0.1": 120,
        "172.16.0.1": 90,
        "8.8.8.8": 80,
        "1.1.1.1": 70
    }
    
    db.save_top_attackers(test_data, "test_file.xlsx", "test_execution_001", "../blacklist.csv")
    
    # 查询最近执行
    recent = db.get_recent_executions(5)
    print("最近执行记录:", recent)
    
    # 查询特定执行的top攻击源
    top_attackers = db.get_top_attackers_by_execution("test_execution_001")
    print("特定执行的top攻击源:", top_attackers)
    
    # 查询总体top攻击源
    all_top = db.get_all_top_attackers(10)
    print("总体top攻击源:", all_top)
    
    # 清理测试数据库
    os.remove("test_attackers.db")
    print("测试完成")


if __name__ == "__main__":
    test_database()
