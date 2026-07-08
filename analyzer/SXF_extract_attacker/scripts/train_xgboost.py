#!/usr/bin/env python3
"""从 data/attackers.db 提取真实特征训练 XGBoost 威胁评分模型"""

import sqlite3
import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from xgboost import XGBClassifier
import joblib

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DB_PATH = str(REPO_ROOT / "data" / "attackers.db")
MODEL_PATH = str(REPO_ROOT / "modules" / "threat_scorer_v1.pkl")


def fetch_features(conn):
    """从 top_attackers 提取每个 IP 的聚合特征"""
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            source_ip,
            SUM(ip_count)                         AS total_attacks,
            COUNT(DISTINCT execution_id)           AS execution_count,
            AVG(rank_in_execution)                 AS avg_rank,
            MAX(ip_count)                          AS max_single_run,
            COUNT(DISTINCT threat_type)            AS threat_diversity,
            MAX(execution_time)                    AS last_seen
        FROM top_attackers
        GROUP BY source_ip
    ''')
    rows = cursor.fetchall()

    features = []
    ips = []
    for r in rows:
        ip, total_attacks, exec_cnt, avg_rank, max_run, diversity, last_seen = r
        ips.append(ip)
        features.append([
            total_attacks or 0,
            exec_cnt or 0,
            avg_rank or 10,
            max_run or 0,
            diversity or 0,
        ])

    return ips, np.array(features, dtype=float), rows


def enrich_with_keywords(conn, ips):
    """检测每个 IP 的威胁类型中是否包含高危关键词"""
    cursor = conn.cursor()
    high_risk_patterns = [
        '%SQL%', '%注入%', '%injection%', '%RCE%', '%代码执行%',
        '%WebShell%', '%webshell%', '%上传%', '%upload%',
        '%暴力%', '%brute%', '%爆破%', '%口令%',
        '%扫描%', '%scan%', '%漏洞%', '%vuln%',
    ]
    ip_risk_flags = {ip: 0 for ip in ips}

    for pattern in high_risk_patterns:
        cursor.execute('''
            SELECT DISTINCT source_ip FROM top_attackers
            WHERE source_ip IN ({seq}) AND threat_type LIKE ?
        '''.format(seq=','.join('?' * len(ips))), [*ips, pattern])
        for (ip,) in cursor.fetchall():
            ip_risk_flags[ip] += 1

    return np.array([[ip_risk_flags[ip]] for ip in ips], dtype=float)


def generate_labels(features, threshold_total=500, threshold_exec=3):
    """基于启发式规则生成标签: 1=建议封禁, 0=观察"""
    total_attacks = features[:, 0]
    exec_count = features[:, 1]

    labels = np.zeros(len(features), dtype=int)
    # 高频 OR 跨多次执行 OR (中等频率 + 多次出现)
    mask = (total_attacks > threshold_total) | \
           (exec_count >= threshold_exec) | \
           ((total_attacks > 200) & (exec_count >= 2))
    labels[mask] = 1
    return labels


def train():
    conn = sqlite3.connect(DB_PATH)

    print(f"正在从 {DB_PATH} 提取特征...")
    ips, base_features, raw_rows = fetch_features(conn)

    if len(base_features) < 20:
        print(f"数据不足（仅 {len(base_features)} 个 IP），至少需要 20 个。使用模拟数据演示。")
        conn.close()
        return _train_with_synthetic()

    print(f"  → 提取到 {len(ips)} 个 IP 的基础特征")

    risk_features = enrich_with_keywords(conn, ips)
    print(f"  → 高危关键词特征提取完成")

    conn.close()

    X = np.hstack([base_features, risk_features])
    feature_names = [
        'total_attacks', 'execution_count', 'avg_rank', 'max_single_run',
        'threat_diversity', 'high_risk_keyword_count',
    ]

    y = generate_labels(X)
    n_positive = y.sum()
    print(f"  → 标签分布: {n_positive} 建议封禁, {len(y) - n_positive} 观察")

    if n_positive < 3 or n_positive == len(y):
        print("标签分布不均衡，调整为更宽松的阈值...")
        y = generate_labels(X, threshold_total=200, threshold_exec=2)
        n_positive = y.sum()
        print(f"  → 调整后标签分布: {n_positive} 建议封禁, {len(y) - n_positive} 观察")

    class_counts = np.bincount(y.astype(int), minlength=2)
    if class_counts.min() < 2:
        print("标签仍然不足以训练分类模型，使用模拟数据演示。")
        return _train_with_synthetic()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = XGBClassifier(n_estimators=80, max_depth=5, learning_rate=0.05,
                          random_state=42, eval_metric='logloss')
    model.fit(X_train, y_train)

    acc = model.score(X_test, y_test)
    cv_scores = cross_val_score(model, X, y, cv=min(5, class_counts.min()))
    print(f"\n模型评估:")
    print(f"  Test Accuracy: {acc:.3f}")
    print(f"  CV Accuracy:   {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")

    importances = sorted(zip(feature_names, model.feature_importances_), key=lambda x: -x[1])
    print("\n特征重要性:")
    for name, imp in importances:
        print(f"  {name:25s}: {imp:.3f}")

    joblib.dump(model, MODEL_PATH)
    print(f"\n模型已保存至 {MODEL_PATH}")


def _train_with_synthetic():
    """数据不足时使用模拟数据演示（保留作为 fallback）"""
    print("\n使用模拟数据训练演示模型...")
    n = 500
    X = np.random.rand(n, 8) * [100, 5, 1, 1, 1, 10, 1, 100]
    y = (X[:, 0] > 30) | (X[:, 2] > 0.5) | (X[:, 4] == 1)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    model = XGBClassifier(n_estimators=50, max_depth=4, random_state=42)
    model.fit(X_train, y_train)
    print(f"Test Accuracy: {model.score(X_test, y_test):.3f}")

    joblib.dump(model, MODEL_PATH)
    print(f"模型已保存至 {MODEL_PATH}")


if __name__ == "__main__":
    train()
