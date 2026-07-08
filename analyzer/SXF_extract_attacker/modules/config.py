"""配置模块 - 管理IP排除列表和其他配置项"""

import os
from typing import Dict

def load_excluded_ips() -> Dict[str, str]:
    """从文件加载排除IP列表"""
    excluded_ips = {}
    ip_file_path = os.path.join(os.path.dirname(__file__), "..", "config", "ip_whitelist.txt")
    if os.path.exists(ip_file_path):
        with open(ip_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ',' in line:
                    ip, reason = line.split(',', 1)
                    excluded_ips[ip.strip()] = reason.strip()
    return excluded_ips

# 从文件加载要排除的 IP 及原因
EXCLUDED_IPS = load_excluded_ips()

# 支持的AF报表列名
AF_THREAT_CANDIDATES = ['威胁类型', 'Threat Type', '攻击类型', '事件类型', 'Attack Type']
AF_IP_CANDIDATES = ['源IP', 'Source IP', 'src_ip', '源地址', '攻击源IP', 'Source Address', 'Src IP']

# SIP报表固定列名
SIP_REQUIRED_COLS = ['攻击类型', '源IP']

# 文件名模式
AF_FILE_PATTERN = r'sangfor-AF-report-\d{14}\.xlsx'
SIP_FILE_PATTERN = r'sangfor-sip-report-KsearchLog-(\d{10}|\d{14})\.xlsx'

# 默认跳过的行数
AF_SKIP_ROWS = 11
SIP_SKIP_ROWS = 7

# 输出编码
OUTPUT_ENCODING = 'utf-8-sig'

# 数据库配置
DEFAULT_DB_PATH = "data/attackers.db"
ENABLE_DATABASE_LOGGING = True
DATABASE_RETENTION_DAYS = 90  # 数据保留天数
