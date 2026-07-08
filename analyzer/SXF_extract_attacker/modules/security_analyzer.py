"""安全分析模块 - 威胁检测和统计"""

import pandas as pd
import sys
from modules.config import AF_THREAT_CANDIDATES, AF_IP_CANDIDATES, SIP_REQUIRED_COLS, DEFAULT_DB_PATH, ENABLE_DATABASE_LOGGING
from modules.database_manager import DatabaseManager


def process_af_report(df, excluded_ips, ip_col='源IP', threat_col='威胁类型'):
    """处理 AF 报表逻辑（复用统计和排除）"""
    df_processed = df.copy()
    df_processed[ip_col] = df_processed[ip_col].astype(str)

    mask_exclude = df_processed[ip_col].isin(excluded_ips)
    count_excluded = mask_exclude.sum()
    excluded_any = count_excluded > 0

    if excluded_any:
        print(f"\n🔍 检测到 {count_excluded} 条记录属于需排除的 IP，统计时将忽略：")
        seen_ips = df_processed[mask_exclude][ip_col].unique()
        for ip in seen_ips:
            reason = excluded_ips.get(ip, "未知原因")
            example_threats = df_processed[df_processed[ip_col] == ip][threat_col].dropna().unique()
            example = example_threats[0] if len(example_threats) > 0 else "无威胁类型"
            print(f"  - {ip}：{reason}（示例威胁：{example}）")
    else:
        print("\n未发现需排除的 IP。")

    df_for_stats = df_processed[~mask_exclude]

    top_threats = df_for_stats[threat_col].value_counts(dropna=True).head(10)
    top_ips = df_for_stats[ip_col].value_counts(dropna=True).head(10)
    top_ips_list = top_ips.index.astype(str).tolist()

    return df_for_stats, top_threats, top_ips, top_ips_list, excluded_any


def process_sip_report(df, excluded_ips):
    """处理 SIP KsearchLog 报表：跳过前7行已在调用处处理，此处只处理列匹配和统计"""
    df.columns = df.columns.str.strip()

    # SIP 报表固定列（根据你提供的）
    if not all(col in df.columns for col in SIP_REQUIRED_COLS):
        print("错误：SIP 报表缺少必要列：攻击类型、源IP", file=sys.stderr)
        print(f"实际列名: {list(df.columns)}")
        sys.exit(1)

    threat_col = '攻击类型'
    ip_col = '源IP'

    return process_af_report(df, excluded_ips, ip_col=ip_col, threat_col=threat_col)


def find_af_columns(df):
    """查找AF报表中的威胁类型和源IP列"""
    df.columns = df.columns.str.strip()
    
    threat_col = next((col for col in df.columns if col in AF_THREAT_CANDIDATES), None)
    ip_col = next((col for col in df.columns if col in AF_IP_CANDIDATES), None)
    
    if not threat_col or not ip_col:
        print("错误：AF 报表未找到威胁类型或源IP列。", file=sys.stderr)
        print(f"实际列名: {list(df.columns)}")
        sys.exit(1)
    
    print(f"使用列 -> 威胁类型: '{threat_col}', 源IP: '{ip_col}'")
    
    return threat_col, ip_col


def save_to_database(top_ips, source_file=None, db_path=None, enable_logging=None, blacklist_file=None, execution_id=None):
    """将top IP数据保存到数据库"""
    if enable_logging is None:
        enable_logging = ENABLE_DATABASE_LOGGING
    
    if not enable_logging:
        return
    
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    
    try:
        db_manager = DatabaseManager(db_path)
        # 将pandas Series转换为字典，确保数据格式正确
        if hasattr(top_ips, 'to_dict'):
            # 如果是pandas Series，转换为字典
            top_ips_dict = top_ips.to_dict()
        elif isinstance(top_ips, dict):
            # 如果已经是字典，直接使用
            top_ips_dict = top_ips
        else:
            # 其他情况尝试转换
            top_ips_dict = dict(top_ips)
        
        db_manager.save_top_attackers(
            top_ips_dict,
            source_file,
            execution_id=execution_id,
            blacklist_file=blacklist_file or '../blacklist.csv',
        )
    except Exception as e:
        print(f"数据库记录失败: {e}", file=sys.stderr)


def print_statistics(top_threats, top_ips, top_ips_list):
    """输出统计结果"""
    print("\n📊 威胁类型 Top 10（已排除指定 IP）:")
    print(top_threats.to_string())
    print("\n🌐 源IP Top 10（已排除指定 IP）:")
    print(top_ips.to_string())
    print("\n" + ",".join(top_ips_list))
    # 生成SIP查询语法
    print(f'src_ip:({" OR ".join(top_ips_list)})')

def print_exclusion_info(exclude_from_csv, excluded_any):
    """输出排除信息"""
    if exclude_from_csv:
        print(f"\nℹ️  已从输出 CSV 中移除排除的 IP。")
    elif excluded_any:
        print(f"\nℹ️  排除的 IP 仍保留在 CSV 中（仅统计时忽略）。如需从 CSV 中移除，请添加 --exclude-from-csv 参数。")