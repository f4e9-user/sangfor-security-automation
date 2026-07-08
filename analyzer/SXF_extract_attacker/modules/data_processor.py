"""数据处理模块 - 处理Excel和CSV文件"""

import pandas as pd
import sys
import os
import re
from pathlib import Path
from modules.config import AF_SKIP_ROWS, SIP_SKIP_ROWS, AF_FILE_PATTERN, SIP_FILE_PATTERN


def load_blacklist(blacklist_file):
    """从 CSV 文件加载黑名单 IP（第一列），自动清洗格式如 \"'1.2.3.4\" → 1.2.3.4"""
    if not blacklist_file:
        return {}
    if not os.path.isfile(blacklist_file):
        print(f"警告：黑名单文件不存在 - {blacklist_file}", file=sys.stderr)
        return {}
    try:
        df = pd.read_csv(blacklist_file, header=None, dtype=str, encoding='utf-8')
        if df.empty or df.shape[0] == 0:
            print(f"警告：黑名单文件为空 - {blacklist_file}", file=sys.stderr)
            return {}
        raw_ips = df.iloc[:, 0].dropna().astype(str)
        cleaned_ips = []
        skipped_non_ip = 0
        for ip in raw_ips:
            ip = ip.strip()
            if ip.startswith('"') and ip.endswith('"'):
                ip = ip[1:-1]
            if ip.startswith("'"):
                ip = ip[1:]
            ip = ip.strip()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                parts = ip.split('.')
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                    cleaned_ips.append(ip)
                    continue
            # 非 IP 条目静默跳过（黑名单中常混有域名等）
            skipped_non_ip += 1
        unique_ips = list(dict.fromkeys(cleaned_ips))
        if skipped_non_ip > 0:
            print(f"ℹ️  黑名单已加载 {len(unique_ips)} 个 IP（跳过 {skipped_non_ip} 条非 IP 条目）", file=sys.stderr)
        return {ip: "来自黑名单" for ip in unique_ips}
    except Exception as e:
        print(f"错误：读取黑名单 CSV 文件失败 - {e}", file=sys.stderr)
        sys.exit(1)


def detect_report_type(input_file):
    """检测报表类型"""
    basename = os.path.basename(input_file)
    if re.match(AF_FILE_PATTERN, basename):
        report_type = 'AF'
        skiprows = AF_SKIP_ROWS
    elif re.match(SIP_FILE_PATTERN, basename):
        report_type = 'SIP'
        skiprows = SIP_SKIP_ROWS
    else:
        print(f"警告：无法自动识别报表类型（文件名不符合约定），默认按 AF 报表处理（跳过{AF_SKIP_ROWS}行）", file=sys.stderr)
        report_type = 'AF'
        skiprows = AF_SKIP_ROWS
    
    return report_type, skiprows


def read_excel_file(input_file, skiprows):
    """读取Excel文件"""
    try:
        df = pd.read_excel(input_file, engine='openpyxl', skiprows=skiprows)
    except Exception as e:
        print(f"错误：读取 Excel 失败 - {e}", file=sys.stderr)
        sys.exit(1)
    
    if df.empty:
        print(f"警告：跳过前{skiprows}行后数据为空。", file=sys.stderr)
        sys.exit(1)
    
    return df


def save_to_csv(df, output_csv):
    """保存DataFrame到CSV文件"""
    try:
        Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_csv, index=False, encoding='utf-8-sig')
        print(f"\n✅ 处理完成！结果已保存至: {output_csv}")
    except Exception as e:
        print(f"错误：保存 CSV 失败 - {e}", file=sys.stderr)
        sys.exit(1)
