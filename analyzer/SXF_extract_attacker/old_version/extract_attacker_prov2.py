import pandas as pd
import argparse
import sys
import os
import re

# 定义要排除的 IP 及原因（硬编码）
EXCLUDED_IPS = {
    "123.120.49.172": "返回 404，非真实威胁",
    "183.129.153.150": "百度爬虫，良性流量"
}

def load_blacklist(blacklist_file):
    """从 CSV 文件加载黑名单 IP（第一列），自动清洗格式如 \"'1.2.3.4\" → 1.2.3.4"""
    if not blacklist_file:
        return {}
    if not os.path.isfile(blacklist_file):
        print(f"警告：黑名单文件不存在 - {blacklist_file}", file=sys.stderr)
        return {}
    try:
        # 尝试读取 CSV，不指定 header（假设无 header 或 header 无用）
        df = pd.read_csv(blacklist_file, header=None, dtype=str, encoding='utf-8')
        if df.empty or df.shape[0] == 0:
            print(f"警告：黑名单文件为空 - {blacklist_file}", file=sys.stderr)
            return {}
        # 取第一列
        raw_ips = df.iloc[:, 0].dropna().astype(str)
        cleaned_ips = []
        for ip in raw_ips:
            # 去除首尾空白
            ip = ip.strip()
            # 去掉外层双引号（如果存在）
            if ip.startswith('"') and ip.endswith('"'):
                ip = ip[1:-1]
            # 去掉开头的单引号（常见于 Excel 导出防止科学计数法）
            if ip.startswith("'"):
                ip = ip[1:]
            # 再次 strip
            ip = ip.strip()
            # 简单验证是否为 IPv4 格式（可选，避免垃圾数据）
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                # 进一步验证每段是否 <= 255
                parts = ip.split('.')
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                    cleaned_ips.append(ip)
                else:
                    print(f"警告：跳过无效 IP 格式（数值越界）: {ip}", file=sys.stderr)
            else:
                print(f"警告：跳过无效 IP 格式（非标准 IPv4）: {ip}", file=sys.stderr)
        # 去重并转为字典
        unique_ips = list(dict.fromkeys(cleaned_ips))  # 保留顺序去重
        return {ip: "来自黑名单" for ip in unique_ips}
    except Exception as e:
        print(f"错误：读取黑名单 CSV 文件失败 - {e}", file=sys.stderr)
        sys.exit(1)

def process_xlsx(input_file, output_csv=None, exclude_from_csv=False, blacklist_file=None):
    # 合并硬编码排除项 + 黑名单
    excluded_ips = EXCLUDED_IPS.copy()
    blacklist_dict = load_blacklist(blacklist_file)
    excluded_ips.update(blacklist_dict)

    if output_csv is None:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        output_csv = f"{base_name}_processed.csv"

    try:
        df = pd.read_excel(input_file, engine='openpyxl', skiprows=11)
    except Exception as e:
        print(f"错误：读取 Excel 失败 - {e}", file=sys.stderr)
        sys.exit(1)

    if df.empty:
        print("警告：跳过前11行后数据为空。", file=sys.stderr)
        sys.exit(1)

    df.columns = df.columns.str.strip()

    threat_candidates = ['威胁类型', 'Threat Type', '攻击类型', '事件类型', 'Attack Type']
    ip_candidates = ['源IP', 'Source IP', 'src_ip', '源地址', '攻击源IP', 'Source Address', 'Src IP']

    threat_col = None
    ip_col = None
    for col in df.columns:
        if col in threat_candidates:
            threat_col = col
        if col in ip_candidates:
            ip_col = col

    if not threat_col or not ip_col:
        print("错误：未找到威胁类型或源IP列。", file=sys.stderr)
        print(f"实际列名: {list(df.columns)}")
        sys.exit(1)

    print(f"使用列 -> 威胁类型: '{threat_col}', 源IP: '{ip_col}'")

    excluded_any = False
    df_for_stats = df.copy()
    df_for_stats[ip_col] = df_for_stats[ip_col].astype(str)

    mask_exclude = df_for_stats[ip_col].isin(excluded_ips)
    count_excluded = mask_exclude.sum()
    if count_excluded > 0:
        excluded_any = True
        print(f"\n🔍 检测到 {count_excluded} 条记录属于需排除的 IP，统计时将忽略：")
        seen_ips = df_for_stats[mask_exclude][ip_col].unique()
        for ip in seen_ips:
            reason = excluded_ips.get(ip, "未知原因")
            example_threats = df_for_stats[df_for_stats[ip_col] == ip][threat_col].dropna().unique()
            example = example_threats[0] if len(example_threats) > 0 else "无威胁类型"
            print(f"  - {ip}：{reason}（示例威胁：{example}）")
    else:
        print("\n✅ 未发现需排除的 IP。")

    df_for_stats = df_for_stats[~mask_exclude]

    top_threats = df_for_stats[threat_col].value_counts(dropna=True).head(10)
    top_ips = df_for_stats[ip_col].value_counts(dropna=True).head(10)
    top_ips_list = top_ips.index.astype(str).tolist()

    print("\n📊 威胁类型 Top 10（已排除指定 IP）:")
    print(top_threats.to_string())
    print("\n🌐 源IP Top 10（已排除指定 IP）:")
    print(top_ips.to_string())
    print("\n" + ",".join(top_ips_list))

    if exclude_from_csv:
        df_final = df_for_stats
        print(f"\nℹ️  已从输出 CSV 中移除排除的 IP。")
    else:
        df_final = df
        if excluded_any:
            print(f"\nℹ️  排除的 IP 仍保留在 CSV 中（仅统计时忽略）。如需从 CSV 中移除，请添加 --exclude-from-csv 参数。")

    try:
        df_final.to_csv(output_csv, index=False, encoding='utf-8-sig')
        print(f"\n✅ 处理完成！结果已保存至: {output_csv}")
    except Exception as e:
        print(f"错误：保存 CSV 失败 - {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="处理 Sangfor AF 报表：跳过前11行，统计威胁类型与源IP Top10（自动排除404、爬虫及黑名单IP）"
    )
    parser.add_argument("input_file", help="输入的 XLSX 文件路径")
    parser.add_argument("-o", "--output", help="输出 CSV 路径")
    parser.add_argument(
        "--exclude-from-csv",
        action="store_true",
        help="不仅统计时排除，也从输出的 CSV 中删除排除的 IP 记录"
    )
    parser.add_argument(
        "-b", "--blacklist",
        help="黑名单 IP 的 CSV 文件路径（第一列为 IP，支持格式如 \"'1.2.3.4\"）"
    )
    args = parser.parse_args()
    process_xlsx(
        input_file=args.input_file,
        output_csv=args.output,
        exclude_from_csv=args.exclude_from_csv,
        blacklist_file=args.blacklist
    )

if __name__ == "__main__":
    main()
