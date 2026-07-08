import pandas as pd
import argparse
import sys
import os

# 定义要排除的 IP 及原因
EXCLUDED_IPS = {
    "123.120.49.172": "返回 404，非真实威胁",
    "183.129.153.150": "百度爬虫，良性流量"
}

def process_xlsx(input_file, output_csv=None, exclude_from_csv=False):
    if output_csv is None:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        output_csv = f"{base_name}_processed.csv"

    try:
        # 跳过前11行，第12行作为 header
        df = pd.read_excel(input_file, engine='openpyxl', skiprows=11)
    except Exception as e:
        print(f"错误：读取 Excel 失败 - {e}", file=sys.stderr)
        sys.exit(1)

    if df.empty:
        print("警告：跳过前11行后数据为空。", file=sys.stderr)
        sys.exit(1)

    # 清理列名空格
    df.columns = df.columns.str.strip()

    # 自动识别列
    threat_col = None
    ip_col = None
    threat_candidates = ['威胁类型', 'Threat Type', '攻击类型', '事件类型', 'Attack Type']
    ip_candidates = ['源IP', 'Source IP', 'src_ip', '源地址', '攻击源IP', 'Source Address', 'Src IP']

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

    # --- 开始处理 IP 排除 ---
    excluded_any = False
    df_for_stats = df.copy()

    # 转换源IP列为字符串（防止数值型IP）
    df_for_stats[ip_col] = df_for_stats[ip_col].astype(str)

    # 检查有多少条记录会被排除
    mask_exclude = df_for_stats[ip_col].isin(EXCLUDED_IPS)
    count_excluded = mask_exclude.sum()
    if count_excluded > 0:
        excluded_any = True
        print(f"\n🔍 检测到 {count_excluded} 条记录属于需排除的 IP，统计时将忽略：")
        excluded_detail = (
            df_for_stats[mask_exclude][[ip_col, threat_col]]
            .drop_duplicates(subset=[ip_col])
            .set_index(ip_col)
            .to_dict()[threat_col]
        )
        for ip in EXCLUDED_IPS:
            if ip in excluded_detail:
                print(f"  - {ip}：{EXCLUDED_IPS[ip]}（示例威胁：{excluded_detail[ip]}）")
            else:
                print(f"  - {ip}：{EXCLUDED_IPS[ip]}（未在数据中出现）")
    else:
        print("\n✅ 未发现需排除的 IP。")

    # 用于统计的数据：排除指定 IP
    df_for_stats = df_for_stats[~mask_exclude]

    # 统计 Top 10（忽略 NaN）
    top_threats = df_for_stats[threat_col].value_counts(dropna=True).head(10)
    top_ips = df_for_stats[ip_col].value_counts(dropna=True).head(10)
    top_ips_list = top_ips.index.astype(str).tolist()

    print("\n📊 威胁类型 Top 10（已排除指定 IP）:")
    print(top_threats.to_string())
    print("\n🌐 源IP Top 10（已排除指定 IP）:")
    print(top_ips.to_string())
    print("\n" + ",".join(top_ips_list))

    # 决定最终保存到 CSV 的数据
    if exclude_from_csv:
        df_final = df_for_stats
        print(f"\nℹ️  已从输出 CSV 中移除排除的 IP。")
    else:
        df_final = df  # 默认保留原始数据（含排除IP）
        if excluded_any:
            print(f"\nℹ️  排除的 IP 仍保留在 CSV 中（仅统计时忽略）。如需从 CSV 中移除，请添加 --exclude-from-csv 参数。")

    # 保存 CSV
    try:
        df_final.to_csv(output_csv, index=False, encoding='utf-8-sig')
        print(f"\n✅ 处理完成！结果已保存至: {output_csv}")
    except Exception as e:
        print(f"错误：保存 CSV 失败 - {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="处理 Sangfor AF 报表：跳过前11行，统计威胁类型与源IP Top10（自动排除404和爬虫IP）"
    )
    parser.add_argument("input_file", help="输入的 XLSX 文件路径")
    parser.add_argument("-o", "--output", help="输出 CSV 路径")
    parser.add_argument(
        "--exclude-from-csv",
        action="store_true",
        help="不仅统计时排除，也从输出的 CSV 中删除这两个 IP 的记录"
    )
    args = parser.parse_args()
    process_xlsx(args.input_file, args.output, args.exclude_from_csv)

if __name__ == "__main__":
    main()
