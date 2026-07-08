import pandas as pd
import argparse
import sys
import os

def process_xlsx(input_file, output_csv=None):
    if output_csv is None:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        output_csv = f"{base_name}_processed.csv"

    try:
        # ✅ 关键修复：skiprows=11 表示跳过前11行（0~10行），第12行（索引11）自动作为列名
        df = pd.read_excel(input_file, engine='openpyxl', skiprows=11)
    except Exception as e:
        print(f"错误：读取 Excel 失败 - {e}", file=sys.stderr)
        sys.exit(1)

    # 打印实际列名用于调试（可选）
    print("实际列名：")
    print(df.columns.tolist())

    # 去除列名中的多余空格（Sangfor 报表常有空格）
    df.columns = df.columns.str.strip()

    # 现在尝试匹配常见列名（支持多种可能）
    threat_col = None
    ip_col = None

    # 威胁类型可能的列名
    threat_candidates = ['威胁类型', 'Threat Type', '攻击类型', '事件类型']
    for col in df.columns:
        if col in threat_candidates:
            threat_col = col
            break

    # 源IP可能的列名
    ip_candidates = ['源IP', 'Source IP', 'src_ip', '源地址', '攻击源IP', 'Source Address']
    for col in df.columns:
        if col in ip_candidates:
            ip_col = col
            break

    if not threat_col or not ip_col:
        print("错误：未找到威胁类型或源IP列。请检查以下列名是否匹配：", file=sys.stderr)
        print(f"  威胁类型候选: {threat_candidates}", file=sys.stderr)
        print(f"  源IP候选: {ip_candidates}", file=sys.stderr)
        print(f"  实际列名: {list(df.columns)}", file=sys.stderr)
        sys.exit(1)

    print(f"使用列 -> 威胁类型: '{threat_col}', 源IP: '{ip_col}'")

    # 统计 Top 10（忽略 NaN）
    top_threats = df[threat_col].value_counts(dropna=True).head(10)
    top_ips = df[ip_col].value_counts(dropna=True).head(10)

    print("\n威胁类型 Top 10:")
    print(top_threats.to_string())
    print("\n源IP Top 10:")
    print(top_ips.to_string())

    # 保存完整数据（已跳过前11行）
    df.to_csv(output_csv, index=False, encoding='utf-8-sig')
    print(f"\n✅ 处理完成！结果已保存至: {output_csv}")

def main():
    parser = argparse.ArgumentParser(description="处理 Sangfor AF 报表 XLSX 文件")
    parser.add_argument("input_file", help="输入的 XLSX 文件路径")
    parser.add_argument("-o", "--output", help="输出 CSV 路径（默认自动命名）")
    args = parser.parse_args()
    process_xlsx(args.input_file, args.output)

if __name__ == "__main__":
    main()
