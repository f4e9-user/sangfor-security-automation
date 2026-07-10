"""主应用模块 - 整合所有功能"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from os.path import basename
from typing import Any
from modules.config import EXCLUDED_IPS, DEFAULT_DB_PATH, load_excluded_ips
from modules.data_processor import load_blacklist, detect_report_type, read_excel_file, save_to_csv
from modules.output_paths import build_report_output_path, build_blocklist_output_path
from modules.security_analyzer import process_af_report, process_sip_report, find_af_columns, print_statistics, print_exclusion_info, save_to_database


def _print_ai_results(result):
    """打印 AI 分析结果"""
    print(f"\n{'='*60}")
    print(f"🤖 AI 安全分析报告")
    print(f"{'='*60}")

    risk_labels = {"critical": "🔴 严重", "high": "🟠 高风险", "medium": "🟡 中风险",
                   "low": "🟢 低风险", "unknown": "⚪ 未知"}
    risk = result.get("risk_assessment", "unknown")
    print(f"整体风险评估: {risk_labels.get(risk, risk)}")
    print(f"风险摘要: {result.get('risk_summary', 'N/A')}")

    blocks = result.get("recommended_blocks", [])
    if blocks:
        print(f"\n建议封禁 IP ({len(blocks)} 个):")
        for b in blocks:
            print(f"  - {b['ip']}: {b['reason']} (风险: {b['risk_level']}, 置信度: {b['confidence']:.0%})")
    else:
        print("\n未发现需要立即封禁的 IP。")

    trends = result.get("attack_trends", "")
    if trends:
        print(f"\n攻击趋势: {trends}")

    defenses = result.get("defense_recommendations", [])
    if defenses:
        print("\n防御建议:")
        for d in defenses:
            print(f"  - {d}")

    print(f"{'='*60}")


def _to_native(value: Any) -> Any:
    """递归把 pandas/numpy/Counter 等转成 JSON 原生类型。"""
    if isinstance(value, Counter):
        return {str(k): _to_native(v) for k, v in value.items()}
    if isinstance(value, dict):
        return {str(k): _to_native(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_native(v) for v in value]
    if isinstance(value, (str, bool)) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    # numpy 标量等：尝试转 int/float，失败则转 str
    try:
        if hasattr(value, "item"):
            return _to_native(value.item())
    except Exception:
        pass
    try:
        return int(value)
    except (TypeError, ValueError):
        pass
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    return str(value)


def _series_to_top(series: Any, key_name: str) -> list[dict[str, Any]]:
    """pandas Series (index=标签, value=计数) → [{key_name, count}, ...]。"""
    items = series.to_dict().items() if hasattr(series, "to_dict") else dict(series).items()
    return [{key_name: str(k), "count": int(v)} for k, v in items]


def _write_stats(stats_out: str, df: Any, df_for_stats: Any, top_threats: Any,
                 top_ips: Any, local_results: dict | None) -> None:
    """把结构化统计写为 JSON，供 pipeline 日报/控制台摘要消费。"""
    if not stats_out:
        return
    total_records = int(len(df))
    excluded_count = int(len(df) - len(df_for_stats)) if df_for_stats is not None else 0
    stats: dict[str, Any] = {
        "total_records": total_records,
        "excluded_count": excluded_count,
        "threat_type_top10": _series_to_top(top_threats, "type") if top_threats is not None else [],
        "source_ip_top10": _series_to_top(top_ips, "ip") if top_ips is not None else [],
    }
    if local_results:
        for field in ("attack_results", "defense_posture", "temporal_patterns", "attack_chains"):
            if local_results.get(field):
                stats[field] = _to_native(local_results[field])
    try:
        with open(stats_out, "w", encoding="utf-8") as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        print(f"\n📝 结构化统计已写出: {stats_out}")
    except Exception as e:
        print(f"\n⚠️ 写出统计失败: {e}", file=sys.stderr)


def process_xlsx(input_file, output_csv=None, exclude_from_csv=False, blacklist_file=None,
                 db_path=None, enable_db_logging=True, enable_local_analysis=False,
                 enable_ai_analysis=False, enable_blocklist=False, whitelist_file=None,
                 stats_out=None):
    """处理XLSX文件的主函数"""
    # 合并排除项（whitelist_file 由 pipeline 指向统一的 secrets/ip_whitelist.txt；
    # 未传则回退到模块自带白名单，保证分析器可独立运行）
    excluded_ips = load_excluded_ips(whitelist_file) if whitelist_file else EXCLUDED_IPS.copy()
    blacklist_dict = load_blacklist(blacklist_file)
    excluded_ips.update(blacklist_dict)

    # 自动推导输出文件名
    if output_csv is None:
        output_csv = build_report_output_path(input_file)

    execution_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f") if enable_db_logging else None

    # 检测报表类型并读取文件
    report_type, skiprows = detect_report_type(input_file)
    df = read_excel_file(input_file, skiprows)

    # 根据报表类型处理
    if report_type == 'AF':
        threat_col, ip_col = find_af_columns(df)
        df_for_stats, top_threats, top_ips, top_ips_list, excluded_any = process_af_report(
            df, excluded_ips, ip_col=ip_col, threat_col=threat_col
        )
        df_final = df_for_stats if exclude_from_csv else df

    elif report_type == 'SIP':
        print("识别为 SIP KsearchLog 报表，使用固定列：攻击类型、源IP")
        df_for_stats, top_threats, top_ips, top_ips_list, excluded_any = process_sip_report(df, excluded_ips)
        df_final = df_for_stats if exclude_from_csv else df

    # 输出统计结果
    print_statistics(top_threats, top_ips, top_ips_list)
    print_exclusion_info(exclude_from_csv, excluded_any)

    # 本地攻击特征分析
    local_results = None
    if enable_local_analysis:
        try:
            from modules.local_analyzer import LocalAnalyzer
            local_analyzer = LocalAnalyzer(df)
            local_results = local_analyzer.analyze(top_ips.to_dict() if hasattr(top_ips, 'to_dict') else dict(top_ips))
            local_analyzer.print_report(local_results)
        except Exception as e:
            print(f"\n⚠️ 本地分析失败: {e}")

    # 封禁建议清单（带证据卡）
    if enable_blocklist:
        try:
            from modules.blocklist_advisor import BlocklistAdvisor
            from modules.database_manager import DatabaseManager
            db = DatabaseManager(db_path or DEFAULT_DB_PATH) if enable_db_logging else None
            advisor = BlocklistAdvisor(
                df_for_stats, db_manager=db, current_execution_id=execution_id
            )
            scored_ips = advisor.score_all_ips(min_attacks=3)
            blocklist = advisor.generate_blocklist(min_attacks=3)
            recommended_ips = {item["ip"] for item in blocklist}
            advisor.print_report(blocklist, top_n=30)
            advisor.export_csv(blocklist, path=build_blocklist_output_path(input_file))

            if db is not None:
                observations = []
                score_records = []
                for item in scored_ips:
                    evidence = item.get("evidence") or {}
                    observations.append({
                        "source_ip": item.get("ip"),
                        "attack_count": item.get("attack_count") or evidence.get("attack_count") or 0,
                        "threat_types": evidence.get("threat_types") or {},
                        "severity_dist": evidence.get("severity_levels") or {},
                    })
                    score_records.append({
                        **item,
                        "is_recommended": item.get("ip") in recommended_ips,
                    })

                db.save_ip_observations(execution_id, observations)
                db.save_ip_scores(execution_id, score_records)
        except Exception as e:
            print(f"\n⚠️ 封禁建议生成失败: {e}")

    # 保存top10 IP到数据库
    if enable_db_logging:
        save_to_database(top_ips, source_file=basename(input_file), db_path=db_path,
                         enable_logging=enable_db_logging, blacklist_file=blacklist_file,
                         execution_id=execution_id)

    # AI 安全分析（脱敏后发送到云端）
    if enable_ai_analysis:
        try:
            from modules.qwen_analyzer import analyze_with_qwen
            top_ips_dict = top_ips.to_dict() if hasattr(top_ips, 'to_dict') else dict(top_ips)
            top_threats_dict = top_threats.to_dict() if hasattr(top_threats, 'to_dict') else dict(top_threats)
            result = analyze_with_qwen(df, top_ips_dict, top_threats_dict, basename(input_file))
            _print_ai_results(result)
        except ValueError as e:
            print(f"\n⚠️ AI 分析跳过: {e}")
        except Exception as e:
            print(f"\n⚠️ AI 分析失败: {e}")

    # 保存结果
    save_to_csv(df_final, output_csv)

    # 写出结构化统计（pipeline 日报/控制台摘要消费）
    if stats_out and df_for_stats is not None:
        _write_stats(stats_out, df, df_for_stats, top_threats, top_ips, local_results)


def main():
    parser = argparse.ArgumentParser(
        description="智能处理 Sangfor AF/SIP 报表：自动识别类型，排除误报 IP，统计 Top10"
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
    parser.add_argument(
        "--db-path",
        help=f"SQLite数据库文件路径（默认: {DEFAULT_DB_PATH}）",
        default=DEFAULT_DB_PATH
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="禁用数据库记录功能"
    )
    parser.add_argument(
        "--local-analyze",
        action="store_true",
        help="启用本地攻击特征分析（从报表字段提取攻击链、扫描器指纹、payload特征等）"
    )
    parser.add_argument(
        "--ai-analyze",
        action="store_true",
        help="启用 AI 安全分析（数据经脱敏后发送到云端，需要设置 ALIBABA_CLOUD_API_KEY 环境变量）"
    )
    parser.add_argument(
        "--blocklist",
        action="store_true",
        help="生成封禁建议清单：对每个IP打分+取证，输出到 outputs/<原文件名>_blocklist_recommendations.csv"
    )
    parser.add_argument(
        "--whitelist-file",
        default=None,
        help="排除IP白名单文件路径（IP,原因 每行一条）。不传则用模块自带 config/ip_whitelist.txt",
    )
    parser.add_argument(
        "--stats-out",
        default=None,
        help="将结构化统计（总记录/排除数/Top威胁/Top源IP/防御态势/攻击链）写为 JSON 到该路径",
    )
    args = parser.parse_args()
    process_xlsx(
        input_file=args.input_file,
        output_csv=args.output,
        exclude_from_csv=args.exclude_from_csv,
        blacklist_file=args.blacklist,
        db_path=args.db_path,
        enable_db_logging=not args.no_db,
        enable_local_analysis=args.local_analyze,
        enable_ai_analysis=args.ai_analyze,
        enable_blocklist=args.blocklist,
        whitelist_file=args.whitelist_file,
        stats_out=args.stats_out,
    )
