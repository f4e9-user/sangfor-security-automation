"""本地攻击分析模块 - 从报表字段中提取深层威胁情报

所有分析在本地完成，不依赖任何外部 API。
分析结果脱敏后可喂给 AI 做定性解读。

支持的报表字段：
- 时间、描述、日志类型、攻击类型、攻击子类
- 源IP、源端口、目的IP、目的端口、请求URL
- 严重等级、状态码、攻击结果、命中白名单、X-Forwarded-For
"""

import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

import pandas as pd

# ── 列名自动匹配 ─────────────────────────────────────────────────

# 各字段的候选列名（同时匹配 AF 和 SIP 报表）
_COLUMN_CANDIDATES = {
    "time": ["时间", "Time", "date", "日期", "发生时间", "timestamp", "检测时间"],
    "description": ["描述", "Description", "desc", "说明", "事件描述", "威胁描述"],
    "log_type": ["日志类型", "Log Type", "log_type"],
    "threat_type": ["攻击类型", "威胁类型", "Threat Type", "事件类型", "Attack Type",
                    "threat_type", "attack_type"],
    "threat_subtype": ["攻击子类", "Threat Subtype", "子类型", "sub_type"],
    "src_ip": ["源IP", "Source IP", "src_ip", "源地址", "攻击源IP", "Source Address", "Src IP"],
    "src_port": ["源端口", "Source Port", "src_port", "sport"],
    "dst_ip": ["目的IP", "Destination IP", "dst_ip", "目的地址", "目标IP", "Dest IP"],
    "dst_port": ["目的端口", "Destination Port", "dst_port", "dport", "目标端口"],
    "url": ["请求URL", "URL", "Request URL", "url", "请求地址", "目标URL", "request_url"],
    "severity": ["严重等级", "Severity", "severity", "严重级别", "风险等级", "威胁等级"],
    "status_code": ["状态码", "Status Code", "status_code", "HTTP状态码"],
    "data_source": ["数据来源", "Data Source", "source", "来源"],
    "attack_result": ["攻击结果", "Attack Result", "result", "结果", "处理结果", "动作结果"],
    "hit_whitelist": ["命中白名单", "Hit Whitelist", "whitelist", "白名单", "is_whitelist"],
    "xff": ["X-Forwarded-For", "XFF", "xff", "x_forwarded_for"],
}


def _find_column(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    """在 DataFrame 中按候选名查找列"""
    for col in candidates:
        if col in df.columns:
            return col
    # 模糊匹配
    for c in df.columns:
        c_lower = str(c).lower()
        for cand in candidates:
            if cand.lower() in c_lower:
                return c
    return None


def _resolve_columns(df: pd.DataFrame) -> Dict[str, Optional[str]]:
    """解析所有可用字段列名"""
    df.columns = df.columns.str.strip()
    return {key: _find_column(df, candidates) for key, candidates in _COLUMN_CANDIDATES.items()}


# ── 攻击结果分析 ─────────────────────────────────────────────────

def _analyze_attack_results(df: pd.DataFrame, cols: Dict) -> Optional[Dict]:
    """分析攻击结果：成功/失败/阻断分布"""
    result_col = cols.get("attack_result")
    if not result_col:
        return None

    results = df[result_col].fillna("未知").astype(str)
    # 统一结果分类
    def _normalize_result(r: str) -> str:
        r = r.strip()
        if not r or r in ("~", "-", "null", "None", "nan"):
            return "未知"
        r_lower = r.lower()
        if any(w in r_lower for w in ["成功", "success", "succeed", "blocked", "阻断", "拒绝"]):
            if any(w in r_lower for w in ["blocked", "阻断", "拒绝"]):
                return "已阻断"
            return "攻击成功"
        if any(w in r_lower for w in ["失败", "fail", "尝试", "attempt", "未遂"]):
            return "攻击失败"
        if r_lower == "尝试":
            return "探测尝试"
        return r[:30]

    normalized = results.apply(_normalize_result)
    distribution = normalized.value_counts().to_dict()
    success_count = normalized.isin(["攻击成功"]).sum()
    blocked_count = normalized.isin(["已阻断"]).sum()
    total = len(normalized)

    return {
        "distribution": distribution,
        "success_rate": round(success_count / total, 4) if total > 0 else 0,
        "blocked_rate": round(blocked_count / total, 4) if total > 0 else 0,
        "success_ips": (
            df.loc[normalized == "攻击成功", cols["src_ip"]]
            .dropna().astype(str).unique().tolist()
            if cols.get("src_ip") else []
        ),
    }


# ── 目标热点分析 ─────────────────────────────────────────────────

def _analyze_target_hotspots(df: pd.DataFrame, cols: Dict) -> Optional[Dict]:
    """分析 HTTP 请求路径，找出高频攻击目标"""
    url_col = cols.get("url")
    if not url_col:
        return None

    urls = df[url_col].dropna().astype(str)

    path_counter = Counter()
    endpoint_patterns = Counter()
    hosts = Counter()

    for u in urls:
        u = u.strip()
        if not u or u in ("~", "-"):
            continue

        # 尝试解析 URL（有些是 host/path 格式，不是完整 URL）
        if "://" not in u:
            u = "http://" + u

        try:
            parsed = urlparse(u)
            host = parsed.netloc or parsed.path.split("/")[0]
            path = parsed.path or "/"

            # 提取主机
            if host and not host[0].isdigit():
                hosts[host] += 1

            # 归一化路径：数字 → :id, 长哈希 → :hash
            normalized = re.sub(r"/\d+", "/:id", path)
            normalized = re.sub(r"/\d+\.\d+", "/:id", normalized)
            normalized = re.sub(r"/[a-f0-9]{32,}", "/:hash", normalized)
            normalized = re.sub(r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                               "/:uuid", normalized)
            endpoint_patterns[normalized] += 1
            path_counter[path] += 1
        except Exception:
            path_counter[u[:80]] += 1

    return {
        "top_targets": path_counter.most_common(20),
        "top_endpoints": endpoint_patterns.most_common(15),
        "top_hosts": hosts.most_common(10),
        "unique_paths": len(path_counter),
        "unique_endpoints": len(endpoint_patterns),
    }


# ── 时间模式分析 ─────────────────────────────────────────────────

def _analyze_temporal_patterns(df: pd.DataFrame, cols: Dict) -> Optional[Dict]:
    """分析攻击的时间分布模式"""
    time_col = cols.get("time")
    if not time_col:
        return None

    times = pd.to_datetime(df[time_col], errors="coerce").dropna()
    if len(times) < 2:
        return None

    # 按小时分布
    hourly = times.dt.hour.value_counts().sort_index().to_dict()
    hourly = {str(k): v for k, v in hourly.items()}

    # 活跃时段识别
    total = len(times)
    peak_hour = max(hourly, key=hourly.get) if hourly else 0
    peak_count = hourly.get(peak_hour, 0)

    # 时间跨度
    span = (times.max() - times.min()).total_seconds()
    span_hours = span / 3600
    span_minutes = span / 60

    # 攻击频率（每小时）
    attacks_per_hour = round(total / max(span_hours, 0.1), 1)

    # 间隔分析
    sorted_times = times.sort_values()
    intervals = sorted_times.diff().dropna().dt.total_seconds()
    avg_interval = intervals.mean() if len(intervals) > 0 else 0
    min_interval = intervals.min() if len(intervals) > 0 else 0

    # 突发检测：找出间隔 < 1 秒的连续攻击簇
    burst_count = (intervals < 1).sum()

    # 持续性判断
    if span_hours > 24:
        persistence = "长期持续（>24h）"
    elif span_hours > 6:
        persistence = "中等持续（6-24h）"
    elif span_hours > 1:
        persistence = "短期（1-6h）"
    else:
        persistence = "一次性扫描（<1h）"

    # 自动化判断
    if avg_interval < 1 and burst_count > total * 0.5:
        automation = "高度自动化（平均间隔 < 1s）"
    elif avg_interval < 60:
        automation = "半自动化（平均间隔 < 60s）"
    else:
        automation = "手工操作可能性高"

    return {
        "span_hours": round(span_hours, 1),
        "span_minutes": round(span_minutes, 0),
        "total_attacks": total,
        "attacks_per_hour": attacks_per_hour,
        "peak_hour": int(peak_hour),
        "peak_count": peak_count,
        "hourly_distribution": hourly,
        "avg_interval_seconds": round(avg_interval, 2),
        "min_interval_seconds": round(min_interval, 2),
        "burst_attacks": int(burst_count),
        "persistence": persistence,
        "automation": automation,
    }


# ── 扫描器/工具识别 ───────────────────────────────────────────────

def _identify_scanner_traits(df: pd.DataFrame, cols: Dict) -> Optional[Dict]:
    """通过端口/状态码/URL模式识别扫描器和攻击工具特征"""
    indicators = {}

    # 源端口分布特征（单一端口 → 定向攻击，多端口轮转 → 扫描器）
    src_port_col = cols.get("src_port")
    if src_port_col:
        ports = df[src_port_col].dropna()
        ports_numeric = pd.to_numeric(ports, errors="coerce").dropna().astype(int)
        if len(ports_numeric) > 0:
            port_dist = ports_numeric.value_counts().to_dict()
            unique_ports = len(port_dist)
            total = len(ports_numeric)
            # 端口集中度
            top_port_pct = max(port_dist.values()) / total if port_dist else 0
            indicators["src_port_unique_count"] = unique_ports
            indicators["src_port_top3"] = sorted(port_dist.items(), key=lambda x: -x[1])[:3]
            indicators["src_port_concentration"] = round(top_port_pct, 3)
            # 随机高端口 → 可能是 Nmap 扫描
            high_ports = sum(1 for p in ports_numeric if p > 1024)
            indicators["high_port_ratio"] = round(high_ports / total, 3) if total > 0 else 0

    # 状态码分布
    status_col = cols.get("status_code")
    if status_col:
        statuses = df[status_col].dropna().astype(str)
        status_dist = statuses.value_counts().to_dict()
        total = len(statuses)
        indicators["status_distribution"] = status_dist
        # 404 率 → 目录扫描特征
        not_found = sum(v for k, v in status_dist.items() if "404" in str(k))
        indicators["not_found_rate"] = round(not_found / total, 3) if total > 0 else 0
        # 403 率 → 权限探测
        forbidden = sum(v for k, v in status_dist.items() if "403" in str(k))
        indicators["forbidden_rate"] = round(forbidden / total, 3) if total > 0 else 0

    # 扫描器行为模式判断
    traits = []
    if indicators.get("high_port_ratio", 0) > 0.7:
        traits.append("端口扫描特征（高端口占比高）")
    if indicators.get("src_port_unique_count", 0) > 50:
        traits.append("源端口高多样性（疑似Nmap）")
    if indicators.get("not_found_rate", 0) > 0.5:
        traits.append("目录爆破特征（404率高）")
    if indicators.get("forbidden_rate", 0) > 0.3:
        traits.append("权限探测（403率高）")
    if indicators.get("src_port_concentration", 1) > 0.9:
        traits.append("单一源端口（定向攻击或单工具）")

    indicators["traits"] = traits
    return indicators


# ── Payload 关键词提取 ────────────────────────────────────────────

_SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop", "exec", "execute",
    "information_schema", "substr", "ascii", "sleep", "benchmark", "waitfor",
    "concat", "group_concat", "load_file", "outfile", "dumpfile",
    "xp_cmdshell", "sp_executesql", "declare", "cast", "convert",
]
_XSS_KEYWORDS = [
    "script", "alert", "onerror", "onload", "onclick", "img",
    "javascript:", "document\\.", "eval", "expression",
]
_PATH_TRAVERSAL_KEYWORDS = [
    "\\.\\./", "%2e%2e", "etc/passwd", "boot\\.ini", "win\\.ini",
    "/windows/", "system32", "cmd\\.exe",
]
_WEBSHELL_KEYWORDS = [
    "eval\\(", "assert", "system\\(", "exec\\(", "shell_exec",
    "passthru", "popen", "proc_open", "base64_decode",
    "WebShell", "webshell", "一句话", "小马", "大马",
]


def _extract_payload_indicators(df: pd.DataFrame, cols: Dict) -> Optional[Dict]:
    """从描述和URL字段提取 payload 特征（本地关键词提取，不发送数据）"""
    text_cols = []
    for key in ["description", "url"]:
        c = cols.get(key)
        if c:
            text_cols.append(c)

    if not text_cols:
        return None

    combined = df[text_cols[0]].dropna().astype(str)
    for c in text_cols[1:]:
        combined += " " + df[c].dropna().astype(str)

    all_text = combined.str.cat(sep=" ") if len(combined) > 0 else ""

    def _count_keywords(text: str, keywords: List[str]) -> Dict[str, int]:
        counts = {}
        t = text.lower()
        for kw in keywords:
            cnt = len(re.findall(kw, t, re.IGNORECASE))
            if cnt > 0:
                counts[kw] = cnt
        return dict(sorted(counts.items(), key=lambda x: -x[1]))

    sql_hits = _count_keywords(all_text, _SQL_KEYWORDS)
    xss_hits = _count_keywords(all_text, _XSS_KEYWORDS)
    traversal_hits = _count_keywords(all_text, _PATH_TRAVERSAL_KEYWORDS)
    webshell_hits = _count_keywords(all_text, _WEBSHELL_KEYWORDS)

    # 推断攻击工具
    tool_indicators = []
    if sql_hits:
        tool_indicators.append("SQL注入工具（sqlmap/手工注入）" if len(sql_hits) > 3 else "SQL注入探测")
    if xss_hits:
        tool_indicators.append("XSS扫描器")
    if traversal_hits:
        tool_indicators.append("目录遍历工具")
    if webshell_hits:
        tool_indicators.append("WebShell攻击")

    return {
        "sql_keywords": dict(list(sql_hits.items())[:10]),
        "xss_keywords": dict(list(xss_hits.items())[:10]),
        "path_traversal_keywords": dict(list(traversal_hits.items())[:10]),
        "webshell_keywords": dict(list(webshell_hits.items())[:10]),
        "tool_indicators": tool_indicators,
    }


# ── 攻击链检测 ────────────────────────────────────────────────────

def _detect_attack_chains(
    df: pd.DataFrame, cols: Dict, top_n: int = 10
) -> List[Dict]:
    """检测来自同一源 IP 的多阶段攻击链路"""
    ip_col = cols.get("src_ip")
    threat_col = cols.get("threat_type")
    time_col = cols.get("time")

    if not ip_col or not threat_col:
        return []

    df = df.copy()
    df[ip_col] = df[ip_col].astype(str)

    chains = []
    # 取 Top N 攻击源
    top_ips = df[ip_col].value_counts().head(top_n).index.tolist()

    for ip in top_ips:
        ip_data = df[df[ip_col] == ip].copy()
        threats = ip_data[threat_col].dropna().astype(str)
        threat_seq = threats.tolist()

        # 攻击多样性
        unique_threats = threats.nunique()
        total_threats = len(threats)

        # 时序分析
        time_order = None
        if time_col:
            times = pd.to_datetime(ip_data[time_col], errors="coerce").dropna()
            if len(times) >= 2:
                time_order = {
                    "first": times.min().isoformat(),
                    "last": times.max().isoformat(),
                    "duration_seconds": (times.max() - times.min()).total_seconds(),
                }

        # 攻击阶段推断（基于威胁类型序列）
        stages = []
        seen_categories = set()
        for t in threat_seq[:50]:  # 只看前50个
            lower_t = t.lower()
            if any(w in lower_t for w in ["扫描", "scan", "探测", "probe", "指纹"]) and "scan" not in seen_categories:
                stages.append("侦察")
                seen_categories.add("scan")
            elif any(w in lower_t for w in ["注入", "injection", "sql", "xss"]) and "injection" not in seen_categories:
                stages.append("漏洞利用")
                seen_categories.add("injection")
            elif any(w in lower_t for w in ["上传", "upload", "webshell", "shell"]) and "webshell" not in seen_categories:
                stages.append("WebShell投递")
                seen_categories.add("webshell")
            elif any(w in lower_t for w in ["命令执行", "rce", "code exec", "执行"]) and "rce" not in seen_categories:
                stages.append("代码执行")
                seen_categories.add("rce")

        # 目标的广度
        dst_col = "url"  # use URL as target indicator
        url_col = cols.get("url")
        target_count = 0
        if url_col:
            target_count = ip_data[url_col].dropna().nunique()

        chains.append({
            "ip": ip,
            "total_attacks": total_threats,
            "unique_threat_types": unique_threats,
            "attack_stages": stages,
            "threat_sequence": threat_seq[:10],  # 前10个威胁作为序列摘要
            "time_profile": time_order,
            "target_diversity": target_count,
        })

    # 按阶段数降序（攻击链越长越靠前）
    chains.sort(key=lambda x: -len(x["attack_stages"]))
    return chains


# ── 防御态势评估 ─────────────────────────────────────────────────

def _assess_defense_posture(df: pd.DataFrame, cols: Dict) -> Optional[Dict]:
    """评估现有防御态势"""
    posture = {}

    # 白名单命中率
    wl_col = cols.get("hit_whitelist")
    if wl_col:
        hits = df[wl_col].fillna("否").astype(str)
        total = len(hits)
        hit_count = hits.apply(
            lambda x: 1 if x.strip() not in ("否", "~", "-", "No", "False", "0", "") else 0
        ).sum()
        posture["whitelist_hit_rate"] = round(hit_count / total, 4) if total > 0 else 0

    # 阻断率（从 attack_result 提取）
    result_col = cols.get("attack_result")
    if result_col:
        results = df[result_col].fillna("").astype(str).str.lower()
        total = len(results)
        blocked = results.apply(
            lambda x: 1 if any(w in x for w in ["block", "阻断", "拒绝", "deny"]) else 0
        ).sum()
        posture["waf_block_rate"] = round(blocked / total, 4) if total > 0 else 0

    # 严重等级分布
    sev_col = cols.get("severity")
    if sev_col:
        sevs = df[sev_col].fillna("未知").astype(str)
        sev_counts = sevs.value_counts().to_dict()
        total = len(sevs)
        critical_high = sum(v for k, v in sev_counts.items()
                           if any(w in k for w in ["高危", "严重", "critical", "high", "高", "紧急"]))
        posture["severity_distribution"] = sev_counts
        posture["critical_high_ratio"] = round(critical_high / total, 4) if total > 0 else 0

    return posture if posture else None


# ── 主分析入口 ────────────────────────────────────────────────────

class LocalAnalyzer:
    """本地攻击特征分析器"""

    def __init__(self, df: pd.DataFrame):
        self.df = df.copy()
        self.df.columns = self.df.columns.str.strip()
        self.cols = _resolve_columns(self.df)

    def analyze(self, top_ips: Dict[str, int] = None) -> Dict[str, Any]:
        """执行全部分析，返回结构化结果"""
        results = {
            "analysis_time": datetime.now().isoformat(),
            "total_records": len(self.df),
            "columns_found": {k: v for k, v in self.cols.items() if v is not None},
        }

        # 1. 攻击结果
        attack_results = _analyze_attack_results(self.df, self.cols)
        if attack_results:
            results["attack_results"] = attack_results

        # 2. 目标热点
        hotspots = _analyze_target_hotspots(self.df, self.cols)
        if hotspots:
            results["target_hotspots"] = hotspots

        # 3. 时间模式
        temporal = _analyze_temporal_patterns(self.df, self.cols)
        if temporal:
            results["temporal_patterns"] = temporal

        # 4. 扫描器识别
        scanner = _identify_scanner_traits(self.df, self.cols)
        if scanner:
            results["scanner_indicators"] = scanner

        # 5. Payload 指纹
        payload = _extract_payload_indicators(self.df, self.cols)
        if payload:
            results["payload_indicators"] = payload

        # 6. 攻击链
        chains = _detect_attack_chains(self.df, self.cols, top_n=10)
        if chains:
            results["attack_chains"] = chains

        # 7. 防御态势
        posture = _assess_defense_posture(self.df, self.cols)
        if posture:
            results["defense_posture"] = posture

        return results

    def print_report(self, results: Dict[str, Any] = None):
        """打印格式化的分析报告"""
        if results is None:
            results = self.analyze()

        print(f"\n{'=' * 65}")
        print("  📊 本地攻击特征分析报告")
        print(f"{'=' * 65}")
        print(f"  总记录数: {results['total_records']}")
        print(f"  识别字段: {len(results['columns_found'])} 个")

        # 攻击结果
        ar = results.get("attack_results")
        if ar:
            print(f"\n── 攻击结果 ──")
            print(f"  攻击成功率: {ar['success_rate']:.1%}")
            print(f"  阻断率: {ar['blocked_rate']:.1%}")
            print(f"  分布: {ar['distribution']}")
            if ar.get("success_ips"):
                print(f"  攻击成功IP: {', '.join(ar['success_ips'][:5])}"
                      f"{'...' if len(ar['success_ips']) > 5 else ''}")

        # 目标热点
        th = results.get("target_hotspots")
        if th:
            print(f"\n── 攻击目标 Top 5 ──")
            for path, cnt in th["top_targets"][:5]:
                print(f"  {cnt:>5}  {path[:80]}")
            print(f"  归一化端点模式 Top 5:")
            for ep, cnt in th["top_endpoints"][:5]:
                print(f"  {cnt:>5}  {ep[:80]}")

        # 时间模式
        tp = results.get("temporal_patterns")
        if tp:
            print(f"\n── 时间模式 ──")
            print(f"  时间跨度: {tp['span_hours']}h")
            print(f"  攻击频率: {tp['attacks_per_hour']} 次/小时")
            print(f"  高峰时段: {tp['peak_hour']}:00 ({tp['peak_count']} 次)")
            print(f"  平均间隔: {tp['avg_interval_seconds']}s")
            print(f"  持续性: {tp['persistence']}")
            print(f"  自动化程度: {tp['automation']}")

        # 扫描器
        si = results.get("scanner_indicators")
        if si:
            print(f"\n── 扫描器特征 ──")
            for trait in si.get("traits", []):
                print(f"  ⚡ {trait}")
            if si.get("status_distribution"):
                print(f"  HTTP 状态码: {si['status_distribution']}")

        # Payload 指纹
        pi = results.get("payload_indicators")
        if pi:
            print(f"\n── Payload 指纹 ──")
            for tool in pi.get("tool_indicators", []):
                print(f"  🔧 {tool}")
            for label, keywords in [
                ("SQL关键词", pi.get("sql_keywords", {})),
                ("XSS关键词", pi.get("xss_keywords", {})),
                ("路径遍历", pi.get("path_traversal_keywords", {})),
            ]:
                if keywords:
                    top_items = list(keywords.items())[:5]
                    print(f"  {label}: {', '.join(f'{k}({v})' for k, v in top_items)}")

        # 攻击链
        chains = results.get("attack_chains", [])
        if chains:
            multi_stage = [c for c in chains if len(c["attack_stages"]) >= 2]
            if multi_stage:
                print(f"\n── 多阶段攻击链 ({len(multi_stage)} 条) ──")
                for c in multi_stage[:5]:
                    stages_str = " → ".join(c["attack_stages"])
                    print(f"  {c['ip']}: {c['total_attacks']}次攻击, "
                          f"{c['unique_threat_types']}类威胁")
                    print(f"   攻击链: {stages_str}")

        # 防御态势
        dp = results.get("defense_posture")
        if dp:
            print(f"\n── 防御态势 ──")
            if "whitelist_hit_rate" in dp:
                print(f"  白名单命中率: {dp['whitelist_hit_rate']:.1%}")
            if "waf_block_rate" in dp:
                print(f"  WAF阻断率: {dp['waf_block_rate']:.1%}")
            if "critical_high_ratio" in dp:
                print(f"  高位/严重占比: {dp['critical_high_ratio']:.1%}")

        print(f"{'=' * 65}")


# ── 便捷函数 ─────────────────────────────────────────────────────

def analyze_locally(df: pd.DataFrame) -> Dict[str, Any]:
    """对 DataFrame 执行本地分析"""
    analyzer = LocalAnalyzer(df)
    return analyzer.analyze()


def analyze_and_print(df: pd.DataFrame) -> Dict[str, Any]:
    """分析并打印报告"""
    analyzer = LocalAnalyzer(df)
    results = analyzer.analyze()
    analyzer.print_report(results)
    return results


# ── 自测 ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    # 构造模拟数据
    import numpy as np

    np.random.seed(42)
    n = 200

    mock_df = pd.DataFrame({
        "时间": pd.date_range("2024-01-01 02:00", periods=n, freq="45s"),
        "描述": np.random.choice([
            "SQL注入攻击 - UNION SELECT", "XSS跨站脚本 - <script>alert(1)</script>",
            "路径遍历 - ../../../etc/passwd", "暴力破解登录",
            "端口扫描探测",
        ], n),
        "攻击类型": np.random.choice([
            "SQL注入", "XSS跨站", "路径遍历", "暴力破解", "端口扫描",
        ], n),
        "攻击子类": np.random.choice([
            "代码注入", "跨站脚本", "目录遍历", "口令爆破", "服务探测",
        ], n),
        "源IP": np.random.choice([
            "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
        ], n),
        "源端口": np.random.choice(["31456", "51234", "12345", "8080", "443"], n),
        "目的IP": "172.16.99.125",
        "目的端口": np.random.choice(["80", "443", "8080", "22"], n),
        "请求URL": np.random.choice([
            "www.target.com/login.php?id=1", "www.target.com/search?q=test",
            "www.target.com/admin/config.php", "www.target.com/../../../etc/passwd",
            "www.target.com/api/user/123",
        ], n),
        "严重等级": np.random.choice(["高危", "中危", "低危"], n, p=[0.3, 0.5, 0.2]),
        "状态码": np.random.choice(["200", "404", "403", "500"], n, p=[0.4, 0.35, 0.15, 0.1]),
        "攻击结果": np.random.choice(["失败", "尝试", "成功"], n, p=[0.5, 0.35, 0.15]),
        "命中白名单": np.random.choice(["否", "是"], n, p=[0.85, 0.15]),
    })

    results = analyze_and_print(mock_df)
