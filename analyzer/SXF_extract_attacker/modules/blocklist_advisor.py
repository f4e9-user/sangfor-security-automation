"""封禁建议引擎 - 从报表数据生成带证据的封禁清单

核心理念：
- 不再只输出 Top 10，而是对每个有威胁的 IP 打分
- 每个建议封禁的 IP 附带完整证据卡（攻击类型/目标/payload样本/历史对比）
- 分析人员无需回到 Sangfor 设备核对，证据在报告中自包含
"""

import base64
import hashlib
import math
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

import pandas as pd

from modules.output_paths import build_blocklist_output_path

# ── 评分权重 ──────────────────────────────────────────────────────

SCORE_WEIGHTS = {
    "volume": 20,
    "diversity": 10,
    "severity": 20,
    "persistence": 10,
    "attack_chain": 10,
    "payload_risk": 15,
    "behavior_confidence": 15,
}

HIGH_RISK_INTENT_PATTERNS = (
    "命令执行", "代码执行", "远程代码执行", "rce", "code exec",
    "webshell", "后门", "反序列化", "deserialize",
)


# ── HTTP 数据包解析 ────────────────────────────────────────────────


def _parse_http_packet(packet_text: str) -> Optional[Dict[str, str]]:
    """从数据包字段解析 HTTP 请求"""
    if not packet_text or not isinstance(packet_text, str):
        return None

    # 处理 "REQUEST:\n..." 格式
    text = packet_text.strip()
    if text.startswith("REQUEST:"):
        text = text[len("REQUEST:"):].strip()
    elif text.startswith("RESPONSE:"):
        return None  # 暂不解析响应

    lines = text.split("\n")
    if not lines:
        return None

    result = {}
    # 第一行：METHOD /path HTTP/version
    first = lines[0].strip()
    parts = first.split()
    if len(parts) >= 2 and parts[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
        result["method"] = parts[0]
        result["url"] = parts[1]
        result["protocol"] = parts[2] if len(parts) >= 3 else ""
    else:
        return None

    # 解析 headers
    for line in lines[1:]:
        line = line.strip()
        if not line:
            break  # 空行 = header 结束
        if ":" in line:
            key, _, val = line.partition(":")
            result[key.strip().lower()] = val.strip()

    return result


def _parse_base64_packet(packet_text: str) -> Optional[str]:
    """尝试解码 Base64 编码的数据包，提取可读内容"""
    if not packet_text or not isinstance(packet_text, str):
        return None

    for line in packet_text.strip().split("\n")[:3]:
        line = line.strip()
        if len(line) < 20:
            continue
        if not re.match(r'^[A-Za-z0-9+/=]+$', line):
            continue
        try:
            decoded = base64.b64decode(line)
            # 提取可打印字符段
            readable = bytes(b if 32 <= b < 127 else ord(' ') for b in decoded)
            text = readable.decode('ascii', errors='replace')
            # 提取有意义的片段（如 Cookie、认证信息）
            snippets = []
            for pattern in [r'Cookie:\s*(\S+)', r'Host:\s*(\S+)',
                          r'User-Agent:\s*(.+)', r'Authorization:\s*(\S+)',
                          r'([a-zA-Z_]\w{3,}=[^\s]+)']:
                m = re.search(pattern, text)
                if m:
                    snippets.append(m.group(0)[:120])
            if snippets:
                return " | ".join(snippets[:5])
            # 返回前 120 个可打印字符
            clean = re.sub(r'\s+', ' ', text).strip()
            return clean[:120] if clean else None
        except Exception:
            continue
    return None


def _extract_packet_evidence(df: pd.DataFrame, ip: str, ip_col: str,
                             packet_col: str = "数据包") -> Dict[str, Any]:
    """为单个 IP 提取数据包证据"""
    ip_data = df[df[ip_col].astype(str) == ip]
    packets = ip_data[packet_col].dropna().astype(str)

    http_requests = []
    b64_snippets = []
    urls = Counter()
    user_agents = Counter()
    hosts = Counter()
    methods = Counter()

    for pkt in packets:
        # 尝试 HTTP 解析
        http = _parse_http_packet(pkt)
        if http:
            http_requests.append(http)
            if http.get("url"):
                urls[http["url"]] += 1
            if http.get("user-agent"):
                user_agents[http["user-agent"][:80]] += 1
            if http.get("host"):
                hosts[http["host"]] += 1
            if http.get("method"):
                methods[http["method"]] += 1
            continue

        # 尝试 Base64 解码
        b64 = _parse_base64_packet(pkt)
        if b64:
            b64_snippets.append(b64)

    # HTTP 请求样本（去重取最多5条）
    sample_requests = []
    seen = set()
    for h in http_requests:
        key = f"{h.get('method','')} {h.get('url','')}"
        if key not in seen:
            seen.add(key)
            sample_requests.append({
                "method": h.get("method", ""),
                "url": h.get("url", ""),
                "host": h.get("host", ""),
                "user_agent": (h.get("user-agent", "") or "")[:80],
            })
        if len(sample_requests) >= 5:
            break

    # Base64 解码样本
    unique_b64 = list(dict.fromkeys(b64_snippets))[:3]

    return {
        "http_count": len(http_requests),
        "b64_count": len(b64_snippets),
        "total_packet_count": len(packets),
        "sample_requests": sample_requests,
        "top_urls": urls.most_common(5),
        "top_user_agents": user_agents.most_common(3),
        "top_hosts": hosts.most_common(3),
        "http_methods": methods.most_common(3),
        "b64_snippets": unique_b64,
    }


# ── IP 评分引擎 ────────────────────────────────────────────────────


def _score_ip(
    ip: str,
    ip_data: pd.DataFrame,
    cols: Dict[str, Optional[str]],
    packet_evidence: Dict[str, Any],
    max_attacks: int,
    max_diversity: int,
) -> Tuple[int, Dict[str, Any]]:
    """对单个 IP 进行多维度评分，返回 (score, details)"""

    details = {}
    score = 0

    # 1. 攻击量：固定对数刻度，避免批次极端值扭曲其他 IP。
    attack_count = len(ip_data)
    volume_score = round(
        min(math.log1p(attack_count) / math.log1p(1000), 1) * SCORE_WEIGHTS["volume"],
        1,
    )
    score += volume_score
    details["volume"] = {"score": volume_score, "attacks": attack_count}

    # 2. 威胁多样性 (0-15)
    threat_col = cols.get("threat_type")
    if threat_col and threat_col in ip_data.columns:
        threats = ip_data[threat_col].dropna().astype(str)
        unique_threats = threats.nunique()
        diversity_score = round(min(unique_threats / max(max_diversity, 1), 1) * SCORE_WEIGHTS["diversity"], 1)
        score += diversity_score
        details["diversity"] = {"score": diversity_score, "unique_types": unique_threats,
                               "types": threats.value_counts().head(5).to_dict()}
    else:
        details["diversity"] = {"score": 0, "unique_types": 0}

    # 3. 严重等级 (0-25)
    sev_col = cols.get("severity")
    if sev_col and sev_col in ip_data.columns:
        sevs = ip_data[sev_col].fillna("未知").astype(str)
        sev_dist = sevs.value_counts().to_dict()
        total = len(sevs)
        critical_count = sum(v for k, v in sev_dist.items()
                           if any(w in k.lower() for w in ["高危", "严重", "critical", "致命", "高"]))
        critical_ratio = critical_count / total if total > 0 else 0
        severity_score = round(critical_ratio * SCORE_WEIGHTS["severity"], 1)
        score += severity_score
        details["severity"] = {"score": severity_score, "distribution": sev_dist,
                              "critical_ratio": round(critical_ratio, 3)}
    else:
        details["severity"] = {"score": 0}

    # 4. 持续性 (0-15)
    time_col = cols.get("time")
    if time_col and time_col in ip_data.columns:
        times = pd.to_datetime(ip_data[time_col], errors="coerce").dropna()
        if len(times) >= 2:
            span_hours = (times.max() - times.min()).total_seconds() / 3600
            if span_hours > 24:
                persistence_score = SCORE_WEIGHTS["persistence"]  # 跨天持续
            elif span_hours > 6:
                persistence_score = SCORE_WEIGHTS["persistence"] * 0.7
            elif span_hours > 1:
                persistence_score = SCORE_WEIGHTS["persistence"] * 0.4
            else:
                persistence_score = SCORE_WEIGHTS["persistence"] * 0.1
            score += persistence_score
            details["persistence"] = {"score": round(persistence_score, 1),
                                     "span_hours": round(span_hours, 1),
                                     "first_seen": times.min().strftime("%m-%d %H:%M"),
                                     "last_seen": times.max().strftime("%m-%d %H:%M")}
        else:
            details["persistence"] = {"score": 0}
    else:
        details["persistence"] = {"score": 0}

    # 5. 攻击链 (0-10)
    if threat_col and threat_col in ip_data.columns:
        threats = ip_data[threat_col].dropna().astype(str)
        stages = set()
        for t in threats:
            lower_t = t.lower()
            if any(w in lower_t for w in ["扫描", "scan", "探测", "probe", "指纹"]):
                stages.add("侦察")
            elif any(w in lower_t for w in ["注入", "injection", "sql", "xss", "代码执行", "命令执行"]):
                stages.add("漏洞利用")
            elif any(w in lower_t for w in ["上传", "upload", "webshell", "shell", "后门"]):
                stages.add("WebShell投递")
            elif any(w in lower_t for w in ["执行", "rce", "code exec", "cmd"]):
                stages.add("代码执行")
            elif any(w in lower_t for w in ["暴力", "brute", "爆破", "口令"]):
                stages.add("凭证攻击")
            elif any(w in lower_t for w in ["信息泄露", "info leak", "信息泄漏"]):
                stages.add("信息窃取")
        chain_score = min(len(stages) / 4, 1) * SCORE_WEIGHTS["attack_chain"]
        score += chain_score
        details["attack_chain"] = {"score": round(chain_score, 1),
                                  "stages": sorted(stages)}
    else:
        details["attack_chain"] = {"score": 0}

    # 6. Payload 危险度 (0-10)
    danger_score = 0
    danger_reasons = []

    # 从请求 URL 判断
    url_col = cols.get("url")
    if url_col and url_col in ip_data.columns:
        urls = ip_data[url_col].dropna().astype(str)
        all_urls = " ".join(urls)
        if re.search(r'\.\./|%2e%2e|etc/passwd|boot\.ini', all_urls):
            danger_score += 4
            danger_reasons.append("路径遍历攻击")
        if re.search(r'union|select|sleep\(|benchmark|information_schema', all_urls, re.IGNORECASE):
            danger_score += 3
            danger_reasons.append("SQL注入特征")
        if re.search(r'script|alert\(|onerror|onload|javascript:', all_urls, re.IGNORECASE):
            danger_score += 2
            danger_reasons.append("XSS特征")
        if re.search(r'cmd\.exe|/bin/sh|/bin/bash|system32', all_urls):
            danger_score += 3
            danger_reasons.append("命令执行尝试")
        if re.search(r'\.jsp|\.php|\.asp|webshell|upload', all_urls, re.IGNORECASE):
            danger_score += 2
            danger_reasons.append("WebShell/上传探测")

    # 从数据包判断
    for req in packet_evidence.get("sample_requests", []):
        url = req.get("url", "")
        if re.search(r'\.rar|\.7z|\.bak|\.sql|\.tar|\.gz|\.zip|backup|config', url, re.IGNORECASE):
            danger_score += 1
            danger_reasons.append("源码/备份文件探测")
            break

    for ua, _ in packet_evidence.get("top_user_agents", []):
        if any(tool in ua.lower() for tool in ["sqlmap", "nmap", "nikto", "burp", "dirbuster",
                                                "gobuster", "feroxbuster", "masscan", "zgrab"]):
            danger_score += 2
            danger_reasons.append(f"已知攻击工具: {ua[:50]}")
            break

    high_risk_intent = _detect_high_risk_intent(ip_data, cols, danger_reasons)
    if high_risk_intent["detected"] and danger_score < 10:
        danger_score = 10
        danger_reasons.append("明确高危攻击意图")
    danger_score = min(danger_score, SCORE_WEIGHTS["payload_risk"])
    score += danger_score
    details["payload_risk"] = {"score": danger_score, "reasons": danger_reasons}

    behavior = _score_behavior_confidence(ip_data, cols)
    score += behavior["score"]
    details["behavior_confidence"] = behavior
    details["high_risk_intent"] = high_risk_intent

    return round(score, 1), details


def _text_matches(value: str, pattern: str) -> bool:
    value = str(value).strip().lower()
    pattern = pattern.lower()
    if pattern.isascii():
        return re.search(rf"(?<![a-z0-9]){re.escape(pattern)}(?![a-z0-9])", value) is not None
    return pattern in value


def _rate_matching(
    series: pd.Series,
    patterns: Tuple[str, ...],
    excluded: Tuple[str, ...] = (),
) -> float:
    """计算命中 patterns 且未命中 excluded 的行占比（向量化）。

    语义与原逐行实现一致：ASCII 模式按词边界匹配，非 ASCII（中文）按子串匹配。
    """
    values = series.fillna("").astype(str).str.strip().str.lower()
    if values.empty:
        return 0.0

    def _build_alternation(pats: Tuple[str, ...]):
        ascii_pats, text_pats = [], []
        for pattern in pats:
            lowered = pattern.lower()
            (ascii_pats if lowered.isascii() else text_pats).append(re.escape(lowered))
        alternatives = []
        if ascii_pats:
            alternatives.append("(?<![a-z0-9])(?:" + "|".join(ascii_pats) + ")(?![a-z0-9])")
        if text_pats:
            alternatives.append("(?:" + "|".join(text_pats) + ")")
        return "|".join(alternatives) if alternatives else None

    include = _build_alternation(patterns)
    if include is None:
        return 0.0
    hits = values.str.contains(include, regex=True, na=False)
    exclude = _build_alternation(excluded) if excluded else None
    if exclude is not None:
        hits = hits & ~values.str.contains(exclude, regex=True, na=False)
    return round(float(hits.mean()), 4)


def _score_behavior_confidence(ip_data: pd.DataFrame, cols: Dict[str, Optional[str]]) -> Dict[str, Any]:
    """Score evidence that malicious activity reached useful targets or responses."""
    action_col = cols.get("action")
    result_col = cols.get("attack_result")
    status_col = cols.get("status_code")
    dst_col = cols.get("dst_ip")

    allowed_rate = blocked_rate = failed_rate = None
    not_found_rate = effective_response_rate = status_coverage_rate = None
    reasons = []
    positive = 0.0
    negative = 0.0

    if action_col and action_col in ip_data.columns:
        actions = ip_data[action_col]
        allowed_rate = _rate_matching(
            actions,
            ("允许", "allow", "放行", "pass"),
            ("不允许", "禁止", "disallow", "not allowed"),
        )
        blocked_rate = _rate_matching(actions, ("拒绝", "阻断", "deny", "block", "drop"))
        positive += allowed_rate * 5
        negative += blocked_rate * 0.35
        if allowed_rate >= 0.5:
            reasons.append(f"允许率 {allowed_rate:.0%}")
        if blocked_rate >= 0.5:
            reasons.append(f"拒绝率 {blocked_rate:.0%}")

    if result_col and result_col in ip_data.columns:
        results = ip_data[result_col]
        failed_rate = _rate_matching(results, ("失败", "fail", "未遂"))
        positive += _rate_matching(
            results,
            ("成功", "success", "succeed"),
            ("不成功", "未成功", "unsuccessful", "not successful"),
        ) * 3
        negative += failed_rate * 0.25
        if failed_rate >= 0.5:
            reasons.append(f"失败率 {failed_rate:.0%}")

    if status_col and status_col in ip_data.columns:
        numeric = pd.to_numeric(ip_data[status_col], errors="coerce")
        if numeric.notna().any():
            denominator = max(len(ip_data), 1)
            status_coverage_rate = round(numeric.notna().sum() / denominator, 4)
            effective_response_rate = round(numeric.between(200, 399).sum() / denominator, 4)
            not_found_rate = round((numeric == 404).sum() / denominator, 4)
            positive += effective_response_rate * 4
            negative += not_found_rate * 0.4
            if effective_response_rate >= 0.3:
                reasons.append(f"有效响应率 {effective_response_rate:.0%}")
            if not_found_rate >= 0.5:
                reasons.append(f"404率 {not_found_rate:.0%}")

    target_count = 0
    if dst_col and dst_col in ip_data.columns:
        target_count = int(ip_data[dst_col].dropna().astype(str).nunique())
        positive += min(target_count / 5, 1) * 3
        if target_count >= 3:
            reasons.append(f"攻击 {target_count} 个目标")

    score = round(max(0.0, positive * max(0.2, 1 - min(negative, 0.8))), 1)
    return {
        "score": min(score, SCORE_WEIGHTS["behavior_confidence"]),
        "allowed_rate": allowed_rate,
        "blocked_rate": blocked_rate,
        "failed_rate": failed_rate,
        "not_found_rate": not_found_rate,
        "effective_response_rate": effective_response_rate,
        "status_coverage_rate": status_coverage_rate,
        "target_count": target_count,
        "reasons": reasons,
    }


def _detect_high_risk_intent(
    ip_data: pd.DataFrame,
    cols: Dict[str, Optional[str]],
    payload_reasons: List[str],
) -> Dict[str, Any]:
    evidence = []
    for key in ("threat_type", "description", "url"):
        col = cols.get(key)
        if not col or col not in ip_data.columns:
            continue
        text = " ".join(ip_data[col].dropna().astype(str).drop_duplicates()).lower()
        for pattern in HIGH_RISK_INTENT_PATTERNS:
            if _text_matches(text, pattern) and pattern not in evidence:
                evidence.append(pattern)
    for reason in payload_reasons:
        if reason in {"命令执行尝试", "WebShell/上传探测"} and reason not in evidence:
            evidence.append(reason)
    return {"detected": bool(evidence), "evidence": evidence[:6]}


# ── 历史对比 ────────────────────────────────────────────────────────

def _check_history(ip: str, db_manager=None, before_execution_id: str = None) -> Dict[str, Any]:
    """查询 IP 是否在历史数据库中出现过。"""
    if db_manager is None:
        return {"seen_before": False, "note": "无历史数据"}

    try:
        if hasattr(db_manager, "get_ip_history_summary"):
            return db_manager.get_ip_history_summary(
                ip, before_execution_id=before_execution_id
            )

        # 查询该 IP 在所有记录中的出现次数
        conn = db_manager._get_connection() if hasattr(db_manager, '_get_connection') else None
        if conn is None:
            import sqlite3
            conn = sqlite3.connect(db_manager.db_path)

        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) as cnt, MAX(execution_time) as last_seen "
            "FROM top_attackers WHERE source_ip = ?",
            (ip,)
        )
        row = cursor.fetchone()
        if row and row[0] > 0:
            return {
                "seen_before": True,
                "historical_occurrences": row[0],
                "prior_execution_count": row[0],
                "prior_total_attacks": 0,
                "prior_days_seen": 0,
                "last_seen": row[1] if row[1] else "未知",
                "previous_recommendation_count": 0,
                "recent_recommendation": None,
                "note": f"历史出现 {row[0]} 次" if row[0] <= 3 else f"⚠️ 历史出现 {row[0]} 次，重复攻击者",
            }
        return {"seen_before": False, "note": "首次出现"}
    except Exception as e:
        return {"seen_before": False, "note": f"查询失败: {e}"}


def _load_history_summaries(ips: List[str], db_manager=None, current_execution_id: str = None) -> Dict[str, Dict[str, Any]]:
    if db_manager is None:
        return {ip: {"seen_before": False, "note": "无历史数据"} for ip in ips}
    try:
        if hasattr(db_manager, "get_ip_history_summaries"):
            return db_manager.get_ip_history_summaries(
                ips, before_execution_id=current_execution_id
            )
        return {ip: _check_history(ip, db_manager, current_execution_id) for ip in ips}
    except Exception as e:
        return {ip: {"seen_before": False, "note": f"查询失败: {e}"} for ip in ips}


def _score_history(history: Dict[str, Any]) -> Dict[str, Any]:
    """将历史摘要转换为封顶 15 分的历史评分详情。"""
    if not history or not history.get("seen_before"):
        return {
            "score": 0,
            "seen_before": False,
            "prior_execution_count": 0,
            "prior_total_attacks": 0,
            "prior_days_seen": 0,
            "last_seen": None,
            "previous_recommendation_count": 0,
            "recent_recommendation": None,
            "reasons": [],
        }

    prior_count = int(history.get("prior_execution_count") or history.get("historical_occurrences") or 0)
    recent_execution_count = int(history.get("recent_execution_count") or 0)
    previous_recommendation_count = int(history.get("previous_recommendation_count") or 0)
    prior_recommendation = history.get("prior_max_recommendation")
    last_seen_days = history.get("last_seen_days")

    score = 0
    reasons = []

    if prior_count >= 4:
        score += 9
        reasons.append(f"历史出现 {prior_count} 次")
    elif prior_count >= 2:
        score += 6
        reasons.append(f"历史出现 {prior_count} 次")
    elif prior_count == 1:
        score += 3
        reasons.append("历史出现 1 次")

    if recent_execution_count > 0:
        score += 3
        reasons.append(f"近7天重复出现 {recent_execution_count} 次")

    if last_seen_days is not None and last_seen_days <= 2:
        score += 2
        reasons.append("最近2天内再次出现")

    if previous_recommendation_count > 0:
        score += 3
        reasons.append(f"过去曾 {previous_recommendation_count} 次进入推荐清单")
    elif prior_recommendation in ("持续监控", "建议封禁", "立即封禁"):
        score += 2
        reasons.append(f"历史曾达到{prior_recommendation}")

    return {
        "score": min(score, 15),
        "seen_before": True,
        "prior_execution_count": prior_count,
        "prior_total_attacks": int(history.get("prior_total_attacks") or 0),
        "prior_days_seen": int(history.get("prior_days_seen") or 0),
        "last_seen": history.get("last_seen"),
        "last_seen_days": last_seen_days,
        "previous_recommendation_count": previous_recommendation_count,
        "recent_recommendation": history.get("recent_recommendation"),
        "prior_max_recommendation": prior_recommendation,
        "prior_max_score": history.get("prior_max_score"),
        "note": history.get("note", ""),
        "reasons": reasons,
    }


def _build_recommendation_reasons(item: Dict[str, Any]) -> List[str]:
    """从评分和历史细节生成最多 4 条推荐理由。"""
    reasons = []
    evidence = item.get("evidence", {})
    score_details = item.get("score_details", {})

    attack_count = item.get("attack_count") or evidence.get("attack_count")
    unique_threats = evidence.get("unique_threats")
    if attack_count and unique_threats:
        reasons.append(f"累计 {attack_count} 次攻击，覆盖 {unique_threats} 种威胁类型")
    elif attack_count:
        reasons.append(f"累计 {attack_count} 次攻击")

    stages = score_details.get("attack_chain", {}).get("stages") or []
    if stages:
        reasons.append(f"攻击链覆盖{'、'.join(stages[:3])}")

    for reason in score_details.get("calibration", {}).get("reasons", []):
        if reason and reason not in reasons:
            reasons.append(reason)
        if len(reasons) >= 4:
            break

    for reason in score_details.get("payload_risk", {}).get("reasons", []):
        if reason and reason not in reasons:
            reasons.append(reason)
            break

    for reason in score_details.get("history", {}).get("reasons", []):
        if reason and reason not in reasons:
            reasons.append(reason)
        if len(reasons) >= 4:
            break

    return reasons[:4]


def _classify_recommendation(
    attack_count: int,
    base_score: float,
    final_score: float,
    score_details: Dict[str, Any],
) -> Tuple[str, str, List[str]]:
    """Classify an IP using score plus explicit evidence gates."""
    behavior = score_details.get("behavior_confidence", {})
    stages = score_details.get("attack_chain", {}).get("stages") or []
    high_risk = bool(score_details.get("high_risk_intent", {}).get("detected"))
    payload_score = score_details.get("payload_risk", {}).get("score", 0)
    history = score_details.get("history", {})

    allowed_rate = behavior.get("allowed_rate") or 0
    effective_rate = behavior.get("effective_response_rate") or 0
    target_count = behavior.get("target_count") or 0
    failed_rate = behavior.get("failed_rate") or 0
    not_found_rate = behavior.get("not_found_rate") or 0
    previous_recommendations = history.get("previous_recommendation_count") or 0

    positive_execution = allowed_rate >= 0.3 and effective_rate >= 0.2
    low_outcome_confidence = failed_rate >= 0.8 or not_found_rate >= 0.8
    strong_chain = len(stages) >= 3 and not low_outcome_confidence
    repeated_high_risk = high_risk and payload_score >= 10 and previous_recommendations > 0
    if final_score >= 70 and high_risk and (
        positive_execution or strong_chain or repeated_high_risk
    ):
        reasons = ["高危意图叠加有效放行响应"] if positive_execution else ["高危多阶段或历史重复攻击"]
        return "立即封禁", "🔴", reasons

    high_volume_scan = attack_count >= 200 and (
        "侦察" in stages or failed_rate >= 0.5 or not_found_rate >= 0.5
    )
    multi_target_persistent = (
        target_count >= 3
        and score_details.get("persistence", {}).get("span_hours", 0) >= 1
        and base_score >= 25
    )
    supported_current_risk = high_risk and base_score >= 25
    historical_support = (
        base_score >= 25
        and final_score >= 40
        and previous_recommendations > 0
        and (high_risk or any(stage != "侦察" for stage in stages))
    )
    if high_volume_scan or multi_target_persistent or supported_current_risk or historical_support:
        reasons = []
        if high_volume_scan:
            reasons.append(f"高频恶意扫描 {attack_count} 次")
        if supported_current_risk:
            reasons.append("检测到明确高危攻击意图")
        if multi_target_persistent:
            reasons.append(f"持续攻击 {target_count} 个目标")
        if historical_support:
            reasons.append("当前风险得到历史重复记录支撑")
        return "建议封禁", "🟠", reasons

    if final_score >= 25:
        return "持续监控", "🟡", []
    return "观察", "⚪", []


# ── 主引擎 ─────────────────────────────────────────────────────────

class BlocklistAdvisor:
    """封禁建议引擎"""

    RECOMMEND_MIN_FINAL_SCORE = 25
    RECOMMEND_MIN_BASE_SCORE = 15
    RECOMMEND_HIGH_BASE_SCORE = 45

    def __init__(self, df: pd.DataFrame, db_manager=None, current_execution_id: str = None):
        self.df = df.copy()
        self.df.columns = self.df.columns.str.strip()

        # 列名解析
        self._resolve_columns()

        # 数据库连接（可选）
        self.db = db_manager
        self.current_execution_id = current_execution_id

        # 全局统计（用于归一化评分）
        ip_col = self.cols.get("src_ip")
        if ip_col and ip_col in self.df.columns:
            ips = self.df[ip_col].dropna().astype(str)
            self.ip_counts = ips.value_counts().to_dict()
            self.max_attacks = max(self.ip_counts.values()) if self.ip_counts else 1

            threat_col = self.cols.get("threat_type")
            if threat_col and threat_col in self.df.columns:
                # 向量化：一次 groupby 求每个 IP 的威胁类型数，避免逐 IP 全表扫描
                valid = self.df[ip_col].notna()
                src = self.df.loc[valid, ip_col].astype(str)
                threats = self.df.loc[valid, threat_col]
                if len(src):
                    per_ip_nunique = threats.groupby(src).nunique()
                    self.max_diversity = int(per_ip_nunique.max())
                else:
                    self.max_diversity = 1
            else:
                self.max_diversity = 1
        else:
            self.ip_counts = {}
            self.max_attacks = 1
            self.max_diversity = 1

    def _resolve_columns(self):
        """解析各分析列的列名"""
        # 导入 local_analyzer 的列名映射（处理直接运行和包导入两种场景）
        try:
            from modules.local_analyzer import _COLUMN_CANDIDATES, _find_column
        except ImportError:
            from local_analyzer import _COLUMN_CANDIDATES, _find_column
        self.cols = {}
        for key, candidates in _COLUMN_CANDIDATES.items():
            self.cols[key] = _find_column(self.df, candidates)

    def _compile_evidence(
        self, ip: str, ip_data: pd.DataFrame
    ) -> Dict[str, Any]:
        """为单个 IP 编译完整证据卡"""
        evidence = {"ip": ip}

        # 攻击概览
        evidence["attack_count"] = len(ip_data)

        threat_col = self.cols.get("threat_type")
        if threat_col and threat_col in ip_data.columns:
            threats = ip_data[threat_col].dropna().astype(str)
            evidence["threat_types"] = threats.value_counts().head(8).to_dict()
            evidence["unique_threats"] = threats.nunique()

        sev_col = self.cols.get("severity")
        if sev_col and sev_col in ip_data.columns:
            evidence["severity_levels"] = ip_data[sev_col].fillna("?").astype(str).value_counts().to_dict()

        # 攻击描述样本
        desc_col = self.cols.get("description")
        if desc_col and desc_col in ip_data.columns:
            descs = ip_data[desc_col].dropna().astype(str)
            unique_descs = list(dict.fromkeys(descs))[:5]
            evidence["sample_descriptions"] = unique_descs

        # 数据包证据：直接用已过滤的 ip_data（原来传 self.df 会再次全表扫描）
        packet_col = next((c for c in self.df.columns if "数据包" in str(c) or "packet" in str(c).lower()), None)
        ip_col = self.cols.get("src_ip")
        if packet_col and ip_col and ip_col in ip_data.columns:
            evidence["packet_evidence"] = _extract_packet_evidence(
                ip_data, ip, ip_col, packet_col
            )

        # 目标 URL
        url_col = self.cols.get("url")
        if url_col and url_col in ip_data.columns:
            urls = ip_data[url_col].dropna().astype(str)
            evidence["top_urls"] = urls.value_counts().head(5).to_dict()

        return evidence

    def generate_blocklist(
        self, min_attacks: int = 3, min_score: float = None
    ) -> List[Dict[str, Any]]:
        """生成封禁建议清单（按评分降序）

        历史分只作为当前风险的补充：低基线分 IP 不能仅凭历史高频进入推荐。
        """
        final_threshold = (
            self.RECOMMEND_MIN_FINAL_SCORE if min_score is None else min_score
        )

        blocklist = []
        for item in self.score_all_ips(min_attacks=min_attacks):
            final_score = item.get("final_score", item.get("score", 0))
            if final_score < final_threshold:
                continue
            if item.get("recommendation") not in ("立即封禁", "建议封禁"):
                continue
            blocklist.append(dict(item, is_recommended=True))

        blocklist.sort(key=lambda x: -x["score"])
        return blocklist

    def score_all_ips(
        self, min_attacks: int = 3, min_score: float = 0
    ) -> List[Dict[str, Any]]:
        """对所有满足攻击次数阈值的 IP 评分，补齐历史分字段。"""
        ip_col = self.cols.get("src_ip")
        if not ip_col or ip_col not in self.df.columns:
            return []

        eligible_ips = [
            ip for ip, count in self.ip_counts.items()
            if count >= min_attacks
        ]
        history_by_ip = _load_history_summaries(
            eligible_ips, self.db, self.current_execution_id
        )

        # 一次性转 str，避免逐 IP 循环里重复全列 astype + 全表扫描
        src_full = self.df[ip_col].astype(str)
        filtered = []
        for ip in eligible_ips:
            count = self.ip_counts[ip]
            ip_data = self.df[src_full == ip]
            evidence = self._compile_evidence(ip, ip_data)
            packet_evidence = evidence.get("packet_evidence", {})
            base_score, score_details = _score_ip(
                ip, ip_data, self.cols, packet_evidence,
                self.max_attacks, self.max_diversity
            )

            history = history_by_ip.get(
                ip, {"seen_before": False, "note": "无历史数据"}
            )
            history_details = _score_history(history)
            history_score = history_details["score"]
            final_score = min(100, round(base_score + history_score, 1))

            if final_score < min_score:
                continue

            score_details["history"] = history_details

            recommendation, label, calibration_reasons = _classify_recommendation(
                count, base_score, final_score, score_details
            )
            score_details["calibration"] = {"reasons": calibration_reasons}

            item = {
                "ip": ip,
                "score": final_score,
                "attack_count": count,
                "label": label,
                "recommendation": recommendation,
                "score_details": score_details,
                "evidence": evidence,
                "history": {**history, **history_details},
                "base_score": base_score,
                "history_score": history_score,
                "final_score": final_score,
            }
            item["recommendation_reasons"] = _build_recommendation_reasons(item)
            filtered.append(item)

        filtered.sort(key=lambda x: -x["score"])
        return filtered

    def print_report(self, blocklist: List[Dict] = None, top_n: int = 20):
        """打印格式化的封禁建议报告"""
        if blocklist is None:
            blocklist = self.generate_blocklist()

        if not blocklist:
            print("\n未发现需要封禁的 IP。")
            return

        # 统计
        immediate = [b for b in blocklist if b["recommendation"] == "立即封禁"]
        recommend = [b for b in blocklist if b["recommendation"] == "建议封禁"]
        monitor = [b for b in blocklist if b["recommendation"] == "持续监控"]

        print(f"\n{'=' * 70}")
        print(f"  🛡️  封禁建议报告")
        print(f"{'=' * 70}")
        print(f"  立即封禁: {len(immediate)} | 建议封禁: {len(recommend)} "
              f"| 持续监控: {len(monitor)}")
        print(f"  总计 {len(blocklist)} 个 IP 需要处置\n")

        # 摘要表
        print(f"  {'IP':<20} {'评分':>5} {'攻击数':>7} {'等级':>4} 建议")
        print(f"  {'-' * 60}")
        for b in blocklist[:top_n]:
            sev = b["evidence"].get("severity_levels", {})
            max_sev = ""
            for s in ["高危", "严重", "critical", "高", "中危", "低危"]:
                if s in sev:
                    max_sev = s
                    break
            print(f"  {b['label']} {b['ip']:<17} {b['score']:>5.0f} "
                  f"{b['attack_count']:>7} {max_sev:>4}  {b['recommendation']}")

        # 详细证据卡（立即封禁 + 建议封禁的前几个）
        for b in blocklist[:top_n]:
            if b["recommendation"] in ("立即封禁", "建议封禁"):
                self._print_evidence_card(b)

        print(f"\n{'=' * 70}")

    def _print_evidence_card(self, b: Dict):
        """打印单个 IP 的详细证据卡"""
        ip = b["ip"]
        se = b["evidence"]
        sd = b["score_details"]
        hist = b["history"]

        print(f"\n{'─' * 70}")
        print(f"  {b['label']} {ip}  — 评分: {b['score']:.0f}/100"
              f"  —  {b['recommendation']}")
        print(f"{'─' * 70}")
        print(
            f"  评分拆解: 当前 {b.get('base_score', b.get('score', 0)):.1f} "
            f"+ 历史 {b.get('history_score', 0):.1f} "
            f"= 最终 {b.get('final_score', b.get('score', 0)):.1f}"
        )

        print(f"  攻击次数: {b['attack_count']}")
        print(f"  威胁类型: {se.get('unique_threats', '?')} 种 → "
              f"{list(se.get('threat_types', {}).keys())[:5]}")

        # 时间
        if "persistence" in sd:
            p = sd["persistence"]
            if p.get("span_hours"):
                print(f"  活跃时段: {p.get('first_seen','?')} ~ {p.get('last_seen','?')}"
                      f" (持续 {p['span_hours']:.1f}h)")

        # 严重等级
        sevs = se.get("severity_levels", {})
        if sevs:
            sev_str = " ".join(f"{k}:{v}" for k, v in sorted(sevs.items(), key=lambda x: -x[1]))
            print(f"  严重等级: {sev_str}")

        # 攻击链
        chain = sd.get("attack_chain", {})
        if chain.get("stages"):
            print(f"  攻击链: {' → '.join(chain['stages'])}")

        # 攻击目标
        urls = se.get("top_urls", {})
        if urls:
            print(f"  攻击目标:")
            for url, cnt in list(urls.items())[:5]:
                print(f"    [{cnt}次] {url[:90]}")

        # 描述
        descs = se.get("sample_descriptions", [])
        if descs:
            print(f"  攻击描述:")
            for d in descs[:3]:
                print(f"    • {d[:100]}")

        # HTTP 请求证据
        pkt = se.get("packet_evidence", {})
        sample_reqs = pkt.get("sample_requests", [])
        if sample_reqs:
            print(f"  HTTP 请求证据 ({pkt.get('http_count', 0)} 条):")
            for req in sample_reqs[:3]:
                print(f"    {req['method']} {req['url'][:80]}")
                if req.get("host"):
                    print(f"    Host: {req['host']}")
                if req.get("user_agent"):
                    print(f"    UA: {req['user_agent'][:70]}")

        # C2/Base64 证据
        b64 = pkt.get("b64_snippets", [])
        if b64:
            print(f"  C2/隧道流量证据 ({pkt.get('b64_count', 0)} 条):")
            for s in b64[:2]:
                print(f"    • {s[:130]}")

        # Payload 风险理由
        pr = sd.get("payload_risk", {})
        if pr.get("reasons"):
            print(f"  Payload 风险: {', '.join(pr['reasons'])}")

        # 历史
        if hist.get("seen_before"):
            print(f"  历史: {hist['note']}")

        reasons = b.get("recommendation_reasons") or []
        if reasons:
            print("  推荐理由:")
            for reason in reasons:
                print(f"    • {reason}")

        # 处置建议
        print(f"\n  ▶ 建议: {b['recommendation']}")

    def export_csv(self, blocklist: List[Dict], path: str = None, input_file: str = None) -> str:
        """导出封禁清单为 CSV"""
        if path is None:
            path = build_blocklist_output_path(input_file) if input_file else "outputs/blocklist_recommendations.csv"

        rows = []
        for b in blocklist:
            se = b["evidence"]
            sd = b["score_details"]
            hist = b.get("history", {})
            hist_details = sd.get("history", {})
            rows.append({
                "IP": b["ip"],
                "评分": b["score"],
                "建议": b["recommendation"],
                "攻击次数": b["attack_count"],
                "威胁类型数": se.get("unique_threats", 0),
                "主要威胁": "|".join(list(se.get("threat_types", {}).keys())[:5]),
                "最高严重等级": next((k for k in se.get("severity_levels", {}) if k in ["高危", "严重"]), ""),
                "攻击链": " → ".join(sd.get("attack_chain", {}).get("stages", [])),
                "Payload风险": "|".join(sd.get("payload_risk", {}).get("reasons", [])),
                "首次出现": sd.get("persistence", {}).get("first_seen", ""),
                "末次出现": sd.get("persistence", {}).get("last_seen", ""),
                "历史出现次数": hist.get("historical_occurrences", ""),
                "样本描述": "|".join(se.get("sample_descriptions", [])[:2]),
                "样本URL": "|".join(list(se.get("top_urls", {}).keys())[:3]),
                "base_score": b.get("base_score", ""),
                "history_score": b.get("history_score", hist_details.get("score", "")),
                "final_score": b.get("final_score", b.get("score", "")),
                "historical_occurrences": hist.get("historical_occurrences", ""),
                "previous_recommendation_count": hist.get(
                    "previous_recommendation_count",
                    hist_details.get("previous_recommendation_count", ""),
                ),
                "first_seen": hist.get("first_seen", ""),
                "last_seen": hist.get("last_seen", hist_details.get("last_seen", "")),
                "recommendation_reasons": "|".join(b.get("recommendation_reasons", [])),
                "behavior_confidence_score": sd.get("behavior_confidence", {}).get("score", ""),
                "allowed_rate": sd.get("behavior_confidence", {}).get("allowed_rate", ""),
                "blocked_rate": sd.get("behavior_confidence", {}).get("blocked_rate", ""),
                "failed_rate": sd.get("behavior_confidence", {}).get("failed_rate", ""),
                "not_found_rate": sd.get("behavior_confidence", {}).get("not_found_rate", ""),
                "effective_response_rate": sd.get("behavior_confidence", {}).get("effective_response_rate", ""),
                "target_count": sd.get("behavior_confidence", {}).get("target_count", ""),
                "high_risk_intent": sd.get("high_risk_intent", {}).get("detected", False),
                "calibration_reasons": "|".join(sd.get("calibration", {}).get("reasons", [])),
            })

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_csv(path, index=False, encoding="utf-8-sig")
        print(f"\n✅ 封禁清单已导出: {path} ({len(rows)} 条)")
        return path


# ── 便捷函数 ─────────────────────────────────────────────────────

def generate_blocklist_report(df: pd.DataFrame, db_manager=None,
                              min_attacks: int = 3, min_score: float = 15,
                              top_n: int = 20, export_csv: bool = True) -> List[Dict]:
    """生成封禁建议报告（一站式）"""
    advisor = BlocklistAdvisor(df, db_manager=db_manager)
    blocklist = advisor.generate_blocklist(min_attacks=min_attacks, min_score=min_score)
    advisor.print_report(blocklist, top_n=top_n)
    if export_csv and blocklist:
        advisor.export_csv(blocklist)
    return blocklist


# ── 自测 ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import numpy as np
    np.random.seed(99)
    n = 500

    df = pd.DataFrame({
        "时间": pd.date_range("2024-01-01", periods=n, freq="90s"),
        "描述": np.random.choice([
            "SQL注入 - UNION SELECT", "XSS跨站脚本", "路径遍历 ../../../etc/passwd",
            "WebShell上传", "暴力破解登录", "信息泄露探测",
        ], n),
        "攻击类型": np.random.choice([
            "SQL注入", "代码注入", "XSS跨站", "路径遍历", "WebShell上传",
            "暴力破解", "信息泄露", "网站扫描",
        ], n),
        "源IP": np.random.choice([
            "10.0.0.1", "10.0.0.2", "10.0.0.3",
            "192.168.1.100", "192.168.1.200",
        ], n, p=[0.4, 0.2, 0.2, 0.15, 0.05]),
        "源端口": np.random.choice(["31456", "51234", "443", "8080"], n),
        "目的IP": "198.51.100.125",
        "目的端口": "80",
        "请求URL": np.random.choice([
            "/cgi-bin/../../../bin/sh", "/login.php?id=1' OR '1'='1",
            "/upload/shell.jsp", "/admin/config.php",
            "/.env", "/api/user",
        ], n),
        "严重等级": np.random.choice(["高危", "中危", "低危"], n, p=[0.4, 0.4, 0.2]),
        "攻击结果": np.random.choice(["失败", "尝试"], n),
        "数据包": np.random.choice([
            "REQUEST:\nGET /cgi-bin/../../../bin/sh HTTP/1.1\nHost: target.com\nUser-Agent: Mozilla/5.0\n\n",
            "REQUEST:\nPOST /upload/shell.jsp HTTP/1.1\nHost: target.com\nUser-Agent: python-requests/2.28\n\n",
            "AwAAKybgAAAAAABDb29raWU6IG1zdHNoYXNoPWhlbGxvDQoBAAgAAwAAAA==",
        ], n),
    })

    blocklist = generate_blocklist_report(df)
