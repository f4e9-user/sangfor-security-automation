"""AI 分析模块 - 本地特征提取 + 云端脱敏分析

安全设计原则：
- 原始 IP、payload、URL 等敏感数据永不出本地
- 只向云端 API 发送聚合统计和哈希化匿名标识
- AI 返回的封禁建议通过本地哈希映射表还原为真实 IP
"""

import hashlib
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

import pandas as pd
from openai import OpenAI

from modules.database_manager import DatabaseManager

# 哈希盐值（生产环境通过环境变量覆盖）
_HASH_SALT = os.getenv("ANALYZER_HASH_SALT", "soc-analyzer-salt-2024")

# 威胁类型 → 严重等级（本地规则，不依赖 AI）
_SEVERITY_KEYWORDS = {
    "critical": ["sql注入", "sql injection", "rce", "remote code", "command injection",
                 "反序列化", "文件上传", "webshell", "权限提升", "后门",
                 "代码执行", "命令执行", "远程代码", "任意文件", "缓冲区溢出",
                 "提权", "exploit", "cve-"],
    "high": ["xss", "csrf", "ssrf", "xxe", "文件包含", "目录遍历", "信息泄露",
             "暴力破解", "爆破", "漏洞扫描", "端口扫描", "弱口令", "拒绝服务",
             "dos", "ddos", "欺骗", "劫持", "注入"],
    "medium": ["扫描", "爬虫", "探测", "fingerprint", "扫描器", "目录枚举",
               "信息收集", "banner", "sensitive"],
    "low": ["正常访问", "误报", "白名单", "其他", "正常", "允许"],
}


def _classify_severity(threat_type: str) -> str:
    """本地规则推断威胁严重等级"""
    t = threat_type.lower()
    for level, keywords in _SEVERITY_KEYWORDS.items():
        if any(kw in t for kw in keywords):
            return level
    return "medium"


def _hash_ip(ip: str) -> str:
    """SHA256(ip + salt) 截取前 12 位作为匿名标识"""
    return hashlib.sha256((ip + _HASH_SALT).encode()).hexdigest()[:12]


def _looks_like_ip(value: str) -> bool:
    """检查值是否看起来像 IP 地址"""
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _column_is_sensitive(col_name: str) -> bool:
    """判断列名是否属于敏感字段（其值不应发送到云端）"""
    lower = col_name.lower()
    sensitive_patterns = [
        "ip", "addr", "address", "host", "domain", "dns",
        "url", "uri", "path", "link", "href",
        "payload", "body", "data", "content", "request", "response",
        "header", "cookie", "token", "auth", "session",
        "user-agent", "useragent", "referer", "referrer",
        "id", "name", "email", "phone", "account", "password",
        "源ip", "源地址", "目的ip", "目的地址", "主机", "域名",
    ]
    return any(p in lower for p in sensitive_patterns)


class QwenAnalyzer:
    """本地特征提取 + 云端脱敏 AI 分析器"""

    def __init__(self, api_key: Optional[str] = None, model: str = "qwen-max"):
        self._api_key = api_key or os.getenv("ALIBABA_CLOUD_API_KEY")
        self._client = None
        self.model = model

    @property
    def client(self):
        """惰性初始化 API 客户端（纯本地操作不需要 key）"""
        if self._client is None:
            if not self._api_key:
                raise ValueError("请设置环境变量 ALIBABA_CLOUD_API_KEY 或提供api_key参数")
            self._client = OpenAI(
                api_key=self._api_key,
                base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            )
        return self._client

    # ── 本地特征提取（敏感数据不离开本机）──────────────────────────

    def _extract_ip_behaviors(
        self,
        df: pd.DataFrame,
        ip_col: str,
        threat_col: str,
        top_ips: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        """为每个 Top IP 提取本地行为特征"""
        behaviors = []
        for ip, count in top_ips.items():
            ip_rows = df[df[ip_col].astype(str) == ip]
            threat_types = ip_rows[threat_col].dropna().astype(str)
            threat_dist_series = threat_types.value_counts()
            threat_dist = threat_dist_series.to_dict()

            # 主威胁类型
            primary_threat = threat_dist_series.index[0] if len(threat_dist_series) > 0 else "未知"

            # 严重等级分布
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for t, c in threat_dist.items():
                severity_counts[_classify_severity(t)] += c

            # 时间集中度（如果有时间列）
            time_concentration = None
            for col in df.columns:
                if any(kw in str(col).lower() for kw in ["time", "时间", "date", "日期"]):
                    try:
                        times = pd.to_datetime(ip_rows[col], errors="coerce").dropna()
                        if len(times) >= 2:
                            span_hours = (times.max() - times.min()).total_seconds() / 3600
                            time_concentration = round(count / max(span_hours, 0.1), 1)
                    except Exception:
                        pass
                    break

            behaviors.append({
                "actor_id": _hash_ip(ip),
                "attack_count": count,
                "unique_threat_types": len(threat_dist),
                "primary_threat": primary_threat,
                "threat_distribution": threat_dist,
                "severity_breakdown": severity_counts,
                "attacks_per_hour": time_concentration,
            })

        return behaviors

    def extract_sanitized_features(
        self,
        df: pd.DataFrame,
        top_ips: Dict[str, int],
        top_threats: Dict[str, int],
        source_file: str = "",
    ) -> Dict[str, Any]:
        """主特征提取入口 - 所有操作在本地完成，只产出脱敏聚合数据"""
        # 列名清洗
        df = df.copy()
        df.columns = df.columns.str.strip()

        # 定位关键列
        ip_col = next(
            (c for c in df.columns if any(kw in c for kw in ["源IP", "Source IP", "src_ip", "源地址"])),
            None,
        )
        threat_col = next(
            (c for c in df.columns if any(kw in c for kw in ["威胁类型", "Threat Type", "攻击类型", "事件类型"])),
            None,
        )

        if not ip_col or not threat_col:
            raise ValueError("无法定位源IP列或威胁类型列，特征提取失败")

        # 1. 严重等级分布（全量统计）
        all_threats = df[threat_col].dropna().astype(str)
        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for t in all_threats:
            severity_dist[_classify_severity(t)] += 1

        # 2. 每个 Top IP 的行为特征（带哈希 ID）
        ip_behaviors = self._extract_ip_behaviors(df, ip_col, threat_col, top_ips)

        # 3. 时间分布（按小时聚合，不发送具体时间戳）
        time_distribution = {}
        for col in df.columns:
            if any(kw in str(col).lower() for kw in ["time", "时间", "date", "日期"]):
                try:
                    times = pd.to_datetime(df[col], errors="coerce").dropna()
                    if len(times) > 0:
                        hourly = times.dt.hour.value_counts().sort_index().to_dict()
                        time_distribution = {str(k): v for k, v in hourly.items()}
                except Exception:
                    pass
                break

        # 4. IP ↔ 哈希映射表（本地保留，用于结果还原）
        ip_hash_map = {_hash_ip(ip): ip for ip in top_ips}
        reverse_map = {ip: _hash_ip(ip) for ip in top_ips}

        return {
            "source_file": source_file,
            "analysis_time": datetime.now().isoformat(),
            "total_records": len(df),
            "total_unique_ips": df[ip_col].nunique(),
            "total_threat_types": all_threats.nunique(),
            # 脱敏后的聚合数据（以下内容发送到云端）
            "sanitized": {
                "severity_distribution": severity_dist,
                "top_threats": [
                    {"type": t, "count": c, "severity": _classify_severity(t)}
                    for t, c in top_threats.items()
                ],
                "top_actors": ip_behaviors,  # IP 已哈希化
                "time_distribution": time_distribution,
            },
            # 本地映射表（永不发送）
            "ip_hash_map": ip_hash_map,
            "reverse_map": reverse_map,
        }

    # ── 构建脱敏提示 ──────────────────────────────────────────────

    def _build_safe_prompt(self, features: Dict[str, Any]) -> str:
        """用脱敏后的聚合数据构建 AI 提示"""
        s = features["sanitized"]

        top_threats_json = json.dumps(s["top_threats"], ensure_ascii=False, indent=2)
        top_actors_json = json.dumps(s["top_actors"], ensure_ascii=False, indent=2)
        severity_json = json.dumps(s["severity_distribution"], ensure_ascii=False)
        time_json = json.dumps(s["time_distribution"], ensure_ascii=False)

        return f"""分析以下安全事件的聚合统计数据并提供专业建议。

数据概览：
- 源文件: {features['source_file']}
- 总记录数: {features['total_records']}
- 独立 IP 数: {features['total_unique_ips']}
- 威胁类型数: {features['total_threat_types']}

严重等级分布:
{severity_json}

Top 威胁类型及发生次数:
{top_threats_json}

Top 攻击源行为画像（IP 已匿名化为 actor_id）:
{top_actors_json}

按小时的攻击分布:
{time_json}

注意：
- actor_id 是匿名标识符，请使用它来引用具体攻击源
- 请综合考虑攻击频率、威胁多样性、严重程度来给出建议

请以 JSON 格式返回，结构如下：
{{
  "risk_assessment": "critical|high|medium|low",
  "risk_summary": "整体风险评估（中文，200字以内）",
  "recommended_blocks": [
    {{
      "actor_id": "对应上文中的actor_id",
      "reason": "封禁理由（中文）",
      "risk_level": "high|medium|low",
      "confidence": 0.0-1.0
    }}
  ],
  "attack_trends": "攻击趋势分析（中文，100字以内）",
  "defense_recommendations": ["具体防御建议1", "建议2"]
}}

只返回 JSON，不要附带其他文字。"""

    # ── 结果映射 ──────────────────────────────────────────────────

    def _map_block_recommendations(
        self,
        ai_result: Dict[str, Any],
        ip_hash_map: Dict[str, str],
    ) -> Dict[str, Any]:
        """将 AI 返回的 actor_id 映射为真实 IP"""
        mapped_blocks = []
        for rec in ai_result.get("recommended_blocks", []):
            actor_id = rec.get("actor_id", "")
            real_ip = ip_hash_map.get(actor_id)
            if real_ip:
                mapped_blocks.append({
                    "ip": real_ip,
                    "reason": rec.get("reason", ""),
                    "risk_level": rec.get("risk_level", "medium"),
                    "confidence": rec.get("confidence", 0.0),
                })
            else:
                # actor_id 不在映射表中，保留原始 ID 并标注
                mapped_blocks.append({
                    "ip": f"unknown({actor_id})",
                    "reason": rec.get("reason", ""),
                    "risk_level": rec.get("risk_level", "medium"),
                    "confidence": rec.get("confidence", 0.0),
                })

        ai_result["recommended_blocks"] = mapped_blocks
        return ai_result

    # ── 主分析入口 ────────────────────────────────────────────────

    def analyze(
        self,
        df: pd.DataFrame,
        top_ips: Dict[str, int],
        top_threats: Dict[str, int],
        source_file: str = "",
    ) -> Dict[str, Any]:
        """主分析流程：特征提取 → 脱敏 → AI 分析 → 结果映射"""
        # Step 1: 本地提取脱敏特征
        features = self.extract_sanitized_features(df, top_ips, top_threats, source_file)
        prompt = self._build_safe_prompt(features)

        print(f"\n🤖 正在调用 {self.model} 进行安全分析...")
        print(f"   发送数据: {len(json.dumps(features['sanitized']))} 字节（已脱敏）")

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "你是一个 SOC 安全分析专家。你收到的数据已经过脱敏处理："
                            "IP 地址已替换为匿名 actor_id，不包含任何 payload、URL 或原始日志。"
                            "请基于聚合统计和行为画像给出专业分析。"
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=2000,
                response_format={"type": "json_object"},
            )

            ai_result = json.loads(response.choices[0].message.content)

        except Exception as e:
            print(f"AI 分析失败: {e}，返回本地评估结果")
            return {
                "risk_assessment": "unknown",
                "risk_summary": f"AI 分析不可用: {e}",
                "recommended_blocks": [],
                "attack_trends": "",
                "defense_recommendations": ["请人工审核"],
                "_fallback": True,
            }

        # Step 3: 哈希 ID → 真实 IP 映射
        result = self._map_block_recommendations(ai_result, features["ip_hash_map"])
        result["_features"] = {k: v for k, v in features.items() if k != "ip_hash_map"}
        return result

    # ── 辅助方法 ──────────────────────────────────────────────────

    def get_historical_context(self, db_path: str = "data/attackers.db") -> Dict[str, Any]:
        """获取历史攻击数据上下文（也已脱敏）"""
        try:
            db = DatabaseManager(db_path)
            historical = db.get_all_top_attackers(limit=50)

            return {
                "total_historical_ips": len(historical),
                "historical_actors": [
                    {
                        "actor_id": _hash_ip(h["source_ip"]),
                        "total_count": h["total_count"],
                        "execution_count": h["execution_count"],
                    }
                    for h in historical[:20]
                ],
            }
        except Exception as e:
            print(f"获取历史数据失败: {e}")
            return {"total_historical_ips": 0, "historical_actors": []}

    def generate_blocklist_update(
        self,
        analysis_result: Dict[str, Any],
        existing_blocklist: Dict[str, str],
    ) -> Dict[str, str]:
        """根据 AI 分析结果更新封禁列表（本地操作，不出网）"""
        new_blocklist = existing_blocklist.copy()

        for rec in analysis_result.get("recommended_blocks", []):
            ip = rec.get("ip", "")
            if not ip or ip.startswith("unknown("):
                continue
            reason = rec.get("reason", "AI 建议封禁")
            risk = rec.get("risk_level", "medium")
            conf = rec.get("confidence", 0)

            if ip not in new_blocklist or risk == "high":
                new_blocklist[ip] = f"{reason} (风险: {risk}, 置信度: {conf:.0%})"

        return new_blocklist


# ── 便捷函数 ─────────────────────────────────────────────────────

def analyze_with_qwen(
    df: pd.DataFrame,
    top_ips: Dict[str, int],
    top_threats: Dict[str, int],
    source_file: str = "",
    api_key: Optional[str] = None,
    model: str = "qwen-max",
) -> Dict[str, Any]:
    """使用 Qwen 分析攻击流量的便捷函数"""
    analyzer = QwenAnalyzer(api_key=api_key, model=model)
    return analyzer.analyze(df, top_ips, top_threats, source_file)


# ── 自测 ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    print("Qwen Analyzer 自测")
    print(f"  _hash_ip('192.168.1.1') = {_hash_ip('192.168.1.1')}")
    print(f"  _classify_severity('SQL注入攻击') = {_classify_severity('SQL注入攻击')}")
    print(f"  _classify_severity('端口扫描') = {_classify_severity('端口扫描')}")
    print(f"  _looks_like_ip('192.168.1.1') = {_looks_like_ip('192.168.1.1')}")
    print(f"  _looks_like_ip('example.com') = {_looks_like_ip('example.com')}")
    print(f"  _column_is_sensitive('源IP') = {_column_is_sensitive('源IP')}")
    print(f"  _column_is_sensitive('威胁类型') = {_column_is_sensitive('威胁类型')}")

    # 用模拟数据测试脱敏流程
    mock_df = pd.DataFrame({
        "威胁类型": ["SQL注入", "XSS", "端口扫描", "SQL注入", "暴力破解"] * 10,
        "源IP": [f"10.0.0.{i}" for i in range(1, 6)] * 10,
        "发生时间": pd.date_range("2024-01-01", periods=50, freq="5min"),
    })

    mock_top_ips = {"10.0.0.1": 20, "10.0.0.2": 15, "10.0.0.3": 10}
    mock_top_threats = {"SQL注入": 20, "XSS": 10, "端口扫描": 10, "暴力破解": 10}

    analyzer = QwenAnalyzer(api_key="test-key")
    features = analyzer.extract_sanitized_features(
        mock_df, mock_top_ips, mock_top_threats, "test.xlsx"
    )

    print("\n脱敏后的 sanitized 数据（发送到云端的内容）:")
    print(json.dumps(features["sanitized"], ensure_ascii=False, indent=2))
    print(f"\n本地 IP 映射表（不发送）: {features['ip_hash_map']}")
