# 封禁建议可信度与历史闭环设计

## 背景

当前项目从 Sangfor AF/SIP 报表中提取攻击源 IP，生成统计结果、封禁建议、CSV 和 SQLite 记录。下一步改进聚焦安全运营效果：让每个封禁建议既能解释本次为什么危险，也能看到该 IP 在历史执行中的复现情况。

## 目标

- 每个推荐封禁 IP 输出清晰评分拆解：本次行为分、历史加权分、最终分。
- 每个推荐封禁 IP 输出历史摘要：历史出现次数、首次出现、最近出现、历史最高分、过去推荐次数、最近一次推荐摘要。
- 保持现有 CLI 使用方式，继续通过 `--blocklist` 生成报告、CSV 和 SQLite 记录。
- 数据库不可用时仍能完成本次报表分析，并退化为仅基于本次行为评分。

## 非目标

- 不实现封禁审批流。
- 不自动下发防火墙或安全设备策略。
- 不实现工单系统、Web 看板或完整 SOC 编排。
- 不重构整个数据库迁移体系。

## 架构设计

### BlocklistAdvisor

`BlocklistAdvisor` 继续负责当前报表内的证据提取和评分。它需要输出以下结构化字段：

- `base_score`：本次报表行为分。
- `history_score`：历史复现加权分。
- `final_score`：最终用于排序和推荐的分数。
- `score_details`：攻击量、威胁多样性、严重等级、持续性、攻击链、payload 风险、历史加权的拆解。
- `recommendation_reasons`：面向分析人员的 2-4 条推荐理由。

### DatabaseManager

`DatabaseManager` 增加面向 IP 列表的历史摘要查询能力。查询结果按 IP 返回：

- `historical_occurrences`
- `first_seen`
- `last_seen`
- `max_historical_score`
- `previous_recommendation_count`
- `recent_recommendation`

历史摘要优先从 `ip_scores` 读取推荐和评分记录，结合 `ip_observations` 获取更完整的出现历史。

### main_app

`process_xlsx()` 保持现有串联职责：读取报表、排除白名单、创建 `DatabaseManager`、创建 `BlocklistAdvisor`、生成封禁建议、导出 CSV、保存 SQLite。新增行为只发生在启用 `--blocklist` 或数据库记录可用时。

数据流：

```text
XLSX
  ↓
DataFrame 清洗/排除白名单
  ↓
BlocklistAdvisor 提取本次证据
  ↓
DatabaseManager 查询历史摘要
  ↓
BlocklistAdvisor 计算 base_score + history_score = final_score
  ↓
CLI 报告 / CSV 导出 / SQLite 保存
```

## 评分规则

### base_score

`base_score` 表示当前报表内的危险程度，来自现有维度：

- 攻击量
- 威胁类型多样性
- 严重等级
- 持续性
- 攻击链阶段
- payload 风险

### history_score

`history_score` 表示历史复现风险，封顶 15 分。建议规则：

- 历史多次不同执行中出现：加分。
- 历史曾被推荐封禁：加分。
- 最近一段时间持续出现：加分。
- 历史最高分较高：加分。

历史分不得替代当前证据。没有历史记录时，`history_score = 0`。

### final_score

`final_score = base_score + history_score`。

推荐口径：

- `attack_count >= 3` 且 `final_score` 达到推荐阈值时推荐封禁。
- 当 `base_score` 达到高危阈值时，即使没有历史记录，也可以推荐封禁。
- 历史分只提高排序和置信度，不让低风险当前行为仅凭历史记录进入推荐清单。

## 输出设计

### CLI 报告

每个推荐 IP 显示：

- `base_score / history_score / final_score`
- 历史出现次数
- 首次出现和最近出现
- 过去推荐次数
- 推荐理由列表

### CSV

封禁建议 CSV 增加列：

- `base_score`
- `history_score`
- `final_score`
- `historical_occurrences`
- `previous_recommendation_count`
- `first_seen`
- `last_seen`
- `recommendation_reasons`

### SQLite

复用现有 `ip_scores` 字段保存评分拆解和历史快照：

- `base_score`
- `history_score`
- `final_score`
- `history_details_json`
- `evidence_json`
- `is_recommended`

如果字段不存在，继续由现有初始化逻辑补齐。

## 错误处理

- 历史查询失败时，不中断本次分析。
- 历史查询失败时，`history_score = 0`，CLI 提示历史上下文不可用。
- CSV 和 SQLite 仍保存本次证据与基础评分。
- 数据库完全不可用时，`--blocklist` 仍输出当前报表的封禁建议。

## 测试计划

- 无历史记录：`history_score = 0`，`final_score = base_score`。
- 多次历史出现：历史分按规则增加且不超过 15 分。
- 历史曾推荐封禁：`previous_recommendation_count` 正确影响历史分和推荐理由。
- 历史查询异常：仍生成当前报表封禁建议。
- CSV 导出包含新增字段。
- SQLite 保存评分拆解和历史快照。
- 高 `base_score` 无历史记录时仍可推荐。
- 低 `base_score` 仅凭历史记录不能进入推荐清单。

## 范围检查

本设计只覆盖封禁建议可信度和历史复现闭环，不包含自动化封禁、审批、工单、Web UI 或完整迁移框架。实现范围可由一个实现计划覆盖。
