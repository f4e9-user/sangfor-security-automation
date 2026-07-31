# 本地分析器风险置信度校准实施计划

> **For Hermes:** Use test-driven development to implement this plan task-by-task.

**Goal:** 为本地封禁建议引擎增加稳定攻击量评分、行为置信度校准和偏激进但有上限的推荐门控。

**Architecture:** 在 `blocklist_advisor.py` 中新增纯函数提取行为信号并决定推荐等级，`_score_ip()` 负责基础分，`score_all_ips()` 负责合并历史分和计算展示等级，`generate_blocklist()` 只筛选建议封禁及以上。保持数据库和现有 CSV 字段兼容。

**Tech Stack:** Python 3.11、pandas、pytest。

---

### Task 1: 稳定攻击量与严重度修复

**Files:**
- Modify: `analyzer/SXF_extract_attacker/tests/test_blocklist_history_loop.py`
- Modify: `analyzer/SXF_extract_attacker/modules/blocklist_advisor.py`

1. 新增测试：相同 50 次攻击 IP 在有无 4,449 次极端 IP 时量分相同。
2. 新增测试：“致命”计入高危比例。
3. 运行定向测试确认 RED。
4. 用 `log1p(count)/log1p(1000)` 实现稳定量分，封顶 20。
5. 补充致命等级识别并运行定向测试确认 GREEN。

### Task 2: 行为置信度信号

**Files:**
- Modify: `analyzer/SXF_extract_attacker/tests/test_blocklist_history_loop.py`
- Modify: `analyzer/SXF_extract_attacker/modules/blocklist_advisor.py`

1. 新增测试：允许+2xx+多目标的行为分高于拒绝+失败+404。
2. 新增测试：缺失行为字段时返回 0 分和空比率，不报错。
3. 运行测试确认 RED。
4. 实现 `_score_behavior_confidence()`，输出分数、比率、目标数和理由。
5. 接入 `_score_ip()` 并运行测试确认 GREEN。

### Task 3: 高危意图与推荐门控

**Files:**
- Modify: `analyzer/SXF_extract_attacker/tests/test_blocklist_history_loop.py`
- Modify: `analyzer/SXF_extract_attacker/modules/blocklist_advisor.py`

1. 新增测试：高频失败/404 扫描进入建议封禁但不立即封禁。
2. 新增测试：失败的 RCE/WebShell/反序列化仍标记高危意图。
3. 新增测试：高危意图加允许/2xx 或 3 阶段链可立即封禁。
4. 运行测试确认 RED。
5. 实现 `_detect_high_risk_intent()` 和 `_classify_recommendation()`。
6. 让 `score_all_ips()` 使用门控后的推荐等级，`generate_blocklist()` 只保留建议封禁和立即封禁。
7. 运行测试确认 GREEN。

### Task 4: 输出兼容与报告字段

**Files:**
- Modify: `analyzer/SXF_extract_attacker/modules/blocklist_advisor.py`
- Modify: `pipeline/commands.py`
- Modify: `pipeline/reports.py`
- Modify: `analyzer/SXF_extract_attacker/tests/test_blocklist_history_loop.py`
- Modify: `tests/test_pipeline_phase2.py`

1. 新增 CSV 和标准化字段测试，确认 RED。
2. 输出行为置信度、允许率、拒绝率、失败率、404率、目标数、高危意图和校准理由。
3. 在控制台/日报证据链中按可用字段展示，不破坏旧运行报告。
4. 运行定向测试确认 GREEN。

### Task 5: 离线回放与全量验证

**Files:**
- No production changes unless verification exposes defects.

1. 对 `runs/20260731_163422/exports/sangfor-sip-report-KsearchLog-2026073199.xlsx` 执行只读分析。
2. 对比升级前基线：1,327 个 eligible、136 个旧候选、1 个立即封禁、5 个建议封禁。
3. 核对 4,449 次且 4,346 条 404 的 IP：可建议封禁，不得立即封禁。
4. 运行 `PYTHONPATH=. .venv/bin/pytest -q`。
5. 运行 `py_compile` 与 `git diff --check`。
6. 审查 diff 中是否存在凭据、运行产物和无关改动。
