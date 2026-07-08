# Sangfor 自动化流水线实现方案

## 目标

本文档作为后续实现的单一参考，避免只依赖聊天上下文。目标是在新项目 `/home/user/projects/sangfor-security-automation` 中，把现有 Sangfor 态势感知、防火墙和攻击源分析工具串成一个可长期运行、可审计、默认安全的自动化流水线。

本文档优先级高于当前 `README.md` 和 `docs/workflow.md` 中的旧描述。后续实现和文档更新均以本文档为准；`README.md` 只保留项目入口说明并链接到本文档。

`/home/user/projects/SXF_extract_attacker` 不是本项目根目录，只作为上游分析引擎来源。后续实现应把需要的分析代码复制或以子模块形式放到本项目的 `analyzer/SXF_extract_attacker/` 下，再由统一入口调用。

流水线覆盖以下阶段：

1. 本地登录：用户在本地完成态势感知和防火墙登录，生成 `session.json`。
2. 登录态维持：态势感知使用 HTTP keepalive；防火墙使用 headless Chromium 每 5 分钟刷新 `/framework.php`。
3. 日志导出：读取态势感知 session，导出 SIP KsearchLog Excel 报表。
4. 黑名单导出：读取防火墙 session，导出当前防火墙黑名单 CSV。
5. 日志分析：执行 `extract_attacker.py`，结合防火墙黑名单生成恶意 IP 建议清单。
6. 封禁 IP：读取防火墙 session，将恶意 IP 下发到防火墙。默认 dry-run，显式 `--apply` 才真实执行。

## 现有工具边界

### 登录脚本

态势感知登录脚本：

```bash
python /home/user/projects/sangfor-security-automation/situation-awareness/sangfor_login_session.py
```

默认生成：

```text
/home/user/.config/sangfor/session.json
```

要求字段：

```json
{
  "base_url": "https://172.16.1.118",
  "cookie": "...",
  "xid": "...",
  "created_at": "..."
}
```

防火墙登录脚本：

```bash
python /home/user/projects/sangfor-security-automation/firewall/sangfor_firewall_login_session.py
```

默认生成：

```text
/home/user/.config/sangfor-firewall/session.json
```

要求字段：

```json
{
  "base_url": "https://172.16.1.116",
  "product": "sangfor-firewall",
  "cookie": "...",
  "csrf": {
    "_cftoken": "...",
    "gcs_csrf": "..."
  },
  "created_at": "..."
}
```

登录脚本只应由用户在本地终端执行。流水线和 Docker 服务不接收、不保存、不打印密码或验证码。

### 态势感知日志导出

现有脚本：

```text
situation-awareness/sangfor_log_export.py
```

关键能力：

- 支持 `--session-file` 读取 `cookie + xid + base_url`。
- 按收藏条件和时间范围查询总数。
- 按接近 10000 条分段导出。
- 输出 Excel 文件和 manifest。
- 文件名格式为 `sangfor-sip-report-KsearchLog-YYYYMMDDNN.xlsx`。

示例命令：

```bash
python situation-awareness/sangfor_log_export.py \
  --session-file /app/secrets/sip_session.json \
  --start "2026-06-26 17:30:00" \
  --end "2026-07-03 17:30:00" \
  --favorite-name "3" \
  --output-dir /app/runs/<run_id>/exports \
  --export-date "2026-07-07"
```

### SIP Cookie 保活

项目内脚本：

```text
situation-awareness/sangfor_sip_cookie_keepalive.py
```

目标行为：

- 每 300 秒向轻量查询接口发送请求。
- 如果 HTTP 302 或接口返回 `need_login=true`，判定 session 失效。
- 写入 `state/sip_session.status.json`。
- 不修改设备配置。

当前需要改造：

- 增加 `--session-file`。
- 从 session 文件读取 `base_url/host + cookie + xid`。
- 删除内置默认 cookie/xid。
- 缺少 session 或字段时直接失败。

### 防火墙黑名单工具

项目内脚本：

```text
firewall/sangfor_firewall_blocklist.py
```

当前能力：

- 导出并下载防火墙黑名单 CSV。
- 根据命令行目标或文件目标构造封禁请求。
- 默认 dry-run；加 `--execute` 才真实提交。
- `_cftoken` 可由 `SESSID` 自动派生。

当前需要改造：

- 删除内置默认 Cookie。
- 增加 `--session-file`。
- 从 session 文件读取 `base_url + cookie + csrf`。
- `--check-login` 应访问 `/framework.php`，不要用 `/` 判断。
- session 缺失、cookie 缺失或 CSRF 不可派生时应失败。

### 防火墙 headless 保活

当前实现策略先采用“新开 headless Chromium，读取 `firewall_session.json` 注入 Cookie，然后每 5 分钟访问 `/framework.php`”的方式。

该策略作为当前版本的保活方案，必须满足：

- 每次刷新访问 `/framework.php`，不使用 `/` 作为健康检查入口。
- 如果 URL 跳到 `login.php`、标题变为 `欢迎登录`、或页面出现用户名/密码/验证码输入框，立即判定失效。
- 失效后写入 `state/firewall_session.status.json`，并让进程退出。
- 不在日志中输出 Cookie、CSRF token 或页面请求头。
- 如果后续实测新开 browser context 仍不能长期维持，再升级为“登录脚本完成登录后不关闭 browser context，直接进入 keepalive loop”的可靠模式。

### 分析入口

项目主入口：

```text
analyzer/SXF_extract_attacker/extract_attacker.py
```

关键能力：

- 自动识别 AF / SIP 报表。
- 读取防火墙黑名单 CSV，排除已封禁 IP。
- 读取 `config/ip_whitelist.txt`，排除白名单 IP。
- 输出处理后 CSV。
- 使用 `--blocklist` 输出封禁建议 CSV。
- 使用 SQLite 记录历史攻击源、评分和建议。

当前需要改造：

- `analyzer/SXF_extract_attacker/modules/config.py` 的 SIP 文件名模式必须兼容 `YYYYMMDDNN`，否则会把现有导出文件误判为 AF。
- 建议新增 `--output-dir`，让每次运行产物落到 `runs/<run_id>/analysis/`。

## 总体架构

新增统一入口和编排模块：

```text
/home/user/projects/sangfor-security-automation/
  situation-awareness/
    sangfor_login_session.py
    sangfor_log_export.py
    sangfor_sip_cookie_keepalive.py
  firewall/
    sangfor_firewall_login_session.py
    sangfor_firewall_blocklist.py
    firewall_keepalive.py
  analyzer/
    SXF_extract_attacker/
      extract_attacker.py
      modules/
      config/
  pipeline/
    run_pipeline.py          # 统一入口
    config.py                # 读取 config/pipeline.yaml
    state.py                 # 写入 state/*.json
    artifacts.py             # 管理每次运行产物目录
    sessions.py              # 检查 session 文件和登录态
    commands.py              # 调用现有脚本的封装
  config/
    pipeline.example.yaml
    ip_whitelist.txt
  docker/
    Dockerfile
    Dockerfile.playwright
  docker-compose.yml
  state/
    latest.json
    sip_session.status.json
    firewall_session.status.json
  runs/
    20260707_130000/
      manifest.json
      exports/
      blacklist/
      analysis/
      block/
```

统一入口只负责编排，不重写业务逻辑。具体能力仍由现有脚本承担：

- 登录：`situation-awareness/sangfor_login_session.py`、`firewall/sangfor_firewall_login_session.py`
- SIP 保活：`situation-awareness/sangfor_sip_cookie_keepalive.py`
- 防火墙保活：`firewall/firewall_keepalive.py`
- 日志导出：`situation-awareness/sangfor_log_export.py`
- 黑名单导出和封禁：`firewall/sangfor_firewall_blocklist.py`
- 日志分析：`analyzer/SXF_extract_attacker/extract_attacker.py`

## 运行目录约定

Docker 内建议使用：

```text
/app/config   # 配置和白名单
/app/data     # SQLite 数据库
/app/outputs  # 兼容旧输出目录
/app/exports  # 可选导出目录
/app/runs     # 每次流水线运行产物
/app/state    # 服务健康状态
/app/secrets  # session 文件，只读挂载，不进 Git
```

`session.json` 放在：

```text
/app/secrets/sip_session.json
/app/secrets/firewall_session.json
```

`/app/secrets` 必须加入 `.gitignore`，Docker 挂载时使用只读模式。

## 统一入口命令设计

统一入口为：

```bash
python pipeline/run_pipeline.py <command> [options]
```

建议支持以下命令。

### `check-sessions`

检查态势感知和防火墙 session 文件是否存在、字段是否完整、登录态是否可用。

```bash
python pipeline/run_pipeline.py check-sessions
```

检查内容：

- SIP session 存在，且包含 `cookie` 和 `xid`。
- SIP 轻量查询接口返回正常，且没有 `need_login=true`。
- 防火墙 session 存在，且包含 `cookie`。
- 防火墙访问 `/framework.php` 后没有跳转到登录页。

输出状态文件：

```text
state/sip_session.status.json
state/firewall_session.status.json
```

### `export-logs`

只执行态势感知日志导出。

```bash
python pipeline/run_pipeline.py export-logs \
  --start "2026-06-26 17:30:00" \
  --end "2026-07-03 17:30:00" \
  --favorite-name "3"
```

内部调用：

```bash
python situation-awareness/sangfor_log_export.py \
  --session-file /app/secrets/sip_session.json \
  --start "$START" \
  --end "$END" \
  --favorite-name "$FAVORITE" \
  --output-dir /app/runs/<run_id>/exports \
  --export-date "$EXPORT_DATE"
```

产物：

```text
runs/<run_id>/exports/*.xlsx
runs/<run_id>/exports/manifest-*.json
```

### `export-firewall-blacklist`

只导出防火墙当前黑名单。

```bash
python pipeline/run_pipeline.py export-firewall-blacklist
```

内部调用：

```bash
python firewall/sangfor_firewall_blocklist.py \
  --session-file /app/secrets/firewall_session.json \
  --export \
  --output-dir /app/runs/<run_id>/blacklist
```

产物：

```text
runs/<run_id>/blacklist/sangfor_firewall_blacklists.csv
```

### `analyze`

分析指定或本次导出的 SIP Excel 报表。

```bash
python pipeline/run_pipeline.py analyze \
  --xlsx runs/<run_id>/exports/sangfor-sip-report-KsearchLog-2026070701.xlsx \
  --blacklist runs/<run_id>/blacklist/sangfor_firewall_blacklists.csv
```

内部调用时必须把工作目录设置为 `/app/analyzer/SXF_extract_attacker`，避免 `modules/`、`config/`、`outputs/`、`data/` 相对路径错位。命令由统一入口以 `cwd=/app/analyzer/SXF_extract_attacker` 执行：

```bash
python extract_attacker.py "$XLSX" \
  --blacklist "$FIREWALL_BLACKLIST_CSV" \
  --exclude-from-csv \
  --local-analyze \
  --blocklist \
  --db-path /app/data/attackers.db
```

理想状态下，`extract_attacker.py` 应支持 `--output-dir` 和 `--whitelist-file`：

```bash
python extract_attacker.py "$XLSX" \
  --blacklist "$FIREWALL_BLACKLIST_CSV" \
  --exclude-from-csv \
  --local-analyze \
  --blocklist \
  --db-path /app/data/attackers.db \
  --whitelist-file /app/config/ip_whitelist.txt \
  --output-dir /app/runs/<run_id>/analysis
```

如果暂时不实现 `--output-dir`，统一入口需要把 `outputs/*_blocklist_recommendations.csv` 复制到本次运行目录。

### `block`

根据封禁建议 CSV 生成封禁目标，并执行 dry-run 或真实封禁。

Dry-run：

```bash
python pipeline/run_pipeline.py block \
  --recommendations runs/<run_id>/analysis/*_blocklist_recommendations.csv
```

真实执行：

```bash
python pipeline/run_pipeline.py block \
  --recommendations runs/<run_id>/analysis/*_blocklist_recommendations.csv \
  --apply
```

统一入口从封禁建议 CSV 读取：

- `IP`
- `建议`
- `评分`
- `final_score`
- `recommendation_reasons`

默认只选取：

```text
建议 in ["立即封禁", "建议封禁"]
```

不自动封禁 `持续监控`。

### 封禁建议 CSV 标准 schema

为了让封禁和日报不依赖分析引擎内部中文列名，统一入口应把分析结果转换为标准 CSV：

```text
runs/<run_id>/analysis/blocklist_recommendations.normalized.csv
```

标准字段：

| 字段 | 说明 |
| --- | --- |
| `ip` | 攻击源 IP |
| `recommendation` | `立即封禁`、`建议封禁`、`持续监控`、`观察` |
| `final_score` | 最终评分 |
| `base_score` | 当前报表行为分 |
| `history_score` | 历史加权分 |
| `attack_count` | 本次报表攻击次数 |
| `threat_types` | 主要威胁类型，使用 `|` 分隔 |
| `severity` | 最高严重等级 |
| `attack_chain` | 攻击链阶段，使用 `>` 分隔 |
| `evidence_summary` | 截断后的证据摘要 |
| `sample_urls` | 样本 URL，使用 `|` 分隔并截断 |
| `historical_occurrences` | 历史出现次数 |
| `recommendation_reasons` | 推荐理由，使用 `|` 分隔 |
| `source_report` | 来源 Excel 报表路径 |
| `already_blacklisted` | 是否已在防火墙黑名单 |
| `blocked_this_run` | 本次是否真实封禁 |
| `skip_reason` | 未封禁原因 |

`block` 和 `daily_report` 只读取标准 schema，不直接依赖原始 `*_blocklist_recommendations.csv`。分析引擎原始输出字段变化时，只需要修改归一化转换层。

目标写入：

```text
runs/<run_id>/block/targets.txt
runs/<run_id>/block/dry_run.json
```

真实封禁时内部调用：

```bash
python firewall/sangfor_firewall_blocklist.py \
  --session-file /app/secrets/firewall_session.json \
  --file /app/runs/<run_id>/block/targets.txt \
  --desc "7月自动封禁" \
  --execute
```

### `full`

串联完整流程。默认 dry-run，不真实封禁。

```bash
python pipeline/run_pipeline.py full \
  --start "2026-06-26 17:30:00" \
  --end "2026-07-03 17:30:00" \
  --favorite-name "3"
```

真实封禁必须显式加 `--apply`：

```bash
python pipeline/run_pipeline.py full \
  --start "2026-06-26 17:30:00" \
  --end "2026-07-03 17:30:00" \
  --favorite-name "3" \
  --apply
```

`full` 阶段顺序：

1. `check-sessions`
2. `export-logs`
3. `export-firewall-blacklist`
4. `analyze`
5. `block` dry-run
6. 如果传入 `--apply`，执行真实封禁

## 风险控制规则

封禁 IP 属于高风险动作，必须采用保守策略。

### 默认 dry-run

所有封禁相关命令默认只打印和记录请求，不提交到防火墙。只有显式传入 `--apply`，统一入口才允许调用 `sangfor_firewall_blocklist.py --execute`。

### `--apply` 前置条件

真实封禁前必须全部满足：

- 防火墙 session 检查健康。
- SIP session 检查健康，或本次日志导出阶段已经成功。
- 本次运行有明确的 `run_id`。
- 推荐 CSV 来自本次运行或用户显式指定。
- 目标 IP 文件非空。
- 目标 IP 不在 `config/ip_whitelist.txt`。
- 目标 IP 不在本次导出的防火墙黑名单 CSV。
- 目标 IP 来自 `建议 = 立即封禁` 或 `建议 = 建议封禁`。
- 单次封禁数量不超过配置的上限，例如 `max_targets_per_run: 200`。

### 禁止行为

- 不允许没有 session 文件时使用默认 Cookie。
- 不允许打印 Cookie、xid、CSRF token、密码、验证码。
- 不允许 `--apply` 与 `--skip-checks` 同时存在。
- 不允许在登录态失效时继续执行真实封禁。
- 不允许把 `持续监控` 自动下发封禁。

### 运行记录

每次运行必须写入：

```text
runs/<run_id>/manifest.json
```

manifest 记录：

- `run_id`
- 开始和结束时间
- 命令参数
- 每个阶段状态
- 输入文件路径
- 输出文件路径
- 目标 IP 数量
- dry-run 或 apply 模式
- 错误摘要

manifest 不记录任何秘密值。

## 定时任务和日报

系统需要支持每天固定时间自动执行指定时间段的日志导出、分析和封禁流程，并在执行结束后生成日报。

### 调度目标

定时任务应支持：

- 每天指定时间运行，例如每天 `08:30`。
- 配置日志时间窗口，例如导出昨天 `00:00:00` 到 `23:59:59`，或最近 24 小时。
- 指定收藏条件，例如态势感知收藏 `3`。
- 指定执行模式：默认 dry-run，可配置是否允许自动 `--apply`。
- 执行结束后生成日报，记录今天封禁了哪些 IP、为什么封禁、证据链是什么。

### 推荐实现方式

调度机制采用“配置文件定义任务 + scheduler 服务执行任务”的模式。

- `config/pipeline.yaml` 是唯一调度配置入口，所有定时任务都写在 `schedules` 下。
- Docker Compose 增加 `scheduler` 常驻服务。
- `scheduler` 读取 `config/pipeline.yaml`，按 `cron` 表达式触发对应任务。
- `scheduler` 到点后调用 `python pipeline/run_pipeline.py scheduled <job_name>`。
- 不再依赖宿主机 crontab 作为主路径；宿主机 cron 仅作为临时 fallback。

统一入口新增命令：

```bash
python pipeline/run_pipeline.py scheduled <job_name> [--apply]
```

`scheduled` 从 `config/pipeline.yaml` 读取任务定义，计算时间窗口后调用 `full`。

定时任务真实封禁必须同时满足 3 个条件：

1. 任务配置 `allow_apply: true`。
2. scheduler 或人工调用时显式传入 `--apply`。
3. `full --apply` 的全部风险检查通过。

因此，每日自动封禁的实际调用方式是：

```bash
python pipeline/run_pipeline.py scheduled daily-default --apply
```

如果任务配置没有 `allow_apply: true`，即使命令行传了 `--apply`，也必须降级为 dry-run 并记录原因。

### 配置示例

```yaml
schedules:
  daily-default:
    enabled: true
    cron: "30 8 * * *"
    timezone: Asia/Shanghai
    allow_apply: false
    favorite_name: "3"
    window:
      type: previous_day
      timezone: Asia/Shanghai
      start_time: "00:00:00"
      end_time: "23:59:59"
    report:
      enabled: true
      output_formats: [markdown, json]
```

`allow_apply: true` 只表示该任务允许在调度场景中真实封禁；本次执行仍必须显式带 `--apply`，并通过 session 健康检查、白名单检查、已封禁检查和数量上限检查。

### 运行产物

每日任务应生成：

```text
runs/<run_id>/
  manifest.json
  exports/
  blacklist/
  analysis/
  block/
    targets.txt
    dry_run.json
    apply_result.json
  reports/
    daily_report.md
    daily_report.json
  logs/
    pipeline.log
    events.jsonl
```

### 日报内容

`reports/daily_report.md` 至少包含：

- 运行时间和日志时间范围。
- session 检查结果。
- 导出日志文件数量和总日志条数。
- 导出防火墙黑名单数量。
- 本次分析发现的候选恶意 IP 数量。
- 本次实际封禁 IP 数量。
- 每个封禁 IP 的证据链：
  - IP
  - 建议等级
  - 最终评分
  - 攻击次数
  - 主要威胁类型
  - 最高严重等级
  - 攻击链阶段
  - 样本 URL 或样本描述
  - 历史出现次数
  - 推荐理由
- 未封禁原因：白名单、已在黑名单、低置信度、超过单次上限、session 异常等。

日报中的证据链来自 `*_blocklist_recommendations.csv` 和 SQLite 历史库，不包含 Cookie、xid、CSRF token 或原始敏感 payload 全量内容。样本 URL 和描述需要截断，避免报告过长。

### 通知方式

第一阶段只落本地文件。后续可增加通知器：

- 企业微信 / 微信机器人。
- Feishu webhook。
- 邮件。
- Hermes 定时任务回推当前会话。

通知正文只放摘要和报告路径，不直接发送完整敏感日志。

## 日志记录

系统需要完整记录流水线执行过程，便于审计和排错。

### 日志类型

建议同时写两种日志：

1. 人类可读日志：`runs/<run_id>/logs/pipeline.log`
2. 结构化事件日志：`runs/<run_id>/logs/events.jsonl`

### 日志字段

每条结构化事件建议包含：

```json
{
  "ts": "2026-07-07T08:30:00+08:00",
  "run_id": "20260707_083000",
  "stage": "export-logs",
  "level": "INFO",
  "event": "stage_completed",
  "message": "exported 3 files",
  "data": {
    "file_count": 3,
    "total_count": 25737
  }
}
```

### 日志要求

- 每个阶段开始、成功、失败都必须记录。
- 外部命令的 stdout/stderr 要保存到阶段日志，但必须过滤秘密值。
- 命令退出码、耗时、输入输出路径必须记录。
- 异常要记录错误类型和摘要。
- 日志不记录 Cookie、xid、CSRF token、密码、验证码、API key。
- 日志保留策略可配置，例如保留 90 天或最近 200 次运行。

### 脱敏机制

新增 `pipeline/redaction.py`，所有日志、manifest 错误摘要、日报错误摘要在写入前必须经过统一脱敏函数。

脱敏规则至少覆盖：

- HTTP 头：`Cookie:`、`Authorization:`、`Set-Cookie:`。
- JSON 字段：`cookie`、`xid`、`csrf`、`_cftoken`、`gcs_csrf`、`password`、`token`、`api_key`、`secret`。
- 命令行参数：`--cookie`、`--xid`、`--csrf-token`、`--password`。
- 常见 key-value：`cookie=...`、`xid=...`、`token=...`。

脱敏后统一替换为 `[REDACTED]`。如果某段日志无法可靠脱敏，则只记录摘要和退出码，不保存原文。

### 目录权限和 `.gitignore`

本地 secrets 权限要求：

```bash
chmod 700 secrets
chmod 600 secrets/*.json
```

`.gitignore` 必须包含：

```gitignore
secrets/
runs/
logs/
state/
data/
outputs/
exports/
*.pyc
__pycache__/
.pytest_cache/
```

`/app/secrets` 在容器中只读挂载，任何服务都不能修改 session 文件。

### 日志目录

```text
logs/
  scheduler.log
  keepalive-sip.log
  keepalive-firewall.log
runs/<run_id>/logs/
  pipeline.log
  events.jsonl
  export-logs.stdout.log
  export-logs.stderr.log
  analyze.stdout.log
  analyze.stderr.log
  block.stdout.log
  block.stderr.log
```

常驻服务写全局日志，单次流水线写 run 内日志。

## Web 控制台评估

### 是否需要 Web 控制台

短期不实现 Web 控制台。当前版本范围只包含命令行流水线、定时任务、日志、日报和风险控制。Web 控制台会引入认证、权限、审计、前端、后端 API 和额外运维成本，先作为后续可选增强。

### 建议阶段

第一阶段不做 Web 控制台，只保留文件产物和命令行：

- `runs/<run_id>/manifest.json`
- `reports/daily_report.md`
- `logs/events.jsonl`
- `state/*.json`

第二阶段可以做轻量只读控制台，不提供封禁按钮：

- 查看最近运行记录。
- 查看 session 健康状态。
- 查看每日报告。
- 查看封禁建议和证据链。
- 下载 CSV 和 Markdown 报告。

第三阶段再考虑受控操作能力：

- 手动触发 dry-run。
- 手动触发导出。
- 对封禁建议做人工确认。
- 真实封禁仍需二次确认和审计记录。

### 控制台技术建议

如果后续实现，建议使用简单本地 Web 应用：

- 后端：FastAPI。
- 前端：服务端模板或轻量 React。
- 数据来源：读取 `runs/`、`state/`、SQLite，不直接管理秘密。
- 默认只监听 `127.0.0.1`，如需远程访问再通过反向代理和认证保护。

控制台不应直接持有密码。真实封禁 API 必须复用 `pipeline/run_pipeline.py block --apply` 的同一套风险检查。

## 配置文件

新增示例配置：

```text
config/pipeline.example.yaml
```

建议内容：

```yaml
paths:
  sip_session_file: /app/secrets/sip_session.json
  firewall_session_file: /app/secrets/firewall_session.json
  data_dir: /app/data
  outputs_dir: /app/outputs
  runs_dir: /app/runs
  state_dir: /app/state

sip:
  base_url: https://172.16.1.118
  default_favorite_name: "3"
  export_limit: 10000
  keepalive_interval_seconds: 300
  verify_tls: false

firewall:
  base_url: https://172.16.1.116
  framework_path: /framework.php
  keepalive_interval_seconds: 300
  verify_tls: false

analysis:
  db_path: /app/data/attackers.db
  whitelist_file: /app/config/ip_whitelist.txt
  recommendation_levels:
    - 立即封禁
    - 建议封禁
  min_final_score: 45

blocking:
  default_apply: false
  description_template: "{month}月自动封禁"
  max_targets_per_run: 200

logging:
  retention_days: 90
  redact_secrets: true
  write_jsonl_events: true

schedules:
  daily-default:
    enabled: true
    cron: "30 8 * * *"
    timezone: Asia/Shanghai
    allow_apply: false
    favorite_name: "3"
    window:
      type: previous_day
      timezone: Asia/Shanghai
      start_time: "00:00:00"
      end_time: "23:59:59"
    report:
      enabled: true
      output_formats: [markdown, json]

scheduler:
  enabled: true
  poll_interval_seconds: 30

web:
  enabled: false
  host: 127.0.0.1
  port: 8080
  readonly: true
```

## Docker 部署方案

建议把长期保活服务和一次性流水线任务拆开。

### 服务拆分

- `sip-keepalive`：常驻，维持态势感知 session。
- `firewall-keepalive`：常驻，使用新开 headless Chromium 注入 Cookie 并刷新 `/framework.php`。
- `pipeline`：一次性任务，用于执行 `check-sessions`、`full`、`block` 等命令。
- `scheduler`：常驻，读取 `config/pipeline.yaml`，按 `schedules` 定义触发每日任务。

### Compose 示例

```yaml
services:
  sip-keepalive:
    build:
      context: .
      dockerfile: docker/Dockerfile.playwright
    command:
      - python
      - situation-awareness/sangfor_sip_cookie_keepalive.py
      - --session-file
      - /app/secrets/sip_session.json
      - --interval
      - "300"
      - --stop-on-need-login
      - --insecure
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./outputs:/app/outputs
      - ./runs:/app/runs
      - ./state:/app/state
      - ./secrets:/app/secrets:ro
    restart: unless-stopped

  firewall-keepalive:
    build:
      context: .
      dockerfile: docker/Dockerfile.playwright
    command:
      - python
      - firewall/firewall_keepalive.py
      - --session-file
      - /app/secrets/firewall_session.json
      - --interval
      - "300"
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./outputs:/app/outputs
      - ./runs:/app/runs
      - ./state:/app/state
      - ./secrets:/app/secrets:ro
    restart: unless-stopped

  pipeline:
    build:
      context: .
      dockerfile: docker/Dockerfile
    command: ["python", "pipeline/run_pipeline.py", "--help"]
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./outputs:/app/outputs
      - ./exports:/app/exports
      - ./runs:/app/runs
      - ./state:/app/state
      - ./secrets:/app/secrets:ro

  scheduler:
    build:
      context: .
      dockerfile: docker/Dockerfile
    command: ["python", "pipeline/scheduler.py", "--config", "/app/config/pipeline.yaml"]
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./outputs:/app/outputs
      - ./exports:/app/exports
      - ./runs:/app/runs
      - ./state:/app/state
      - ./logs:/app/logs
      - ./secrets:/app/secrets:ro
    restart: unless-stopped
```

### Dockerfile 注意事项

当前 `docker/Dockerfile` 只适合普通分析和 HTTP 工具。防火墙保活和日志导出都依赖 Playwright/Chromium，Docker 镜像需要增加：

```bash
python -m pip install playwright
python -m playwright install --with-deps chromium
```

可选设计：

- 简化版：一个 `docker/Dockerfile` 同时包含分析依赖和 Playwright。
- 稳定版：拆成 `docker/Dockerfile` 和 `docker/Dockerfile.playwright`，让分析任务镜像保持轻量，保活服务单独使用 Playwright 镜像。

初期建议先用一个 Dockerfile 跑通闭环，稳定后再拆镜像。

## 必须先修的兼容和安全问题

### 1. SIP 文件名兼容

当前 `analyzer/SXF_extract_attacker/modules/config.py` 只识别 14 位时间戳：

```python
SIP_FILE_PATTERN = r'sangfor-sip-report-KsearchLog-\d{14}\.xlsx'
```

实际导出文件是 10 位日期加序号：

```text
sangfor-sip-report-KsearchLog-2026070701.xlsx
```

应改为同时支持 14 位和 10 位：

```python
SIP_FILE_PATTERN = r'sangfor-sip-report-KsearchLog-(\d{14}|\d{10})\.xlsx'
```

### 2. 删除默认 Cookie

以下脚本不能内置默认 Cookie 或 xid：

- `firewall/sangfor_firewall_blocklist.py`
- `situation-awareness/sangfor_sip_cookie_keepalive.py`

缺少 session 文件时必须失败，而不是使用示例值。

### 3. 防火墙登录态检查入口

防火墙验证入口必须使用：

```text
/framework.php
```

不要使用 `/`。此前实测 `/` 可能返回登录页或不可靠，`/framework.php` 才能准确判断是否仍在登录后页面。

## 实施顺序

### 第一阶段：安全和兼容修复

1. 确认本项目已有 `situation-awareness/sangfor_log_export.py`、`situation-awareness/sangfor_login_session.py`、`firewall/sangfor_firewall_login_session.py`，并把上游分析引擎放入 `analyzer/SXF_extract_attacker/`。
2. 修复 SIP 文件名识别，兼容 `YYYYMMDDNN`。
3. 删除防火墙黑名单工具里的默认 Cookie。
4. 删除 SIP keepalive 工具里的默认 Cookie/xid。
5. 给 SIP keepalive 增加 `--session-file`。
6. 给防火墙黑名单工具增加 `--session-file`。
7. 修复防火墙 `--check-login`，使用 `/framework.php`。

### 第二阶段：统一入口最小闭环

1. 新增 `pipeline/run_pipeline.py`。
2. 实现 `check-sessions`。
3. 实现 `export-logs`。
4. 实现 `export-firewall-blacklist`。
5. 实现 `analyze`。
6. 实现 `block`，默认 dry-run。
7. 实现 `full`，默认 dry-run。
8. 实现 run 目录、manifest、阶段日志和结构化事件日志。
9. 每个阶段写入 `runs/<run_id>/manifest.json` 和 `runs/<run_id>/logs/events.jsonl`。

### 第三阶段：长期服务和定时任务

1. 新增 `firewall/firewall_keepalive.py`，按当前策略新开 headless Chromium、注入 `firewall_session.json` Cookie，并每 5 分钟刷新 `/framework.php`。
2. 修改 `docker/Dockerfile.playwright`，支持 Playwright。
3. 修改 `docker-compose.yml`，增加 `sip-keepalive`、`firewall-keepalive`、`pipeline`、`scheduler`。
4. `state/*.json` 记录健康状态。
5. 保活失败时进程退出，让 Docker restart policy 或外部告警接管。
6. 新增 `pipeline/run_pipeline.py scheduled <job_name>`。
7. 新增 `config/pipeline.yaml` 中的 `schedules` 配置。
8. 支持每日指定时间、指定日志时间窗口执行自动导出、分析和封禁。
9. 每日任务结束后生成 `reports/daily_report.md` 和 `reports/daily_report.json`。

### 第四阶段：真实封禁保护

1. `full --apply` 和 `scheduled` 的 apply 模式加强前置检查。
2. 限制每次最多封禁数量。
3. 保存 dry-run 预览和 apply 结果。
4. 生成包含证据链的日报。
5. 可选增加二次确认文件，例如必须存在 `state/approve_apply` 才允许批量 apply。

### 第五阶段：Web 控制台（可选）

1. 先实现只读控制台，读取 `runs/`、`state/` 和 SQLite。
2. 展示最近运行、session 健康状态、每日报告和封禁证据链。
3. 暂不提供真实封禁按钮。
4. 如果后续需要操作能力，必须复用统一入口的风险检查和审计记录。

## 验证计划

实现过程中应补充测试：

- 10 位 SIP 文件名能识别为 SIP。
- 缺少 session 文件时工具失败，不使用默认秘密。
- SIP session 缺少 `cookie` 或 `xid` 时失败。
- 防火墙 session 缺少 `cookie` 时失败。
- `block` 默认 dry-run，不调用真实提交接口。
- `full --apply` 在 session 不健康时拒绝执行。
- 只选择 `立即封禁` 和 `建议封禁` 的 IP。
- 白名单 IP 不进入 `targets.txt`。
- 已存在于防火墙黑名单 CSV 的 IP 不进入 `targets.txt`。
- 每次运行生成 manifest，且 manifest 不包含 Cookie、xid、CSRF token。
- 每个阶段生成 `pipeline.log` 和 `events.jsonl`。
- 结构化日志会脱敏 Cookie、xid、CSRF token、密码、验证码、API key。
- `scheduled daily-default` 能按配置计算上一天时间窗口。
- 定时任务 dry-run 模式不会真实封禁。
- 定时任务 apply 模式仍执行全部风险检查。
- 每日任务生成 `reports/daily_report.md` 和 `reports/daily_report.json`。
- 日报包含实际封禁 IP、未封禁原因和证据链。
- Web 控制台默认关闭；如果开启只读模式，不暴露真实封禁接口。

建议验证命令：

```bash
python -m pytest situation-awareness firewall tests analyzer/SXF_extract_attacker/tests -q
```

如果系统 Python 没有 `pytest`，先创建虚拟环境：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt pytest
python -m pytest situation-awareness firewall tests analyzer/SXF_extract_attacker/tests -q
```

## 最终运行方式

本地生成 session：

```bash
python situation-awareness/sangfor_login_session.py --session-file ./secrets/sip_session.json
python firewall/sangfor_firewall_login_session.py --session-file ./secrets/firewall_session.json
```

启动保活：

```bash
docker compose up -d sip-keepalive firewall-keepalive
```

执行完整 dry-run：

```bash
docker compose run --rm pipeline \
  python pipeline/run_pipeline.py full \
  --start "2026-06-26 17:30:00" \
  --end "2026-07-03 17:30:00" \
  --favorite-name "3"
```

确认 `runs/<run_id>/block/targets.txt` 和 dry-run 结果后，真实封禁：

```bash
docker compose run --rm pipeline \
  python pipeline/run_pipeline.py block \
  --run-id <run_id> \
  --apply
```

## 结论

本方案保留现有脚本的职责边界，通过 `pipeline/run_pipeline.py` 增加统一编排、前置检查、产物记录和风险控制。Docker 部署分为常驻保活服务和一次性流水线任务。真实封禁默认关闭，必须显式 `--apply`，并通过 session 健康、白名单、已封禁列表和数量上限等检查后才允许执行。
