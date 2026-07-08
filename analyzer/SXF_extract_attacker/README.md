# Extract Attacker

用于处理 Sangfor AF / SIP 安全报表的攻击源分析工具。项目可以自动识别报表类型，排除白名单或已封禁 IP，统计高频攻击源和威胁类型，并可生成带证据的封禁建议清单。

## 功能特性

- 自动识别 Sangfor AF 报表和 SIP KsearchLog 报表。
- 从 Excel 报表中统计威胁类型 Top 10 和源 IP Top 10。
- 支持通过 `config/ip_whitelist.txt` 和外部黑名单 CSV 排除误报或已处理 IP。
- 支持将每次分析结果写入 SQLite 数据库 `data/attackers.db`。
- 支持本地攻击特征分析，包括攻击结果、目标热点、时间模式、扫描器特征等。
- 支持生成封禁建议清单，包含评分和证据，CSV 统一输出到 `outputs/` 目录。
- 支持调用通义千问兼容 OpenAI API 的 AI 分析流程，发送前会做本地脱敏。
- 提供 Sangfor 防火墙黑名单导出和批量封禁辅助工具。

## 项目结构

```text
.
├── extract_attacker.py                   # 主入口，推荐使用
├── Dockerfile                            # Docker 镜像构建文件
├── docker-compose.yml                    # 本地容器运行配置
├── requirements.txt                      # 运行依赖
├── config/                              # 配置文件，例如 IP 白名单
├── data/                                # 本地数据库等运行数据
├── outputs/                             # CSV 输出目录
├── modules/
│   ├── main_app.py                      # CLI 参数和主流程
│   ├── data_processor.py                # Excel / CSV 读取与报表类型识别
│   ├── security_analyzer.py             # Top 统计和基础安全分析
│   ├── blocklist_advisor.py             # 封禁评分和证据卡生成
│   ├── database_manager.py              # SQLite 持久化
│   ├── local_analyzer.py                # 本地攻击特征分析
│   ├── qwen_analyzer.py                 # AI 脱敏分析
│   └── config.py                        # 列名、文件名和数据库配置
├── tools/
│   ├── sangfor_firewall_blocklist.py    # 防火墙黑名单导出和批量封禁工具
│   └── sangfor_sip_cookie_keepalive.py  # SIP Cookie 保活和登录态探测工具
├── scripts/
│   ├── update_database_schema.py        # 数据库表结构更新脚本
│   └── train_xgboost.py                 # 基于历史数据训练 XGBoost 模型
├── tests/                               # pytest 测试
└── README.md
```

## 环境准备

项目使用 Python 3.11。依赖安装：

```bash
python3 -m pip install -r requirements.txt
```

如需运行 `scripts/train_xgboost.py`，还需要安装：

```bash
python3 -m pip install numpy scikit-learn xgboost joblib
```

## Docker 部署

构建镜像：

```bash
docker build -t extract-attacker .
```

直接运行分析。下面示例把当前目录挂载到 `/work`，报表文件从 `/work` 读取，数据库、配置和输出目录分别挂载到容器内对应位置：

```bash
docker run --rm \
  -v "$PWD/config:/app/config" \
  -v "$PWD/data:/app/data" \
  -v "$PWD/outputs:/app/outputs" \
  -v "$PWD:/work" \
  extract-attacker /work/report.xlsx --blocklist
```

使用 Docker Compose：

```bash
mkdir -p work
cp report.xlsx work/
docker compose run --rm extract-attacker /work/report.xlsx --blocklist
```

容器默认入口是 `python extract_attacker.py`。需要传入 AI 分析密钥时，可在宿主机设置 `ALIBABA_CLOUD_API_KEY` 后再运行 `docker compose run`。

## GitHub Actions

仓库包含 `.github/workflows/docker-build.yml`。在 push、pull request 和手动触发时会执行：

- 安装 `requirements.txt` 依赖。
- 运行轻量测试。
- 构建 Docker 镜像 `extract-attacker:ci`。

当前 workflow 只构建镜像，不推送到镜像仓库；需要发布到 GHCR 或其他 registry 时，可在此基础上增加登录和 `push: true`。

## 快速开始

处理一份报表：

```bash
python3 extract_attacker.py sangfor-sip-report-KsearchLog-20260703180201.xlsx
```

指定输出文件：

```bash
python3 extract_attacker.py report.xlsx -o report_processed.csv
```

默认输出目录为 `outputs/`，默认文件名为 `<原文件名>_processed.csv`，编码为 `utf-8-sig`，便于 Excel 打开。显式传入 `-o` 时使用指定路径。

## 报表要求

工具按文件名自动识别报表类型：

| 报表类型 | 文件名模式 | 默认跳过行数 | 必要字段 |
| --- | --- | --- | --- |
| AF | `sangfor-AF-report-YYYYMMDDHHMMSS.xlsx` | 11 | 威胁类型、源 IP |
| SIP | `sangfor-sip-report-KsearchLog-YYYYMMDDHHMMSS.xlsx` | 7 | 攻击类型、源 IP |

如果文件名不符合约定，工具会默认按 AF 报表处理。

AF 报表支持多组候选列名，例如 `威胁类型`、`Threat Type`、`攻击类型`、`源IP`、`Source IP`、`攻击源IP` 等。SIP 报表当前使用固定列：`攻击类型` 和 `源IP`。

## 常用命令

只统计时排除白名单 IP，但保留完整 CSV：

```bash
python3 extract_attacker.py report.xlsx
```

统计和输出 CSV 都排除白名单 IP：

```bash
python3 extract_attacker.py report.xlsx --exclude-from-csv
```

加载外部黑名单 CSV，第一列作为要排除的 IP：

```bash
python3 extract_attacker.py report.xlsx --blacklist blacklists.csv
```

禁用数据库记录：

```bash
python3 extract_attacker.py report.xlsx --no-db
```

指定数据库文件：

```bash
python3 extract_attacker.py report.xlsx --db-path data/attackers.db
```

启用本地攻击特征分析：

```bash
python3 extract_attacker.py report.xlsx --local-analyze
```

生成封禁建议清单：

```bash
python3 extract_attacker.py report.xlsx --blocklist
```

启用 AI 安全分析：

```bash
export ALIBABA_CLOUD_API_KEY="你的 API Key"
python3 extract_attacker.py report.xlsx --ai-analyze
```

组合使用：

```bash
python3 extract_attacker.py report.xlsx \
  --blacklist blacklists.csv \
  --exclude-from-csv \
  --local-analyze \
  --blocklist
```

## 输出说明

主流程会在终端输出：

- 威胁类型 Top 10。
- 源 IP Top 10。
- 可直接用于 SIP 查询的 `src_ip:(...)` 查询语法。
- 被白名单或黑名单排除的 IP 和原因。
- 可选的本地分析报告、AI 分析报告或封禁建议报告。

常见输出文件：

| 文件 | 说明 |
| --- | --- |
| `outputs/<原文件名>_processed.csv` | 处理后的报表 CSV |
| `data/attackers.db` | SQLite 历史分析数据库 |
| `outputs/<原文件名>_blocklist_recommendations.csv` | 封禁建议清单 |
| `outputs/sangfor_firewall_blacklists.csv` | 防火墙黑名单导出结果 |

## 白名单和黑名单

默认白名单文件为 `config/ip_whitelist.txt`，格式为每行一个 IP 和原因：

```text
192.0.2.10,内部扫描器
198.51.100.20,误报资产
```

外部黑名单 CSV 通过 `--blacklist` 传入。工具读取第一列，支持清洗类似 `"'1.2.3.4"` 的格式，并会跳过非 IP 条目。

## 数据库维护

默认数据库路径为 `data/attackers.db`。第一次运行时会自动创建基础表，也可以手动执行幂等更新脚本：

```bash
python3 scripts/update_database_schema.py
```

数据库主要保存：

- 每次执行的 Top 攻击源。
- 每个 IP 的观测摘要。
- 封禁评分和历史推荐结果。

## 防火墙黑名单工具

`tools/sangfor_firewall_blocklist.py` 可用于导出当前黑名单，并批量提交封禁目标。

检查登录状态：

```bash
python3 tools/sangfor_firewall_blocklist.py --check-login
```

导出并下载当前黑名单：

```bash
python3 tools/sangfor_firewall_blocklist.py --export --output-dir .
```

未指定 `--output-dir` 时，导出文件默认保存为 `outputs/sangfor_firewall_blacklists.csv`。

预览封禁请求（dry-run，不会提交）：

```bash
python3 tools/sangfor_firewall_blocklist.py 117.72.195.41 evil.example --desc "应急处置"
```

真正提交封禁：

```bash
python3 tools/sangfor_firewall_blocklist.py 117.72.195.41 --desc "应急处置" --execute
```

从文件读取封禁目标：

```bash
python3 tools/sangfor_firewall_blocklist.py --file targets.txt --desc "7月封禁" --execute
```

Cookie 默认优先从 `/home/user/.config/sangfor-firewall/session.json` 读取，文件示例：

```json
{
  "cookie": "SESSID=...; PHPSESSID=...; language=zh_CN"
}
```

也可以通过 `--cookie` 直接传入。未传 `--csrf-token` 时，工具会使用 Cookie 中的 `SESSID` 自动计算 `_cftoken`。

> 注意：`--execute` 会真实修改防火墙黑名单。执行前请先用 dry-run 确认目标和说明。

## SIP Cookie 保活工具

`tools/sangfor_sip_cookie_keepalive.py` 用于维持 Sangfor SIP Cookie 的存活状态。它会按固定间隔向日志查询接口发送轻量查询请求，让服务端持续看到有效会话，同时输出接口状态，便于发现 Cookie 是否已经失效或接口是否返回 `need_login`。

默认每 300 秒请求一次 `/apps/secvisual/log_query2/ksearch_log/check_query_string`，查询条件为 `src_ip:1.1.1.1`。

基础用法：

```bash
python3 tools/sangfor_sip_cookie_keepalive.py --host 172.16.1.118 --insecure
```

指定保活查询语句和请求间隔：

```bash
python3 tools/sangfor_sip_cookie_keepalive.py \
  --host 172.16.1.118 \
  --query "src_ip:117.72.195.41" \
  --interval 60 \
  --insecure
```

当接口提示需要重新登录时退出：

```bash
python3 tools/sangfor_sip_cookie_keepalive.py --stop-on-need-login --insecure
```

Cookie 可以通过 `--cookie` 传入，`xid` 请求头可通过 `--xid` 覆盖。如果接口返回 HTTP 302，工具会认为会话已被重定向并立即退出，不再重试。该工具只发送用于会话保活的查询请求，不会修改防火墙黑名单。

## 测试

运行单元测试：

```bash
python3 -m pytest tests tools/test_sangfor_firewall_blocklist.py
```

也可以单独运行防火墙工具测试：

```bash
PYTHONPATH=tools python3 -m unittest tools/test_sangfor_firewall_blocklist.py
```

## 安全注意事项

- `--ai-analyze` 会调用云端 API，但代码会先在本地脱敏，只发送聚合统计和哈希化标识。
- `ANALYZER_HASH_SALT` 可用于覆盖默认哈希盐值，生产环境建议自行设置。
- 不要将真实 Cookie、API Key、报表原始数据或大体量数据库提交到代码仓库。
- 防火墙工具默认不校验 TLS 证书；如需校验证书，请加 `--verify-tls`。
- 批量封禁前建议先执行不带 `--execute` 的 dry-run。
