# 两段式运行手册（导出与封锁解耦）

## 为什么要拆

这台环境的防火墙会话是**硬性 TTL**（2026-09-11 实测：18:39:04 登录写入会话，90 秒一次的心跳一直 200，
到 18:52:07 仍直接 302 → login.php），即**活动不会延长会话**，寿命约 10–12 分钟。

而 SIP 日志导出（7 天窗口、8 万行）要 **约 14 分钟**。所以一步式 `full --apply` 必然在跑到
`block --apply` 时会话已失效，被守卫拦下：

```
[ERROR] full pipeline_failed: apply requires a healthy firewall session (status 302, login_page=True)
```

结论：**长导出**与**防火墙动作**必须分两次执行，第二次在刷新会话后的几分钟窗口内跑完。

## 三段式操作

```bash
cd /home/user/projects/sangfor-security-automation
export PLAYWRIGHT_BROWSERS_PATH=.playwright-browsers

# 1) 长导出（不需要防火墙会话，~14 分钟）。记住输出的 Run ID。
.venv/bin/python -m pipeline.run_pipeline export-logs \
    --start "2026-08-28 17:30:00" --end "2026-09-05 17:30:00"

# 2) 刷新防火墙会话（交互登录；GPG 凭据无法非交互解密，需人工）
.venv/bin/python -m pipeline.run_pipeline login --target firewall

# 3) 立刻（几分钟内）跑完防火墙相关阶段：黑名单导出 → 分析 → 封禁 → 日报
.venv/bin/python -m pipeline.run_pipeline --run-id <上一步的 Run ID> firewall-phase --apply
```

第 3 步不加 `--apply` 就只做 dry-run；`--xlsx` 可显式指定复用的导出文件。
不传 `--run-id` 也可以：会在新 run 里复用**其他 run 的最新导出**（run 日志里记 `export_reused` WARNING）。

`full` 依然可用：它跑完导出/分析后若发现会话已失效，会明确报「需要刷新会话」并停在守卫处 —— 
此时导出数据已经落盘，直接执行第 2、3 步即可，**不必重新导出**。

## 每个阶段都能单独执行

| 命令 | 说明 |
|---|---|
| `check-sessions` | 校验 SIP/防火墙会话健康 |
| `export-logs --start --end` | 导出 SIP 日志并合并为分析输入 |
| `export-firewall-blacklist` | 导出防火墙现有黑名单（需会话） |
| `analyze [--xlsx --blacklist]` | 本地分析，产出 `blocklist_recommendations.normalized.csv` |
| `block [--recommendations --apply]` | 选择目标并（可选）下发封禁（`--apply` 需会话） |
| `unblock --targets <file> [--apply]` | 解除封禁 |
| `firewall-phase [--apply] [--xlsx]` | 上面「防火墙三连」的封装：黑名单导出 → 分析 → 封禁 → 日报 |
| `report [--run-id]` | 只读打印某个 run 的摘要 |

`--run-id <id>` 用于在同一 run 内续跑：manifest 会**保留**既有阶段记录（`export-logs`、
`export-firewall-blacklist`、`analyze` 等），因此 apply 守卫能通过；若误用会清空记录，
`--run-id <id> block --apply` 会报 `apply requires completed same-run export-logs`。

## apply 守卫规则

`block --apply` 会校验（任一条不满足即拒绝，不会下发任何封禁）：

1. SIP 会话与防火墙会话都健康；
2. 同 run 的 `export-firewall-blacklist`、`analyze` 阶段为 completed；
3. 同 run 的 `export-logs` 阶段为 completed **或** 本 run 的 `analyze` 已在 manifest 里记录所用
   导出的 `inputs.sip_xlsx.sha256`（即 `firewall-phase` 复用其他 run 导出的场景，数据来源可追溯）；
4. 推荐清单必须是本 run 的 `analysis/blocklist_recommendations.normalized.csv`。

## 定时任务

`scheduled` 走的是同一条 `full` 逻辑，因此同样受会话 TTL 限制。若需要无人值守，
建议拆成一个「导出」定时任务 + 一个「刷新会话后 firewall-phase」的定时任务，
或在定时任务前用可自动化的会话刷新方式（当前 GPG 凭据无法非交互解密）。
