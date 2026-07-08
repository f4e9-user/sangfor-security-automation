# 流程评估

## 结论

整体流程合理，建议按“登录态维护”和“业务动作”分层实现：

- 登录态维护只负责生成/保持 session，不做导出、分析、封禁。
- 业务动作脚本只读取 session 和输入文件，输出明确 artifact。
- 封禁动作必须先 dry-run，再执行，避免误封。

## 你设计的流程逐项评估

### 1. 登录

合理。

密码不进聊天，由你在本地终端登录，这是正确边界。登录脚本只输出 session 文件。

当前文件：

```text
situation-awareness/sangfor_login_session.py
firewall/sangfor_firewall_login_session.py
```

### 2. 态势感知和防火墙自动维持登录

方向合理，但两边方式不同。

态势感知：

- 当前可通过 cookie + xid 执行导出。
- 维持脚本还没放上来，后续应该确认它是刷新会话还是重新生成 session。

防火墙：

- 已实测纯 cookie 方式 20 分钟有效，之后会掉。
- 所以防火墙保活应使用同一个 Playwright browser context，每 5 分钟访问 `/framework.php`。
- 脚本掉回 `login.php` 或出现登录输入框时退出并提示。

### 3. 读取态势感知 session.json 导出日志

合理，而且已经有基础脚本。

当前文件：

```text
situation-awareness/sangfor_log_export.py
```

关键规则：

- session 需要 `cookie` 和 `xid`。
- 文件名按 `sangfor-sip-report-KsearchLog-YYYYMMDDNN.xlsx`。
- 分片尽量接近每份 10000 条。

### 4. 读取防火墙 session.json 导出黑名单 CSV

合理，但脚本还缺。

注意点：

- 防火墙没有 xid，不要强行要求 xid。
- session 里应包含 cookie 和 csrf 派生值。
- API 可能要用：

```text
_cftoken = md5(md5(md5(SESSID)))
gcs_csrf = md5(x-anti-csrf-gcs)
```

需要先抓浏览器请求，确认黑名单导出接口和参数。

### 5. 分析日志，指定黑名单 CSV，输出恶意 IP

合理，但要定义输出 schema。

建议输出 CSV 至少包含：

```text
ip,reason,evidence_count,first_seen,last_seen,already_blacklisted,confidence,source_file
```

这样后续封禁脚本能判断哪些是新增、哪些已在黑名单。

### 6. 封禁 IP

合理，但这是高风险动作，必须加保护。

建议强制两阶段：

1. dry-run 输出计划：新增 IP、已存在 IP、非法 IP、私网 IP、白名单 IP。
2. 用户确认后执行封禁。

封禁脚本必须记录 manifest：

```text
target_object/action/result/request_id/time
```

## 当前还缺的关键件

1. 态势感知维持登录脚本。
2. 防火墙黑名单导出 CSV 脚本。
3. 日志分析脚本。
4. 防火墙封禁 IP 脚本。
5. 一个总控脚本或 README 命令，把各阶段串起来。

## 推荐下一步

先补防火墙黑名单导出脚本，因为它决定后续分析脚本的输入格式；再补封禁脚本的 dry-run 模式。不要一开始就写总控脚本，否则接口还没稳定，后面会反复改。
