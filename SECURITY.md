# 安全策略

## 支持范围

| 版本 | 受支持 | 说明 |
|---|---|---|
| v0.2.0 | 是 | 当前开发中的版本 |
| < v0.2.0 | 否 | 安全修复只针对 v0.2.0 及之后的代码，不提供旧版本回溯修复 |

v0.2.0 尚在开发中，**不应用于生产环境**。安全策略与实现会随版本演进，请以本文件
随附的代码版本为准。

## 报告漏洞

**请不要在公开 Issue、PR 或讨论区披露漏洞。**

请通过本仓库 **Security** 标签页的 **Report a vulnerability** 入口私下报告。

若该入口不可用，请先开一个**不含任何漏洞细节**的 Issue，请求维护者提供私下联系渠道，
再通过该渠道提交细节。

请尽量包含：影响的版本或提交、复现步骤、预期与实际结果、可能的影响范围。
我们通过私下渠道与你沟通，修复发布前请保密。

## 密钥管理

* 仓库内**不含任何密钥、口令或数据库文件**。
* production 环境**必须**通过环境变量提供下列密钥，缺失时进程直接拒绝启动
  （退出码非 0）：

  | 环境变量 | 用途 |
  |---|---|
  | `JWT_PRIVATE_KEY`（或 `JWT_PUBLIC_KEY`） | RS256 会话令牌签名私钥（PEM，换行可写成字面量 `\n`） |
  | `INITIAL_ADMIN_PASSWORD` | 初始管理员口令，至少 8 位 |

* `SECRET_KEY` 与 `PASSWORD_SALT` 在当前实现中**不参与任何签名或加密**
  （JWT 用的是 `JWT_PRIVATE_KEY`；口令哈希用 argon2id，盐由库随机生成并编入哈希串），
  因此它们是**可选**的。设置它们不会增强安全性。
* development / testing 环境缺失必需密钥时会自动生成临时值并打印 warning
  （进程重启后失效）。**不要**把这些临时值用于任何共享环境。

## 已实现的安全措施

| 措施 | 说明 |
|---|---|
| 认证 | 会话以 RS256 签名的 JWT 下发，载荷只含 `session_id` 与会话类型；有效性以服务端会话表为准 |
| 口令存储 | Argon2id（`argon2-cffi`），盐随机生成并编入哈希串；响应永不回显口令或哈希 |
| 账户枚举防护 | 登录失败时"账户不存在"与"口令错误"返回**相同**的文案与状态码；账户不存在时也执行一次等成本的哑哈希校验 |
| RBAC | 权限由 `Role.permissions`（JSONField，格式 `{资源: [动作]}`）承载，资源/动作取值由 `app/auth/permissions.py` 的注册表约束；`is_admin` 账户拥有全部权限 |
| 默认拒绝 | `/api/...` 蓝图组注册了组级请求中间件，**未认证请求一律 401**，授权由各资源自行判定 |
| 字段白名单 | 账户/角色等资源的创建与更新只接受白名单字段；`is_admin`、`verified`、`disabled`、`roles`、`deleted`、`id` 一律丢弃（防 mass-assignment 与越权提权） |
| 口令修改 | 改密后该账户的全部既有认证会话立即失效 |
| SQL 只读分析 | `/api/database/query-plan` 只接受单条 `SELECT`/`WITH`；拒绝多语句、注释、写入/DDL 关键字与有副作用的函数；只发 `EXPLAIN`（SQLite 下是 `EXPLAIN QUERY PLAN`），**不执行**传入的 SQL |
| 上传路径隔离 | 存储文件名完全由服务端生成（uuid + 由 libmagic 探测出的 MIME 推导扩展名），不使用客户端文件名；分类走固定白名单；写入/读取/删除前用 `realpath` 校验路径必须位于上传目录内 |
| 上传内容校验 | 用 libmagic 检测**真实**类型并按白名单放行，不信任扩展名或客户端声明的 Content-Type |
| 上传目录不公开 | 上传目录**不做静态托管**；下载走需要鉴权的 `GET /api/v1/files/<id>/download`，并强制 `Content-Disposition: attachment` 与 `X-Content-Type-Options: nosniff` |
| 错误信息收敛 | 统一错误格式 `{"success": false, "message": ..., "error": "<CODE>"}`；非 DEBUG 环境不返回原始异常文本与堆栈 |
| 生产默认收紧 | production 下 `CORS_ALLOWED_ORIGINS` 默认为空（不允许任何跨域来源）、`ENABLE_API_DOCS` 默认关闭、Session Cookie 带 `Secure` |
| 响应压缩豁免 | 流式响应与已压缩内容不重复压缩 |

## 已知安全限制

以下限制**当前确实存在**，请在评估风险时一并考虑。

* **登录限流（v0.3.0 起）。** 登录接口按**账户**与**来源 IP** 双维度独立计数，
  5 次失败 / 15 分钟触发 429（任一维度超限即拒；成功登录双键清零）。IP 维度默认只信
  socket 直连对端，`X-Forwarded-For` 仅在配置 `TRUSTED_PROXIES` 后按可信代理规则采信
  （该配置暂无环境变量接线，见 v0.3.0 Release Notes 已知限制）。
* **两步验证（2FA）默认关闭。** 由 `REQUIRE_TWO_FACTOR=true` 开启，且是**全局**开关
  （不支持按账户开关）。验证码的投递渠道尚未接入——非 DEBUG 环境下验证码不会出现在
  响应里，相关流程需先接入邮件/短信渠道才能使用。
* **上传大小上限。** 通用文件 10MB、头像 2MB，请求体整体上限 16MB
  （`REQUEST_MAX_SIZE`，v0.3.0 起真实生效；注意 Sanic 25 下超限客户端通常表现为
  连接中断而非收到 413 响应，服务端日志仍记录 413）。
* **SQL 分析接口需要高权限。** 任何持有 `system:database:query` 权限的账户都能提交
  SQL 文本。虽然只发 `EXPLAIN`、不执行语句，但 `EXPLAIN` 本身仍由数据库执行，
  恶意构造的语句可能造成资源消耗（例如超大 `CROSS JOIN` 的计划计算）。
* **验证码/两步验证的投递渠道未接入。** 只能用于本地联调。
* **CSRF 保护（v0.3.0 起默认启用）。** 携带会话 Cookie 且不带 `Authorization` 头的
  写请求校验双提交 token（`X-CSRF-Token` 头 + `csrf_token` Cookie）；AMIS 控制台经
  `requestAdaptor` 自动注入。已知残留：登录/注册端点豁免（无预登录 token，login-CSRF
  在 backlog）。既有底线防护不变：会话 Cookie 为 `HttpOnly` + `SameSite=Lax`，以及 API 使用
  `Authorization` 头而非 Cookie 承载凭据。
* **development 环境的 CORS 默认是 `*`。** production 下默认为空。
* **仓库历史中提交过示例 JWT 私钥、默认管理员口令和一个 SQLite 数据库。**
  这些**均视为已泄露，必须更换**，不得用于任何真实环境。
* **amis 管理界面默认未鉴权即可访问静态页**（页面本身不含数据）。
  数据接口全部需要登录，但生产部署时应确认是否需要额外的访问控制。

## 版本号与依赖

依赖的已知漏洞请以 `pip-audit` / `safety` 的实际扫描结果为准。本文档只陈述
本项目自身的行为，不对第三方依赖的安全状态作保证。
