# 更新日志

本文件格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

v0.2.0 迭代 M1（功能闭环）的变更汇总。v0.2.0 尚未发布。

### Added

**测试**
- 重建测试套件：原 `tests/` 引用了不存在的模块（`app.auth.jwt`、
  `app.models.permission`、`app.models.system_log`），pytest 收集阶段报 6 个
  collection error，测试数为 0。现覆盖：登录成功/失败、全部受保护接口的 401 遍历
  （路由从 `app.router.routes` **动态提取**）、伪造 token 401、权限不足 403、
  管理员全权限、账户 CRUD、角色 CRUD、上传路径穿越、SQL 只读分析、
  production 缺密钥 fail-closed。
- 新增 `requirements-dev.txt` 里的 `httpx`（ASGI 测试客户端）与 `requests`（冒烟脚本）。

**权限模型**
- 新增 `app/auth/permissions.py`：资源与动作的注册表，以及权限串的归一化规则。
  解决 `system` 与 `system:database` 并存、以及 `system:database:connectionpool`
  读写拆分后 resource 不一致导致授权无法覆盖的问题。权限由 `Role.permissions`
  （JSONField）承载，**不引入**独立的 Permission 数据表。

**管理界面（AMIS）**
- AMIS 页面菜单对齐真实 API：仪表盘 → 账户列表 → 角色列表 → 操作日志 → 系统设置，
  分别接 `/api/v1/dashboard/summary`、`/api/v1/accounts`、`/api/v1/roles`、
  `/api/v1/logs`、`/api/v1/settings`。
- 新增 `amis/pages/account-list.json`、`role-list.json`、`log-list.json`、
  `setting-list.json`；重写 `dash_board.json` 与 `site.json`。

**文档**
- 新增 `SECURITY.md`：支持版本、漏洞报告方式、已实现的安全措施、**已知安全限制**
  （无登录限流、2FA 默认关闭且无投递渠道、上传 10MB/头像 2MB 上限、SQL 分析需高权限
  且 `EXPLAIN` 仍由数据库执行、CSRF 装饰器未挂载等）。

### Changed

**安全基线**
- `/api/...` 蓝图组新增组级请求中间件：**默认拒绝**未认证请求（401），
  OPTIONS 预检放行。授权仍由各资源自己判定。
- 移除 `/uploads` 静态挂载：上传目录不再对外公开，下载统一走需要鉴权的
  `GET /api/v1/files/<id>/download`（强制 `Content-Disposition: attachment`
  与 `X-Content-Type-Options: nosniff`）。
- 错误响应统一为 `{"success": false, "message": ..., "error": "<CODE>"}`；
  非 DEBUG 环境不再返回原始异常文本与堆栈。
- 账户/角色/个人资料/操作日志四个资源重写为 `HTTPMethodView` + `APIResponse`：
  创建与更新走**字段白名单**（`is_admin`、`verified`、`disabled`、`roles`、
  `deleted`、`id` 一律丢弃），消除 mass-assignment 与越权提权；
  口令用 Argon2id 哈希后落库，响应不含口令或哈希；
  非 admin 不能改/删 admin 账户，不能授予超出自身权限的角色；
  删除改为软删除，列表默认过滤已删除记录。
- 上传：存储文件名完全由服务端生成（uuid + 由 libmagic 探测出的 MIME 推导扩展名），
  不使用客户端文件名；分类走固定白名单；写入/读取/删除前用 `realpath` 校验路径
  必须位于上传目录内；按**真实** MIME 类型做白名单校验。
- 集中修复 9 组重名路由（同一视图注册到多个 URL 时路由名重复，导致 Sanic 23.6
  启动即抛 `ServerError`）。
- SQL 查询分析只接受单条 `SELECT`/`WITH`：拒绝多语句、注释、写入/DDL 关键字与
  有副作用的函数；只发 `EXPLAIN`（SQLite 下 `EXPLAIN QUERY PLAN`），不执行语句。
- 设置项写入走键白名单（`ALLOWED_SETTING_KEYS`），并按 `value_type` 校验取值。

**配置**
- `MAIL_USE_TLS` 改用宽松布尔解析：真值 `1/true/yes/on`（大小写不敏感）。
  **Breaking**：旧实现只把字符串 `"True"` 当作真；新实现无法识别的值
  （例如 `"True"` 之外的大小写变体、或任意其他字符串）会抛 `ConfigError`
  **导致启动失败**，而不是静默当作假。
- `SECRET_KEY` 与 `PASSWORD_SALT` 降为**可选**：当前实现中它们不参与任何签名或
  加密（JWT 用 `JWT_PRIVATE_KEY`，口令哈希的盐由 argon2 自行生成），
  不再作为 production 启动的必需项。production 缺 `JWT_PRIVATE_KEY` 或
  `INITIAL_ADMIN_PASSWORD` 仍然拒绝启动（退出码非 0）。
- 新增 `ENABLE_API_DOCS`（API 文档路由开关，production 默认关闭）与
  `REQUIRE_TWO_FACTOR`（全局两步验证开关，默认关闭）。
- 初始管理员口令显式提供时长度不足 8 位直接报错。

**缓存与压缩**
- 路由缓存装饰器兼容视图方法；响应压缩配置不再重复注册中间件，流式响应与
  已压缩内容不重复压缩。

### Removed

- 删除 `tests/` 下引用不存在模块的旧测试文件（`test_auth.py`、
  `test_account_api.py`、`test_cache.py`、`test_db_optimizer.py`、
  `test_integration.py`、`test_performance.py`、`test_docs/`、`utils/`、
  `generate_coverage_report.py`）。
- 删除 `app/api/example.py`、`app/api/routes.py`。
- 删除 `app/models/permission.py` 的引用（该模型**不存在**，也不需要：
  权限由 `Role.permissions` 承载）。
- 删除 AMIS 自带的演示页（依赖并不存在的 mock 接口，点开必然报错）：
  `pages/console.json`、`pages/login.json`、`pages/crud-list.json`、
  `pages/crud-new.json`、`pages/crud-view.json`、`pages/crud-edit.json`、
  `pages/crud-advance.json`、`pages/editor.json`、`pages/form-basic.json`、
  `pages/wizard.json`、`pages/jsonp.js`。
- 移除 `amis/login_form.html`（依赖不存在的 `base_login.html`）。

### Fixed

- 修复 `app/api/resources/__init__.py` 里对已删除的
  `FileDownloadCounterMiddleware` 的死引用（`import app` 直接 ImportError，
  应用无法启动）。
- 修复同一视图注册到多个 URL 时的重名路由导致 Sanic 启动失败的问题。
- 修复 `validate_request` 把 `request.validated_data` 赋到 `Request` 实例上
  必然抛 `AttributeError` 的问题（Sanic 的 `Request` 使用 `__slots__`）。
- 修复账户/角色等资源序列化 `datetime` 失败导致的 500。
- 修复角色成员列表对已物化 list 调用 `await ...count()` 导致的 500。

### Notes

- AMIS SDK 版本较老（3.31.0），本版本不升级 SDK，只做页面对接。
- `amis/server.js`（零依赖 Node 开发服务器）保留，用于后端尚未集成静态托管时
  本地预览；M1 起后端直接托管 AMIS，浏览器同源访问，不需要它参与运行。
