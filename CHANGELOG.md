# 更新日志

本文件格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

<!-- 下一版变更写在这里。 -->

## [0.3.4] — 2026-10-24

鉴权加固版本（SA-v034-L1）。新增认证审计日志、改密限速、口令强度校验与会话轮换。
**含一处 breaking**：改密后当前会话一并作废并轮换；初始口令强度不足时 production 拒绝启动。

### Changed

- **改密成功后不再保留当前会话。** `POST /auth/change-password` 过去只作废其它
  会话、保留发起改密的那个；现在**一并作废**，并轮换签发新会话（响应新增
  `token_rotated: true`，通过 `Set-Cookie` 与 `Authorization` 头下发）。
  浏览器 cookie 客户端无需改动；**自己管理 token 的客户端必须改用响应里新下发的
  `Authorization`**，否则下一次请求 401。

### Security

- **认证路径开始写入操作日志。** 登录成功/失败、登出、改密（成功/失败/2FA 未完成）、
  2FA 成功/失败均记入 `OperationLog`（`operation_type="auth"`）。此前
  `OperationLog` 的模型、只读 API 与仪表盘统计都存在，但**没有任何写入点**。
  审计不含口令、token 与验证码。
- **改密的当前口令试错限速**：复用登录限流器，账户维度独立计数，窗口内达阈值 429。
- **新口令强度**：除长度外要求至少两类字符，且不得为 `SAdmin@123`、当前
  `INITIAL_ADMIN_PASSWORD` 的值，或与本人邮箱相同（**拒绝清单与邮箱比较均不区分大小写**，
  `sAdmin@123` 等大小写变体同样被拒）。
  校验收敛到 `Account.set_password`，所有口令入口统一经过它。
- **口令规则覆盖所有写入路径**（**breaking**）：注册、管理员创建账户、管理员重置口令
  原先不受新规则约束，现在同样受强度校验与拒绝清单约束——比如注册时用 `SAdmin@123`
  会被拒。原因同上：校验在 `Account.set_password` 里，而不是某一个端点里。
- **初始口令也要求强度**（**breaking**）：`INITIAL_ADMIN_PASSWORD` 若少于两类字符
  或超过 128 位，**production 启动即报 `ConfigError`**；development/testing 只打 warning。
  升级到 v0.3.4 前请确认该值足够强。
  注意：启动时只做**强度检查**，不走拒绝清单——`SAdmin@123` 在 production 下仍能启动，
  但它不能被**改密**成这个值，建议设成独立的口令。

### Known behaviour

- **并发改密会互相踢下线。** 改密成功会作废该账户的其它会话，因此两个会话同时改同一
  账户的口令时，各自都会作废对方；只有最后完成的那次保留有效会话。这是「作废所有会话」
  的预期结果，不是需要绕开的竞态——不要让两个客户端同时改同一账户的口令。

## [0.3.3] — 2026-10-24

v0.3.2 的热修版本。修复控制台角色弹窗无法渲染的回归，并修复从未真正生效的浏览器 E2E 门禁脚本。无 API、配置或部署变更。

### Fixed

- **AMIS 角色表单的校验写法导致弹窗打不开（v0.3.2 回归）。** v0.3.2 把两处
  `permissions` 文本域的 `validations.isJson` 改成了字符串形式的 `validate`，
  而 AMIS 3.4.0 对 `$schema.validate` 直接执行 `validate.bind(...)`，字符串没有
  `bind` 方法 —— 新增/编辑对话框在 `componentDidMount` 抛
  `TypeError: i.bind is not a function`，弹窗根本不渲染。已改回
  `validations.isJson` + `validationErrors.isJson`（3.4.0 与 6.13.0 均支持）。
  该缺陷会让「控制台建/改角色」完全不可用，pytest 覆盖不到（AMIS 页面不在
  API 测试范围）。
- **AMIS E2E 门禁脚本（`scripts/amis_e2e_check.py`）从未真正跑绿。** 修正四处
  脚本缺陷：密码字段选择器 `password` → `pass`；弹窗选择器 `.amis-dialog` →
  `.amis-dialog-widget`；清理断言 `_cleanup_role(...) is None or True` 恒真
  （改为 cookie 会话清理 + 删除后重新查询核验）；编辑用例提交的
  `{"account": ["write"]}` 中 `write` 不是注册表里的合法动作（应为 `update`）。
  另修正三处会静默放宽门禁的写法：`--admin-password` 为 `must_change_password=True`
  的账户时脚本会停住（新增 `--new-password` 走完强制改密）；amis 空表仍渲染占位行
  使 `tbody tr > 0` 恒真（改为排除空态行并核对探针数据）；断言总数被钉在 19，
  少一条即报错。

### Added

- **AMIS E2E 正向对照。** `--negative-control {dialog,login_password}` 故意把选择器
  改错，要求对应断言**必须**失败；断言仍通过说明它是恒真的，脚本以退出码 1 报警。
- **CI 新增 `amis-e2e` 门禁**：`amis-e2e-probe` 先探测浏览器可用性并输出 `available`，
  `amis-e2e` job 用 `if` 依赖该输出。浏览器可用时：起服务（固定端口 22222、临时
  SQLite、一次性口令）→ 跑 19 项 E2E → 跑正向对照；**不可用时整个 job 显示为
  `skipped`**，不会被记成绿色通过。
- **CI 触发白名单加入 `release/**`**：补丁版从 `release/` 分支拉 hotfix 分支，原先
  `push` / `pull_request` 只列了 `main, master, develop, vj-mp3`，发补丁版的 PR 根本
  不会触发 CI。`ci.yml` 与 `docker.yml` 两份 workflow 都已加入（前者跑测试与 E2E，
  后者跑容器验收）——`docker.yml` 原本只盯 `master` 与 `v*` tag，不加这条时 docker
  验收要等到打 tag 才跑，那时再发现失败回滚成本更高。仅改 workflow 配置，不动运行时。
- **仪表盘断言改为比对真实数值**：原先只要求「有标题的卡片存在」，现在读取卡片实际
  渲染的数字，与 `/api/v1/dashboard/summary` 返回的 `data.accounts.total` 比对
  （同一会话、同源，两个数才真正可比）。已做双向验证：破坏 `.cxd-Card-fieldValue`
  选择器会让它失败；把页面模板改成 `${accounts.totalTYPO}` 后页面回落到 0、API 仍
  返回 1，该断言失败而其余 18 条通过。

## [0.3.2] — 2026-10-24

鉴权收尾版本。新增首登强制改密，修复 2FA 登录 500 与 AMIS 角色表单校验；**存量库需手工跑一次迁移脚本**（见下）。

**API 契约变更**：登录与 `/auth/validate-2fa` 响应新增 `must_change_password` 布尔字段；新增错误码 `PASSWORD_CHANGE_REQUIRED`（HTTP 403，改密未完成时返回）。请求体与路径未变。

### Added

- **首次登录强制改密。** 由 `INITIAL_ADMIN_PASSWORD` 创建的初始管理员携带
  `must_change_password=True`；改密前该会话访问 `/api/**` 一律返回
  **403 `PASSWORD_CHANGE_REQUIRED`**（仅登录/登出/改密端点、AMIS 控制台、健康检查
  与 API 文档放行）。新增 `POST /auth/change-password`
  （`current_password` / `new_password` / `confirm_password`），改密成功后作废该账户
  的其它会话。AMIS 登录页在响应带该标志时显示改密对话框。
- 中间件顺序显式化：强制改密检查为应用级中间件并设置显式 priority，保证先于
  `/api` 蓝图鉴权执行（测试钉住顺序）。

### Fixed

- **开启 `REQUIRE_TWO_FACTOR` 时登录返回 500**：登录响应在加标志时把字符串当映射用。
  2FA 分支改为返回 `{"code": …, "must_change_password": …}`，`/auth/validate-2fa`
  同样透出该标志。
- **2FA 未完成的会话无法完成二次验证**：`/auth/validate-2fa` 加入强制改密白名单；
  `/auth/change-password` 反过来要求二次验证已完成（否则 403）。
- **AMIS 角色表单的 `permissions` 被后端拒绝（400）**：表单按字符串原文提交而后端要求
  对象。两表单改为提交前解析 JSON、校验解析结果为对象、字段必填，编辑时把存储的对象
  回填为缩进 JSON。

### Migration — 存量库必读

> **破坏性提示：** 升级并完成迁移后，口令仍是 `INITIAL_ADMIN_PASSWORD` 或历史默认
> `SAdmin@123` 的管理员，访问 `/api/**` 会返回 **403 `PASSWORD_CHANGE_REQUIRED`**，
> 必须先调用 `POST /auth/change-password` 改密（或用控制台的改密对话框）。

项目尚未引入迁移框架，`generate_schemas` 不会给已有表加列。**v0.3.1 及更早版本升级
必须手工执行一次**：

```bash
export SANIC_ENV=production            # 或用 DB_URL 指定
export INITIAL_ADMIN_PASSWORD='...'    # 当前在用的口令
python scripts/migrate_v0_3_2_must_change_password.py
```

脚本补 `account.must_change_password` 列，并把**未禁用的管理员**中口令仍等于当前
`INITIAL_ADMIN_PASSWORD` 或历史硬编码默认口令 `SAdmin@123` 的账户置为强制改密。
支持 SQLite / MySQL（生产默认）/ PostgreSQL，不打印任何口令；幂等可重复执行。
管理员邮箱已改过（有管理员但无 `INITIAL_ADMIN_EMAIL` 账户）时警告并跳过创建，
需强制创建时加 `--create-initial-admin`。全新安装无需迁移。

### Known limitations

- **aerich 迁移链推迟到 v0.4 M1**：审核发现其基线只在 SQLite 上可跑，生产用的 MySQL
  跑不了，因此 v0.3.2 仍用手写迁移脚本。
- v0.3.1 的已知限制全部继续有效：登录端点豁免 CSRF、`TRUSTED_PROXIES` 暂无环境变量
  接线、Sanic 25 下非 GET 的 405 `Allow` 头仍列 `HEAD`。

## [0.2.1] — 2026-10-22

v0.2.0 的维护补丁版本，不含新功能。除下列修复外，公开 API、配置契约与部署路径均未变化。
完整的改动说明与实测证据见 [v0.2.1 发布说明](docs/release/v0.2.1-release-notes.md)。

测试规模：**95 → 171 例**（新增 4 个测试文件）。路由表实测 **116 条路由 / 77 个不同 path**，
OpenAPI 规范内 **68 条 path**。

### Fixed

**API 文档**
- OpenAPI 规范不再收进 405 兜底路由的方法。此前 `/api/v1/logs` 在规范里显示
  `delete/get/patch/post/put`，而该路径实际只支持 `GET`；`/api/v1/roles` 等 39 个路径
  同样被塞入了不存在的方法。修复后规范只列出真实支持的方法
  （`/api/v1/logs` 只剩 `get`，`/api/v1/settings` 保留真实的 `get` 与 `post`）。
  该缺陷在 v0.2.0 中同样存在（当时影响 14 个路径），不是 v0.2.1 引入的；
  v0.2.1 把兜底覆盖面扩到 39 个路径，因此一并修掉。
  兜底路由本身仍在路由表中（116 条里的 39 条），只是不再写进规范。

**AMIS 静态挂载**（以下三项是 v0.2.1 引入的回归，v0.2.0 整目录托管时不存在）
- AMIS 的 `public/` 子目录未挂载，导致仪表盘 logo 加载 404、显示为破图
  （`amis/index.html` 引用 `public/logo.png`）。改为枚举磁盘上实际存在的子目录逐个挂载，
  不再使用硬编码清单，避免将来新增资源目录时再次漏挂。
- AMIS 与 `/static` 的裸目录路径（如 `/amis/css/`）由 404 变成 500 ——
  Sanic 23.6 的 `DirectoryHandler` 会抛未捕获的 `IsADirectoryError`，
  等于开了一个无需鉴权即可外部触发的 500 面。改用返回 404 的目录处理器。
- 裸 `/amis` 由 404 变成 200 —— 入口页原用 `app.static("/amis/", login.html)` 挂载，
  而 Sanic 会去掉 uri 尾部斜杠再注册，加上全局 `strict_slashes=False` 使
  `/amis` 与 `/amis/` 等价，裸路径因此命中静态路由。改用 `strict_slashes=True` 的
  普通路由精确控制：`/amis/` 返回登录页，`/amis/<path>` 提供文件，裸 `/amis` 不匹配
  任何路由、返回 404（与 v0.2.0 一致）。这是 `docker-acceptance` 报红的根因。
  AMIS 的四个开发文件（`server.js`、`package.json`、`nodemon.json`、`README.md`）仍为 404，
  12 种路径穿越与编码绕过变体也全部 404。

**系统设置接口**
- `category: null` 触发 500（`category` 在模型里不允许 null，未捕获的校验异常）。
- `value: null` 被落库成字面量 `"None"`，读回来又是一个「合法」的配置值 ——
  此前 `value_type: string` 分支完全缺失，null 穿过校验后被 `str()` 化。
  现所有 `value_type` 一律拒绝 null，并补上 string 分支
  （此前 JSON 对象也能当 string 存入，被存成 `"{'a': 1}"`）。
- `is_public` 的 400 文案已列出全部可接受取值（`true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off`，
  大小写不敏感），此前只写了 `'true'/'false'`。

### Changed

- 分页参数集中到 `parse_pagination`：`page` 超出数据库整数范围时钳制到上限并返回 200，
  不再 500。
- 方法不匹配一律返回 405 并带 `Allow` 头（`log`、`cache`、`dashboard` 等资源也一并接入
  `register_view`）；405 兜底路由覆盖 39 个路径。
- **Docker 构建支持换 pip 源**：`docker-compose.yml` 的 build 段新增
  `args.PIP_INDEX_URL`。受限网络（无法直连 pypi.org）时在 `.env` 里设
  `PIP_INDEX_URL` 指向可用镜像源即可，`docker compose up -d --build` 照常执行，
  无需手工加 `--build-arg`。不设时仍用官方源 `https://pypi.org/simple`，默认行为不变。

### Notes

- AMIS 改用枚举子目录挂载的代价：**将来新增的开发子目录会被自动公开**。
  v0.3 需要补黑名单，或改回显式白名单。
- 设置项 `value` 仍无业务长度上限（框架实际上限为 100MB），且 `MAX_CONTENT_LENGTH`
  配置项在 Sanic 23.6 下不被读取；两项留到 v0.3。

## [0.2.0] — 2026-10-22

v0.2.0 迭代 M1（功能闭环）的变更汇总。

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
