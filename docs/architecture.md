# Sanic-Admin 架构文档

> 适用范围：Sanic-Admin 后端（Sanic 23.6 + Tortoise ORM 0.20 + Redis + PyJWT），前端 AMIS 低代码框架。
> 基线：`sa-oss/m23-doc` 分支，base `9a8f946`。
> 事实来源：逐文件阅读 `app/` 源码 + 在临时虚拟环境中实际启动应用、抓取路由表与响应头。
> 标注约定：
> - **【读码确认】** = 源码可查证，且多数经过运行时实测。
> - **> 待 M1 交付后核实** = 当前基线尚未具备该能力，只描述现状，不做前瞻承诺。

---

## 1. 架构总览

### 1.1 分层图

```mermaid
graph TD
    Client[浏览器 / AMIS / curl]

    subgraph Sanic["Sanic 23.6 应用进程"]
        subgraph MW["中间件链 app/middleware"]
            MW1["注册1 响应: CORS 头<br/>security_middleware.py:20-35"]
            MW2["注册2 请求: OPTIONS 预检短路<br/>security_middleware.py:37-41"]
            MW3["注册3 请求: 日志<br/>app/middleware/__init__.py:24-27"]
            MW4["注册4 响应: 耗时日志<br/>app/middleware/__init__.py:29-33"]
            MW5["注册5 请求: 认证中间件<br/>auth_middleware.py:41-45"]
            MW6["注册6 请求: 文件下载计数<br/>api/resources/upload.py:279-312"]
            MW7["注册7 响应: gzip 压缩<br/>compression.py:180-209"]
            MW8["异常处理 (非中间件)<br/>error_handler.py:19-40"]
        end

        subgraph BP["蓝图层"]
            B1[auth_bp /capt_bp<br/>/auth/* /capt/*<br/>app/auth/routes.py]
            B2[v1_bp<br/>/api/v1/*<br/>app/api/resources/*]
            B3[database_bp / compression_bp<br/>/api/database/* /api/compression/*]
            B4[静态文件 /static /uploads<br/>app/__init__.py:71-74]
        end

        subgraph SVC["服务层 app/services + app/auth"]
            S1[认证 authentication.py<br/>登录/注册/会话校验]
            S2[授权 authorization.py<br/>RBAC 权限判定]
            S3[验证 verification.py<br/>验证码/两步/令牌]
            S4[工具 utils.py + 异常 exceptions.py]
        end

        subgraph CACHE["缓存层 app/cache"]
            C1[cache.get_cache<br/>按 CACHE_TYPE 单例]
            C2[MemoryCache]
            C3[RedisCache]
        end

        subgraph ORM["ORM 层 app/models"]
            O1[Account / Role / Profile]
            O2[Session 家族<br/>Authentication / TwoStep / Captcha]
            O3[OperationLog / SystemSetting / UploadedFile]
            O4[BaseModel 公共字段]
        end
    end

    DB[(数据库<br/>SQLite / MySQL / PostgreSQL)]
    REDIS[(Redis)]
    MAIL[SMTP 服务器<br/>尚未接线]
    FS[本地文件系统<br/>uploads/ 目录]

    Client --> MW
    MW --> BP
    BP --> SVC
    SVC --> ORM
    SVC --> CACHE
    ORM --> DB
    CACHE --> REDIS
    CACHE -.内存实现.-> C2
    SVC -.预留.-> MAIL
    BP --> FS
```

**【读码确认】** 关键点：

- **中间件的实际注册顺序**（`app/middleware/__init__.py:36-58` 的 `register_all_middlewares`）：
  1. `setup_error_handlers(app)`（`:43`）——注册异常处理器，不是中间件
  2. `setup_security_middleware(app)`（`:44`）——注册 **CORS 响应中间件** + **OPTIONS 请求中间件**
  3. `_setup_request_logging(app)`（`:45`）——注册 **请求日志** + **响应日志**中间件
  4. `AuthMiddleware()`（`:46`）——注册认证请求中间件
  5. `FileDownloadCounterMiddleware()`（`:49-56`）——注册文件下载计数请求中间件，**包在 try/except 里**：
     development/testing 失败只 warning 降级，production 失败抛 `ConfigError` 拒绝启动

  随后 `app/__init__.py:76-81` 再注册 gzip 响应压缩中间件（`configure_compression`）。

- **Sanic 的中间件执行顺序**（实测，见 §1.2）：请求中间件按注册顺序执行；
  响应中间件按**注册逆序**执行。

- **压缩与 CORS 的先后**：`configure_compression` 在 `register_all_middlewares` **之后**调用，
  所以压缩中间件后注册 ⇒ 在响应阶段**先于** CORS 执行。
  实测大响应（3 KB）的响应头顺序为 `Content-Encoding: gzip` → `Vary: Accept-Encoding`
  → `Access-Control-Allow-Origin`，两者都正确生效（`compression.py:180-191` 的注释
  明确说明「返回响应对象会使 Sanic 跳过其余响应中间件（如 CORS 头）」，
  所以压缩中间件必须返回 `None` 原地修改响应——代码确实这么做了）。

### 1.2 中间件顺序实测

**【实测】** 用 Sanic 23.6.0 起一个最小应用注册 3 个请求 + 3 个响应中间件：

```
请求中间件: req1 → req2 → req3 → handler      （注册顺序）
响应中间件: resp3 → resp2 → resp1              （注册逆序）
```

Sanic 源码印证：`register_middleware()` 对 REQUEST 用 `append`、对 RESPONSE 用 `appendleft`
插入 deque（`sanic/app.py` 的 `register_middleware`），因此后注册的响应中间件排在队首；
`_run_response_middleware` 按 deque 顺序遍历，**任一中间件返回非 None 的响应就会 break**。

**【实测】** 在本项目真实应用上 dump 两个 deque（`app.request_middleware` / `app.response_middleware`）：

```
REQUEST  执行顺序: 1. handle_preflight  2. log_request  3. AuthMiddleware
RESPONSE 执行顺序: 1. compression_middleware  2. log_response  3. add_cors_headers
```

即：

- **请求阶段**：`OPTIONS 预检短路 → 请求日志 → 认证中间件`（文件下载计数中间件因
  `app.api` 导入失败而降级，当前基线未进入队列，见 §7）。
- **响应阶段**：`gzip 压缩 → 耗时日志 → CORS 头`。
  压缩最早执行、且必须原地修改响应并返回 `None`，
  否则后面的 CORS 头会被跳过（`compression.py:180-191` 注释已说明此约束）。

### 1.3 蓝图层级

**【读码确认】** `app/api/__init__.py:16-38`：

```python
api_bp = Blueprint.group('api', url_prefix='/api')   # :16
v1_bp = Blueprint('v1', url_prefix='/v1')            # :19
api_bp.add_blueprint(v1_bp)                          # :22
# 遍历 app/api/resources/*.py，凡模块有 bp 就加入 api_bp  :25-33
```

最终 URL 前缀为 `/api` + `/v1` = `/api/v1/...`，以及独立的
`/api/database/...`（`app/api/resources/database.py:29`）、
`/api/compression/...`（`app/api/resources/compression.py:26`）。

> **> 待 M1 交付后核实**：当前 `Blueprint.group()` 返回的 `BlueprintGroup` 在 sanic 23.6.0 中
> **没有 `add_blueprint` 方法**（实测 `hasattr(Blueprint.group(...), 'add_blueprint') == False`），
> 因此 `app/api/__init__.py:22` 在 import 期就抛
> `AttributeError: 'BlueprintGroup' object has no attribute 'add_blueprint'`，
> 导致整个 `app.api` 包导入失败、API v1 蓝图整体降级（详见 §7）。
> `sa-oss/m1` 分支已把这里改成 `Blueprint.group(v1_bp, database_bp, compression_bp, url_prefix='/api')`
> 并删除了 `app/api/routes.py`、`app/api/example.py`。**M1 合并后本节需重新核实。**

---

## 2. 模块职责表

### 2.1 `app/` 顶层包

| 模块 | 职责 | 关键文件 | 状态 |
|---|---|---|---|
| `app/__init__.py` | 应用工厂 `create_app(config)`；注册中间件、静态路由、`/health`、蓝图、生命周期监听器 | `app/__init__.py:50-89` | 可用 |
| `app/config.py` | 全部配置项；三套环境；密钥注入与 fail-closed 校验 | `app/config.py` | 可用 |
| `main.py` | 进程入口；捕获 `ConfigError` 并退出 | `main.py:11-27` | 可用 |

### 2.2 `app/api` —— API 资源层

| 模块 | 职责 |
|---|---|
| `app/api/__init__.py` | 蓝图组装配（`api_bp` / `v1_bp`）；自动导入 `resources/` 下所有模块 |
| `app/api/base.py` | `BaseResource`（分页 / 排序 / 搜索 / 过滤的统一处理）与 `CRUDResource`（标准 GET/POST/PUT/PATCH/DELETE） |
| `app/api/responses.py` | `APIResponse` 统一响应封装（`success` / `error` / `list` / `created` / `serialize`）+ `APIError` 错误码常量表 |
| `app/api/validators.py` | 参数校验装饰器：`validate_request` / `validate_path_param`，规则类 `Required` / `Type` / `Length` / `Range` / `Regex` / `Email` / `OneOf` / `Custom` |
| `app/api/resources/` | 12 个业务资源模块（见 §2.3） |
| `app/api/routes.py` | 旧版 API 蓝图（`api_bp` + `register_api_blueprints`）。**当前无任何调用点**，且它 import 的 `account_api` / `role_api` 在资源模块中已不存在 |
| `app/api/example.py` | 文档装饰器用法示例（`example_bp`）。**蓝图未被注册**，纯示例代码 |

`app/api/resources/` 下的资源清单（**【读码确认】** `app/api/resources/__init__.py:32-59` 的
`all_resources` 列表，共 25 个资源类）：

| 文件 | 资源类 | 注册路径（`v1_bp.add_route`） |
|---|---|---|
| `account.py` | `AccountResource` / `AccountPasswordResource` / `AccountMeResource` | `/accounts`、`/accounts/<id>`、`/accounts/<id>/password`、`/accounts/me` |
| `role.py` | `RoleResource` / `RoleMembersResource` / `AccountRolesResource` | `/roles`、`/roles/<id>`、`/roles/<id>/members`、`/accounts/<id>/roles` |
| `profile.py` | `ProfileResource` / `MyProfileResource` | `/profiles/<id>`、`/me/profile` |
| `log.py` | `LogResource` / `LogStatisticsResource` | `/logs`、`/logs/<id>`、`/logs/statistics` |
| `setting.py` | `SettingResource` / `SettingByKeyResource` / `SettingBulkResource` | `/settings`、`/settings/<id>`、`/settings/key/<key>`、`/settings/bulk` |
| `upload.py` | `FileUploadResource` / `AvatarUploadResource` / `FileListResource` / `FileDeleteResource` + `FileDownloadCounterMiddleware` | `/upload`、`/upload/<category>`、`/upload/avatar`、`/files`、`/files/<id>` |
| `dashboard.py` | `DashboardSummaryResource` / `DashboardActivitiesResource` / `DashboardStorageResource` | `/dashboard/summary`、`/dashboard/activities`、`/dashboard/storage` |
| `dashboard_user.py` | `UserActivityResource` / `FeatureUsageResource` / `PermissionAnalysisResource` | `/dashboard/user-activity`、`/dashboard/feature-usage`、`/dashboard/permission-analysis` |
| `dashboard_performance.py` | `PerformanceResource` / `ExceptionsResource` / `AlertsResource` | `/dashboard/performance`、`/dashboard/exceptions`、`/dashboard/alerts` |
| `cache.py` | `CacheResource` / `CacheKeysResource` / `CacheKeyResource` | `/cache`、`/cache/keys`、`/cache/keys/<key>` |
| `database.py` | `QueryLogsResource` / `SlowQueriesResource` / `QueryPlanResource` / `ConnectionPoolResource` / `DatabaseAnalysisResource` | `/api/database/query-logs` 等（独立 `bp`） |
| `compression.py` | `CompressionStatsResource` 等 | `/api/compression/...`（独立 `bp`） |

### 2.3 `app/auth` —— 认证与授权

| 文件 | 职责 |
|---|---|
| `app/auth/__init__.py` | 导出 5 个蓝图与 `register_auth_blueprints()`（**当前无调用点**，`app/__init__.py:146-164` 直接从 `app.auth.routes` 取蓝图） |
| `app/auth/routes.py` | 认证路由：`POST /auth/login`、`/auth/register`、`/auth/verify`、`/auth/validate-2fa`、`/auth/logout`、`/auth/associated`、`/auth/`（续期）；`GET /capt/request`、`/capt/image` |
| `app/auth/authentication.py` | 注册、登录、注销、二次验证；`authenticate_request()`；`requires_authentication` 装饰器 |
| `app/auth/authorization.py` | RBAC：`has_role` / `has_permission` / `get_account_permissions`；`check_roles` / `check_permissions` / `requires_permission` 装饰器 |
| `app/auth/verification.py` | 验证码会话、两步验证会话、一次性验证令牌（激活 / 改密） |

### 2.4 `app/cache` —— 缓存

| 文件 | 职责 |
|---|---|
| `app/cache/__init__.py` | `get_cache()` 工厂；进程内单例；Redis 探测与 production fail-closed 降级策略 |
| `app/cache/base.py` | `CacheBackend` 抽象基类（`get`/`set`/`delete`/`expire`/`ttl`/`keys`/`clear`/`increment`/`get_many`/`set_many`/`delete_many`/`get_stats`/`get_or_set`） |
| `app/cache/memory.py` | `MemoryCache`——字典 + 过期表 + `threading.RLock`，写时深拷贝防外部篡改 |
| `app/cache/redis.py` | `RedisCache`——键前缀隔离、JSON 序列化、pipeline 批量写 |
| `app/cache/decorators.py` | `cached()` 路由响应缓存装饰器（**只缓存 GET**）、`generate_cache_key()`、`clear_route_cache()` |

### 2.5 `app/database` —— 数据库工具

| 文件 | 职责 |
|---|---|
| `app/database/__init__.py` | 统一导出查询优化、连接池、查询分析接口 |
| `app/database/query_optimizer.py` | `optimize_query` / `prefetch_related` / `paginate_optimized` / `batch_fetch` |
| `app/database/connection_pool.py` | 连接池配置（`min_size=5`、`max_size=20`、`connect_timeout=10.0`）、`get_connection_pool`、健康检查任务、`connection_context` 上下文管理器 |
| `app/database/query_analyzer.py` | `log_query` / `get_query_logs` / `get_slow_queries` / `analyze_query_plan` / `validate_readonly_sql`（只读 SQL 校验）+ MySQL / PostgreSQL / SQLite 三套优化建议生成器 |

### 2.6 `app/docs` —— API 文档

| 文件 | 职责 |
|---|---|
| `app/docs/__init__.py` | `setup_docs(app)`：一键挂载 Swagger UI / ReDoc / OpenAPI JSON，并关闭 sanic-ext 自带 OAS |
| `app/docs/openapi.py` | 从已注册路由反射生成 OpenAPI 3.0.3 规范（`_SKIP_PREFIXES` 排除文档与静态资源路由） |
| `app/docs/swagger.py` | Swagger UI / ReDoc HTML 模板（CDN 引 cdnjs.cloudflare.com 与 jsdelivr） |
| `app/docs/routes.py` | `/docs`、`/docs/models`、`/docs/tags`、`/docs/paths`、`/redoc` 路由 |
| `app/docs/models.py` | Pydantic 模型注册与 Schema 生成 |
| `app/docs/decorators.py` | `api_tags` / `api_summary` / `api_description` / `api_body` / `api_response` / `api_response_list` / `api_response_pagination` / `api_param` / `api_paginated_params` / `api_security` / `api_exclude` |

> **> 待 M1 交付后核实**：`setup_docs()` **当前没有任何调用点**（全仓库 grep 只命中定义处），
> 因此 `/swagger`、`/swagger.json`、`/redoc`、`/docs/models` 实测全部 **404**。
> 现在能访问的 `/docs` 是 **sanic-ext 自带**的 OAS 页面（实测 `/docs/openapi.json` 返回 200），
> 不是本模块产出的规范。`sa-oss/m1` 已在 `app/__init__.py` 中加入
> `if app.config.get("ENABLE_API_DOCS"): setup_docs(app)`，并新增 `ENABLE_API_DOCS` 开关
> （production 默认 `False`）。**M1 合并后需重新核实本文档所有 `/swagger` 相关路径。**

### 2.7 `app/middleware` —— 中间件

| 文件 | 职责 |
|---|---|
| `app/middleware/__init__.py` | `register_all_middlewares(app)`——集中注册全部中间件 |
| `app/middleware/error_handler.py` | 三级异常处理：`BaseError`（业务异常，返回 `exception.to_dict()`）→ `SanicException` → 兜底 `Exception`（DEBUG 时附 traceback） |
| `app/middleware/security_middleware.py` | CORS 响应中间件、OPTIONS 预检短路、`csrf_protect()` 装饰器（**当前无路由使用**） |
| `app/middleware/auth_middleware.py` | `AuthMiddleware`——从 `Authorization: Bearer` 或 Cookie 提取令牌，查有效会话并挂到 `request.ctx.authentication_session`；**失败不中断请求** |
| `app/middleware/compression.py` | gzip 响应压缩：阈值 / 可压缩类型 / 排除路径 / 压缩统计 |
| `app/middleware/_headers.py` | `append_vary(headers, value)`——Vary 头合并去重 |

### 2.8 `app/models` —— ORM 模型

全部继承 `app/models/base.py` 的 `BaseModel`（`id` / `created_at` / `updated_at` / `deleted` 软删除标记）。

| 模型 | 表名 | 说明 |
|---|---|---|
| `Account` | `account` | 账户；argon2id 口令哈希；`verified` / `disabled` / `is_admin`；与 `Role` 多对多（中间表 `account_role`） |
| `Role` | `role` | 角色；`permissions` 为 JSON 字段 `{资源: [操作]}` |
| `Session`（抽象） | — | 会话基类；`ip` / `user_agent` / `expires` / `disabled` / `bearer` FK |
| `VerificationSession`（抽象） | — | 验证码会话基类；`code` / `attempts`；原子计数 + 常数时间比较 |
| `AuthenticationSession` | `authentication_session` | 登录会话；`requires_second_factor` / `second_factor_verified` |
| `TwoStepSession` | `two_step_session` | 两步验证会话；Cookie `two_step_session` / 头 `X-Two-Step-Token` |
| `CaptchaSession` | `captcha_session` | 图形验证码会话；Cookie `captcha_session` / 头 `X-Captcha-Token` |
| `VerificationToken` | `verification_tokens` | 一次性令牌（激活 / 改密） |
| `Profile` | `profile` | 与 Account 一对一的个人资料 |
| `SystemSetting` | `system_setting` | 系统参数；值统一存字符串，`value_type` 指明解释方式 |
| `OperationLog` | `operation_log` | 操作日志；账户删除后 `account_id` 置空，保留 `account_name` 快照 |
| `UploadedFile` | `uploaded_file` | 上传文件元信息 + `download_count` |

`app/models/__init__.py` 是**模型注册的唯一入口**——`init_db()` 以本包为 Tortoise 的
`modules={'models': ['app.models']}`，只有出现在包命名空间里的模型才会建表（`:6-9` 注释）。

### 2.9 `app/services` —— 公共设施

| 文件 | 职责 |
|---|---|
| `app/services/utils.py` | `get_ip`（`X-Forwarded-For` → `X-Real-IP` → `request.ip`）、`get_code`（secrets 随机验证码）、`get_request_value`（表单优先于 JSON）、`utcnow` / `ensure_aware` / `get_expiration_date`、统一响应 `json(message, data, status)` |
| `app/services/exceptions.py` | 全部业务异常类型，继承 `BaseError`，携带 `status_code` / `error_code` / `message`；`to_dict()` 直接转 JSON 响应体 |

### 2.10 `app/web` —— Web 页面渲染

| 文件 | 职责 |
|---|---|
| `app/web/routes.py` | `login_bp`（`/login`）与 `index_bp`（`/index`），用 Jinja2 渲染 `frontend/templates/login.html` / `site.html` |
| `app/web/__init__.py` | 仅模块 docstring |

> **> 待 M1 交付后核实**：`register_web_blueprints()` **当前无调用点**，且
> `frontend/templates/` 目录在仓库中**不存在**（Jinja2 `FileSystemLoader('frontend/templates')`
> 会直接失败）。这批 Web 渲染路由在当前基线是**死代码**。
> M1 已把前端主线切到 AMIS 静态页（`amis/index.html`），Web 渲染路线预计会被移除。

---

## 3. 认证流程

### 3.1 登录时序

```mermaid
sequenceDiagram
    autonumber
    participant C as 客户端
    participant A as /auth/login<br/>(app/auth/routes.py:89)
    participant AU as authentication.login<br/>(app/auth/authentication.py:136)
    participant AR as app/models/account.py
    participant M as app/models/session.py
    participant DB as 数据库

    C->>A: POST /auth/login<br/>{email, password}
    A->>AU: login(request, require_second_factor)

    AU->>AR: Account.get_via_email(email)
    alt 账户不存在
        AR-->>AU: NotFoundError
        AU->>AR: verify_dummy_password(password)<br/>等成本哑哈希，防时序枚举
        AU-->>A: CredentialsError(401)
        A-->>C: 401 {"error":"CREDENTIALS_ERROR"}
    end

    AU->>AR: account.verify_password(password)<br/>argon2id 校验
    alt 口令错误
        AR-->>AU: False
        AU-->>A: CredentialsError(401)
    end

    AU->>AR: account.validate()<br/>检查 deleted/verified/disabled
    AR-->>AU: 通过

    AU->>M: AuthenticationSession.create_from_request()<br/>expires_in = 7 天
    M->>DB: INSERT authentication_session

    AU-->>A: AuthenticationSession
    A->>M: session.encode(response)
    Note over M: jwt.encode(payload, BaseConfig.SECRET, RS256)<br/>payload = {session_id, session_type}<br/>Set-Cookie: session=JWT, HttpOnly, SameSite=Lax<br/>Authorization: Bearer JWT
    A-->>C: 200 登录成功 + 会话令牌
```

**【读码确认 + 实测】** 实测 `POST /auth/login` 返回体：

```json
{"status":0,"msg":"登录成功!","data":{"id":1,"email":"SAdmin@Sanic.com","username":"SAdmin",
 "disabled":false,"verified":true,"is_admin":true, ...}}
```

响应头实测（`Set-Cookie` 与 `Authorization` **同时**下发）：

```
Set-Cookie: session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...; Path=/; SameSite=Lax; HttpOnly
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**关键设计**：JWT 的 payload **只有 `session_id` 与 `session_type` 两个字段**
（`app/models/session.py:128-133`），不含账户、角色、权限信息。
所有授权判定都回到服务端查会话表与账户状态完成。

### 3.2 后续请求的鉴权

```mermaid
sequenceDiagram
    autonumber
    participant C as 客户端
    participant MW as AuthMiddleware<br/>(auth_middleware.py:41)
    participant H as 路由处理函数
    participant AU as authenticate_request<br/>(authentication.py:238)
    participant AUZ as authorization<br/>(authorization.py:84)
    participant DB as 数据库

    C->>MW: POST /api/v1/roles<br/>Cookie: session=JWT 或<br/>Authorization: Bearer JWT
    MW->>DB: Session.get_valid_session(token)
    Note over DB: JWT 解签 + 查会话行 + 校验<br/>deleted/disabled/expired + 账户状态
    DB-->>MW: AuthenticationSession 或 None
    MW->>H: request.ctx.authentication_session = session

    H->>AU: authenticate_request(request)
    Note over AU: 已挂载则直接复用；否则重新解码
    AU->>AU: session.bearer.validate()<br/>检查 deleted/verified/disabled
    AU->>AU: require_second_factor 时检查<br/>second_factor_pending

    H->>AUZ: @check_permissions("role", "read")
    AUZ->>DB: account.roles.filter(deleted=False)<br/>合并各角色 permissions
    AUZ->>AUZ: has_permission():<br/>is_admin → True<br/>权限含 "all" → True<br/>否则逐个 action 判定
    alt 权限不足
        AUZ-->>H: InsufficientPermissionsError(403)
    else 通过
        AUZ-->>H: 继续执行
    end
```

**【读码确认，实测】** 两种携带方式都实测通过：

```bash
curl -X POST /auth/associated -H "Cookie: session=<JWT>"      # 200
curl -X POST /auth/associated -H "Authorization: Bearer <JWT>" # 200
```

### 3.3 RBAC 权限模型

**【读码确认】** `app/auth/authorization.py`：

- 权限数据格式：`{资源: [操作, ...]}`；操作含 `"all"` 表示该资源全部权限（`:5-9` 注释）。
- `Account.is_admin == True` 的账户**拥有全部权限**（`:78-79`、`:88-89`），是 RBAC 的短路路径。
- `get_account_permissions()`（`:57-71`）合并账户所有**未删除**角色的权限集合。
- `has_permission(account, resource, *actions)`（`:84-95`）要求**全部**指定 action 都命中。
- 三个装饰器：

| 装饰器 | 位置 | 语义 |
|---|---|---|
| `@check_roles("admin", ...)` | `:107-120` | 拥有指定角色**之一**即可；无角色 → `RoleRequiredError`(403) |
| `@check_permissions("role", "read")` | `:123-153` | 需要 `role` 资源的 `read` 权限；也可作函数调用 `check_permissions(..., request=..., check_only=True)` 返回 bool |
| `@requires_permission("system:database:query")` | `:156-165` | `"资源:操作"` 字符串形式；最后一个冒号之后是操作，之前是资源（如 `system:database` 的 `query`）；不含冒号时按资源的 `all` 判定 |

未认证 → 401（`AuthenticationError`）；已认证但权限不足 → 403（`InsufficientPermissionsError`）。
两者都经 `app/services/exceptions.py` 的 `BaseError.to_dict()` 变成统一 JSON 响应体。

### 3.4 两步验证与验证码

**【读码确认】**

- `VerificationSession.check_code()`（`app/models/session.py:276-294`）用**原子更新**
  `filter(id=..., attempts__lt=5).update(attempts=F("attempts")+1)` 计数，
  并发下计数不丢失也不会超上限；达到上限抛 `RateLimitExceededError`(429)。
  验证码比较用 `secrets.compare_digest`（常数时间）。
- `TwoStepSession` / `CaptchaSession` 各有独立表与独立 Cookie 名
  （`two_step_session` / `captcha_session`），避免互相覆盖。
- 二次验证由服务端配置 `settings.REQUIRE_TWO_FACTOR` 决定，
  **忽略客户端传入的参数**（`app/auth/routes.py:94-95`）。
  当前基线该配置项不存在 → `getattr(..., False)` 恒为 `False` → 二次验证默认关闭。
- **> 待 M1 交付后核实**：M1 已新增 `REQUIRE_TWO_FACTOR` 布尔环境变量
  （`_bool_env()`，接受 `1/true/yes/on` 与 `0/false/no/off/`）。

### 3.5 认证中间件与会话校验的分工

**【读码确认】** 两条并存的路径，职责不同：

| 路径 | 位置 | 行为 |
|---|---|---|
| **中间件** | `app/middleware/auth_middleware.py:14-38` | 尽力而为：从 `Authorization: Bearer` 或 Cookie 取令牌，查有效会话，挂到 `request.ctx.authentication_session`。**失败不抛异常、不中断请求** |
| **装饰器 / 显式调用** | `app/auth/authentication.py:238-269` | 强制校验：无令牌 → `AuthenticationError`(401)；会话/账户不可用 → 抛对应异常；二次验证未完成 → `AuthenticationError` |

**注意一个当前基线的缺陷**：中间件读的是 Cookie `session_id`
（`auth_middleware.py:25`），而会话实际下发的 Cookie 名是 `session`
（`app/models/session.py:66`）。二者对不上，因此**中间件路径在 Cookie 场景下取不到会话**，
只有 `Authorization: Bearer` 路径能命中中间件。
（`sa-oss/m1` 已改为读 `AuthenticationSession.cookie_name`。
**> 待 M1 交付后核实**。）

实际鉴权不依赖中间件——`requires_authentication` / `check_permissions` 都会调用
`authenticate_request()` 自行解码（`authentication.py:252-257`：已挂载则复用，否则重新解码），
所以功能上是正确的，只是中间件的那次尝试在 Cookie 场景下白做了。

---

## 4. 目录结构

```
Sanic-Admin/
├── main.py                       # 进程入口；捕获 ConfigError 后 sys.exit
├── pyproject.toml
├── requirements.txt              # 运行时依赖（sanic 23.6 / tortoise-orm 0.20 / PyJWT / argon2-cffi / cryptography / captcha / redis ...）
├── requirements-dev.txt
├── README.md / README_cn.md / SECURITY.md / CHANGELOG.md / CONTRIBUTING.md
├── upgrade_schema.md
│
├── app/                          # ── 后端应用包 ─────────────────────────
│   ├── __init__.py               # create_app()：中间件 → 静态 → /health → 蓝图 → 监听器
│   ├── config.py                 # ★ 全部配置项与密钥注入、fail-closed 校验
│   │
│   ├── api/                      # ── API 资源层 ───────────────────────────
│   │   ├── __init__.py           # api_bp / v1_bp 蓝图组装配 + 自动导入 resources/
│   │   ├── base.py               # BaseResource / CRUDResource
│   │   ├── responses.py          # APIResponse / APIError
│   │   ├── validators.py         # 参数校验装饰器与规则
│   │   ├── example.py            # 文档装饰器示例（蓝图未注册）
│   │   ├── routes.py             # 旧版 API 蓝图（无调用点）
│   │   └── resources/            # 12 个业务资源模块 + __init__.py
│   │       ├── account.py        #   账户 / 改密 / 当前用户
│   │       ├── role.py           #   角色 / 角色成员 / 账户角色
│   │       ├── profile.py        #   个人资料 / 我的资料
│   │       ├── log.py            #   操作日志 / 日志统计
│   │       ├── setting.py        #   系统设置 / 按键读写 / 批量
│   │       ├── upload.py         #   文件上传 / 头像 / 列表 / 删除 / 下载计数中间件
│   │       ├── dashboard.py      #   概览 / 活动 / 存储
│   │       ├── dashboard_user.py #   用户活动 / 功能使用 / 权限分析
│   │       ├── dashboard_performance.py  # 性能 / 异常 / 告警
│   │       ├── cache.py          #   缓存管理
│   │       ├── database.py       #   查询日志 / 慢查询 / 执行计划 / 连接池 / 分析（独立 bp）
│   │       └── compression.py    #   压缩统计与配置（独立 bp）
│   │
│   ├── auth/                     # ── 认证与授权 ──────────────────────────
│   │   ├── __init__.py           # 蓝图导出 + register_auth_blueprints（无调用点）
│   │   ├── routes.py             # /auth/*、/capt/* 路由
│   │   ├── authentication.py     # 注册 / 登录 / 注销 / 二次验证 / authenticate_request
│   │   ├── authorization.py      # RBAC：has_permission / check_permissions / requires_permission
│   │   └── verification.py       # 验证码 / 两步验证 / 一次性令牌
│   │
│   ├── cache/                    # ── 缓存 ────────────────────────────────
│   │   ├── __init__.py           # get_cache() 工厂 + 单例 + 降级策略
│   │   ├── base.py               # CacheBackend 抽象接口
│   │   ├── memory.py             # MemoryCache
│   │   ├── redis.py              # RedisCache
│   │   └── decorators.py         # cached() / generate_cache_key() / clear_route_cache()
│   │
│   ├── database/                 # ── 数据库工具 ──────────────────────────
│   │   ├── __init__.py
│   │   ├── query_optimizer.py    # optimize_query / paginate_optimized / batch_fetch
│   │   ├── connection_pool.py    # 连接池配置 / 状态 / 健康检查
│   │   └── query_analyzer.py     # 查询日志 / 慢查询 / 执行计划 / 只读 SQL 校验
│   │
│   ├── docs/                     # ── API 文档 ────────────────────────────
│   │   ├── __init__.py           # setup_docs()（当前无调用点）
│   │   ├── openapi.py            # OpenAPI 3.0.3 规范生成
│   │   ├── swagger.py            # Swagger UI / ReDoc HTML
│   │   ├── routes.py             # /docs/*、/redoc
│   │   ├── models.py             # Schema 注册
│   │   └── decorators.py         # api_tags / api_summary / api_body / api_response ...
│   │
│   ├── middleware/               # ── 中间件 ──────────────────────────────
│   │   ├── __init__.py           # register_all_middlewares()：集中注册
│   │   ├── error_handler.py      # 三级异常处理
│   │   ├── security_middleware.py# CORS / OPTIONS / csrf_protect
│   │   ├── auth_middleware.py    # AuthMiddleware
│   │   ├── compression.py        # gzip 响应压缩 + 统计
│   │   └── _headers.py           # append_vary()
│   │
│   ├── models/                   # ── ORM 模型 ────────────────────────────
│   │   ├── __init__.py           # ★ 模型注册唯一入口 + init_db()
│   │   ├── base.py               # BaseModel（id/created_at/updated_at/deleted）
│   │   ├── account.py            # Account（argon2id 口令）
│   │   ├── role.py               # Role（JSON permissions）
│   │   ├── session.py            # Session 家族（JWT RS256 签发与校验）
│   │   ├── verification.py       # VerificationToken
│   │   ├── profile.py            # Profile
│   │   ├── system_setting.py     # SystemSetting
│   │   ├── operation_log.py      # OperationLog
│   │   └── uploaded_file.py      # UploadedFile
│   │
│   ├── services/                 # ── 公共设施 ────────────────────────────
│   │   ├── __init__.py
│   │   ├── utils.py              # get_ip / get_code / get_request_value / utcnow / json
│   │   └── exceptions.py         # ★ 全部业务异常（BaseError 体系）
│   │
│   └── web/                      # ── Web 页面渲染（当前是死代码）────────
│       ├── __init__.py
│       └── routes.py             # login_bp / index_bp（Jinja2）
│
├── amis/                         # ── AMIS 前端主线 ─────────────────────────
│   ├── server.js                 # Express 静态服务器（开发用）
│   ├── package.json / nodemon.json
│   ├── site.html                 # 站点外壳
│   ├── login.html / login_form.html
│   ├── pages/                    # AMIS 页面 JSON（site / crud-* / dash_board / login ...）
│   ├── sdk/                      # AMIS SDK（vendored，含 sdk.js / sdk.css）
│   ├── css/ fonts/ images/ vendor/ js/
│   └── public/                   # logo.png
│
├── frontend/                     # ── Vue 3 前端（实验性）──────────────────
│   ├── package.json / vue.config.js
│   ├── .env.development / .env.production    # VUE_APP_BASE_API=/api
│   ├── public/index.html
│   └── src/
│       ├── main.js / App.vue
│       ├── api/index.js          # axios 封装
│       ├── utils/{auth,request}.js
│       ├── router/index.js       # vue-router
│       ├── store/index.js
│       ├── styles/{index,variables}.scss
│       ├── components/layout/{index,Header,Sidebar}.vue
│       └── views/{login,dashboard}/index.vue
│
├── tests/                        # ── 测试 ────────────────────────────────
│   ├── conftest.py               # app / db / client fixtures
│   ├── utils/{data_generator,helpers}.py
│   ├── test_auth.py / test_account_api.py / test_cache.py
│   ├── test_db_optimizer.py / test_performance.py / test_integration.py
│   ├── test_docs/{test_decorators,test_swagger,test_openapi}.py
│   └── generate_coverage_report.py
│
├── .github/workflows/ci.yml      # ruff（E9,F63,F7,F82）+ pytest --cov=app
├── docs/                         # ★ 本目录：configuration.md / architecture.md
└── SECURITY.md / CODE_OF_CONDUCT.md / CONTRIBUTING.md / LICENSE
```

---

## 5. 扩展指引：新增一个 API 资源

以新增 `app/api/resources/article.py` 为例。**参照现有 `role.py` 的写法**。

### 5.1 步骤

**第 1 步 —— 建模型**（若还没有对应表）。
在 `app/models/article.py` 中继承 `BaseModel`，并**必须**在 `app/models/__init__.py` 中导入，
否则 Tortoise 不会注册该模型（`app/models/__init__.py:6-9` 注释明确说明）。

```python
# app/models/article.py
from tortoise import fields
from app.models.base import BaseModel

class Article(BaseModel):
    title: str = fields.CharField(max_length=255)
    content: str = fields.TextField(null=True)
    status: str = fields.CharField(max_length=16, default="draft")

    class Meta:
        table = "article"

    @property
    def json(self) -> dict:
        return {"id": self.id, "title": self.title,
                "content": self.content, "status": self.status}

    def validate(self) -> None:
        """文章没有额外的状态约束。"""
```

**第 2 步 —— 写资源类**。两种基类可选：

- `CRUDResource`（`app/api/base.py:288`）：自带标准 GET / POST / PUT / PATCH / DELETE，
  通过 `allowed_create_fields` / `required_create_fields` 等类属性声明字段白名单。
- `HTTPMethodView`（Sanic 原生）：完全自己控制，适合非 CRUD 端点。

```python
# app/api/resources/article.py
from sanic.request import Request
from app.api import CRUDResource, APIResponse, v1_bp
from app.models import Article
from app.api.validators import (
    validate_request, validate_path_param,
    Required, Length, Type,
)
from app.auth.authorization import check_permissions
from typing import Dict, Any


class ArticleResource(CRUDResource):
    """文章资源"""
    model_class = Article
    resource_name = "文章"

    default_sort_field = "created_at"
    default_sort_direction = "desc"
    default_page_size = 20

    searchable_fields = ["title"]
    filterable_fields = ["status"]

    allowed_create_fields = ["title", "content", "status"]
    allowed_update_fields = ["content", "status"]
    required_create_fields = ["title"]

    @classmethod
    def format_model(cls, model: Article) -> Dict[str, Any]:
        return {"id": model.id, "title": model.title,
                "content": model.content, "status": model.status,
                "created_at": model.created_at, "updated_at": model.updated_at}

    async def get(self, request: Request, article_id: str = None):
        @validate_path_param("article_id", [Required(), Type(int)])
        @check_permissions("article", "read")
        async def get_article(request, article_id=None):
            return await super(ArticleResource, self).get(request, article_id)
        return await get_article(request, article_id)

    async def post(self, request: Request):
        @validate_request({
            "title": [Required(), Length(min_=1, max_=255)],
            "content": [Length(max_=100000)],
            "status": [Type(str)],
        })
        @check_permissions("article", "create")
        async def create_article(request):
            data = request.validated_data
            article = await Article.create(**data)
            return APIResponse.created(
                data=self.format_model(article),
                message="文章创建成功",
                location=f"/api/v1/articles/{article.id}",
            )
        return await create_article(request)
```

**第 3 步 —— 注册路由**。在模块末尾把资源挂到 `v1_bp`：

```python
article_resource = ArticleResource()
v1_bp.add_route(article_resource.as_view(), "/articles", methods=["GET", "POST"])
v1_bp.add_route(article_resource.as_view(), "/articles/<article_id:int>",
                methods=["GET", "PUT", "DELETE"])
```

**第 4 步 —— 加入资源清单**。在 `app/api/resources/__init__.py` 的 `all_resources`
列表和 `__all__` 中登记新类（该列表被注释标注为「用于配置文档」）。

**第 5 步 —— 加权限**。新资源需要在 `Role.permissions` 里加上对应条目，格式为
`{"article": ["create", "read", "update", "delete"]}`。
内置 `admin` 角色在 `app/auth/authentication.py:120-130` 硬编码了
`users` / `roles` / `settings` 三组权限——新资源需要一并补上，或直接依赖
`Account.is_admin` 短路。

### 5.2 约定要点

| 约定 | 说明 |
|---|---|
| 蓝图 | 资源模块 `from app.api import v1_bp` 取蓝图，路由用 `v1_bp.add_route(...)`（`role.py:608-615` 是范本）。**只有**需要独立前缀（如 `/api/database`）时才自建 `bp` |
| 装饰器顺序 | `@validate_request` / `@validate_path_param` 在外，`@check_permissions` 在内（见 `role.py:97-103`、`:155-161`） |
| 响应 | 统一用 `APIResponse.success` / `.error` / `.list` / `.created`，不要手拼 dict |
| 权限粒度 | 资源名 + 操作名；字符串简写用 `@requires_permission("article:read")`（`authorization.py:156-165`） |
| 文档注解 | 在函数上加 `@api_tags` / `@api_summary` / `@api_response`，OpenAPI 规范会反射收集 |
| 异常 | 抛 `app/services/exceptions.py` 里的业务异常，异常处理器会自动转成统一 JSON |

### 5.3 需要上游配合的事项

- **当前基线的 `app.api` 包无法 import**（见 §1.3 的 `BlueprintGroup.add_blueprint` 问题），
  因此新增的 API 资源**不会生效**。必须等 `sa-oss/m1` 合并。
- `app/api/routes.py` 与 `app/api/example.py` 是死代码，M1 已删除，合并后请勿基于它们扩展。
- `app/api/resources/database.py` 与 `compression.py` 依赖**不存在的** `app.utils.validator`
  （`app/utils/` 目录在仓库中不存在，且全部 git 历史中从未有过）。
  这两个模块当前无法 import，**不要参照它们的写法**；参照 `role.py` / `account.py`。
- `app/api/resources/dashboard.py` 与 `dashboard_user.py` 从 `app.models` 导入 `File`，
  但 `File` 模型不存在（模型实际叫 `UploadedFile`）——这两个模块同样当前无法 import。

---

## 6. 前端说明

### 6.1 AMIS 页面 JSON 放在哪

**目录：`amis/pages/`**（**【读码确认】** 实际文件清单）

| 文件 | 用途 |
|---|---|
| `site.json` | 站点布局与菜单树；通过 `schemaApi` 引用各页面 JSON |
| `crud-list.json` | 列表页（用户管理） |
| `crud-new.json` | 新建页 |
| `crud-view.json` | 详情页 |
| `crud-edit.json` | 编辑页 |
| `crud-advance.json` | 高级 CRUD 示例 |
| `dash_board.json` | 仪表盘 |
| `login.json` | 登录页 |
| `form-basic.json` / `editor.json` / `wizard.json` / `console.json` | 表单 / 编辑器 / 向导 / 控制台示例 |

### 6.2 路由怎么挂

**主路径（M1 起）：由后端同源托管。** 应用把 `amis/` 目录挂在 `/amis` 下，并以 `login.html` 作为索引，
因此管理界面的入口是 **`http://127.0.0.1:22222/amis/login.html`**。页面与 API 同源，
`HttpOnly` 的 `session` Cookie 由浏览器自动携带，不涉及 CORS。

挂载代码（由集成方在 `app/__init__.py` 中接入，`amis/` 目录本身不负责）：

```python
AMIS_DIR = app.config.get("AMIS_DIR")
if AMIS_DIR and os.path.isdir(AMIS_DIR):
    app.static("/amis", AMIS_DIR, index="login.html")
```

`AMIS_DIR` 默认指向应用旁的 `amis/` 目录，并可通过环境变量覆盖；置空或指向不存在的目录则不挂载，
生产环境可据此关闭管理界面。

> **> 待 M1 交付后核实**：以上按 M1 的 `amis/README.md` 契约写成，落地实现在 M1 的 Lane L 中
> （`app/config.py` 的 `AMIS_DIR` 配置项 + `app/__init__.py` 的 `/amis` 挂载）。
> 回填时按 M1 的最终交付实测核对。

**【读码确认】** `amis/pages/site.json` 的菜单节点用 `schemaApi` 引用页面 JSON：

```json
{
  "label": "用户管理",
  "url": "/user",
  "redirect": "/user/crud/list",
  "children": [
    {
      "label": "详细信息",
      "url": "/user/crud/list",
      "schemaApi": "get:./static/pages/crud-list.json"
    },
    {
      "label": "新增",
      "url": "/user/crud/new",
      "schemaApi": "get:./static/pages/crud-new.json"
    }
  ]
}
```

`schemaApi` 的值是 `get:<URL>`，**相对于 AMIS 开发服务器的静态根**。
`site.json` 位于 `amis/pages/`，但引用路径写的是 `./static/pages/xxx.json`——
说明页面 JSON 期望被放在**服务器的 `static/` 目录**下，而不是 `amis/pages/`。

> **> 待 M1 交付后核实**：当前基线的 `amis/server.js`（Express 版）把 `./public`、`./pages`、`./sdk`
> 三个目录挂为静态资源，但**没有 `static/` 目录**，所以 `site.json` 里的
> `./static/pages/*.json` 在当前基线**取不到**。同时 `amis/index.html` 在当前基线**不存在**
> （只有 `site.html`；`site.html` → `index.html` 的重命名发生在 `sa-oss/m1` 的提交 `81e51bb`，
> 不在当前分支历史中）。
> `sa-oss/m1` 已把 `amis/server.js` 换成零依赖 Node 服务器，把 `pages/` 直接作为静态根，
> 并把页面引用改成相对路径（`sa-oss/m1:amis/pages/crud-list.json` 的 `api.url` 从
> `http://127.0.0.1:22222/refapi/account/0` 改为 `/refapi/account/0`）。
> **M1 合并后本节必须重新核实。**

### 6.3 AMIS 的 API 地址

**【读码确认】** `amis/pages/crud-list.json` 当前写的是**绝对地址 + 硬编码后端端口**：

```json
"api": { "method": "get", "url": "http://127.0.0.1:22222/refapi/account/0" }
```

问题有两点：

1. 硬编码 `127.0.0.1:22222`——后端端口一变所有页面 JSON 都要改。
2. `/refapi/account/0` 这个路径**后端并不存在**（全仓库 grep `refapi` 只命中这 3 个 AMIS JSON 文件）。
   后端实际的账户列表路径是 `/api/v1/accounts`（`app/api/resources/account.py:424`），
   而该路径当前因 `app.api` 导入失败而**不可达**。

> **> 待 M1 交付后核实**：M1 的 `amis/server.js` 把 `/refapi` 等前缀**反向代理到后端**，
> 并删除 `Origin` 头做同源转发。因此 M1 之后 `/refapi/*` 是代理前缀而非后端真实路径，
> 前端 JSON 里的 `api.url` 用相对路径 + 代理前缀即可，不必写绝对地址。

### 6.4 开发服务器（可选）

**这是可选的开发辅助，不是正式接入方式。** 正式方式是 §6.2 的后端同源托管
（`http://127.0.0.1:22222/amis/login.html`）。Node 服务器只在「后端还没接好静态托管」时用于本地预览界面。

**【读码确认】** 当前基线 `amis/server.js` 用 Express：

```js
app.use('./public', express.static('public'));
app.use('./pages',  express.static('pages'));
app.use('./sdk',     express.static('sdk'));
app.get('/*', ... sendFile(path.join(__dirname, 'index.html')));
```

默认端口 `process.env.PORT || 3000`（`:10`）。**没有反向代理**，后端地址由页面 JSON 里的绝对 URL 决定。

> **> 待 M1 交付后核实**：M1 已换成零依赖 Node 服务器（`PORT` 默认 3000，
> `API_TARGET` 默认 `http://127.0.0.1:22222`），并把 `/auth`、`/capt`、`/api`、`/health`、
> `/uploads`、`/refapi`、`/account` 反代到后端。

### 6.5 Vue 前端（实验性）

**【读码确认】** `frontend/` 是 Vue 3 + Element Plus + Vite 的实验性前端，
当前只有 login 与 dashboard 两个页面：

- `frontend/src/router/index.js` 引用了 **7 个不存在的视图组件**
  （`views/user/index.vue`、`views/user/profile.vue`、`views/role/index.vue`、
  `views/role/permission.vue`、`views/system/settings.vue`、`views/system/logs.vue`、
  `views/error/404.vue`），实际只有 `views/login/index.vue` 与 `views/dashboard/index.vue`。
  访问这些路由会因动态 import 失败而报错。
- `frontend/src/api/index.js` 调用的 `/auth/login`、`/auth/logout`、`/auth/me`、`/users` 等路径
  与后端实际路径**不匹配**（后端是 `/auth/login` ✓、`/auth/logout` ✓、无 `/auth/me` ✗、
  账户列表是 `/api/v1/accounts` 而非 `/users` ✗）。
- `frontend/.env.development` 与 `.env.production` 的 `VUE_APP_BASE_API` 都是 `/api`。
- `frontend/src/utils/request.js` 用 axios 拦截器注入 `Authorization: Bearer <token>`，
  拦截 `res.success === true` 的业务响应——与后端 `app/services/utils.py:105-128` 的
  `{"status":0,"msg":...,"data":...}` 格式**不一致**，需要 adaptor。

**结论**：`frontend/` 目前只是骨架。**主线是 AMIS**（`README_cn.md:3` 明确写了
「前端以 AMIS 为主线，`frontend/` 下的 Vue 前端为实验性」）。
新增页面优先走 AMIS，不要基于 `frontend/` 扩展。

---

## 7. 当前基线的已知缺口

**【实测】** 在当前基线上实际启动应用（`create_app()`），路由表如下：

```
POST /auth              POST /auth/associated   POST /auth/login
POST /auth/logout       POST /auth/register     POST /auth/validate-2fa
POST /auth/verify
GET  /capt/image        GET  /capt/request
GET  /health
GET  /uploads/<path>
```

**`/api/v1/*` 全部不存在**。启动日志给出两条降级警告：

```
[WARNING] [降级] 文件下载计数中间件未启用（app.api.resources.upload 不可用，待 B1d 修复）:
           AttributeError("'BlueprintGroup' object has no attribute 'add_blueprint'")
[WARNING] [降级] API v1 路由 未启用（导入 app.api 失败，待 B1d (api) 修复）:
           AttributeError("'BlueprintGroup' object has no attribute 'add_blueprint'")
```

根因与影响：

| # | 问题 | 位置 | 影响 |
|---|---|---|---|
| 1 | `Blueprint.group()` 在 sanic 23.6.0 中无 `add_blueprint` | `app/api/__init__.py:22` | **整个 `app.api` 包导入失败**，25 个 API 资源全部不可达 |
| 2 | `app/utils/` 包不存在 | `app/api/resources/database.py:16`、`compression.py:16` | 这两个资源模块无法 import |
| 3 | `from app.models import File` | `dashboard.py:11`、`dashboard_user.py:11` | 模型实际叫 `UploadedFile`；这两个模块无法 import |
| 4 | `from app.api.base import response` | `database.py:14`、`compression.py:14` | `response` 在 `app/api/base.py` 中**不存在**（只有 `json`）；无法 import |
| 5 | `from app.api.resources.account import account_api` | `app/api/routes.py:8` | `account_api` 不存在；`app/api/routes.py` 无法 import（但它本就无调用点） |
| 6 | `setup_docs()` 无调用点 | `app/docs/__init__.py:33` | `/swagger`、`/swagger.json`、`/redoc`、`/docs/models` 全部 404 |
| 7 | `register_web_blueprints()` 无调用点 + `frontend/templates/` 不存在 | `app/web/routes.py:39` | Web 渲染路由是死代码 |
| 8 | `csrf_protect()` 无路由使用 | `app/middleware/security_middleware.py:44` | CSRF 保护未生效（目前靠 SameSite=Lax） |
| 9 | 中间件读 Cookie `session_id`，实际下发的是 `session` | `app/middleware/auth_middleware.py:25` vs `app/models/session.py:66` | 中间件在 Cookie 场景下取不到会话（不影响功能，鉴权走 `authenticate_request`） |
| 10 | 邮件配置无消费方 | `app/config.py:212-217` | production 下验证码无处送达，注册验证 / 两步验证流程无法完成 |
| 11 | `amis/index.html` 不存在；`site.json` 引用不存在的 `static/pages/` | `amis/` | AMIS 页面在当前基线跑不起来 |

其中 #1、#2、#3、#4 都由 `sa-oss/m1` 修复（M1 已删除 `app/api/routes.py`、`app/api/example.py`，
并重写 `app/api/__init__.py` 的蓝图装配）。

**> 待 M1 交付后核实**：上表 #1~#4 在 M1 合并后需重新核实；
#6、#7、#8、#9、#10、#11 的状态也需在合并后复测。

---

## 8. 附：本文档的核实方式

**读过的源码文件**（均在本分支 `sa-oss/m23-doc` / base `9a8f946` 上）：

```
app/__init__.py                  app/config.py                app/main.py(→ 根 main.py)
app/api/__init__.py              app/api/base.py              app/api/responses.py
app/api/validators.py            app/api/routes.py            app/api/example.py
app/api/resources/__init__.py    app/api/resources/account.py app/api/resources/role.py
app/api/resources/profile.py     app/api/resources/log.py     app/api/resources/setting.py
app/api/resources/upload.py      app/api/resources/dashboard.py
app/api/resources/dashboard_user.py app/api/resources/dashboard_performance.py
app/api/resources/cache.py       app/api/resources/database.py
app/api/resources/compression.py
app/auth/__init__.py             app/auth/routes.py           app/auth/authentication.py
app/auth/authorization.py        app/auth/verification.py
app/cache/__init__.py            app/cache/base.py            app/cache/memory.py
app/cache/redis.py               app/cache/decorators.py
app/database/__init__.py         app/database/query_optimizer.py
app/database/connection_pool.py app/database/query_analyzer.py
app/docs/__init__.py             app/docs/openapi.py          app/docs/swagger.py
app/docs/routes.py               app/docs/models.py           app/docs/decorators.py
app/middleware/__init__.py       app/middleware/error_handler.py
app/middleware/security_middleware.py app/middleware/auth_middleware.py
app/middleware/compression.py    app/middleware/_headers.py
app/models/__init__.py           app/models/base.py           app/models/account.py
app/models/role.py               app/models/session.py        app/models/verification.py
app/models/profile.py            app/models/system_setting.py app/models/operation_log.py
app/models/uploaded_file.py
app/services/__init__.py         app/services/utils.py        app/services/exceptions.py
app/web/__init__.py              app/web/routes.py
amis/server.js  amis/package.json  amis/README.md  amis/pages/*.json  amis/site.html
frontend/src/router/index.js  frontend/src/api/index.js  frontend/src/utils/request.js
frontend/.env.development  frontend/.env.production
main.py  requirements.txt  SECURITY.md  .github/workflows/ci.yml  tests/conftest.py
```

**运行时实测**（临时虚拟环境，`sanic==23.6.0` + `tortoise-orm==0.20.0` + `PyJWT` +
`argon2-cffi` + `cryptography` + `captcha` + `pydantic`）：

| 实测项 | 结果 |
|---|---|
| `import app.api` | ❌ `AttributeError: 'BlueprintGroup' object has no attribute 'add_blueprint'` |
| `create_app()` 后的完整路由表 | 11 条（见 §7），无 `/api/v1/*` |
| `app.config` 生效值 | `ENV=development`、`DEBUG=True`、`CACHE_TYPE=memory`、`DATABASE_URL=sqlite://<root>/sanic_admin_dev.sqlite3`、`CORS_ALLOWED_ORIGINS=['*']`、`SESSION_COOKIE_SECURE=False`、`ROUTE_CACHE_ENABLED=False`、`DB_NAME=sanic_admin_dev` |
| production 缺 `SECRET_KEY` | ❌ `ConfigError: 生产环境必须通过环境变量 SECRET_KEY 提供应用密钥`（import 阶段即失败） |
| production 密钥齐备 | ✅ `ENV=production`、`DEBUG=False`、`CACHE_TYPE=redis`、`CORS=[]`、`DB_NAME=sanic_admin_prod`、`SESSION_SECURE=True` |
| `POST /auth/login` | ✅ 200，返回账户 JSON + `Set-Cookie: session=<JWT>` + `Authorization: Bearer <JWT>` |
| `POST /auth/associated`（Cookie） | ✅ 200，返回会话列表 |
| `POST /auth/associated`（Bearer） | ✅ 200，返回会话列表 |
| `GET /auth/me` | 404（该路由不存在） |
| CORS（`Origin` 头 + `*` 白名单） | ✅ 返回 `Access-Control-Allow-Origin: *`，**不带** `Allow-Credentials` |
| OPTIONS 预检 | ✅ 204 + CORS 头 |
| gzip（3 KB 响应 + `Accept-Encoding: gzip`） | ✅ `Content-Encoding: gzip` + `Vary: Accept-Encoding`，且 CORS 头仍在 |
| 小响应（< 1 KB） | ✅ 不压缩 |
| 中间件顺序 | 请求：注册顺序；响应：注册逆序（Sanic 源码 `appendleft` + `_run_response_middleware` 的 break 语义印证） |

**未能实测**：production 下 Redis 不可达的 `ConfigError` 路径、MySQL / PostgreSQL 真实连接、
`/api/v1/*` 全套路由的行为（依赖 M1 修复导入问题）。
这三条依据源码逻辑推断，已在对应章节标注。
