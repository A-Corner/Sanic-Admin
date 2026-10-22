# Sanic-Admin 架构文档

> 适用范围：Sanic-Admin 后端（Sanic 23.6 + Tortoise ORM 0.20 + Redis + PyJWT），前端 AMIS 低代码框架。
> 基线：发布候选 `release/v0.2.0`，M1 候选 `8750d51`（M1 已交付并入）。
> 事实来源：逐文件阅读 `app/` 源码 + 在临时虚拟环境中实际启动应用、抓取路由表与响应头。
> 标注约定：
> - **【读码确认】** = 源码可查证，且多数经过运行时实测。
> - **【已实测】** = 在 M1 候选 `8750d51` 上实际执行命令或发起 HTTP 请求得到的结果。
> - **截至 `8750d51` 仍未实现** = 如实描述现状，不是前瞻承诺。

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
            MW5["注册5 请求: 认证中间件<br/>auth_middleware.py:43-47"]
            MW7["注册6 响应: gzip 压缩<br/>compression.py:240-300"]
            MW8["异常处理 (非中间件)<br/>error_handler.py:19-40"]
        end

        subgraph BP["蓝图层"]
            B1[auth_bp /capt_bp<br/>/auth/* /capt/*<br/>app/auth/routes.py]
            B2[v1_bp<br/>/api/v1/*<br/>app/api/resources/*]
            B3[database_bp / compression_bp<br/>/api/database/* /api/compression/*]
            B4[静态文件 /static /amis<br/>app/__init__.py:58-67]
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

- **中间件的实际注册顺序**（`app/middleware/__init__.py:36-51` 的 `register_all_middlewares`）：
  1. `setup_error_handlers(app)`（`:43`）——注册异常处理器，不是中间件
  2. `setup_security_middleware(app)`（`:44`）——注册 **CORS 响应中间件** + **OPTIONS 请求中间件**
  3. `_setup_request_logging(app)`（`:45`）——注册 **请求日志** + **响应日志**中间件
  4. `AuthMiddleware()`（`:46`）——注册认证请求中间件

  随后 `app/__init__.py:70-74` 再注册 gzip 响应压缩中间件（`configure_compression`）。

  **【已实测】** M1 已移除 `FileDownloadCounterMiddleware`（原 `:49-56`，包在 try/except 里
  做 development/testing 降级、production fail-closed）。上传目录不再静态托管，下载计数改由
  `app/api/resources/upload.py:380` 在资源内部原子自增——因此中间件链少了一环。

- **Sanic 的中间件执行顺序**（实测，见 §1.2）：请求中间件按注册顺序执行；
  响应中间件按**注册逆序**执行。

- **压缩与 CORS 的先后**：`configure_compression` 在 `register_all_middlewares` **之后**调用，
  所以压缩中间件后注册 ⇒ 在响应阶段**先于** CORS 执行。
  实测大响应（3 KB）的响应头顺序为 `Content-Encoding: gzip` → `Vary: Accept-Encoding`
  → `Access-Control-Allow-Origin`，两者都正确生效（`compression.py:251` 的注释
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

- **请求阶段**：`OPTIONS 预检短路 → 请求日志 → 认证中间件`。
- **响应阶段**：`gzip 压缩 → 耗时日志 → CORS 头`。
  压缩最早执行、且必须原地修改响应并返回 `None`，
  否则后面的 CORS 头会被跳过（`compression.py:251` 注释已说明此约束）。

### 1.3 蓝图层级

**【读码确认】** `app/api/__init__.py:14-24`：

```python
v1_bp = Blueprint('v1', url_prefix='/v1')                     # :14
from app.api import resources  # noqa: E402,F401              # :18 自动导入资源模块
from app.api.resources.compression import bp as compression_bp  # :20
from app.api.resources.database import bp as database_bp        # :21
api_bp = Blueprint.group(v1_bp, database_bp, compression_bp, url_prefix='/api')  # :24
```

最终 URL 前缀为 `/api` + `/v1` = `/api/v1/...`，以及独立的
`/api/database/...`（`app/api/resources/database.py:28`）、
`/api/compression/...`（`app/api/resources/compression.py:20`）。

**【已实测】** `app/api/__init__.py:24` 用
`Blueprint.group(v1_bp, database_bp, compression_bp, url_prefix='/api')` 装配蓝图组。
这里必须用 `Blueprint.group(...)` 的**可变参数**形式：Sanic 23.6 返回的 `BlueprintGroup`
**没有 `add_blueprint` 方法**（实测 `hasattr(Blueprint.group(...), 'add_blueprint') == False`，
公开方法只有 `append` / `blueprints` / `clear` / `extend` / `insert` / `pop` / `remove`），
早期版本用 `api_bp.add_blueprint(...)` 会在 import 期就抛
`AttributeError`，导致整个 `app.api` 包导入失败、API v1 蓝图整体降级。
M1 已改用上述写法并删除了 `app/api/routes.py`、`app/api/example.py`。

实测：蓝图正常注册，生成的 OpenAPI 规范含 **68 条 path**（v0.2.1 候选 `944a9e2` 实测；
v0.2.0 的 `a0a6b27` 为 57 条）；
`create_app('testing')` 的路由表共 **116 条路由**（**77 个不同 path**，其中 39 个在 `/api/v1` 下）。

> **三个数字各指什么，别混用**（v0.2.1 候选 `944a9e2` 实测）：
>
> | 数字 | 含义 | v0.2.0 | v0.2.1 |
> |---|---|---|---|
> | **116 / 80** | `app.router.routes` 的**路由条数** | 80 | 116 |
> | **77 / 66** | **去重后**的 path 总数 | 66 | 77 |
> | **68 / 57** | **OpenAPI 规范内**的 path 数 | 57 | 68 |
>
> 77 与 68 数值接近但含义不同：去重 path 含 9 个文档自身的路径
> （`/docs`、`/docs/models`、`/docs/paths`、`/docs/redoc`、`/docs/tags`、`/redoc`、
> `/swagger`、`/swagger.json`、`/swagger/index.html`），它们被 `_SKIP_PREFIXES` 排除在规范外。
> 另注意 **66（去重 path，v0.2.0）≠ 68（OpenAPI path，v0.2.1）**——数字相近，不同含义。
>
> 这些数字**绑定具体 commit `944a9e2`**。v0.2.1 在此之前修过几轮 AMIS 静态挂载，
> 每轮都会改动路由表，数字随之变化（`aa992f3` 时是 114/75/66，
> 修 `public/` 与裸目录 500 后是 115/76/67，恢复裸 `/amis` 为 404 后是 116/77/68）。
> **改动路由表后须重测并同步本文。**

另有 `_ensure_unique_route_names()`（`app/api/__init__.py:27-55`）为同一个视图注册到多个 URL 时
补唯一路由名——Sanic 23.6 遇到重名路由会直接抛 `ServerError` 导致进程起不来。

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
| `app/api/resources/route_methods.py` | `register_view()`：用 `Blueprint.route` 原样注册方法并为未支持的方法挂 405 兜底，使方法不匹配稳定返回 405 而不是 404/500（仅部分资源采用） |

**M1 已删除**（不再存在于仓库中）：`app/api/routes.py`（旧版 API 蓝图）与
`app/api/example.py`（文档装饰器示例）。它们在 M1 之前是无调用点的死代码，且 import 的
`account_api` / `role_api` 早已不存在——**不要基于它们扩展**。

`app/api/resources/` 下的资源清单（**【读码确认】** `app/api/resources/__init__.py:36-65` 的
`all_resources` 列表，共 27 个资源类）：

| 文件 | 资源类 | 注册路径（`v1_bp.add_route`） |
|---|---|---|
| `account.py` | `AccountResource` / `AccountPasswordResource` / `AccountMeResource` / `MyAccountPasswordResource` | `/accounts`、`/accounts/<id>`、`/accounts/<id>/password`、`/accounts/me`、`/accounts/me/password` |
| `role.py` | `RoleResource` / `RoleMembersResource` / `AccountRolesResource` | `/roles`、`/roles/<id>`、`/roles/<id>/members`、`/accounts/<id>/roles` |
| `profile.py` | `ProfileResource` / `MyProfileResource` | `/profiles/<id>`、`/profiles`、`/me/profile` |
| `log.py` | `LogResource` / `LogStatisticsResource` | `/logs`、`/logs/<id>`、`/logs/statistics` |
| `setting.py` | `SettingResource` / `SettingByKeyResource` / `SettingBulkResource` | `/settings`、`/settings/<id>`、`/settings/key/<key>`、`/settings/bulk` |
| `upload.py` | `FileUploadResource` / `AvatarUploadResource` / `FileListResource` / `FileDownloadResource` / `FileDeleteResource` | `/upload`、`/upload/<category>`、`/upload/avatar`、`/files`、`/files/<id>/download`、`/files/<id>` |
| `dashboard.py` | `DashboardSummaryResource` / `DashboardActivitiesResource` / `DashboardStorageResource` | `/dashboard/summary`、`/dashboard/activities`、`/dashboard/storage` |
| `dashboard_user.py` | `UserActivityResource` / `FeatureUsageResource` / `PermissionAnalysisResource` | `/dashboard/user-activity`、`/dashboard/feature-usage`、`/dashboard/permission-analysis` |
| `dashboard_performance.py` | `PerformanceResource` / `ExceptionsResource` / `AlertsResource` | `/dashboard/performance`、`/dashboard/exceptions`、`/dashboard/alerts` |
| `cache.py` | `CacheResource` / `CacheKeysResource` / `CacheKeyResource` | `/cache`、`/cache/keys`、`/cache/keys/<key>` |
| `database.py` | `QueryLogsResource` / `SlowQueriesResource` / `QueryPlanResource` / `ConnectionPoolResource` / `DatabaseAnalysisResource` | `/api/database/query-logs` 等（独立 `bp`） |
| `compression.py` | `CompressionStatsResource` / `CompressionConfigResource` | `/api/compression/...`（独立 `bp`） |

**【已实测】** `account.py` / `role.py` / `profile.py` 用 `register_view()` 注册（自带 405 兜底），
其余资源用 `v1_bp.add_route(...)`。`upload.py` 的 `FileDownloadCounterMiddleware` 已随 M1
移除——下载计数改由 `FileDownloadResource.get()` 内部原子自增
（`app/api/resources/upload.py:380`），全局中间件不再需要它。

### 2.3 `app/auth` —— 认证与授权

| 文件 | 职责 |
|---|---|
| `app/auth/__init__.py` | 导出 5 个蓝图与 `register_auth_blueprints()`（**当前无调用点**，`app/__init__.py:146-164` 直接从 `app.auth.routes` 取蓝图） |
| `app/auth/routes.py` | 认证路由：`POST /auth/login`、`/auth/register`、`/auth/verify`、`/auth/validate-2fa`、`/auth/logout`、`/auth/associated`、`/auth/`（续期）；`GET /capt/request`、`/capt/image` |
| `app/auth/authentication.py` | 注册、登录、注销、二次验证；`authenticate_request()`；`requires_authentication` 装饰器 |
| `app/auth/authorization.py` | RBAC：`has_role` / `has_permission` / `get_account_permissions`；`check_roles` / `check_permissions` / `requires_permission` 装饰器 |
| `app/auth/permissions.py` | 权限注册表：`ALL_PERMISSIONS`（资源 → 允许的动作，`"all"` 表示该资源全部动作）、`admin_all_permissions()`（内置 admin 角色的全量权限）、`effective_permissions()`（授权与校验共用的折叠口径，子资源折叠到基资源） |
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

**【已实测】** `setup_docs()` 已接线：`app/__init__.py:81-83` 中有
`if app.config.get("ENABLE_API_DOCS"): setup_docs(app)`，由 `ENABLE_API_DOCS` 开关控制
（development / testing 默认 `True`，production 默认 `False`，见 `app/config.py:240` 与 `:278`；
可用环境变量覆盖，`app/config.py:360`）。`setup_docs()` 同时把 sanic-ext 自带的 OAS 关掉
（`app/docs/__init__.py:43` 的 `app.config.OAS = False`），以本模块为唯一文档来源。

development / testing 下实测（`ENABLE_API_DOCS=True`）：

| 端点 | 结果 |
|---|---|
| `GET /swagger` | 302 → `/swagger/index.html` → **200**（Swagger UI） |
| `GET /swagger.json` | **200**，OpenAPI 3.0.3 规范，**68 条 path** |
| `GET /redoc` | **200**（ReDoc） |
| `GET /docs` | 302 → `/swagger`（别名） |
| `GET /docs/models` `/docs/tags` `/docs/paths` `/docs/redoc` | **200** |

production 下（`ENABLE_API_DOCS=False`，实测）：

| 端点 | 结果 |
|---|---|
| `GET /swagger` `/swagger/index.html` `/swagger.json` `/redoc` `/docs/models` | **404**（本模块的路由未挂载） |
| `GET /docs` | **200**——sanic-ext 自带的 OAS 页面 |
| `GET /docs/openapi.json` | development 下 **404**（`setup_docs()` 接管了 `/docs` 前缀）；production 下 200——sanic-ext 生成的**另一份** OpenAPI 规范 |

**注意**：production 下能访问到的 `/docs` 与 `/docs/openapi.json` 来自 **sanic-ext**，
是**另一套**生成器（标题 `"API"`），与 `app/docs/` 产出的（标题 `"SanicAdmin"`，
68 条 path）**不是同一份**。**规范以 `/swagger.json` 为准**；production 想暴露本模块的规范
需显式设 `ENABLE_API_DOCS=true`。

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

**【已实测】截至 `8750d51`**：`register_web_blueprints()`（`app/web/routes.py:39`）
**仍无调用点**，且 `frontend/templates/` 目录在仓库中**不存在**
（Jinja2 `FileSystemLoader('frontend/templates')` 会直接失败）。
这批 Web 渲染路由是**死代码**——前端主线已切到 AMIS 静态页（`amis/`），
Web 渲染路线是否移除留待后续版本决定。

---

## 3. 认证流程

### 3.1 登录时序

```mermaid
sequenceDiagram
    autonumber
    participant C as 客户端
    participant A as /auth/login<br/>(app/auth/routes.py:89)
    participant AU as authentication.login<br/>(app/auth/authentication.py:157)
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
    participant MW as AuthMiddleware<br/>(auth_middleware.py:43-47)
    participant H as 路由处理函数
    participant AU as authenticate_request<br/>(authentication.py:259)
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
- `Account.is_admin == True` 的账户**拥有全部权限**（`:130`、`:144`），是 RBAC 的短路路径。
- `get_account_permissions()`（`:63`）合并账户所有**未删除**角色的权限集合。
- `has_permission(account, resource, *actions)`（`:136`）要求**全部**指定 action 都命中。
- 三个装饰器：

| 装饰器 | 位置 | 语义 |
|---|---|---|
| `@check_roles("admin", ...)` | `:164` | 拥有指定角色**之一**即可；无角色 → `RoleRequiredError`(403) |
| `@check_permissions("role", "read")` | `:180` | 需要 `role` 资源的 `read` 权限；也可作函数调用 `check_permissions(..., request=..., check_only=True)` 返回 bool |
| `@requires_permission("system:database:query")` | `:213` | `"资源:操作"` 字符串形式；最后一个冒号之后是操作，之前是资源（如 `system:database` 的 `query`）；不含冒号时按资源的 `all` 判定 |

未认证 → 401（`AuthenticationError`）；已认证但权限不足 → 403（`InsufficientPermissionsError`）。
两者都经 `app/services/exceptions.py` 的 `BaseError.to_dict()` 变成统一 JSON 响应体。

**【读码确认】受保护管理员的判定（`app/api/resources/role.py:160-200`）**

`is_protected_admin(account)` 在满足**任一**条件时返回 True：

1. `account.is_admin` 为 True；
2. 账户持有某个授予了**全部权限**的角色（该角色的权限覆盖 `app/auth/permissions.py`
   的 `ALL_PERMISSIONS` 注册表全部资源）。

`actor_may_modify(actor, target)` 与该判定**对称**：管理员形态的账户可以改动任何人，
非管理员**不能**改动受保护的管理员。这种对称性保证「管理员可以改动自己」——
若 actor 持有全权限角色，它本身就是管理员形态，不会把自己锁死。

> **因此：持有全权限角色的账户视同管理员。** 判定只看权限覆盖面，不看角色名，
> 也不要求 `is_admin` 标志位。

### 3.4 两步验证与验证码

**【读码确认】**

- `VerificationSession.check_code()`（`app/models/session.py:276-294`）用**原子更新**
  `filter(id=..., attempts__lt=5).update(attempts=F("attempts")+1)` 计数，
  并发下计数不丢失也不会超上限；达到上限抛 `RateLimitExceededError`(429)。
  验证码比较用 `secrets.compare_digest`（常数时间）。
- `TwoStepSession` / `CaptchaSession` 各有独立表与独立 Cookie 名
  （`two_step_session` / `captcha_session`），避免互相覆盖。
- 二次验证由服务端配置 `settings.REQUIRE_TWO_FACTOR` 决定，
  **忽略客户端传入的参数**（`app/auth/routes.py:95`）。
  该配置项已存在于 `app/config.py:242`，并可用环境变量覆盖
  （`app/config.py:361`，`_bool_env()` 接受 `1/true/yes/on` 与 `0/false/no/off/`）。
  **默认关闭**（`False`），需显式开启才会要求二次验证。
  注意这是**全局开关**，不支持按账户开关——见 Release Notes 的已知限制。

### 3.5 认证中间件与会话校验的分工

**【读码确认】** 两条并存的路径，职责不同：

| 路径 | 位置 | 行为 |
|---|---|---|
| **中间件** | `app/middleware/auth_middleware.py:14-40` | 尽力而为：从 `Authorization: Bearer` 或 Cookie 取令牌，查有效会话，挂到 `request.ctx.authentication_session`。**失败不抛异常、不中断请求** |
| **装饰器 / 显式调用** | `app/auth/authentication.py:259-290` | 强制校验：无令牌 → `AuthenticationError`(401)；会话/账户不可用 → 抛对应异常；二次验证未完成 → `AuthenticationError` |

**【已实测】Cookie 名已对齐**：中间件现在直接读会话模型实际下发的名字
（`app/middleware/auth_middleware.py:27` → `request.cookies.get(AuthenticationSession.cookie_name)`，
即 `session`，见 `app/models/session.py:66`），不再硬编码 `session_id`。
因此 `Authorization: Bearer` 与 Cookie 两条路径都能命中中间件。

实际鉴权不依赖中间件——`requires_authentication` / `check_permissions` 都会调用
`authenticate_request()` 自行解码（`authentication.py:273-278`：已挂载则复用，否则重新解码），
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
│   │   ├── resources/            # 12 个业务资源模块 + route_methods.py + __init__.py
│   │       ├── account.py        #   账户 / 改密 / 当前用户
│   │       ├── role.py           #   角色 / 角色成员 / 账户角色
│   │       ├── profile.py        #   个人资料 / 我的资料
│   │       ├── log.py            #   操作日志 / 日志统计
│   │       ├── setting.py        #   系统设置 / 按键读写 / 批量
│   │       ├── upload.py         #   文件上传 / 头像 / 列表 / 下载 / 删除
│   │       ├── dashboard.py      #   概览 / 活动 / 存储
│   │       ├── dashboard_user.py #   用户活动 / 功能使用 / 权限分析
│   │       ├── dashboard_performance.py  # 性能 / 异常 / 告警
│   │       ├── cache.py          #   缓存管理
│   │       ├── route_methods.py  #   register_view()：405 兜底注册
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
│   ├── server.js                 # 零依赖 Node 开发服务器（静态托管 + 同源反代）
│   ├── package.json / nodemon.json
│   ├── index.html                # 站点外壳（登录态检查 + 菜单）
│   ├── login.html                # 静态登录页（POST /auth/login）
│   ├── pages/                    # AMIS 页面 JSON（site / account-list / role-list / log-list / setting-list / dash_board）
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
│   ├── test_auth.py              # 登录 / 注销 / 会话 / 两步验证
│   ├── test_authorization.py     # RBAC：角色 / 权限 / 装饰器
│   ├── test_account_crud.py      # 账户 CRUD
│   ├── test_role_crud.py         # 角色 CRUD
│   ├── test_upload_security.py   # 上传路径与下载鉴权
│   ├── test_sql_readonly.py      # 只读 SQL 校验
│   └── test_production_failclosed.py  # production 缺密钥拒绝启动
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

**第 3 步 —— 注册路由**。在模块末尾把资源挂到 `v1_bp`。
推荐用 `register_view()`（自带 405 兜底，见 `app/api/resources/route_methods.py`）：

```python
from app.api.resources.route_methods import register_view

article_resource = ArticleResource()
register_view(v1_bp, "/articles", article_resource, ["GET", "POST"], "article_list")
register_view(v1_bp, "/articles/<article_id:int>", article_resource,
              ["GET", "PUT", "DELETE"], "article_detail")
```

**第 4 步 —— 加入资源清单**。在 `app/api/resources/__init__.py` 的 `all_resources`
列表和 `__all__` 中登记新类（该列表被注释标注为「用于配置文档」）。

**第 5 步 —— 加权限**。新资源需要在 `Role.permissions` 里加上对应条目，格式为
`{"article": ["create", "read", "update", "delete"]}`。
**必须先在 `app/auth/permissions.py` 的 `ALL_PERMISSIONS` 注册表里登记该资源**
（`:35-55`）——权限判定只认注册表里的资源名，没登记的资源即使写进了角色权限也不会生效。
内置 `admin` 角色取的是注册表的全量权限（`app/auth/authentication.py:94-116` 的
`_admin_role_permissions()` → `admin_all_permissions()`），新资源登记后自动纳入。

### 5.2 约定要点

| 约定 | 说明 |
|---|---|
| 蓝图 | 资源模块 `from app.api import v1_bp` 取蓝图，路由用 `register_view(v1_bp, ...)` 或 `v1_bp.add_route(...)`（`role.py:565-575` 是 `register_view` 范本，`log.py:179-181` 是 `add_route` 范本）。**只有**需要独立前缀（如 `/api/database`）时才自建 `bp` |
| 参数校验 | 在视图方法体内用 `validate_fields(data, {...})`（`app/api/validators.py`）——**不是** `@validate_request` / `@validate_path_param` 装饰器（那两个装饰器目前只有 docstring 示例，无实际调用点）。范本见 `role.py:244-251` |
| 权限 | 视图方法上加 `@check_permissions("resource", "action")`（`app/auth/authorization.py:180`）。**权限判定在参数校验之前**——`role.py:213` 的 `@check_permissions("role", "read")` 就在 `get` 上，装饰器先于方法体执行 |
| 响应 | 统一用 `APIResponse.success` / `.error` / `.list` / `.created`，不要手拼 dict |
| 权限粒度 | 资源名 + 操作名；字符串简写用 `@requires_permission("article:read")`（`app/auth/authorization.py:213`） |
| 文档注解 | 在函数上加 `@api_tags` / `@api_summary` / `@api_response`，OpenAPI 规范会反射收集 |
| 异常 | 抛 `app/services/exceptions.py` 里的业务异常，异常处理器会自动转成统一 JSON |

### 5.3 M1 已解决的编写障碍

以下四项在 M1 之前会让新增的 API 资源**无法生效**，现已全部解除（**【已实测】**
`import app.api` 成功，`create_app('testing')` 路由表含 39 条 `/api/v1` path）：

- `app.api` 包的 `BlueprintGroup.add_blueprint` 导入失败（见 §1.3）——已改为
  `Blueprint.group(v1_bp, database_bp, compression_bp, url_prefix='/api')`。
- `app/api/resources/database.py` 与 `compression.py` 原先依赖**不存在的**
  `app.utils.validator`（`app/utils/` 目录在仓库中不存在，全部 git 历史中也从未有过）——
  现已改用 `app/api/responses.py` 的 `APIResponse` / `APIError`，并各自实现
  `_bad_request()` 做参数校验（`database.py:34`、`compression.py:26`）。
- `app/api/resources/database.py` 与 `compression.py` 原先 `from app.api.base import response`，
  而 `response` 在 `app/api/base.py` 中**不存在**（只有 `json`）——现已改用 `app/api/responses.py`。
- `app/api/resources/dashboard.py` 与 `dashboard_user.py` 原先 `from app.models import File`，
  而 `File` 模型不存在（模型实际叫 `UploadedFile`）——现已改正。

**注意**：这四个模块在 M1 之前是**重写的**，写法与 `role.py` / `account.py` 差别较大
（前者用 `HTTPMethodView` + 自建 `_bad_request()`，后者用 `app/api/validators.py` 的
`validate_request` / `validate_path_param` 装饰器）。**新增资源请参照 `role.py` / `account.py`**，
不要照抄 `database.py` / `compression.py` 的手工校验写法。

---

## 6. 前端说明

### 6.1 AMIS 页面 JSON 放在哪

**目录：`amis/pages/`**（**【读码确认】** 实际文件清单，M1 后共 6 个）

| 文件 | 用途 |
|---|---|
| `site.json` | 站点布局与菜单树；通过 `schemaApi` 引用各页面 JSON |
| `dash_board.json` | 仪表盘（`initApi` → `/api/v1/dashboard/summary`） |
| `account-list.json` | 账户列表（CRUD，`/api/v1/accounts`） |
| `role-list.json` | 角色列表（CRUD，`/api/v1/roles`） |
| `log-list.json` | 操作日志列表（`/api/v1/logs`） |
| `setting-list.json` | 系统设置列表（`/api/v1/settings`） |

M1 之前的 `crud-list.json` / `crud-new.json` / `crud-view.json` / `crud-edit.json` /
`crud-advance.json` / `login.json` / `form-basic.json` / `editor.json` / `wizard.json` /
`console.json` 已在 M1 提交 `0f05fba` 中**删除**——那些是旧的演示页，菜单已对齐到真实 API。

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

**【已实测】** `AMIS_DIR` 配置项已在 `app/config.py:195` 定义、`app/config.py:348` 支持
环境变量覆盖；`/amis` 挂载在 `app/__init__.py:62-67`。实测 `GET /amis/` 与
`GET /amis/login.html` 均返回 200 并给出登录页 HTML，`GET /amis`（不带尾斜杠）返回 404。

**【读码确认】** `amis/pages/site.json` 的菜单节点用 `schemaApi` 引用页面 JSON
（当前内容，`amis/pages/site.json:17-30`）：

```json
{
  "label": "账户管理",
  "url": "/account",
  "redirect": "/account/list",
  "icon": "fa fa-user",
  "children": [
    {
      "label": "账户列表",
      "url": "/account/list",
      "icon": "fa fa-list",
      "schemaApi": "get:pages/account-list.json?v1"
    }
  ]
}
```

`schemaApi` 的值是 `get:<URL>`，**相对于 AMIS 开发服务器的静态根**。
`site.json` 位于 `amis/pages/`，引用路径写的是 `pages/account-list.json`——
即**同目录相对路径**，与 `amis/server.js` 把 `pages/` 直接作为静态根一致
（`amis/server.js:14` 的 `ROOT = __dirname`，静态根就是 `amis/` 目录本身）。

**【已实测】** M1 已把 `amis/server.js` 换成零依赖 Node 服务器，把 `pages/` 直接作为静态根，
并把页面引用改成相对路径——`site.json` 现在写的是 `get:pages/dash_board.json?v1` 这类路径
（不再是旧的 `./static/pages/xxx.json`），`amis/index.html` 与 `amis/login.html` 也已就位。
列表页文件按实际资源改名（如 `crud-list.json` → `account-list.json`，
后者在 M1 提交 `0f05fba` 中随旧 `crud-*` 系列一并删除）。
实测 `GET /amis/pages/site.json` 与 `GET /amis/pages/dash_board.json` 均返回 200。

### 6.3 AMIS 的 API 地址

**【已实测】** M1 已把页面 JSON 里的 `api.url` 全部改成**相对路径**，直接指向后端真实路由
（`amis/pages/account-list.json:8`、`role-list.json:8`、`log-list.json:8`、`setting-list.json:8`、
`dash_board.json:7`）：

```json
"api": { "method": "get", "url": "/api/v1/accounts", "dataType": "json", "adaptor": "..." }
```

M1 之前的旧写法是**绝对地址 + 硬编码后端端口**：

```json
"api": { "method": "get", "url": "http://127.0.0.1:22222/refapi/account/0" }
```

它有两个问题：硬编码 `127.0.0.1:22222`（后端端口一变所有页面 JSON 都要改）；
`/refapi/*` 这个路径**后端并不存在**——它只是开发服务器的反代前缀，后端真实的账户列表路径是
`/api/v1/accounts`（`app/api/resources/account.py:476`）。M1 已把这两点一并消除。

**【已实测】** `amis/server.js:15` 的 `PROXY_PREFIXES` 仍保留 `/refapi`：

```js
const PROXY_PREFIXES = ['/auth', '/capt', '/api', '/health', '/refapi', '/account'];
```

`amis/server.js` 把这些前缀**反向代理到后端**，并删除 `Origin` 头做同源转发
（`amis/server.js:30` 注释写明「同源转发，避免后端按 Origin 判定跨域」）。
`/refapi` 保留下来是为了兼容旧的页面 JSON 写法；当前页面 JSON 已不再使用它。

**注意它不代理 `/uploads`**（`amis/server.js:5-6` 注释明确说明）：后端已移除上传目录的
静态挂载，文件下载统一走需鉴权的 `GET /api/v1/files/<id>/download`。

### 6.4 开发服务器（可选）

**这是可选的开发辅助，不是正式接入方式。** 正式方式是 §6.2 的后端同源托管
（`http://127.0.0.1:22222/amis/login.html`）。Node 服务器只在「后端还没接好静态托管」时用于本地预览界面。

**【已实测】** `amis/server.js` 现在是**零依赖**的 Node 服务器（只用 Node 内置模块
`http` / `fs` / `path`），M1 之前的 Express 版本已移除：

```js
const PORT = Number(process.env.PORT || 3000);                              // :12
const target = new URL(process.env.API_TARGET || 'http://127.0.0.1:22222'); // :13
const ROOT = __dirname;                                                     // :14
const PROXY_PREFIXES = ['/auth', '/capt', '/api', '/health', '/refapi', '/account'];  // :15
const DENY = new Set(['server.js', 'package.json', 'package-lock.json', 'nodemon.json', 'README.md']);  // :16
```

它静态托管 `login.html` / `index.html` / `pages` / `sdk` / `css` / `fonts` / `images`
（静态根就是 `amis/` 目录本身，见 `:14` 与 `:47`），把 `PROXY_PREFIXES` 里的路径反代到后端
（`:24-25` 的 `isProxied()` + `:28-40` 的 `proxy()`），并**拒绝**直接提供 `DENY` 里的开发文件
（`:50`）。监听地址是 `127.0.0.1`（`:65`），默认端口 `3000`。

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

## 7. 已知缺口（M1 前后对比）

**【已实测】** 在 v0.2.1 候选 `944a9e2` 上实际启动应用（`create_app('testing')`），
路由表共 **116 条路由 / 77 个不同 path**，其中 **39 个 path 在 `/api/v1` 下**，
另有 `/api/database/*`、`/api/compression/*`、`/auth/*`、`/capt/*`、`/health`、
`/swagger*`、`/redoc`、`/docs/*`、`/static/*`、`/amis/*`。

（v0.2.0 的 `a0a6b27` 为 80 条路由 / 66 个不同 path；两者差异来自 v0.2.1 把
`log` / `cache` / `dashboard` 等资源一并接入 `register_view`，每个资源多出一条
405 兜底路由。三个口径的含义对照见 §1.3 的表格。）

M1 之前的基线上，`/api/v1/*` **全部不存在**，启动日志给出两条降级警告：

```
[WARNING] [降级] 文件下载计数中间件未启用（app.api.resources.upload 不可用，待 B1d 修复）:
           AttributeError("'BlueprintGroup' object has no attribute 'add_blueprint'")
[WARNING] [降级] API v1 路由 未启用（导入 app.api 失败，待 B1d (api) 修复）:
           AttributeError("'BlueprintGroup' object has no attribute 'add_blueprint'")
```

这 11 项问题在 M1 后的状态：

| # | 问题 | 位置 | 状态（截至 `8750d51`） |
|---|---|---|---|
| 1 | `Blueprint.group()` 在 sanic 23.6.0 中无 `add_blueprint` | `app/api/__init__.py:24` | **已修复**：改用 `Blueprint.group(v1_bp, database_bp, compression_bp, url_prefix='/api')`；实测 API v1 正常挂载，OpenAPI 规范 68 条 path |
| 2 | `app/utils/` 包不存在（`from app.utils.validator import validate_request`） | `app/api/resources/database.py`、`compression.py` | **已修复**：两个模块已整体重写，改用 `app/api/responses.py` 的 `APIResponse` / `APIError`，各自实现 `_bad_request()` 做参数校验（`database.py:34`、`compression.py:26`）——**并未**改用 `app/api/validators.py` |
| 3 | `from app.models import File` | `dashboard.py:11`、`dashboard_user.py:11` | **已修复**：模型名为 `UploadedFile`；`dashboard_user.py:11` 只导入 `Account` / `Role` / `OperationLog` |
| 4 | `from app.api.base import response`（`response` 在 `app/api/base.py` 中不存在） | `database.py:16`、`compression.py:16` | **已修复**：改用 `from app.api.responses import APIResponse, APIError` |
| 5 | `from app.api.resources.account import account_api` | `app/api/routes.py` | **已消除**：M1 删除了 `app/api/routes.py` 与 `app/api/example.py` |
| 6 | `setup_docs()` 无调用点 | `app/docs/__init__.py:33` | **已修复**：已在 `app/__init__.py:81-83` 接线，由 `ENABLE_API_DOCS` 控制；development 下 `/swagger`（302→200）、`/swagger.json`、`/redoc` 均 200 |
| 7 | `register_web_blueprints()` 无调用点 + `frontend/templates/` 不存在 | `app/web/routes.py:39` | **仍存在**：Web 渲染路由是死代码，前端主线已改用 AMIS 静态页 |
| 8 | `csrf_protect()` 无路由使用 | `app/middleware/security_middleware.py:44` | **仍存在**：CSRF 保护未生效（目前靠 SameSite=Lax） |
| 9 | 中间件读 Cookie `session_id`，实际下发的是 `session` | `app/middleware/auth_middleware.py:27` | **已修复**：改读 `AuthenticationSession.cookie_name`（即 `session`，`app/models/session.py:66`） |
| 10 | 邮件配置无消费方 | `app/config.py:220-225` | **仍存在**：production 下验证码无处送达，注册验证 / 两步验证流程无法完成 |
| 11 | `amis/index.html` 不存在；`site.json` 引用不存在的 `static/pages/` | `amis/` | **已修复**：M1 补齐 `index.html`，并把页面引用改成 `pages/xxx.json` 相对路径 |

**另有一项未在上表但仍是现状的限制**：部分动态路径的方法不匹配仍返回 **404 而非 405**
（405 兜底只覆盖 `account` / `role` / `profile` 三个资源，其余资源仍用
`v1_bp.add_route(...)`）。例如实测 `DELETE /api/v1/settings/key/x` 返回 **404**。

---

## 8. 附：本文档的核实方式

**读过的源码文件**（均在本分支 `release/v0.2.0` / base `8750d51` 上）：

```
app/__init__.py                  app/config.py                app/main.py(→ 根 main.py)
app/api/__init__.py              app/api/base.py              app/api/responses.py
app/api/validators.py            app/api/resources/route_methods.py
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
amis/server.js  amis/package.json  amis/README.md  amis/pages/*.json  amis/index.html  amis/login.html
frontend/src/router/index.js  frontend/src/api/index.js  frontend/src/utils/request.js
frontend/.env.development  frontend/.env.production
main.py  requirements.txt  SECURITY.md  .github/workflows/ci.yml  tests/conftest.py
```

**运行时实测**（临时虚拟环境，`sanic==23.6.0` + `tortoise-orm==0.20.0` + `PyJWT` +
`argon2-cffi` + `cryptography` + `captcha` + `pydantic`）：

| 实测项 | 结果 |
|---|---|
| `import app.api` | ✅ 成功（无 `BlueprintGroup.add_blueprint` 报错） |
| `create_app('testing')` 后的完整路由表 | 116 条路由 / 77 个不同 path，其中 39 个在 `/api/v1` 下 |
| OpenAPI 规范 path 数 | **66**（`GET /swagger.json` 实测） |
| `app.config` 生效值（development） | `ENV=development`、`DEBUG=True`、`CACHE_TYPE=memory`、`DATABASE_URL=sqlite://<root>/sanic_admin_dev.sqlite3`、`CORS_ALLOWED_ORIGINS=['*']`、`SESSION_COOKIE_SECURE=False`、`ROUTE_CACHE_ENABLED=False`、`DB_NAME=sanic_admin_dev` |
| production 真正必填的环境变量 | 仅 `JWT_PRIVATE_KEY` 与 `INITIAL_ADMIN_PASSWORD`；`SECRET_KEY` / `PASSWORD_SALT` 缺失时**照常启动**（`app/config.py:330-331` 已是 `os.getenv(var, "")`） |
| `POST /auth/login` | ✅ 200，返回账户 JSON + `Set-Cookie: session=<JWT>` + `Authorization: Bearer <JWT>` |
| `GET /auth/me` | 404（该路由不存在） |
| `GET /health` | ✅ 200，`{"status":"ok","env":"testing"}` |
| `GET /swagger` | 302 → `/swagger/index.html` → 200（Swagger UI） |
| `GET /redoc` | ✅ 200 |
| `GET /swagger.json` | ✅ 200，OpenAPI 3.0.3 规范，68 条 path |
| `GET /docs` | 302 → `/swagger` |
| `GET /docs/openapi.json` | 404（`app/docs/routes.py` 不注册它；该路径由 sanic-ext 提供，只在 `ENABLE_API_DOCS=false` 时可达） |
| `GET /amis/` / `GET /amis/login.html` | ✅ 200，登录页 HTML |
| `GET /amis`（无尾斜杠） | 404（Sanic `DirectoryHandler` 只对带尾斜杠的路径做 index 查找） |
| `GET /uploads/anything` | 404（上传目录不再静态托管） |
| `DELETE /api/v1/settings/key/x` | 404 而非 405（405 兜底只覆盖 account / role / profile 三个资源） |
| `GET /api/v1/settings`（未认证） | 401 `AUTHENTICATION_ERROR` |
| CORS（`Origin` 头 + `*` 白名单） | ✅ 返回 `Access-Control-Allow-Origin: *`，**不带** `Allow-Credentials` |
| OPTIONS 预检 | ✅ 204 + CORS 头 |
| gzip（3 KB 响应 + `Accept-Encoding: gzip`） | ✅ `Content-Encoding: gzip` + `Vary: Accept-Encoding`，且 CORS 头仍在 |
| 小响应（< 1 KB） | ✅ 不压缩 |
| 中间件顺序（dump `app.request_middleware` / `app.response_middleware`） | 请求：`handle_preflight → log_request → AuthMiddleware`；响应：`compression_middleware → log_response → add_cors_headers` |
| `pytest` | 171 passed, 0 failed, 0 errors（`app/` 覆盖率 52%） |

**未能实测**：production 下 Redis 不可达的 `ConfigError` 路径、MySQL / PostgreSQL 真实连接。
这两条依据源码逻辑推断，已在对应章节标注。
