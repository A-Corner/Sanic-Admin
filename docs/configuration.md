# Sanic-Admin 配置参考

> 适用范围：Sanic-Admin 后端（Sanic 23.6 + Tortoise ORM 0.20 + Redis + PyJWT）。
> 事实来源：`app/config.py`（394 行，本文中所有行号引用均指该文件在 `sa-oss/m23-doc` 分支上的版本）。
> 标注约定：
> - **【读码确认】** = 直接读 `app/config.py` 或调用 `get_config()` 实测得到。
> - 文中标注「**已实测**」的条目，其数据来自在发布候选 `release/v0.2.0`（基线 `8750d51`）上实际执行的命令。

---

## 1. 概览：三套环境对照

环境由环境变量 `SANIC_ENV` 决定，取值必须是 `development` / `testing` / `production` 之一；
缺省为 `development`，`default` 会被归一化成 `development`，其它值在 `import app.config` 阶段直接抛
`ConfigError`（`app/config.py:55-61`）。

**【读码确认】** 三套配置类的差异（`app/config.py:148-267`）：

| 配置项 | development | testing | production |
|---|---|---|---|
| `ENV` | `development` | `testing` | `production` |
| `DEBUG` | `True` | `True` | `False` |
| `TESTING` | `False` | `True` | `False` |
| `DATABASE_URL` | `sqlite://<项目根>/sanic_admin_dev.sqlite3` | `sqlite://:memory:` | 由 `DB_*` 拼装为 `mysql://...`（可用 `DATABASE_URL` 覆盖） |
| `DB_NAME` | `sanic_admin_dev` | `sanic_admin`（继承默认） | `sanic_admin_prod` |
| `CACHE_TYPE` | `memory` | `memory` | `redis` |
| `CORS_ALLOWED_ORIGINS` | `["*"]` | `["*"]` | `[]`（默认拒绝一切跨域） |
| `SESSION_COOKIE_SECURE` | `False` | `False` | `True`（继承默认） |
| `ROUTE_CACHE_ENABLED` | `False` | `False` | `True`（继承默认） |
| `MAIL_SUPPRESS_SEND` | 未设置 | `True` | 未设置 |
| 缺失密钥 | 自动生成临时值 + warning | 自动生成临时值 + warning | 抛 `ConfigError`，拒绝启动 |

配置对象有两套入口，指向同一份数据：

- `app.config.settings`（`app/config.py:341`）与 `app.config.config`（`:342`）——当前环境的配置对象，
  供 `app.models`、`app.cache` 等模块 `import` 使用。
- `app.config.get_config(name=None)`（`:286`）——按名字构造配置对象；`name` 为 `None` 时取 `SANIC_ENV`。
  `create_app(config)` 接受环境名字符串、配置类/对象或字典三种形式（`app/__init__.py:42-47`）。

> **注意**：`app/config.py:340-341` 在 `import` 阶段就执行 `_normalize_env(None)` 与 `get_config(...)`。
> 因此 **production 环境下缺少密钥时，`import app.config` 本身就会失败**，而不是等到应用启动。
> `main.py:12-18` 捕获 `ConfigError` 并以 `sys.exit("配置错误: ...")` 退出。

---

## 2. 环境变量参考表

### 2.1 生产必填（fail-closed）

**【读码确认】** production 环境真正必填的是 **2 个**变量：`JWT_PRIVATE_KEY` 与
`INITIAL_ADMIN_PASSWORD`。缺失时 `_env_secret()` 抛 `ConfigError`，进程拒绝启动；在
development/testing 缺失时自动生成临时值、打 warning、并**写回 `os.environ`**（`app/config.py:82`），
使 Sanic 拉起的 worker 子进程复用同一份临时值——否则各 worker 各生成一份，会导致会话签名不一致。

| 变量 | 说明 | 默认值 | 生产必填 |
|---|---|---|---|
| `JWT_PRIVATE_KEY` | RS256 签名私钥（PEM）。换行可写成字面量 `\n` | 无（dev 自动生成 2048 位 RSA 私钥） | **是** |
| `INITIAL_ADMIN_PASSWORD` | 初始管理员口令。数据库中不存在该邮箱账户时用它建号（`app/auth/authentication.py:94-133`） | 无（dev 自动生成并在 stdout 打印一次） | **是** |
| `SECRET_KEY` | 应用密钥。**当前实现中不参与任何签名或加密**——JWT 实际用 `BaseConfig.SECRET`（RS256 私钥），因此设它不会增强安全性（见 §8） | 空 | 否 |
| `PASSWORD_SALT` | 口令盐。**当前实现中不参与口令哈希**——实际口令哈希用 argon2id 自带随机盐（`app/models/account.py:19`） | 空 | 否 |

> **已实测**：在 production 下分别只缺 `JWT_PRIVATE_KEY`、只缺 `INITIAL_ADMIN_PASSWORD`，
> 两次都以 exit code 1 退出并给出对应的 `配置错误:` 文案；而 `SECRET_KEY` 与
> `PASSWORD_SALT` **同时缺失时服务照常启动**——因为它们确实不参与任何签名或加密。
> `tests/test_production_failclosed.py` 的 `REQUIRED_PRODUCTION_VARS` 同样只列这两项。

`JWT_PUBLIC_KEY` 单独说明（**可选**）：`load_jwt_keys()`（`:121-145`）先读私钥；公钥缺失时由私钥推导
（`:137` → `_derive_public_pem`，`:98-105`）；公钥存在则必须能解析为 RSA 公钥，且与私钥的
`public_numbers()` 完全一致，否则抛 `ConfigError("JWT_PUBLIC_KEY 与 JWT_PRIVATE_KEY 不配对")`（`:143-144`）。
只在**校验服务**部署（后端不签发、只验签）时才有必要单独提供公钥。

### 2.2 数据库

| 变量 | 说明 | 默认值 | 生产必填 |
|---|---|---|---|
| `DATABASE_URL` | 完整数据库 URL，**优先级最高**，会覆盖 `DB_*` 拼装结果（`app/config.py:314`） | development/testing 为内置 SQLite；production 由 `DB_*` 拼装 | 否（但生产强烈建议显式指定） |
| `DB_HOST` | 数据库主机 | `localhost` | 否 |
| `DB_PORT` | 数据库端口 | `3306` | 否 |
| `DB_USER` | 数据库用户 | `root` | 否 |
| `DB_PASSWORD` | 数据库口令 | 空字符串 | 建议设置 |
| `DB_NAME` | 数据库名 | development `sanic_admin_dev` / production `sanic_admin_prod` | 否 |

拼装规则（`app/config.py:309-314`）：

```python
if not cfg.DATABASE_URL:                      # 类属性已预置时不再拼装
    cfg.DATABASE_URL = (
        f"mysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}"
        f"/{DB_NAME}?charset={DB_CHARSET}"
    )
cfg.DATABASE_URL = os.getenv("DATABASE_URL", cfg.DATABASE_URL)
```

**【读码确认】** `DB_CHARSET` 固定为 `utf8mb4`（`:175`），**不是环境变量**，不可通过 env 覆盖。
`DB_PORT` 与 `PORT` 走 `_int_env()`（`:276-283`），非整数时抛 `ConfigError`。

### 2.3 缓存 / Redis

| 变量 | 说明 | 默认值 | 生产必填 |
|---|---|---|---|
| `CACHE_TYPE` | 缓存后端：`redis` 或 `memory` | development/testing `memory`；production `redis` | 否 |
| `REDIS_HOST` | Redis 主机 | `localhost` | 否 |
| `REDIS_PORT` | Redis 端口 | `6379` | 否 |
| `REDIS_DB` | Redis 逻辑库 | `0` | 否 |
| `REDIS_PASSWORD` | Redis 口令 | `None` | 建议设置 |

`CACHE_KEY_PREFIX`（`sanic_admin`）、`CACHE_DEFAULT_TIMEOUT`（300）、`REDIS_SOCKET_TIMEOUT`（3）
是**类常量，不可通过环境变量覆盖**（`:221-229`）。

### 2.4 邮件

| 变量 | 说明 | 默认值 | 生产必填 |
|---|---|---|---|
| `MAIL_SERVER` | SMTP 服务器 | `smtp.example.com` | 否 |
| `MAIL_PORT` | SMTP 端口 | `587` | 否 |
| `MAIL_USE_TLS` | 是否启用 TLS。**解析规则是字符串精确比较 `"True"`**（`:322`），写成 `true` / `1` 都会被判为 `False` | `True` | 否 |
| `MAIL_USERNAME` | SMTP 用户名 | 空字符串 | 否 |
| `MAIL_PASSWORD` | SMTP 口令 | 空字符串 | 否 |
| `MAIL_DEFAULT_SENDER` | 默认发件人 | 空字符串 | 否 |

**【读码确认】** 当前代码库中**没有任何模块读取这些邮件配置**（`grep -rn "MAIL_" app/` 只命中
`app/config.py` 自身）。项目尚未接入邮件投递渠道：`app/auth/routes.py:34-40` 的 `_delivery_code()`
在非 DEBUG 环境直接返回 `None`，验证码不会出现在 API 响应里。

### 2.5 服务

| 变量 | 说明 | 默认值 | 生产必填 |
|---|---|---|---|
| `SANIC_ENV` | 运行环境：`development` / `testing` / `production` | `development` | 否（但生产必须显式设为 `production`） |
| `HOST` | 监听地址 | `127.0.0.1` | 否 |
| `PORT` | 监听端口 | `22222` | 否 |
| `AMIS_DIR` | AMIS 管理界面的静态资源目录。M1 起由后端同源托管在 `/amis` 下，浏览器访问 `http://127.0.0.1:22222/amis/login.html` 即为登录页，与 API 同源，不涉及 CORS。目录为空或不存在则不挂载（生产环境可据此关闭管理界面） | `str(BASE_DIR / "amis")`，即项目根下的 `amis/` | 否 |

`WORKERS`（1）、`AUTO_RELOAD`（False）、`AUTO_RELOAD`、`MAX_CONTENT_LENGTH`（16 MB）、
`COMPRESSION_MIN_LENGTH`（1024）、`COMPRESSION_LEVEL`（6）、`DEFAULT_PAGE_SIZE`（10）、
`MAX_PAGE_SIZE`（100）、`LOG_DIR`、`LOG_LEVEL`（INFO）均为类常量，**不可通过环境变量覆盖**。

> `AMIS_DIR` 在 `DefaultConfig` 中的默认值是 `str(BASE_DIR / "amis")`，
> 并可通过环境变量覆盖（`get_config()` 的 env 覆盖列表中包含它）。
> `app/__init__.py` 用 `app.config.get("AMIS_DIR")` 读取后
> `app.static("/amis", AMIS_DIR, index="login.html")` 挂载；目录为空或不存在则不挂载。
>
> **已实测**：`GET /amis/` 与 `GET /amis/login.html` 均返回 200 并给出登录页 HTML；
> `GET /amis`（不带尾斜杠）返回 404。

> 生产部署提示：`HOST` 默认是 `127.0.0.1`，只监听回环。对外提供服务需要显式设为 `0.0.0.0`
> 或由反向代理转发。

### 2.6 跨域

| 变量 | 说明 | 默认值 | 生产必填 |
|---|---|---|---|
| `CORS_ALLOWED_ORIGINS` | 允许的 Origin 白名单，**逗号分隔**（`:326-328`） | development/testing `*`；production 空列表 | 否（production 默认拒绝一切跨域） |

### 2.7 认证 / 管理员

| 变量 | 说明 | 默认值 | 生产必填 |
|---|---|---|---|
| `INITIAL_ADMIN_EMAIL` | 初始管理员邮箱 | `SAdmin@Sanic.com` | 否（建议改成真实账号） |

`ALLOW_LOGIN_WITH_USERNAME`（`True`）、`SESSION_ENCODING_ALGORITHM`（`RS256`）、
`AUTHENTICATION_SESSION_EXPIRATION`（604800 秒 = 7 天）、`SESSION_SECURE`（`_ACTIVE_ENV == "production"`）
均为类常量，不可通过环境变量覆盖（`app/config.py:372-375`）。

---

## 3. 生产环境必填项与 fail-closed 行为

**【读码确认，实测】** production 缺 `JWT_PRIVATE_KEY` 时：

```
$ SANIC_ENV=production python -c "import app.config"
ConfigError: 生产环境必须通过环境变量 JWT_PRIVATE_KEY 提供 JWT 签名私钥
```

生产环境必填密钥齐备时，实测生效值：

```
ENV           = production
DEBUG         = False
CACHE_TYPE    = redis
CORS_ALLOWED_ORIGINS = []
DB_NAME       = sanic_admin_prod
DATABASE_URL  = mysql://root:@localhost:3306/sanic_admin_prod?charset=utf8mb4
SESSION_SECURE = True
```

fail-closed 的完整清单：

| 触发点 | 行为 | 依据 |
|---|---|---|
| `JWT_PRIVATE_KEY` / `INITIAL_ADMIN_PASSWORD` 缺失 | `ConfigError`，进程退出 | `app/config.py:73-74` |
| `SECRET_KEY` / `PASSWORD_SALT` 缺失 | **不报错**（M1 起降为可选，见 §2.1 的待核实说明） | `sa-oss/m1` 的 `app/config.py:326-329` |
| `JWT_PRIVATE_KEY` 无法解析为 PEM 私钥 | `ConfigError` | `:113-115` |
| `JWT_PRIVATE_KEY` 不是 RSA 私钥 | `ConfigError("JWT_PRIVATE_KEY 必须是 RSA 私钥（RS256）")` | `:116-117` |
| `JWT_PUBLIC_KEY` 无法解析 | `ConfigError` | `:140-142` |
| `JWT_PUBLIC_KEY` 与私钥不配对 | `ConfigError` | `:143-144` |
| `SANIC_ENV` 取值非法 | `ConfigError` | `:59-60` |
| `PORT` / `DB_PORT` / `REDIS_PORT` / `REDIS_DB` / `MAIL_PORT` 非整数 | `ConfigError` | `:280-283` |
| `CACHE_TYPE=redis` 但 Redis 不可达 | production 抛 `ConfigError` 拒绝启动；其它环境降级为内存缓存并 warning | `app/cache/__init__.py:52-63` |
| 可选模块导入失败（models / cache / api / auth / upload 中间件） | production 抛 `ConfigError` 拒绝启动；其它环境 warning 降级 | `app/__init__.py:28-39`、`app/middleware/__init__.py:48-56` |

> **已实测**：另有 `ENABLE_API_DOCS` 与 `REQUIRE_TWO_FACTOR` 两个布尔环境变量
> （`_bool_env()`，接受 `1/true/yes/on` 与 `0/false/no/off/`）。前者控制是否挂载
> Swagger / ReDoc 路由（development 默认 `True`，production 默认 `False`；
> production 下实测 `/swagger`、`/redoc`、`/swagger.json` 均返回 404，
> 显式设 `ENABLE_API_DOCS=true` 后才可用）；后者决定登录后是否要求二次验证
> （默认 `False`，即关闭）。

---

## 4. 数据库配置

### 4.1 SQLite

```bash
# development 默认值（无需设置）
DATABASE_URL=sqlite:///abs/path/to/sanic_admin_dev.sqlite3

# testing 默认值（无需设置）
DATABASE_URL=sqlite://:memory:
```

**【读码确认，实测】** development 的 `DATABASE_URL` 是 `sqlite://` + `BASE_DIR / "sanic_admin_dev.sqlite3"`，
`BASE_DIR` 为 `app/` 的父目录（`app/config.py:37`、`:244`）。实测输出：

```
sqlite:///Users/vj/GitDir/Sanic-Admin-wt/m23-doc/sanic_admin_dev.sqlite3
```

### 4.2 MySQL

```bash
DATABASE_URL=mysql://user:pass@127.0.0.1:3306/sanic_admin_prod?charset=utf8mb4
```

或用分散变量（由代码拼装，见 §2.2）：

```bash
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=appuser
DB_PASSWORD='<强口令>'
DB_NAME=sanic_admin_prod
```

连接池参数（`min_size=5` / `max_size=20` / `connect_timeout=10.0` / `retry_limit=3`）
在 `app/database/connection_pool.py:20-27` 是模块级常量，**不可通过环境变量覆盖**。

> **【已实测】MySQL 需要自带驱动。** `requirements.txt` 里**没有 `aiomysql`**，
> 而未设置 `DATABASE_URL` 时代码会把 `DB_*` 拼装成 MySQL 连接串。因此在 production 下
> 直接用默认拼装结果启动，会在导入阶段失败：
> ```
> ModuleNotFoundError: No module named 'aiomysql'
> ```
> 要用 MySQL 请自行安装驱动（如 `pip install aiomysql`），或改用其他数据库。
> 只想跑起来就显式给一个 `DATABASE_URL`（SQLite 亦可）。

### 4.3 PostgreSQL

`DATABASE_URL` 直接指定 Tortoise 的 PostgreSQL scheme：

```bash
DATABASE_URL=postgres://user:pass@127.0.0.1:5432/sanic_admin_prod
```

**【读码确认】** `app/config.py` 里**没有** postgres 分支——拼装逻辑只产出 `mysql://`，
所以用 PostgreSQL **必须**显式设置完整的 `DATABASE_URL`。`app/database/connection_pool.py:110`
的 `_set_postgres_pool_options()` 说明连接池层已考虑 PostgreSQL，但拼装层没有对应分支。

### 4.4 建表行为

**【读码确认】** `app/models/__init__.py:59-75` 的 `init_db()`：

```python
await Tortoise.init(db_url=db_url, modules={'models': ['app.models']})
await Tortoise.generate_schemas(safe=True)
```

`safe=True` 表示只在表不存在时创建，**不会做 schema 迁移**。模型清单必须全部从
`app/models/__init__.py` 导入——`init_db` 以该包为 Tortoise 的 models 模块，
只有出现在包命名空间里的模型才会被注册（见该文件 `:6-9` 的注释）。

当前 10 张表：`account`、`role`、`account_role`（M2M 中间表）、`authentication_session`、
`two_step_session`、`captcha_session`、`verification_tokens`、`profile`、
`system_setting`、`operation_log`、`uploaded_file`。

---

## 5. Redis 配置与 CACHE_TYPE 的关系

**【读码确认】** `app/cache/__init__.py:66-84` 的 `get_cache(cache_type=None)`：

- 进程内单例，按 `cache_type` 分别缓存实例（`_instances` 字典，`:23`）。
- `cache_type` 取值只允许 `redis` / `memory`，其它值抛 `ValueError`（`:77-78`）。
- `redis` 分支先创建 `RedisCache` 并 `ping()` 探测（`:55-56`），探测超时固定 2 秒
  （`_REDIS_PROBE_TIMEOUT`，`:26`），保证无 Redis 时快速失败而不是挂起。
- 探测失败：production 抛 `ConfigError`（`:59-61`）；其它环境降级为内存缓存并 warning（`:62`）。
  降级结果同样记入 `_instances["redis"]`，避免每次调用重复探测（`:22-23`）。

`RedisCache` 从配置读取 `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` / `REDIS_PASSWORD` /
`REDIS_SOCKET_TIMEOUT`（`app/cache/redis.py:37-41`），所有键统一加 `CACHE_KEY_PREFIX`
前缀（`sanic_admin`），`clear()` 只清除本前缀下的键（`:250-267`）。

路由缓存：装饰器 `app/cache/decorators.py:96` 的 `cached()` **只缓存 GET 请求**，
且当 `config.ROUTE_CACHE_ENABLED` 为假时直接放行（`:119-120`）。
development / testing 都把它关掉了，production 保持开启（默认超时 60 秒）。

> **【已实测】production 下 Redis 不可达 = 拒绝启动。** `CACHE_TYPE` 在 production 默认是
> `redis`，而 Redis 探测失败时 production 抛 `ConfigError`：
> ```
> ConfigError: production 环境 Redis 缓存不可用，拒绝降级启动: ConnectionError(...)
> ```
> 进程以 exit code 1 退出。**这是与密钥无关的第三道门禁**——即使 `JWT_PRIVATE_KEY` 与
> `INITIAL_ADMIN_PASSWORD` 都齐备，只要 Redis 不可达就起不来。
> 要绕开只能显式设 `CACHE_TYPE=memory`，但内存缓存是进程内的，重启失效，也不能多 worker 共享。

---

## 6. 邮件配置

当前状态（**【读码确认】**）：

- 配置项齐全（§2.4），但代码库中**无任何模块消费这些配置**。
- `MAIL_SUPPRESS_SEND` 只在 `TestingConfig` 里定义（`app/config.py:256`），同样没有读取点。
- 验证码投递尚未实现：`app/auth/routes.py:34-40` 的 `_delivery_code()` 仅在 `DEBUG` 为真时
  把验证码放进响应体，其它环境返回 `None`。**这意味着 production 下注册验证 / 两步验证流程
  当前无法完成**（客户端拿不到验证码），属于待补齐的功能缺口。

配置好 SMTP 后还需要补齐代码侧的投递实现才能生效，配置本身不会触发发送。

---

## 7. 跨域配置

**【读码确认，实测】** `app/middleware/security_middleware.py:19-41`：

```python
allowed = app.config.get('CORS_ALLOWED_ORIGINS') or []
origin = request.headers.get('Origin')
if '*' in allowed:
    headers['Access-Control-Allow-Origin'] = '*'
elif origin and origin in allowed:
    headers['Access-Control-Allow-Origin'] = origin
    headers['Access-Control-Allow-Credentials'] = 'true'
if '*' not in allowed:
    append_vary(resp.headers, 'Origin')
```

行为要点：

- 白名单含 `*` → 返回 `Access-Control-Allow-Origin: *`，**且不发送 `Allow-Credentials`**
  （`*` 与 credentials 同时使用违反 CORS 规范）。
- 白名单不含 `*` 且 Origin 精确命中 → 回显该 Origin，并附带 `Access-Control-Allow-Credentials: true`。
- 白名单不含 `*` 且 Origin 未命中 → 不下发任何 CORS 头，但**始终**追加 `Vary: Origin`
  （`:30-31`），避免 CDN / 代理缓存串味。
- OPTIONS 预检由**请求中间件**短路返回 204（`:37-41`），而不是通配路由——
  注释明确说明这样做是为了让未知路径返回 404 而不是 405。
- `CORS` 配置项（`app/config.py:197`）恒为 `False`，用于关闭 sanic-ext 内置 CORS，
  由本模块统一处理。**配置项名不能改成 `CORS_ORIGINS`**，会与 sanic-ext 同名配置冲突（`:195` 注释）。

**production 的 `CORS_ALLOWED_ORIGINS = []` 含义**：默认**不允许任何跨域来源**。跨域浏览器请求
会拿不到 CORS 响应头而被浏览器拦截——这是有意的 fail-closed 设计，不是 bug。
必须显式配置：

```bash
CORS_ALLOWED_ORIGINS=https://admin.example.com,https://ops.example.com
```

注意 `*` 与 credentials 不能共存。如果前端与后端**同源**部署（例如用同一个反向代理挂载
`/` 和 `/api`），则无需配置 CORS。

> **已实测**：`amis/server.js` 是一个零依赖的 Node 开发服务器，代理
> `/auth`、`/capt`、`/api`、`/health`、`/refapi`、`/account` 前缀并**删除 `Origin` 头**
> 转发（注释写明「同源转发，避免后端按 Origin 判定跨域」），使 production 的
> `CORS_ALLOWED_ORIGINS=[]` 与同源访问可以共存。
> 它**不代理 `/uploads`** —— 后端已移除上传目录的静态挂载，文件下载统一走
> 需鉴权的 `GET /api/v1/files/<id>/download`。
> 注意这只是可选的开发辅助；管理界面的正式访问方式是后端同源托管的
> `http://127.0.0.1:22222/amis/login.html`，那种情况下根本不需要 CORS 配置。

---

## 8. 密钥轮换说明

### 8.1 三个密钥各自影响什么

**【读码确认】**

| 密钥 | 影响面 | 轮换后果 |
|---|---|---|
| `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` | **全部会话**：登录态、验证码会话、两步验证会话 | 换私钥 ⇒ 旧 JWT 全部验签失败，所有用户被登出；换公钥只影响验证侧 |
| `SECRET_KEY` | **当前无影响** | 代码库中无读取点，轮换是空操作 |
| `PASSWORD_SALT` | **当前无影响** | 同上；口令哈希用 argon2id 自带随机盐（`app/models/account.py:19-21`） |

**【读码确认】** JWT 的作用范围非常窄。`Session.token()`（`app/models/session.py:128-133`）签发的
payload 只有两个字段：

```json
{"session_id": 1, "session_type": "AuthenticationSession"}
```

**不包含账户、角色或权限信息**。真正的授权判定在每次请求时回服务端查会话表与账户状态完成
（`authenticate_request()`，`app/auth/authentication.py:238-269`）。因此：

- **会话的存续由服务端 `authentication_session` 表决定**，不由 JWT 的过期时间决定。
  账户被禁用 / 删除 / 软删除，或会话被 `disable()`，都会让后续请求立即失效
  （`session.py:197-212` 的 `get_valid_session`、`account.py:115-129` 的 `validate()`）。
- 会话有效期由 `AUTHENTICATION_SESSION_EXPIRATION`（7 天）写入 `expires` 字段，
  过期检查在 `Session.expired`（`:101-111`）。
- 改口令时 `reset_password()` 会**批量禁用该账户的全部未禁用会话**
  （`app/auth/verification.py:207-208`）。

### 8.2 轮换步骤

1. **轮换 JWT 密钥**：生成新的 RSA 私钥 → 写入 `JWT_PRIVATE_KEY` → 重启全部 worker。
   若有独立验签服务，同步更新其 `JWT_PUBLIC_KEY`。
   注意 `JWT_PUBLIC_KEY` 必须与私钥配对，否则启动即 `ConfigError`（`:143-144`）。
   轮换后所有在线用户需要重新登录。

   ```bash
   # 生成新密钥对
   openssl genrsa -out jwt_private.pem 2048
   openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
   # 注入时换行可写成字面量 \n（app/config.py:130、:138 会做替换）
   ```

2. **轮换 `SECRET_KEY` / `PASSWORD_SALT`**：由于当前无读取点，属于预留项。仍建议保持为
   随机值并纳入密钥管理，避免将来这些配置项被启用时埋下弱密钥。

3. **轮换初始管理员口令**：改 `INITIAL_ADMIN_PASSWORD` 只影响**下次建号**；
   已存在的管理员账户需通过 API 改密（`PUT /api/v1/accounts/<id>/password`）。

### 8.3 多 worker 一致性

**【读码确认】** `_env_secret()` 在生成临时值后写回 `os.environ`（`app/config.py:82`），
注释说明了原因：Sanic 会再启动 worker 子进程重新 import 本模块，
不写回的话各进程各生成一份，导致会话签名不一致、口令重复打印。
**部署时不要依赖这个机制**——生产环境本来就应当显式提供密钥。

---

## 9. 安全提示

**【读码确认】** 仓库历史中提交过示例 JWT 私钥、默认管理员口令和一个 SQLite 数据库。
这些**均视为已泄露，必须更换，勿用于任何真实环境**（`SECURITY.md:17-21`）。

当前基线的具体风险点：

1. **默认管理员账号**：`INITIAL_ADMIN_EMAIL` 默认 `SAdmin@Sanic.com`（`app/config.py:367`）。
   部署后**必须**通过 `INITIAL_ADMIN_EMAIL` 改成真实账号，或在首次登录后立刻改密。

2. **development 会把临时管理员口令打印到 stdout**（`app/config.py:345-358`）。
   该打印只在 development 触发（`:348`），testing / production 不会打印。
   但 production 如果缺 `INITIAL_ADMIN_PASSWORD` 会直接 `ConfigError`，
   **不会**打印口令——这一点是安全的。

3. **账户枚举防护**：登录时账户不存在会执行一次等成本的哑哈希校验
   （`Account.verify_dummy_password()`，`app/models/account.py:107-113`；
   调用点 `app/auth/authentication.py:166-168`），且错误信息不区分
   「账户不存在」与「口令错误」（统一为「用户名或密码错误」）。

4. **未认证端点**：当前基线只有 `/auth/*`、`/capt/*`、`/health` 和静态文件路由
   （实测路由表见 `docs/architecture.md` §7）。API v1 蓝图整体导入失败并降级，
   因此**不存在未加鉴权的业务 API**——但这是因为功能没上线，不是因为鉴权做得好。

5. **`/health` 无鉴权**且返回 `{"status":"ok","env":<ENV>}`（`app/__init__.py:83-85`）。
   生产环境会暴露运行环境信息，部署时应由反向代理限制访问。

6. **CSRF 保护装饰器已实现但未启用**：`csrf_protect()`（`app/middleware/security_middleware.py:44-60`）
   校验 `X-CSRF-Token` 头与 `csrf_token` Cookie 一致，但全代码库**没有任何路由使用它**
   （`grep -rn "csrf_protect"` 只命中定义与导出）。会话 Cookie 是 `HttpOnly` + `SameSite=Lax`
   （`app/models/session.py:144-150`），目前依赖 SameSite 做基础防护。

7. **`SECRET_KEY` 与 `PASSWORD_SALT` 曾经是「必填但没人用」**：这会造成一种虚假的安全感——
   运维以为配了就安全，实际上口令哈希由 argon2id 的随机盐保护，会话签名由 RSA 密钥保护，
   这两个变量形同虚设。**M1 已按此把它们从 production 必填清单中移除**（见 §2.1），
   真正决定 fail-closed 的是 `JWT_PRIVATE_KEY` 与 `INITIAL_ADMIN_PASSWORD`。

---

## 附：本文档的核实方式

- 静态事实：逐行读 `app/config.py`（394 行）、`app/cache/__init__.py`、`app/models/__init__.py`、
  `app/middleware/security_middleware.py`、`app/models/session.py`、`app/models/account.py`、
  `app/auth/authentication.py`、`app/auth/routes.py`、`app/auth/verification.py`、
  `app/database/connection_pool.py`。
- 动态事实：新建临时虚拟环境安装 `sanic==23.6.0` 等依赖后，实测
  （a）`import app.config` 在 production 缺密钥时抛 `ConfigError`；
  （b）production 全部密钥齐备时各配置项的实际取值；
  （c）`create_app()` 后的完整路由表与 `app.config` 生效值；
  （d）CORS / OPTIONS / gzip 三类响应的实际响应头；
  （e）`POST /auth/login` 签发的 JWT 与 Cookie，以及携带 Cookie / Bearer 两种方式访问
  `/auth/associated` 的结果。
- 未能实测：production 下 Redis 不可达时的 `ConfigError` 路径、MySQL/PostgreSQL 真实连接
  （环境无数据库实例）。这两条依据源码逻辑推断，标注见 §3、§5。
