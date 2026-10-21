# AGENTS.md — 供 AI 代理参与本仓库维护

本文件是 AI 代理（如 Codex、Claude Code）在本仓库工作时的**唯一操作契约**。
人类贡献者请看 [CONTRIBUTING.md](CONTRIBUTING.md)；本文件只覆盖 AI 代理需要额外知道的
部分（当前基线的真实状态、可验证命令、硬性禁区）。

**所有命令与数字都来自基线 `9a8f946`（分支 `sa-oss/m23-d`）的实测**，不是从文档推断。
未在本文件出现的命令，请先自己跑一遍再写进 PR 描述。

---

## 0. 一句话现状（务必先读）

本仓库正处于**重构中段**，`README.md` 明确写了"尚不可用于生产环境"。
后端骨架（配置 / 中间件 / 模型 / 认证 / 缓存 / 文档装饰器）已可运行，
但 **API v1 资源层当前整体降级不可用**，测试**收集阶段即 6 个模块报错**。

因此：

- 你的第一个 PR 很可能很小。**先读 §10 已知问题**，别把"跑通全量测试"当成自己的锅。
- **不要**为了"让 CI 变绿"去改 `tests/` 或 `app/` 的既有实现来迎合断言——除非那个任务
  本身就是修它（那属于 §9 的上游任务）。
- **不要**把"当前失败"写成"应该通过"。报告测试状态时贴真实数字。

---

## 1. 项目结构

真实目录树（已剔除 `amis/` 下 `vendor`/`sdk`/`fonts`/`images`/`css`/`js`/`public` 等第三方
拷贝，以及 `__pycache__`/缓存目录）：

```
.
├── main.py                     # 唯一入口：create_app(settings) + app.run(...)
├── pyproject.toml              # 项目元数据 + pytest / ruff 配置
├── requirements.txt            # 运行时依赖
├── requirements-dev.txt        # 开发依赖（-r requirements.txt + pytest/ruff 等）
├── AGENTS.md                   # 本文件
├── CONTRIBUTING.md             # 人类贡献指南
├── SECURITY.md                 # 漏洞私下报告流程
├── CHANGELOG.md                # Keep a Changelog 格式，Unreleased 段收集用户可见变更
├── CODE_OF_CONDUCT.md
├── upgrade_schema.md           # 历史进度表（描述性，非验收依据）
├── .github/
│   ├── ISSUE_TEMPLATE/{bug_report.yml,feature_request.yml}
│   ├── pull_request_template.md
│   └── workflows/ci.yml        # CI：ruff + pytest --cov
├── app/                        # ★ 后端主包
│   ├── __init__.py             # create_app()：蓝图/中间件/监听器注册 + /health
│   ├── config.py               # 多环境配置（development/testing/production）
│   ├── api/
│   │   ├── __init__.py         # api_bp(Blueprint.group) + v1_bp，⚠ 当前导入即失败
│   │   ├── base.py             # BaseResource / CRUDResource
│   │   ├── responses.py        # APIResponse / APIError 统一响应
│   │   ├── validators.py       # 参数校验规则
│   │   ├── routes.py           # 另一套 api_bp（历史遗留，未被 create_app 使用）
│   │   ├── example.py          # 文档装饰器用法示例（同样受 ⚠ 影响）
│   │   └── resources/          # account/role/profile/log/setting/upload/cache/
│   │                           # dashboard*/database/compression
│   ├── auth/                   # authentication / authorization / verification / routes
│   ├── cache/                  # base(抽象) / memory / redis / decorators
│   ├── database/               # query_optimizer / query_analyzer / connection_pool
│   ├── docs/                   # OpenAPI 生成 + 装饰器（decorators/openapi/swagger/routes/models）
│   ├── middleware/             # error_handler / security_middleware / auth_middleware
│   │                           # / compression / _headers
│   ├── models/                 # base / account / role / session / verification /
│   │                           # profile / system_setting / operation_log / uploaded_file
│   ├── services/               # exceptions（BaseError 体系）/ utils
│   └── web/                    # Jinja2 页面路由（login/index），⚠ 未被 create_app 注册
├── tests/
│   ├── conftest.py             # app/client/auth_headers 等 fixture
│   ├── test_account_api.py  test_auth.py  test_cache.py
│   ├── test_db_optimizer.py  test_integration.py  test_performance.py
│   ├── test_docs/{test_decorators,test_openapi,test_swagger}.py
│   ├── utils/{__init__,data_generator,helpers}.py
│   └── generate_coverage_report.py
├── frontend/                   # Vue 3 + Element Plus（实验性前端，20 个受版本控制文件）
│   ├── package.json  vue.config.js  .env.development  .env.production
│   ├── public/index.html
│   └── src/{api,components/layout,router,store,styles,utils,views/{dashboard,login}}
├── amis/                       # AMIS 低代码前端（主线方向），236 个受版本控制文件
│   ├── pages/*.json            # 页面 JSON（crud-list / console / login 等）
│   ├── server.js  package.json # express 静态服务器，默认 PORT=3000
│   └── login.html  site.html  login_form.html
└── docs/                       # ★ 架构文档（并行 lane 编写，当前基线尚未存在）
```

### 目录职责速查

| 目录 | 职责 | 改动影响面 |
|---|---|---|
| `app/config.py` | 全部配置与密钥来源 | 极高，牵动所有模块 |
| `app/__init__.py` | 应用工厂、蓝图注册、监听器 | 极高 |
| `app/models/` | Tortoise 模型；`init_db` 以本包为 models 模块 | 高（改字段需迁移） |
| `app/auth/` | 认证/授权/验证码/会话 | 高 |
| `app/api/resources/` | API v1 资源（当前整体降级） | 高 |
| `app/middleware/` | 错误处理、安全、认证、压缩 | 中高 |
| `app/docs/` | OpenAPI 生成与装饰器 | 中 |
| `app/cache/` | memory/redis 双后端 | 中 |
| `amis/` | 前端主线（JSON 驱动页面） | 中 |
| `frontend/` | 实验性 Vue 前端 | 低（主线不依赖） |

---

## 2. 环境与启动

### 2.1 系统依赖

| 依赖 | 版本 | 说明 |
|---|---|---|
| Python | `>= 3.10`（`pyproject.toml` 的 `requires-python`） | 实测环境：Python 3.12.11 |
| Node.js | 未在仓库中约束 | 实测环境：v24.13.0（`frontend/`、`amis/` 用） |
| libmagic | 系统库 | `python-magic` 需要。macOS: `brew install libmagic`；Debian/Ubuntu: `apt install libmagic1` |

### 2.2 安装后端依赖（实测通过）

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
```

实测结果：exit code 0。安装的关键版本：`sanic==23.6.0`、`sanic-ext==23.6.0`、
`tortoise-orm==0.20.0`、`pytest==8.4.2`、`pytest-asyncio==0.23.8`、`ruff==0.17.1`、
`pydantic==2.14.1`、`cryptography==50.0.2`、`redis==5.3.1`。

> `.gitignore` 已忽略 `.venv`（第 124 行）。**若你用了别的 venv 名字（如 `.venv-agent`），
> 它不会被忽略，提交前必须 `rm -rf`。**

### 2.3 启动后端（实测通过）

```bash
.venv/bin/python main.py
```

实测：服务在 `http://127.0.0.1:22222` 起来，日志出现
`Goin' Fast @ http://127.0.0.1:22222`、`mode: debug, single worker`、
`数据库连接初始化完成，使用: sqlite:///.../sanic_admin_dev.sqlite3`、`使用 memory 缓存后端`、
`已创建初始管理员账户: SAdmin@Sanic.com`。

启动后**必须 kill 进程**（含 Sanic 派生的 worker 子进程），否则端口 22222 会被占：
```bash
pkill -f "m23-d/.venv/bin/python main.py"   # 按自己的 worktree 路径调整
```

### 2.4 冒烟检查（实测通过）

```bash
curl -s http://127.0.0.1:22222/health
# {"status":"ok","env":"development"}
```

### 2.5 配置环境

环境由 `SANIC_ENV` 决定，默认 `development`：

| 环境 | 用途 | 数据库 | 缓存 | DEBUG |
|---|---|---|---|---|
| `development` | 本地开发 | SQLite `sanic_admin_dev.sqlite3` | memory | True |
| `testing` | 测试 | SQLite `:memory:` | memory | True |
| `production` | 生产 | MySQL（可换 PG） | **redis** | False |

可用环境变量覆盖（`app/config.py:302-323`）：`HOST`、`PORT`、`DB_HOST`、`DB_PORT`、
`DB_USER`、`DB_PASSWORD`、`DB_NAME`、`DATABASE_URL`、`CACHE_TYPE`、`REDIS_HOST`、
`REDIS_PORT`、`REDIS_DB`、`REDIS_PASSWORD`、`MAIL_*`、`CORS_ALLOWED_ORIGINS`。

### 2.6 前端（可选，两套都是"能装起来"级别）

```bash
# frontend/ — Vue 3 实验性前端
cd frontend && npm install          # 实测：added 1589 packages in 3m
npm run lint                        # 实测：exit 1，8 个 Parsing error（见 §10）
npm run serve                       # 未实测。配置见 vue.config.js：端口 8080，/api 代理 → http://localhost:8000

# amis/ — AMIS 主线前端
cd amis && npm install               # 实测：added 147 packages in 21s
npm start                           # 实测：服务起来，但 GET / → 404（见下）
```

> `frontend/` 的 `npm run lint` **当前必然失败**：仓库里没有跟踪 `.eslintrc*` 或
> `babel.config.js`，ESLint 用默认 espree 解析器读 `.js`/`.vue`，报
> `Parsing error: The keyword 'import' is reserved`。这不是你的改动引入的。
>
> `amis/` 的 `npm start` 会启动但 `GET /` 返回 **404**，因为 `amis/index.html` 不存在
> （`server.js` 的兜底 `res.sendFile(path.join(__dirname, 'index.html'))` 找不到文件）。
> `amis/site.html`、`amis/login.html` 是存在的。

---

## 3. 测试

### 3.1 命令（全部实测）

```bash
# 收集（会报 6 个错，见 §3.2）
.venv/bin/pytest --collect-only -q

# 全量
.venv/bin/pytest -q

# 忽略收集错误，把能跑的跑完
.venv/bin/pytest --continue-on-collection-errors -q

# 只跑当前唯一可完整收集的目录
.venv/bin/pytest tests/test_docs -q

# 单个文件
.venv/bin/pytest tests/test_docs/test_decorators.py -q

# CI 等价命令
.venv/bin/pytest --cov=app tests/ --cov-report=xml
```

### 3.2 基线真实数字（`9a8f946`，不要改这些数字，改了就说明你动了代码）

| 命令 | 真实结果 |
|---|---|
| `pytest --collect-only -q` | **20 tests collected, 6 errors** |
| `pytest -q` | **6 warnings, 6 errors**（`Interrupted: 6 errors during collection`） |
| `pytest --continue-on-collection-errors -q` | **1 failed, 15 passed, 7 warnings, 10 errors** |
| `pytest tests/test_docs -q` | **1 failed, 15 passed, 7 warnings, 4 errors** |
| `pytest tests/test_docs/test_decorators.py -q` | **12 passed, 3 warnings** |
| `pytest tests/test_docs/test_openapi.py -q` | **1 failed, 3 passed, 1 error** |
| `pytest tests/test_docs/test_swagger.py -q` | **3 failed** |
| `pytest --cov=app tests/ --cov-report=xml` | **6 warnings, 6 errors**（同全量） |

**6 个收集错误的根因**（全部是 `ModuleNotFoundError`）：

| 出错模块 | 缺失模块 |
|---|---|
| `tests/test_account_api.py` | `app.models.permission` |
| `tests/test_auth.py` | `app.models.permission` |
| `tests/test_cache.py` | `app.cache.backends` |
| `tests/test_db_optimizer.py` | `app.models.permission` |
| `tests/test_integration.py` | `app.models.permission` |
| `tests/test_performance.py` | `app.models.permission` |

**已可运行部分的失败详情**：

- `test_openapi_spec_generation` — **FAIL**：断言 `"/api/test/" in spec["paths"]`，
  实际规范里是 `"/api/test"`（无尾斜杠）。断言与实现不一致。
- `test_openapi_json_endpoint` / `test_swagger_ui_endpoint` / `test_redoc_endpoint` /
  `test_swagger_json_url_configuration` — **ERROR**：`sanic.exceptions.SanicException:
  Sanic app name "test_app" already in use.`。`tests/test_docs/test_openapi.py:48` 与
  `tests/test_docs/test_swagger.py:20` 各自定义了同名 `Sanic("test_app")` fixture，
  Sanic 的全局 app registry 不允许重名（`Sanic.test_mode` 未开时抛错）。

> 这 6+5 个问题都属于 §9 的上游任务（M1 / 文档 lane），**不是**你的 PR 该顺手修的。
> 除非任务书明确要求，否则请在 PR 描述里如实贴 §3.2 的数字。

### 3.3 覆盖率报告

```bash
.venv/bin/python tests/generate_coverage_report.py
```
未实测（覆盖率需要先解决 §3.2 的收集错误才有意义）。

### 3.4 CI 现状

`.github/workflows/ci.yml`：push/PR 到 `main`、`master`、`develop`、`vj-mp3` 时，
在 Python 3.10 / 3.11 / 3.12 三个版本上跑
`ruff check . --select E9,F63,F7,F82` + `pytest --cov=app tests/ --cov-report=xml`。
**按当前基线，pytest 这一步在 CI 上必然失败**（与本地一致，见 §3.2）。

---

## 4. 代码规范

规范来源是仓库里真实存在的配置与既有代码，不是通用最佳实践的复述。

### 4.1 Python 风格（来自 `pyproject.toml`）

```toml
[tool.ruff]
line-length = 127          # 不是 79，也不是 120
target-version = "py310"
extend-exclude = ["frontend", "amis", "test"]

[tool.ruff.lint]
select = ["E9", "F63", "F7", "F82"]   # 只拦语法错误 / 未定义名称，暂不收紧
```

- **行宽上限 127**。
- ruff 当前只启用 4 条硬规则（`E9` 语法错误、`F63`/`F7` 比较/语法类、`F82` 未定义名）。
  它**不会**报未使用的 import、命名风格、行长——这些靠人眼。
- CI 用 `ruff check . --select E9,F63,F7,F82`（等价于 `ruff check .`，因为 pyproject 里
  就是这四条）。实测：`ruff check .` → `All checks passed!`，exit 0。
- 提交前跑一次：`.venv/bin/ruff check .`

### 4.2 pytest 配置（来自 `pyproject.toml`）

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]      # 裸跑 pytest 自动只收 tests/
asyncio_mode = "auto"      # async def 测试无需 @pytest.mark.asyncio
```

- 新增测试放 `tests/` 下，命名 `test_*.py`。
- `asyncio_mode = "auto"`，async 测试直接写 `async def test_xxx()`。
- `tests/conftest.py` 已有 `app` / `client` / `auth_headers` / `test_user_auth_headers` fixture，
  优先复用，不要自己再造一套 app。

### 4.3 既有代码约定（从代码里读出来，不是发明的）

- **文件头**：每个 Python 文件顶部都是
  ```python
  #!/usr/bin/env python
  # -*- coding: utf-8 -*-
  ```
  后跟一段模块 docstring，说明这个模块"是什么 + 从哪迁来 + 归属哪个批次"。
  新文件照抄这个格式。
- **模块 docstring 是有信息量的**，会写明历史沿革（例如 `app/middleware/__init__.py` 写明
  "原 `app/middleware.py` 被本包同名遮蔽，内容已拆分迁入…"）。改动这类模块时**要同步更新
  docstring**，不要留过时描述。
- **类型注解**：函数签名普遍带注解（`-> dict`、`Optional[str]`、`List[Dict[str, Any]]`）。
- **注释与文档**：中文、英文均可（`CONTRIBUTING.md` 明确允许）。
- **异常体系**：业务异常继承 `app/services/exceptions.py` 的 `BaseError`，自带
  `status_code` / `error_code` / `message` 和 `to_dict()`。由
  `app/middleware/error_handler.py` 统一转成 JSON。**不要在业务代码里裸 `raise Exception`**。
- **响应格式有两套并存**：
  - `app/services/utils.py` 的 `json(message, data, status)` → `{"status":0|1,"msg":...,"data":...}`
  - `app/api/responses.py` 的 `APIResponse.success/error` → `{"success":true,"message":...,"data":...}`
  新增 API 资源用 `APIResponse`；旧的认证路由用 `utils.json`。**跟随所在模块的既有选择**，
  不要在一个文件里混用。
- **时间**：统一用 `app/services/utils.py` 的 `utcnow()`（带时区 UTC），
  比较时间用 `ensure_aware()` 处理 naive datetime。不要直接 `datetime.datetime.now()`。
- **随机值**：用 `secrets`（`get_code()` 用 `secrets.choice`），不要用 `random` 生成令牌/验证码。
- **模型**：继承 `app/models/base.py` 的 `BaseModel`（自带 `id`/`created_at`/`updated_at`/
  `deleted` 软删）。新模型**必须**在 `app/models/__init__.py` 里 import ——
  `init_db` 以 `modules={'models': ['app.models']}` 注册，只有包命名空间里的模型才会建表。
  忘了 import = 静默不建表。
- **模型字段风格**：用 Tortoise 的 `fields.IntField(pk=True)` 等**显式字段声明**（见
  `app/models/role.py`），不是 `class Meta` 里的 `fields` 字典风格。
- **权限模型**：`Role.permissions` 是 `JSONField`，格式 `{资源: [操作, ...]}`，
  `"all"` 表示该资源全部权限（`app/models/role.py:24`）。**不是**独立的 Permission 表。
- **日志脱敏**：数据库 URL 里的口令在日志中用 `app/models/__init__.py` 的 `_redact_db_url()`
  打码。写新日志时不要打印 `DATABASE_URL` 原值。

### 4.4 前端规范

- `frontend/`：`frontend/package.json` 提供 `serve` / `build` / `lint` / `test:unit`。
  依赖：Vue 3 + Element Plus + Pinia + axios + ECharts + SASS。
  `vue.config.js` 的 devServer 端口 **8080**，`/api` 代理到 `http://localhost:8000`
  （注意与后端默认 22222 不一致）。
- `amis/`：页面是 JSON（`amis/pages/*.json`），通过 `url` 字段指向后端接口。
  `amis/package.json` 的 `start` 跑 `node server.js`（express + reload）。
- 两个前端目录都不在 ruff 检查范围内（`extend-exclude`）。

### 4.5 提交信息

仓库历史用 Conventional Commits 风格，中文正文，例如：

```
fix(auth,models): 评审修正 F1/F2/F4/F5/F6（验证码计数原子化、登录等成本、入参校验…）
build(deps): 补充 cryptography 依赖并注明 libmagic 系统依赖
docs: SECURITY 去掉"已作废"表述，改为必须更换 (SA-OSS-B2)
```

类型前缀实测出现过：`fix` / `feat` / `build` / `docs` / `chore` / `refactor` / `test` / `merge`。

---

## 5. 安全底线

以下每一条都对应代码里真实存在的强制点，不是"建议"。

### 5.1 密钥绝不进仓库

- 仓库**不含任何密钥**。`app/config.py` 的密钥只来自环境变量。
- **生产环境缺任一必需变量 → 直接拒绝启动**（`app/config.py:64-83` 的 `_env_secret()`）。
  实测四个变量逐个缺失时的行为（每次只缺一个，其余三个合法）：

  | 缺失变量 | 退出码 | stderr |
  |---|---|---|
  | `SECRET_KEY` | 1 | `配置错误: 生产环境必须通过环境变量 SECRET_KEY 提供应用密钥` |
  | `PASSWORD_SALT` | 1 | `配置错误: 生产环境必须通过环境变量 PASSWORD_SALT 提供口令盐` |
  | `JWT_PRIVATE_KEY` | 1 | `配置错误: 生产环境必须通过环境变量 JWT_PRIVATE_KEY 提供 JWT 签名私钥` |
  | `INITIAL_ADMIN_PASSWORD` | 1 | `配置错误: 生产环境必须通过环境变量 INITIAL_ADMIN_PASSWORD 提供初始管理员口令` |

  `main.py:16-18` 捕获 `ConfigError` 并 `sys.exit(f"配置错误: {exc}")`。

  > **当前 production 仍起不来**，即使四个变量齐全——原因不是密钥，而是 §9 #3 的 B1d 缺陷：
  > `配置错误: 生产环境拒绝降级启动：文件下载计数中间件不可用（待 B1d 修复）`。
  > 把该缺陷隔离掉（进程内打桩 `app.api` 与 `app.api.resources.upload`，不改任何文件）后，
  > production 能正常起，`GET /health` 返回 **200** 且 `{"status":"ok","env":"production"}`。
  > 也就是说 **密钥门禁本身是有效的**，唯一的阻塞是 B1d。
- `JWT_PRIVATE_KEY` 是 **RS256 RSA 私钥 PEM**；只给私钥时公钥由私钥推导
  （`load_jwt_keys()`）。给公钥时必须与私钥配对，否则 `ConfigError`。
  PEM 里的换行可以写成字面量 `\n`。
- development/testing 缺变量时**自动生成临时值并打 warning**（不阻塞开发）。
  临时口令只在 development 打印一次到 stdout，**不进日志文件**。
- **已知泄露**：`SECURITY.md` 记录仓库历史中提交过示例 JWT 私钥、默认管理员口令和一个
  SQLite 数据库。**这些均视为已泄露，勿用于任何真实环境。**

### 5.2 生产环境 fail-closed，不降级

- development/testing：模块导入失败 → 打 `[降级]` warning，功能禁用，应用仍能启动。
- production：**同样情况直接抛 `ConfigError` 拒绝启动**。这条在 `app/__init__.py` 的
  `_optional_import()` 里对 `app.models` / `app.cache` / `app.auth.routes` / `app.api` /
  `app.api.resources` 都生效。
- 生产缓存同理：`app/cache/__init__.py` 的 `_build_redis()` 在 Redis 不可达时——
  production → 抛 `ConfigError` 拒绝降级；其他环境 → warning 并降级为内存缓存。
- **你新加的可选依赖模块时，必须沿用这个双轨模式**：dev 降级 + prod 拒绝。
  只做 dev 降级是安全缺陷。

### 5.3 生产环境的安全默认值

实测 `SANIC_ENV=production`（四个变量齐全）时的配置：

| 配置 | 值 |
|---|---|
| `DEBUG` | `False` |
| `CORS_ALLOWED_ORIGINS` | `[]`（默认**拒绝一切跨域**，必须显式配置） |
| `SESSION_COOKIE_SECURE` | `True` |
| `CACHE_TYPE` | `redis` |

- 生产**不允许** `CORS_ALLOWED_ORIGINS` 含 `*`（默认就是空列表）。
- `app/middleware/security_middleware.py` 的 CORS 逻辑：`"*"` 在白名单时回显 `*`
  且**不发** `Allow-Credentials`（`*` 与 credentials 同用违反规范）；精确命中才回显 Origin
  并带 credentials。
- `app/middleware/error_handler.py`：未捕获异常在 `DEBUG=True` 时才把 `detail` 和
  `traceback` 放进响应体。**不要在生产把 DEBUG 开着**。
- CSRF：`csrf_protect()` 装饰器要求非 GET 请求的 `X-CSRF-Token` 头与 `csrf_token` cookie
  一致，不一致返回 403。

### 5.4 其他硬性禁区

| 禁止 | 原因 / 依据 |
|---|---|
| 提交 `*.sqlite3`、`*.sqlite3-*` | `.gitignore` 已忽略；`SECURITY.md` 记录历史泄露 |
| 提交 `.DS_Store` | 已忽略（`.gitignore` 末尾） |
| 提交任何密钥 / 口令 / PEM | `SECURITY.md` |
| 在公开 Issue / PR 披露漏洞 | `SECURITY.md`：走仓库 Security 标签页的 "Report a vulnerability" |
| 把 `SECRET_KEY` 等改成代码内硬编码默认值 | `app/config.py` 的契约就是"只来自环境变量" |
| 给 production 加"缺变量也能跑"的兜底 | 会把 §5.1 的 fail-closed 拆掉 |

**已知遗留缺口（不是你的锅，但别踩）**：`.gitignore` **没有**忽略 `uploads/`，
而 `create_app()` 启动时会 `os.makedirs(UPLOAD_DIR)` 创建它。目录是空的所以 git 不会跟踪，
但如果你往里放测试文件就会误提交。上传文件属敏感数据，**不要**提交。

### 5.5 验证码不进响应体

`app/auth/routes.py` 的 `_delivery_code()`：验证码只在 `DEBUG=True` 时放进响应体方便联调，
其他环境返回 `None`（客户端拿不到验证码，因为投递渠道尚未接入）。
**不要**为了"让测试好过"把验证码改成无条件返回。

---

## 6. 容器化（Docker / compose）

> 本批由并行 lane（`sa-oss/m23-a`）交付 `Dockerfile` / `docker-compose.yml` /
> `.dockerignore` / `.env.example`。**本文件基线 `9a8f946` 尚无这些文件**，
> 合并后以下描述成立。

### 6.1 核心设计

镜像**不含任何密钥**：所有密钥由运行时环境变量注入。容器内固定 `SANIC_ENV=production`，
而 production 对缺失密钥是 fail-closed 的（§5.1）——
所以**"容器能起来"就等价于"密钥确实由 `.env` 提供了"**。

- `Dockerfile`：`FROM python:3.12-slim`；`apt-get install libmagic1 curl tzdata`
  （libmagic1 是 `python-magic` 的系统依赖，见 §2.1）；`pip install --no-cache-dir -r requirements.txt`；
  `useradd --uid 10001 appuser` + `USER appuser` **非 root 运行**；
  `HEALTHCHECK` 用 `curl -fsS http://127.0.0.1:22222/health`。
- `docker-compose.yml`：`env_file: [.env]` 注入密钥；`environment` 覆盖
  `SANIC_ENV=production` / `HOST=0.0.0.0` / `PORT=22222`；
  宿主机 `22230 → 容器 22222`；`redis` 服务在 `profiles: [redis]` 下，默认不启动。
- `.dockerignore`：排除 `.env` / `*.pem` / `*.key` / `.git` / `.venv/` / `*.sqlite3` /
  `node_modules/` 等；`!.env.example` 白名单保留样例。
- `.env.example`：27 个变量，与 `app/config.py` 实际读取的 27 个变量**完全一致**
  （双向差集为空，实测核对）。

### 6.2 命令

```bash
cp .env.example .env          # 然后把 change-me-* 全换成真实值
docker compose build
docker compose up -d
curl http://127.0.0.1:22230/health
```

### 6.3 本机环境限制（实测）

**本机 Docker daemon 无法启动**，因此 `docker compose up` **没有真实执行过**。
根因：Docker Desktop 需要加载特权助手 `com.docker.vmnetd`
（`/Library/LaunchDaemons/com.docker.vmnetd.plist`），该 helper 需要 sudo 密码交互授权。
本机也无 podman / nerdctl / lima / finch / colima 等替代运行时。

已做的替代验证（全部实测）：

| 替代项 | 方法 | 真实结果 |
|---|---|---|
| compose 静态解析 | 把 `docker-compose.yml` + `.env.example` 复制到临时目录，`.env.example` 当作 `.env`，跑 `docker compose config` | **exit 0**，YAML 合法、变量插值正确（27 个变量全部解析出值，端口映射 `22230→22222`、三个 volume、healthcheck 均正确展开） |
| Dockerfile 安全项自查 | 逐行读 | 见 §6.4 |
| production fail-closed | 本机 production 配置 + 环境变量注入实跑 | 缺任一密钥 → exit 1 + `配置错误: …`（§5.1 表）；四密钥齐全 → 仍因 B1d 缺陷 exit 1，隔离该缺陷后 → `/health` 返回 200 `env=production` |

### 6.4 Dockerfile 安全项自查（逐条结论 + 依据行号）

| 检查项 | 结论 | 依据 |
|---|---|---|
| `FROM python:3.12-slim` | ✅ | Dockerfile:12 |
| `apt-get install libmagic1` | ✅（另装 curl / tzdata / 编译期 build-essential+libffi-dev，装完 `apt-get purge`） | Dockerfile:36-43, 47-49 |
| **非 root 运行** | ✅ `USER appuser`（uid 10001） | Dockerfile:58-60 |
| **镜像内无密钥** | ✅ `ENV` 只有 `PYTHONUNBUFFERED/PYTHONDONTWRITEBYTECODE/PIP_NO_CACHE_DIR/PIP_DISABLE_PIP_VERSION_CHECK/SANIC_ENV/HOST/PORT/PYTHONPATH`，**无任何 `ENV <KEY>=<真实值>`**；密钥全部走运行时环境变量 | Dockerfile:19-26 |
| `.dockerignore` 含 `.env` / `*.sqlite3` / `.git` / `venv` | ✅ 全部存在（`.env`、`.env.*`、`!.env.example`、`*.sqlite3`、`.git`、`.venv/`、`venv/`、`env/`） | .dockerignore:9-11, 18, 37-39, 43 |
| `pip install --no-cache-dir` | ✅ | Dockerfile:47 |

---

## 7. PR 流程

### 7.1 仓库信息

- `origin` = `https://github.com/A-Corner/Sanic-Admin.git`
- `upstream` = `git@github.com:A-Corner/Sanic-Admin.git`
- 默认分支：`master`（`origin/HEAD -> origin/master`；另有 `origin/main`）
- CI 触发分支：`main`、`master`、`develop`、`vj-mp3`

### 7.2 步骤（与 `CONTRIBUTING.md` 一致）

1. **先开 Issue**（`.github/ISSUE_TEMPLATE/` 下的 `bug_report.yml` 或
   `feature_request.yml`）。较大改动先讨论再动手。
   - Bug 模板要求填：问题描述、复现步骤、期望/实际行为、环境（Python 版本 / OS / 提交 SHA）、
     日志或截图（**先去除密钥和口令**）。
2. **从最新的默认分支建功能分支**，命名 `feat/xxx`、`fix/xxx`、`docs/xxx`。
3. **改动聚焦**：一个 PR 只做一件事，不夹带无关格式化或重构。
4. **提交信息**用 Conventional Commits（见 §4.5）。
5. **推送并发起 PR**，按 `.github/pull_request_template.md` 填写：
   - 变更说明（做了什么、为什么；关联 Issue 写 `Closes #xxx`）
   - 变更类型勾选（Bug 修复 / 新功能 / 文档 / 重构·其他）
   - **测试情况**：写明**实际运行的命令与结果**；没跑就如实写没跑
   - 检查清单（改动聚焦 / 补测试 / 更新 CHANGELOG / 没提交密钥·DB·`.DS_Store`）
6. **审阅意见在原分支追加提交**，不要 force push 覆盖已评论的历史。
7. **用户可见的行为变更**要同步更新 `CHANGELOG.md` 的 `Unreleased` 段
   （Keep a Changelog 格式：`### Added` / `### Changed` / `### Removed`）。

### 7.3 AI 代理额外约束

- **不要直接 push 到 `master` / `main`。** 从默认分支切出工作分支再推。
- **不要修改** `.github/workflows/ci.yml` 来让 CI 变绿。
- **不要**为了让测试通过而删测试、skip 测试、或改断言迎合实现，除非修测试本身就是任务。
- **不要**在同一 PR 里做"重构 + 新功能"两件事。
- 每个 PR 都要能独立 review：diff 里不应出现与任务无关的文件。
- 只改 `AGENTS.md` 这类文档时，PR 里写明"无代码变更，仅文档"。

---

## 8. 架构概览

完整架构文档见 **[`docs/architecture.md`](docs/architecture.md)**，
配置项逐条说明见 **[`docs/configuration.md`](docs/configuration.md)**。

> ⚠ `docs/` 目录在基线 `9a8f946` **尚不存在**（由并行 lane `sa-oss/m23-doc` 编写，
> 已产出 `docs/architecture.md` 与 `docs/configuration.md`）。若该目录已合入，
> 本节内容以它为准；若尚未合入，以下是本文件实测得到的运行时事实。

### 8.1 请求生命周期

```
HTTP 请求
  ↓
app/middleware/__init__.py::register_all_middlewares()
  ├─ error_handler.setup_error_handlers()      # BaseError / SanicException / Exception → JSON
  ├─ security_middleware.setup_security_middleware()
  │    ├─ response 中间件：按 CORS_ALLOWED_ORIGINS 加 CORS 头
  │    └─ request 中间件：OPTIONS → 204（避免未知路径 405）
  ├─ _setup_request_logging()                  # request/response 中间件打 debug 日志
  ├─ AuthMiddleware()                          # 从 Authorization: Bearer / cookie 取 session_id
  │                                              → request.ctx.authentication_session
  └─ FileDownloadCounterMiddleware()            # ⚠ 当前因 app.api 导入失败而降级
  ↓
app/middleware/compression.py::configure_compression()
  # Gzip；阈值 COMPRESSION_MIN_LENGTH=1024，级别 COMPRESSION_LEVEL=6
  ↓
蓝图路由（见 §8.2）
  ↓
app/middleware/error_handler.py 统一异常 → JSON
```

### 8.2 已注册路由（实测枚举 `app.router.routes`）

| 路由 | 方法 | 说明 |
|---|---|---|
| `/health` | GET | `app/__init__.py:83` → `{"status":"ok","env":"…"}` |
| `/auth` | POST | 认证会话 |
| `/auth/login` | POST | 登录 |
| `/auth/register` | POST | 注册 |
| `/auth/verify` | POST | 验证 |
| `/auth/validate-2fa` | POST | 两步验证 |
| `/auth/logout` | POST | 登出 |
| `/auth/associated` | POST | 关联会话 |
| `/capt/request` | GET | 验证码请求 |
| `/capt/image` | GET | 验证码图片 |
| `/uploads/<file_uri>` | GET | 上传文件静态服务 |
| `/static/*` | GET | `STATIC_DIR` 存在时才挂载（仓库中无 `static/` 目录，实测未挂载） |

**未注册 / 不可用**（实测 404）：

| 路径 | 状态 |
|---|---|
| `/api/v1/*` | **整体降级**：`app/api/__init__.py:22` 调用 `api_bp.add_blueprint(v1_bp)`，但 `Blueprint.group()` 返回的 `BlueprintGroup` 在 Sanic 23.6 **没有 `add_blueprint` 方法**（实测 `AttributeError: 'BlueprintGroup' object has no attribute 'add_blueprint'`）→ `app.api` 导入失败 → `/api/v1` 蓝图不注册 |
| `/roles`、`/account`、`/two-step` | `app/auth/routes.py:29-31` 定义了 `two_step_bp`/`role_bp`/`account_bp`，但**没有任何路由挂在上面**（只有 `auth_bp`/`capt_bp` 有装饰器路由） |
| `/swagger`、`/redoc`、`/swagger.json` | **404**。`app/docs/__init__.py` 提供了 `setup_docs(app)`，但 **`create_app()` 从未调用它**。仓库里也**不存在 `ENABLE_API_DOCS` 这个配置项**（全仓 grep 无命中），所以不能用它来开关 |
| `/docs`、`/docs/openapi.json` | **200**，但这是 sanic-ext 自带的 OAS，不是 `app/docs/` 生成的。实测它列出的 path 是 `/health` + `/auth*` + `/capt*` 共 10 条 |
| `/login`、`/index` | `app/web/routes.py` 的 `register_web_blueprints()` **从未被调用**；且它渲染的 `frontend/templates/` 目录不存在 |

> 换句话说：**`/swagger` 与 `/redoc` 目前不存在**，`README.md` 里的 "Swagger UI:
> http://localhost:22222/swagger" 是设计目标而非现状。修好它属于 §9 的上游任务。
> 在那之前，不要在 PR 描述里写"文档已在 /swagger 可访问"。

### 8.3 配置契约（`app/config.py`）

```
SANIC_ENV ──► _normalize_env() ──► development | testing | production
                                            │
                        get_config(name) ────┤
                                            ├─ 密钥注入：_env_secret()
                                            │    ├─ production 缺失 → ConfigError（fail-closed）
                                            │    └─ dev/test  缺失 → 生成临时值 + warning + 写回 os.environ
                                            ├─ 环境变量覆盖：HOST/PORT/DB_*/CACHE_*/REDIS_*/MAIL_*/CORS_*
                                            └─ 密钥格式校验：load_jwt_keys()（RSA PEM，配对检查）
```

`BaseConfig`（同一文件内）额外承载认证侧配置：`SECRET`/`PUBLIC_SECRET`（JWT 私钥/公钥）、
`INITIAL_ADMIN_EMAIL`（默认 `SAdmin@Sanic.com`）、`INITIAL_ADMIN_PASSWORD`、
`ALLOW_LOGIN_WITH_USERNAME`、`SESSION_SECURE`（= `ENV == "production"`）、
`SESSION_ENCODING_ALGORITHM = "RS256"`、`AUTHENTICATION_SESSION_EXPIRATION = 604800`。

### 8.4 认证与授权模型

- **会话**：`app/models/session.py` 定义 `Session` / `VerificationSession` / `TwoStepSession` /
  `CaptchaSession` / `AuthenticationSession`。`AuthenticationSession` 持有 JWT bearer，
  `request.ctx.authentication_session.encode(response)` 把令牌写进响应。
- **取会话**：`get_session_token()` → cookie 优先，其次 `Authorization: Bearer`，
  最后 `request.token`。`AuthMiddleware` 也按 Bearer → `session_id` cookie 的顺序找。
- **权限**：`Account.is_admin` 为 True → 全部权限；否则合并其所有未删除 `Role` 的
  `permissions` JSON。`app/auth/authorization.py` 提供 `check_permissions` 等。
- **口令**：argon2-cffi（`requirements.txt`）。`Account.hash_password()`。

### 8.5 缓存

`app/cache/__init__.py::get_cache(cache_type)` 返回进程内单例。
`memory`（默认）/ `redis`。Redis 探测超时 2 秒，不可达时 dev 降级为 memory、
prod 抛 `ConfigError`（见 §5.2）。缓存键前缀 `CACHE_KEY_PREFIX = "sanic_admin"`，
默认超时 300 秒。

### 8.6 数据层

- Tortoise ORM，`init_db()` 以 `modules={'models': ['app.models']}` 注册模型
  → **新模型必须在 `app/models/__init__.py` import**（见 §4.3）。
- `app/database/`：查询优化（`optimize_query` / `prefetch_related` / `paginate_optimized` /
  `batch_fetch`）、只读 SQL 分析（`analyze_query_plan` / `validate_readonly_sql` /
  `log_query` / `get_slow_queries`）、连接池（`get_connection_pool` / `set_pool_options`）。
- **只读分析有黑名单**：拒绝 `pg_advisory_xact_lock` / `pg_try_advisory_*` 全系列，
  以及带引号标识符的函数调用（历史 commit `df0e293` / `40e6124`）。

---

## 9. 需要上游配合的事项（不要在无关 PR 里顺手改）

按依赖顺序：

| # | 事项 | 现状 | 影响 |
|---|---|---|---|
| 1 | `app.models.permission` 模块缺失 | `app/models/` 下只有 account/role/session/verification/profile/system_setting/operation_log/uploaded_file | 6 个测试模块收集失败（§3.2） |
| 2 | `app.cache.backends` 模块缺失 | 实际结构是 `app/cache/{base,memory,redis}.py` | `tests/test_cache.py` 收集失败 |
| 3 | `BlueprintGroup.add_blueprint` 不存在 | `app/api/__init__.py:22,33,38` 用了该方法，Sanic 23.6 的 `BlueprintGroup` 没有 | **整个 `/api/v1` 资源层降级不可用**；`app.api` 导入失败连带 `FileDownloadCounterMiddleware` 降级 |
| 4 | `create_app()` 未调用 `setup_docs()` | `app/docs/__init__.py:33` 有现成实现，未接线 | `/swagger`、`/redoc`、`/swagger.json` 全部 404；`README.md` 的文档访问说明与现状不符 |
| 5 | `tests/test_docs/` 里两个 `Sanic("test_app")` fixture 同名 | `test_openapi.py:48` 与 `test_swagger.py:20` | 4 个测试 ERROR（app registry 重名） |
| 6 | `test_openapi_spec_generation` 断言尾斜杠 | 断言 `"/api/test/"`，实现给 `"/api/test"` | 1 个测试 FAIL |
| 7 | `app/auth/routes.py` 的 `two_step_bp`/`role_bp`/`account_bp` 无路由 | 只有 `auth_bp`/`capt_bp` 挂了装饰器 | `/roles`、`/account`、`/two-step` 404 |
| 8 | `app/web/routes.py` 的 `register_web_blueprints()` 从未调用，且 `frontend/templates/` 不存在 | — | `/login`、`/index` 404 |
| 9 | `frontend/` 缺 `.eslintrc` / `babel.config.js` | ESLint 用默认 espree 解析 ES Module | `npm run lint` exit 1，8 个 Parsing error |
| 10 | `amis/index.html` 不存在 | `server.js` 兜底 `sendFile('index.html')` | `npm start` 后 `GET /` → 404 |
| 11 | production 模式下当前**无法启动** | 实测 `SANIC_ENV=production` + 四变量齐全 → `main.py` exit 1：`生产环境拒绝降级启动：文件下载计数中间件不可用（待 B1d 修复）` | 由 #3 引起；#3 修好后应能起（隔离 #3 后实测：`/health` 返回 200 `env=production`） |
| 12 | `.gitignore` 未忽略 `uploads/` | `create_app()` 会创建该目录 | 上传测试文件可能被误提交 |
| 13 | 真实 `docker compose up` 未能执行 | 本机 Docker daemon 无法启动（特权助手 `com.docker.vmnetd` 需 sudo 密码），也无 podman/nerdctl/lima 等替代运行时 | 容器行为只有静态解析 + 等价路径实测背书，无真实容器运行证据（§6.3） |

---

## 10. 已知问题速查（写 PR 描述时可直接引用）

- **pytest 收集失败 6 个**，根因见 §3.2 的表。
- **已可跑的 20 个用例中**：`1 failed, 15 passed, 4 errors`（`tests/test_docs`），
  失败/错误原因见 §3.2 末尾。
- **`/api/v1` 全部 404**（§8.2、§9 #3）。
- **`/swagger`、`/redoc` 404**（§8.2、§9 #4）——README 写的是设计目标。
- **`ruff check .` 通过**（exit 0）。
- **`frontend/npm run lint` 失败**（exit 1，8 Parsing error，§9 #9）。
- **`amis/npm start` 后 `GET /` 404**（§9 #10）。
- **production 当前起不来**（§9 #11）。
- **真实 `docker compose up` 未执行**（§6.3、§9 #13）——本机 Docker daemon 起不来，
  替代验证为 compose 静态解析 + Dockerfile 安全项自查 + production fail-closed 本机等价实测。

---

## 11. AI 代理行为准则

1. **先读再写。** 改动前先 `grep`/`read` 相关模块，特别是模块 docstring 里的历史沿革说明。
2. **证据优先。** 报告测试状态、覆盖率、接口可用性时，只写你**实际跑过**的输出。
   没跑就写"未测"。
3. **小步、可 review。** 一个 PR 一件事；diff 里不出现无关文件。
4. **改配置/契约时同步文档。** 改了环境变量、路由前缀、依赖，就更新 `README.md` /
   `CHANGELOG.md` / 本文件的相应章节。
5. **不改禁区。** 除非任务书明确授权，不要动 `app/**` 之外的 `tests/**`、`amis/**`、
   `requirements*.txt`、`SECURITY.md`、`CHANGELOG.md`、`README*.md`、`docs/**`、
   `main.py`、`.github/**`。
6. **不要引入新依赖**而不改 `requirements.txt` + `requirements-dev.txt`（并注明系统依赖，
   如 `libmagic`）。
7. **生产路径 fail-closed。** 新增可选模块时保持 dev 降级 / prod 拒绝的双轨。
8. **不引入密钥、DB 文件、`.DS_Store`、上传文件。**
9. **提交前自检**：
   ```bash
   .venv/bin/ruff check .          # 期望 All checks passed!
   .venv/bin/pytest --collect-only -q   # 期望数字与 §3.2 一致或更好
   git status --short              # 期望只有你有意改动的文件
   ```
10. **清理临时产物**：venv、`node_modules`、`package-lock.json`（未被跟踪）、
    `__pycache__`、`.pytest_cache`、`.ruff_cache`、`*.sqlite3*`、启动时生成的 `uploads/`。
    注意 `.gitignore` **只**忽略 `.venv`、`.pytest_cache`、`.ruff_cache`、`*.sqlite3`，
    **不**忽略 `.venv-agent`、`uploads/`、`node_modules`、`package-lock.json`。

---

## 12. 参考文件

| 文件 | 用途 |
|---|---|
| `CONTRIBUTING.md` | 人类贡献流程（Issue → 分支 → PR → CHANGELOG） |
| `SECURITY.md` | 漏洞私下报告渠道；已知泄露项 |
| `CHANGELOG.md` | Keep a Changelog；用户可见变更写 `Unreleased` 段 |
| `CODE_OF_CONDUCT.md` | 行为准则 |
| `docs/architecture.md` | 架构文档（并行 lane `sa-oss/m23-doc` 编写） |
| `docs/configuration.md` | 配置项逐条说明（同上） |
| `upgrade_schema.md` | 历史进度表（描述性，非验收依据） |
| `.cursor/rules/project-auto-developer.mdc` | Cursor 侧的自动化开发规则 |
| `app/config.py` | 配置与密钥的唯一权威来源 |
| `app/__init__.py` | 应用工厂、路由注册、降级策略的权威来源 |
