# AGENTS.md — 供 AI 代理参与本仓库维护

本文件是 AI 代理（如 Codex、Claude Code）在本仓库工作时的**唯一操作契约**。
人类贡献者请看 [CONTRIBUTING.md](CONTRIBUTING.md)；本文件只覆盖 AI 代理需要额外知道的
部分（当前基线的真实状态、可验证命令、硬性禁区）。

**所有命令与数字都来自发布候选 `release/v0.2.0`（M1 候选 `8750d51`）的实测**，不是从文档推断。
未在本文件出现的命令，请先自己跑一遍再写进 PR 描述。

---

## 0. 一句话现状（务必先读）

本仓库正处于**重构中段**，`README.md` 明确写了"尚不可用于生产环境"。
后端骨架（配置 / 中间件 / 模型 / 认证 / 缓存 / 文档装饰器）已可运行，
**API v1 资源层已挂载并可用**，测试**全绿（171 passed）**。

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
| `app/api/resources/` | API v1 资源（已挂载，含 CRUD / 仪表盘 / 上传 / 数据库分析等 13 个模块） | 高 |
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

# 单个测试文件
.venv/bin/pytest tests/test_auth.py -q

# 单个文件
.venv/bin/pytest tests/test_docs/test_decorators.py -q

# CI 等价命令
.venv/bin/pytest --cov=app tests/ --cov-report=xml
```

### 3.2 基线真实数字（`8750d51`，不要改这些数字，改了就说明你动了代码）

| 命令 | 真实结果 |
|---|---|
| `pytest --collect-only -q` | **95 tests collected** |
| `pytest -q` | **171 passed, 136 warnings**（约 65 秒，exit 0） |
| `pytest --cov=app --cov-report=term -q` | **171 passed**，覆盖率 **52%**（5667 语句 / 2726 未覆盖）；加 `--cov` 约 80 秒 |
| `ruff check . --select E9,F63,F7,F82` | **All checks passed!**（exit 0） |

按文件的用例数：

| 文件 | 用例数 | 覆盖什么 |
|---|---|---|
| `tests/test_account_crud.py` | 14 | 账户 CRUD、字段白名单、权限判定 |
| `tests/test_auth.py` | 16 | 注册、登录、注销、验证码、二次验证、会话 |
| `tests/test_authorization.py` | 12 | RBAC 角色与权限合并 |
| `tests/test_production_failclosed.py` | 6 | production 下缺失必需密钥必须拒绝启动 |
| `tests/test_role_crud.py` | 12 | 角色 CRUD、成员管理 |
| `tests/test_sql_readonly.py` | 23 | SQL 分析接口的只读约束 |
| `tests/test_upload_security.py` | 12 | 上传路径穿越防护 |

88 条警告全部是 `websockets.connection` 改名与 Sanic `ode.py` 的 `event.s` 属性弃用，无业务告警。

**覆盖率洼地**（改动这些模块时请留意）：`app/web/routes.py` 0%，`app/middleware/_headers.py` 11%，
`app/docs/decorators.py` 13%，`app/database/connection_pool.py` 20%，`app/database/query_optimizer.py` 20%，
`app/cache/redis.py` 21%，`app/cache/memory.py` 25%，`app/cache/decorators.py` 27%。

> 改代码后请重跑 `pytest -q` 与 `ruff check . --select E9,F63,F7,F82`，两者都是 CI 硬门禁。
> 新增功能请一并补用例——当前 50% 的覆盖率是本版本已知的短板，不是可以长期维持的状态。

### 3.3 覆盖率报告

```bash
.venv/bin/python tests/generate_coverage_report.py
```
已实测：总覆盖率 52%（5667 语句 / 2726 未覆盖），详见 §3.2。

### 3.4 CI 现状

`.github/workflows/ci.yml`：push/PR 到 `main`、`master`、`develop`、`vj-mp3` 时，
在 Python 3.10 / 3.11 / 3.12 三个版本上跑
`ruff check . --select E9,F63,F7,F82` + `pytest --cov=app tests/ --cov-report=xml`。
**按当前基线，pytest 这一步在 CI 上必然失败**（与本地一致，见 §3.2）。

### 3.5 浏览器 E2E 门禁（改 AMIS 页面必跑）

`scripts/amis_e2e_check.py` 用真实浏览器验收控制台。**凡是改了 `amis/**` 下的页面 JSON
或 `login.html` / `index.html`，合入前必须跑通本脚本**——AMIS 的校验写法（如
`validate` 用字符串还是 `validations.isJson`）在 pytest 里覆盖不到，v0.3.2 就是因为
把 `isJson` 改成字符串表达式，导致角色弹窗直接不渲染（v0.3.3 修复）。

```bash
# 起一个隔离服务（独立端口 / 独立 SQLite / 一次性口令）后：
python scripts/amis_e2e_check.py \
    --base-url http://127.0.0.1:<port> \
    --admin-password '<一次性口令>' \
    --new-password '<新口令>'          # v0.3.2 起首登会停在改密表单，必须提供

# 正向对照：故意改错选择器，要求目标断言必须失败
python scripts/amis_e2e_check.py ... --negative-control dialog
python scripts/amis_e2e_check.py ... --negative-control login_password
```

- 全绿的标准是 **19/19 项通过**（脚本钉死断言总数，少一条就报错）。
- `--negative-control` 退出码 0 表示「被篡改的断言确实失败了」——这才是门禁有效性的证明。
- CI 由 `amis-e2e-probe` 先探测浏览器可用性并输出 `available`；`amis-e2e` job 用 `if` 依赖该输出，**浏览器不可用时整个 job 显示为 `skipped`**（不是绿色通过）。

### 3.6 断言必须做破坏实验（写测试时的强制纪律）

**测试全绿不代表测试有效。** 一条从不失败的断言和没有断言是等价的，但前者更危险——它给人虚假的安全感。所以：**每写一条新断言，都要先把它要保护的东西故意破坏一次，确认它会红。**

具体做法：

1. 写下断言，跑通（绿）。
2. **故意破坏实现**：把被测的保护去掉、改错、或换成错误的值。
3. 重跑，**确认这条断言失败**。
4. 恢复实现，重跑，确认重新变绿。

### 第 3 步有一个陷阱：破坏本身可能没破坏到

**「改坏之后测试红了」不等于「改坏生效了」。** 2026-10-24 实测踩到：

> 测试要验证「没有标记文件的临时目录不会被清理」。我删掉了那段检查
> `if not marker.is_file(): continue`，重跑——**测试仍然绿**。
>
> 原因：后面的 `marker.read_text()` 对不存在的文件抛 `OSError`，被外层
> `except OSError: continue` 吞掉，**恰好等价于跳过**。那段检查删不删，
> 代码路径完全一样。

所以第 2 步之后要加一问：**我这次破坏，真的改变了执行路径吗？**

判据：

- 破坏后**至少有一个**观察点变了（测试红、日志变了、返回值不同）。
- 如果测试没红，先别下「断言无效」的结论——**先确认破坏是否真的生效**。
  两种可能都要排查：断言测不到，或者破坏没破到。
- 最稳的做法：故意做**两种不同方向**的破坏。两种都能让测试红，才说明断言覆盖了该行为。

### 第 4 步有第二个陷阱：断言「A 不含 B」时，B 可能根本撞不上

**断言「某内容里不出现 X」时，若 X 是短串，必须证明 X 不会作为合法内容出现在那里。**
否则这条断言可能**恒真**（永远测不到泄露）或**恒假**（总是误报），两种都是失效。

2026-10-27 两个实测反例：

> **反例 1（恒假）**：验证「审计日志不记录字段值」，我挑了 `["in_progress", "1", "2"]`
> 当「值」的候选。结果报「含值」——**误报**。因为 `"1"` 和 `"2"` 撞上了 detail 里
> `id=42` 的数字。换成 `["in_progress", "张三", "13800138000", "secret-token-xyz"]`
> 这种不可能与 id / 字段名撞车的特征串，结论才是可信的。
>
> **反例 2（恒真）**：验证「日志不含密码」，若测试用户的口令恰好是 `"2026"`，而
> 日志里本来就有时戳 `2026-10-27T12:34:56`——即使真的泄露了口令也会命中，
> 你会以为测试在工作，其实它只是撞上了时间戳。

判据：

- 「不含 X」里的 X 必须是**不可能与任何合法内容撞车**的字符串（足够长、含随机段、
  或与已知标识空间不相交）。
- 如果做不到，就不要用「不含」，改用**正向断言**：「内容必须恰好等于 `<预期结构>`」。
  例如 `detail == "id=42 fields=status"` 比 `assert "42" not in detail` 可靠得多。
- 遇到「断言为真」时，先怀疑是撞上了，再怀疑是通过了。

#### 报告破坏实验时，必须贴原始输出行

**不能只写「破坏后测试变红 ✓」。** 必须把那条断言的实际输出贴出来：

```
$ pytest -k expected_sha_to_git
FAILED tests/test_mcp_proposal_hardening.py::test_discard_passes_expected_sha_to_git
```

或者恢复后：

```
$ pytest tests/test_mcp_proposal_hardening.py
23 passed
```

理由：2026-10-24 我做过一次破坏实验，输出是 `1 passed, 21 deselected`，
**我在报告里写成了「契约测试红 ✓」**。看输出时我已经有结论（「破坏应该会让它红」），
输出不符合预期时没有纠正结论，而是照结论写。带了对勾，看起来像验证过的。

这条规矩的作用是**让报告里的每个「✓」背后都有一行可核对的事实**。写「红 ✓」时
如果必须附上 `FAILED` 那行，就编不出来。

同时要贴**破坏是否生效**的证据（`grep` 到改动后的代码行），否则「红了」也可能是
别的原因造成的——这与上面「破坏本身可能没破坏到」是同一类。

#### 恢复文件只能用备份，不能用 `git checkout`

做破坏实验前，**先用 `cp` 把文件备份到 `/tmp/<名字>.bak`**，实验完成后从这个备份恢复：

```bash
cp tools/xxx.py /tmp/xxx.bak          # 实验前
# …破坏、跑测试、看结果…
cp /tmp/xxx.bak tools/xxx.py          # 恢复
```

**不要用 `git checkout <file>` 恢复。** 它只会回到**上一次提交**的状态——你在这个
文件上所有**未提交**的修改会一起丢掉，不只是刚才那次破坏。

2026-10-24 一天之内这个错误发生了两次（我一次、另一位编辑一次）。我那次是在做
`#24` 的破坏实验时用 `git checkout tools/mcp_server/git_isolation.py` 恢复，
把同一轮里刚做的三处修改（hook 屏蔽、原子删除、失败回滚）全部冲掉了，
而且当时没发现——直到测试报错才回头重做。

判据：破坏实验的「恢复」必须精确到**破坏前的文件内容**。备份副本能做到，
`git checkout` 只能做到「上次提交」。

只在脑子里推演「它应该会红」不算——2026-10-24 一天之内，仅 M2 写入路径一项就靠这个方法抓出**五个假测试**：

| 假测试 | 为什么它其实什么都没测 |
|---|---|
| pre-push hook 拦截 push | `shutil.copytree` 默认不保留可执行位，hook 丢了 `+x` 被 git 跳过；「push 失败」的真因是**推了一个不存在的分支** |
| 同上，第二次 | 断言写成 `"hook" in stderr.lower()`，而 `tmp_path` 目录名里恰好含 `hook` |
| fetch 不覆盖已存在分支 | clone 里根本没有同名分支，失败原因是「找不到 ref」，不是「拒绝覆盖」 |
| 同上，第二次 | 断言测的是 git 自身行为（会拒绝非快进），改我的代码（加 `--force`）它照样绿 |
| 分支已存在时必须前置拒绝 | 去掉前置检查后，fetch 仍因非快进失败，测试分辨不出两种失败 |

**报告测试状态时，区分这三件事**：跑了（ran）、通过（passed）、**有效**（可以失败）。只说前两个是不够的。

配套要求：

- 正向对照与目标断言应在**同一次运行**里可复现，不靠人工记忆。
- 断言失败消息要能区分「失败原因 A」和「失败原因 B」——像上面第 1、3 条那样，失败原因根本不是被测对象时，测试必须把这些区分出来，而不是笼统断言「失败了」。
- 涉及外部进程（git、浏览器、容器）的测试，**用不可伪造的证据**（标记文件、ref 列表、步骤数），不用可能巧合成立的字符串匹配。

#### 破坏实验怎么做：三层优先，禁止长期 ready 的破坏 PR

2026-10-27 一天之内出现了**两个故意破坏的 PR**（#29、#32），且**都曾处于可合并状态**。
一个全绿的破坏 PR 比红的更危险——它随时可能被误合。所以负向验证按下面三层选：

| 顺序 | 方式 | 说明 |
|---|---|---|
| 1（首选） | **本地执行** | 改代码 → 跑目标测试 / 脚本 → 看红 → 用 `cp` 恢复 |
| 2 | **单次 `workflow_dispatch`** | 需要真方言、真容器时用；跑完即结束，不产生常驻 PR |
| 3（最后） | 开 PR | **必须 keep-draft**，且**不得推任何指向 master 的分支** |

**禁止**用长期 ready 的 PR 做负向验证。PR 一旦 ready，就进了别人的可合视野，
而破坏内容本身不该被合。

两条同源教训：

- **`use_tz` 负向验证（#29 / #32）**：两次都想靠 PR 触发 CI，第一次因分支与 master
  冲突、`refs/pull/N/merge` 建不出来而**根本没触发**，被误读成「draft 的问题」；
  重建后跑通了，结果**没变红**——因为被测脚本走 `Model.create()` → `to_python_value()`
  的无条件 `make_aware`，压根不经过 `use_tz` 的分支。**破坏没破到目标路径，
  和断言测不到目标行为，是同一类失败。**
- 若当时用的是长期 ready PR，这个「没变红」的结论就会挂在一条可合分支上。

#### 报告「没变红」之前，先证明测量手段本身有效

负向验证的结果如果是**通过**（没变红），不能直接写成「该配置无效」或「契约没问题」。
必须先回答：**我的破坏真的打到了被测路径吗？**

`use_tz` 那次的做法可以作为模板——三种对照同时给出：

1. **读实现**：`grep` 出 `get_use_tz()` 的全部调用点，确认被测脚本走的路径是否经过它；
2. **换一条能观测到的路径做对照**：`auto_now_add` 确实读 `use_tz`，在
   `timezone='Asia/Shanghai'` 下 `False` 存 `+08:00`、`True` 存 `+00:00`——
   证明**开关本身有效**，只是原脚本测不到；
3. **看原始存储值，不看 ORM 读回**：读回经 `to_python_value()` 会被归一，掩盖差异。

**结论的正确写法是「现有验证路径不覆盖 X」，不是「X 已验证有效」，也不是「X 无效」。**

#### 报告数字：默认贴命令 + 原始输出

**这不是「有争议才贴」——争议往往到第四轮才显形，第一轮双方都以为对方和自己算的一样。**
把它变成动作触发，就不必先判断「这算不算争议」：

涉及数字的结论，下列**任一**成立就默认贴「命令 + 该命令对该目标的原始输出」：

1. 数字是**数出来的**（`grep` / `wc` / `diff` 统计 / `jq` 过滤后的计数）
2. 数字**用于判定**（通过 / 不通过、修没修好、够不够）
3. 双方都要用到这个数字

**这是纪律，不是经验。** 经验是「知道有这个坑」，依赖临场想起；纪律是「第一轮就必须贴」，
不依赖判断。前面那些判据（null 竞态、`is-ancestor`、计数口径、零命中先自测）都还停在经验层：
知道有坑，但不能保证下次想起。**把「依赖记忆」改成「依赖动作」，才叫纪律。**

##### 但「默认就贴」≠「贴全部」

**最小充分**：贴命令 + 它对该目标的原始输出，**不是**贴搜索/除错全过程。

不加这条，「默认就贴」会滑向「每次贴一大堆」，人就不愿执行——**纪律因不可执行而失效。**

##### 什么叫「原始输出」

| 环节 | 做法 |
|---|---|
| **可以筛选** | 只贴相关的几项，但每项必须原样 |
| **可以重排** | 但声明「已按 X 排序」 |
| **可以脱敏** | 但按下面的规则声明 |

**判据：读者能否从你贴的内容里，自己推出你要说的那个数字——以及判断该判据是否可靠。**

*不只*是能推出数字。2026-10-27 有一个反例：报告「3 项 CI 在跑」时省略了
`conclusion` 字段（省成 `in_progress` 而非 `in_progress/null`），看起来毫无影响；
但 `null` 恰恰是当天「null 竞态」那个坑的核心，**省略的正是后来出问题的那个字段**。

##### 脱敏：声明两个范围，让重叠自己显形

**脱敏与裁剪的危险不同**：裁剪只是少了几行，读者能看出「这里缺东西」；
**脱敏是替换了内容，读者看不出来**——他会以为这就是全部，连「该不该要求补」都不知道。

所以贴脱敏输出时必须声明两项：

- **A. 隐去了哪些字段**（哪个字段、哪一类内容）
- **B. 本条结论依赖哪些字段**

**若 A ∩ B ≠ ∅（依赖的字段被隐去了），本条不能作为该结论的证据。**

这样写而不是「声明隐去是否影响结论」，是因为后者要求写的人**替读者预测「读者想核什么」**
——预测往往错（写的人以为不影响，读者恰恰要核那个字段）。而 A/B 两个集合，写的人必须知道
B（不知道 B 就提不出结论），读者自己一眼看出重叠，**而且可机械检查**。

**代价只有一行**，而这一行本来就必须有：你提出结论时，本来就该知道自己依赖什么。

##### 数据源换了，判据要重验

同一个「看起来一样」的过滤器，**换个命令可能数据源就变了**：

```
gh pr view --json statusCheckRollup   →  字段是大写 COMPLETED / SUCCESS
gh api .../commits/<sha>/check-runs   →  字段是小写 completed / success
```

**语法完全一样**（都是 `select(.status=="completed")`），**不报错，静默返回错误结果。**

不限于大小写：字段名、嵌套结构、`null` 语义都可能不同。**换源时把判据重跑一遍。**

##### 把判断变成附带

今天沉淀出的规则有三次是同一个形状：

```
「争议才贴」        → 「三条件默认贴」        （去掉「判断是否争议」）
「等人提醒」        → 「主动问能否推出」      （去掉「等对方」）
「记得要问」        → 「贴数字即附问句」      （去掉「记得」）
```

**共同动作：把「要不要做」的判断，变成「做了就自动附带」。**

遇到任何「要求人做某事」的判据，都可以问一句：**这个动作能不能附带到某个必然发生的动作上？**
能，就不需要人记得。

#### 写判据本身也要做破坏实验

判据（检查脚本、grep 条件、jq 筛选、验收标准、自查用的 find）写完，**必须用一个「已知会
失败」的样本跑一遍**，确认它真的报错。没有这一步，判据只是「看起来在用」。

**为什么这一条比上面所有条都靠前**：判据是门禁的门禁。判据错了，所有依赖它的结论都错，
而且错得很安静——因为工具「看起来在用」。

2026-10-27 一天之内五次失效，全是同一个根：

| 判据 | 失效方式 | 边界 |
|---|---|---|
| `select(.conclusion!="success")` | CI 抓取竞态时 `conclusion` 为 `null`，被算成失败 | 字段未填充 |
| `git merge-base --is-ancestor <sha> <tag>` | 祖先不等于相等。v0.4.1 的 `c08bd21` 是 `133a206` 的祖先，用它判等会把**已知错误判为通过** | 关系非等价 |
| `find -maxdepth 2 -name .venv` | 实际 venv 在深度 3，零命中被当成「干净」 | 搜索深度不足 |
| 「15 处占位」 | 实为 15 **行**、23 **个**占位符 | 计数口径 |
| 「发布树 `<SHA>`（本版 squash 提交）」 | 两段式流程下材料轮的 squash 不是 tag 指向的树 | 流程分段 |

**根因不是疏忽，是构造性偏差**：判据是被结论牵引着写出来的。写第一条 `find` 时脑子里
已经有答案（「我的 venv 在外挂盘，内盘应该干净」），带着预期写出的检查会恰好覆盖预期。

**解法**：写判据时先拿一个**已知存在的对象**试命令——能查到才说明命令有效。
已知对象是外部的，它不会被你的预期塑造。

**怎么实施**（以「查内盘有没有 `.venv`」为例）：

```bash
# 前提：你确切知道 <某个路径> 存在（比如自己刚建过、或 ls 过）

# 第 1 步：先拿它试你的命令——能不能查到？
$ find <起点> -maxdepth 2 -name '<目标名>'
（无输出）                        ← 危险信号：命令查不到一个你确定存在的对象

# 第 2 步：确认该对象确实存在、以及它在第几层
$ ls -d <某个路径>
<某个路径>                        ← 数一下相对 <起点> 有几层

# 第 3 步：把 maxdepth 调到能覆盖它，再去查真正的目标
$ find <起点> -maxdepth <足够深度> -name '<目标名>'
<某个路径>                        ← 命令现在可信了，可以拿它查目标
```

**没有第 1、2 步，第 3 步得到的「零命中」是假的**——它只证明「在这个深度没找到」，
不证明「没有」。2026-10-27 的真实事故就是只跑了第 1 步（`maxdepth 2`）就报「干净」，
而当天实际在用的 venv 恰好在深度 3。

具体做法：

- **判绿**（CI 状态）：`[.check_runs[]|select(.status=="completed" and .conclusion!="success")]|length`
  ——`status=="completed"` 必须先成立，否则 `null` 会被算成失败。
  **自测这条需要在 CI 运行中**（此时未完成的 job `conclusion` 才是 `null`）；
  CI 全绿时新旧判据都得 0，看不出差别——这不是判据无效，是样本条件不满足
- **判红**（只认明确失败态）：`[.check_runs[]|select(.status=="completed" and (.conclusion=="failure" or .conclusion=="cancelled" or .conclusion=="timed_out"))]|length`
- **判等**（SHA）：用 `git rev-parse "${sha}^{commit}"` 逐字比对，**不要用 `--is-ancestor`**
- **报「零命中」前**：先拿一个已知存在的路径试自己的搜索命令
- **报任何数字前**：写清口径（`grep -o 'X' | wc -l` 是**个数**，`grep -c 'X'` 是**行数**）

#### 发布门禁：树 SHA 必须等于 tag 解引用

发布材料里出现的每一个**发布树** SHA，必须等于 `git rev-parse 'v<版本>^{commit}'`。

**v0.4.1 在这个点上错过一次**：notes 写「发布树 `c08bd21`（本版 squash 提交）」，但
tag 实际指向 `133a206`（后来补写验证节的 squash）。两条命令都能跑通、CI 也对得上，
**错位至今留在该版本的 Release 正文里**。

危险在于它**表内自洽**：`headBranch=master` ✓、CI 与所填 SHA 对得上 ✓，读者按说明能查到
一棵完整的树——只是那不是发布的那棵。**自洽掩盖了错位。**

判据：

```
1. 该轮 CI 的 headBranch == master
2. 该轮 CI 的 commit == 材料里填的 SHA
3. 材料里填的 SHA == git rev-parse 'v<版本>^{commit}'      ← v0.4.1 漏掉的是这一条
```

第 3 条在**打 tag 之前无法执行**（tag 尚不存在）。因此发布材料里不要承诺一个当时不存在的
SHA，用「全量实测于 `<A>`（回填前的树）；本版最终发布树为回填后的 squash，差异仅
`docs/release/*.md`」这种写法，并给出读者可自行验证的 `git diff --name-only` 命令。

**注意区分两类 SHA**：代码依据 / 审核证据里的分支提交（如「某功能合入时的 `71a0394`」）
**不必**等于 tag——它们的作用是让读者定位当时看到的那份代码。混淆两类会得出错误结论。

#### 量化数字要四样齐：实测 + 口径 + 可复现 + 措辞

四条缺一不可：

| 检查项 | 问什么 | 失效实例 |
|---|---|---|
| **实测** | 数字从哪来？ | 「11 文件 21 处」实为 12 文件 23 处 |
| **口径** | 数字量的是什么？ | 「15 处」是行数，占位符实为 23 个 |
| **可复现** | 读者能自己跑出来吗？ | `31 秒 → 14 秒` 不可复现（实测 4.9/14.7/28.0s） |
| **措辞** | 表述会不会制造歧义？ | 「发布树 `c08bd21`（本版 squash 提交）」 |

**实测解决「数字从哪来」，口径解决「数字量的是什么」，可复现解决「别人能不能验」，
措辞解决「读者会不会理解成另一件事」。**

前三条错了会得到**错的数字**；措辞错了会得到**对的数字、错的结论**——所有数字都对得上，
没有任何异常信号。v0.4.1 那个错位就是：`c08bd21` 真实存在、CI 真实通过、命令真实可跑，
唯一错的是「发布树」三个字。

判断方法：涉及「态」的措辞（当前 / 最终 / 本次 / 已发布），必须问一句——
**这个词指的是流程的哪一步？该步的产物是不是读者以为的那个？**

#### 五层递进：同一个错误为什么逐层失守

上文那些失效实例，**按「判据类型」分类**已经列过（见「写判据本身也要做破坏实验」的表格）。
换个维度——**按「隐蔽程度」排序**——会看到它们其实是同一个错误在五个层次上重复：

| 层 | 问题 | 实例 | 靠什么抓 |
|---|---|---|---|
| 1 | **跑了没跑** | `671 passed` 是预跑还是正式跑 | 对照：跑一次 |
| 2 | **数字准不准** | 「11 文件 21 处」实为 12/23 | 对照：数一遍 |
| 3 | **数字量的是什么** | 「15 处」是行数，占位符 23 个 | 对照：换口径再数 |
| 4 | **措辞指向哪一步** | `c08bd21` 不是发布树 | **无对照物**，只能问「这句话在流程哪一步说的」 |
| 5 | **判据本身可不可信** | `is-ancestor` 是祖先还是相等 | **无对照物**，只能拿已知失败样本试 |

**每往上一层更隐蔽**：前三层靠对照能抓（跑一遍、数一遍、换口径再数）；
第 4、5 层**没有对照物**——你手里没有「应该是什么样」的参照，只能靠回头问或主动造样本。

**第 5 层的特殊性**：前四层错的是「结论」，第 5 层错的是「**判断结论的工具**」。
它错了，前四层全被污染，而且**不会有任何异常信号**——因为工具「看起来在用」。

**为什么会逐层失守**：每层数对了，就不再问它量的是什么；量对了，就不再问这句话说的是哪一步；
结论对了，就不再问判断结论的工具对不对。**默认信任上一层结论是必然倾向，不是疏忽。**

##### 最低效的做法：重新发现已经写过的东西

**比上面五层更常见的浪费，是报「缺 X」之前没有先查 X 是否存在。**

2026-10-28 实例：一份待补条目清单里有 3 条标记「未合入」，实际逐条 grep 后
**2 条已有等价内容**（只是措辞不同），真正缺的只有 1 条。

**同一天另一次**：用自己印象里的标题 `grep -c`，得到 0 就以为内容缺失，
实际标题措辞不同（`:435` 的真实标题是「报告数字：默认贴命令 + 原始输出」）。

**判据**：报「缺 X」之前，**先穷举实际存在的项**：

```
✗ grep -c '<我印象里的措辞>'    ← 未命中只代表措辞不同，不代表缺失
✓ grep -n '^#### '             ← 列出全部实际标题，再找对应内容
```

**这条和「五层递进」是同一个根**：都是**用预期代替实际**——预期「这个措辞应该有」、
预期「这个内容应该还没写」。区别只在于前者查的是措辞，后者查的是存在性。

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

### 4.6 临时产物与报告：不得写入仓库

**完成定义里必须包含「清理临时产物」这一条。**

| 类别 | 放哪 | 保留 |
|---|---|---|
| 测试/构建报告、日志、测量输出 | 项目外的持久目录（如 `$PROJECT_WORKSPACE/reports/YYYY-MM/`） | 30 天 |
| 浏览器自动化输出（`.playwright-mcp/` 等） | 同上，或直接丢弃 | — |
| venv / `node_modules` / 编译产物 | 项目外的 lane 目录（见 §4.4 与构建纪律） | 按需 |

- **不得写入仓库内**：报告、日志、截图、临时数据库都会污染 diff，且来不及在提交前发现。
- 已加入 `.gitignore` 的目录（如 `.playwright-mcp/`）不代表可以随便生成——**仍应指向仓库外**。
- 提交前自查：`git status --porcelain` 的未跟踪项里不应出现产物类文件。

---

## 4b. 改密（`POST /auth/change-password`）的对外语义

**v0.3.4 起行为有变化，集成方需注意：**

| | v0.3.2 及以前 | v0.3.4 起 |
|---|---|---|
| 改密成功后当前会话 | **保留**（只有其它会话被作废） | **一并作废**，随即签发新会话并在响应中下发（`Set-Cookie` + `Authorization` 头 + 新 `csrf_token`） |
| 响应体 | `{"must_change_password": false}` | 增加 `"token_rotated": true` |

影响面：用 cookie 的浏览器客户端**无需改动**——`fetch(..., {credentials: 'same-origin'})`
会自动接收新的 `Set-Cookie`（AMIS `login.html` 即此模式，已实测能接住）。
**自己管理 token 的客户端必须改用响应里新下发的 `Authorization`**，否则下一次请求会 401。

**已知行为**：两个会话并发改密时，后完成的那次会把先完成的新会话也作废（互踢）——
这是「改密作废全部会话」的直接后果，不做特殊处理；客户端遇到 401 重新登录即可。

**升级注意（breaking）**：`INITIAL_ADMIN_PASSWORD` 现在也要求强度——若不足两类字符，
production 启动即报 `ConfigError` 并提示原因。升级到 v0.3.4 前请先确认该值足够强
（例如 `MyDeploy#2026`），否则容器/服务会起不来。

加固项（同一版本引入）：

- 当前口令试错按账户维度限速，窗口内达阈值返回 **429**；
- 新口令除长度外要求**至少两类字符**，且不得为 `SAdmin@123`、
  `INITIAL_ADMIN_PASSWORD` 的值，或与本人邮箱相同；
- 登录/登出/改密/2FA 的成败都会写入 `OperationLog`（`operation_type="auth"`），
  审计中不含口令、token 与验证码。

## 5. 安全底线

以下每一条都对应代码里真实存在的强制点，不是"建议"。

### 5.1 密钥绝不进仓库

- 仓库**不含任何密钥**。`app/config.py` 的密钥只来自环境变量。
- **生产环境缺任一必需变量 → 直接拒绝启动**（`app/config.py` 的 `_env_secret()`）。
  实测（真实 Redis + SQLite `DATABASE_URL`，每次只缺一个，其余齐备）：

  | 缺失变量 | 退出码 | stderr |
  |---|---|---|
  | `JWT_PRIVATE_KEY` | 1 | `配置错误: 生产环境必须通过环境变量 JWT_PRIVATE_KEY 提供 JWT 签名私钥` |
  | `INITIAL_ADMIN_PASSWORD` | 1 | `配置错误: 生产环境必须通过环境变量 INITIAL_ADMIN_PASSWORD 提供初始管理员口令` |

  `main.py` 捕获 `ConfigError` 并 `sys.exit(f"配置错误: {exc}")`。

  > **`SECRET_KEY` 与 `PASSWORD_SALT` 不是生产门禁。** 两者当前不参与任何签名或加密
  > （JWT 用 RS256 私钥，口令哈希用 argon2 自带随机盐），因此走裸 `os.getenv(var, "")`
  > 而不经过 `_env_secret`（`app/config.py:330-331`）。**实测：两者都缺失时 production
  > 照常启动**，只有上表两个变量会拦住进程。`tests/test_production_failclosed.py` 的
  > `REQUIRED_PRODUCTION_VARS` 同样只列这两项。

  > **production 另有两道独立于密钥的门禁**，排查启动失败时先分清是哪一道：
  > - `CACHE_TYPE` 在 production 默认 `redis`，Redis 不可达即
  >   `ConfigError: production 环境 Redis 缓存不可用，拒绝降级启动`；
  > - `DATABASE_URL` 默认拼装为 MySQL，而 **`aiomysql` 不在 `requirements.txt` 里**，
  >   走 MySQL 会先撞 `ModuleNotFoundError: No module named 'aiomysql'`。
  >   要用 MySQL 得自己补装驱动；只想跑起来就显式给一个 `DATABASE_URL`（SQLite 亦可）。
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
  一致，不一致返回 403。**但目前没有任何路由挂上它**——该装饰器已实现却未启用，
  当前**没有**实际的 CSRF 防护，依赖的是会话 Cookie 的 `HttpOnly` + `SameSite=Lax`
  以及 API 用 `Authorization` 头承载凭据。与 `SECURITY.md` 的记载一致。

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

`Dockerfile` / `docker-compose.yml` / `.dockerignore` / `.env.example` 已随本发布候选合入，
以下描述对当前分支成立。

### 6.1 核心设计

镜像**不含任何密钥**：所有密钥由运行时环境变量注入。容器内固定 `SANIC_ENV=production`，
而 production 对缺失密钥是 fail-closed 的（§5.1）——
所以**"容器能起来"就等价于"密钥确实由 `.env` 提供了"**。

- `Dockerfile`：`FROM python:3.12-slim`；`apt-get install libmagic1 curl tzdata`
  （libmagic1 是 `python-magic` 的系统依赖，见 §2.1）；`pip install --no-cache-dir -r requirements.txt`；
  `useradd --uid 10001 appuser` + `USER appuser` **非 root 运行**；
  `HEALTHCHECK` 用 `curl -fsS http://127.0.0.1:22222/health`。
- `docker-compose.yml`：`env_file: [.env]` 注入密钥；`environment` 覆盖
  `SANIC_ENV=production` / `HOST=0.0.0.0` / `PORT=22222` / `AMIS_DIR=/app/amis`；
  宿主机 `22230 → 容器 22222`；`redis` 服务在 `profiles: [redis]` 下，默认不启动。
- `.dockerignore`：排除 `.env` / `*.pem` / `*.key` / `.git` / `.venv/` / `*.sqlite3` /
  `node_modules/` 等；`!.env.example` 白名单保留样例。
- `.env.example`：**30 个变量**，与 `app/config.py` 实际读取的 30 个变量**完全一致**
  （双向差集为空，实测核对；`app/config.py` 是全仓库唯一的环境变量读取点）。

### 6.2 命令

```bash
cp .env.example .env          # 然后把 change-me-* 全换成真实值
docker compose build
docker compose up -d
curl http://127.0.0.1:22230/health
```

### 6.3 本机环境限制（实测）

**本机 Docker daemon 无法启动**，因此本轮 `docker compose up` **没有真实执行过**。
根因：Docker Desktop 需要把特权助手 `com.docker.vmnetd` bootstrap 到 system 域
（`launchctl print system/com.docker.vmnetd` → `Could not find service`），而这一步需要
交互式管理员口令——无人值守会话下提权提示弹不出来（`SecurityAgent` 窗口数为 0），
后端自修复失败后直接崩溃。本机也无 podman / nerdctl / lima / finch / colima 等替代运行时。

**注意**：容器路径此前**已在本机真机跑通过一次**（在 M1 交付之前、应用代码仍有导入缺陷时，
以仅运行时的补丁绕过；结果见 Release Notes 第 4 条）。本轮未复验是因为 daemon 起不来。
**容器路径的最终验收由 CI 承接**：`.github/workflows/docker.yml` 会 build 镜像、起容器、
检查 `/health`、验证管理界面托管、登录，并断言缺 `JWT_PRIVATE_KEY` 时容器非零退出。
该 job 在合入 `master` 的 PR 上运行。

已做的替代验证（全部实测）：

| 替代项 | 方法 | 真实结果 |
|---|---|---|
| compose 静态解析 | 把 `docker-compose.yml` + `.env.example` 复制到临时目录，`.env.example` 当作 `.env`，跑 `docker compose config` | **exit 0**，YAML 合法、变量插值正确（30 个变量全部解析出值，端口映射 `22230→22222`、三个 volume、healthcheck 均正确展开） |
| Dockerfile 安全项自查 | 逐行读 | 见 §6.4 |
| production fail-closed | 本机 production 配置 + 环境变量注入实跑（真实 Redis + SQLite `DATABASE_URL`） | 缺 `JWT_PRIVATE_KEY` 或 `INITIAL_ADMIN_PASSWORD` → exit 1 + `配置错误: …`（§5.1 表）。两者齐备 → **服务正常启动**（`Goin' Fast`），`SECRET_KEY`/`PASSWORD_SALT` 缺失不拦进程 |

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

> `docs/architecture.md` 与 `docs/configuration.md` 已随本发布候选合入，
本节内容以它们为准。

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
  └─ AuthMiddleware()                          # 从 Authorization: Bearer / cookie 取会话
                                                 # cookie 名取 AuthenticationSession.cookie_name
                                                 # → request.ctx.authentication_session
                                                 # （M1 已移除 FileDownloadCounterMiddleware，
                                                 #   下载计数改由 upload 资源内部原子自增）
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
| `/amis/*` | GET | AMIS 管理界面（`app.static('/amis', …, index='login.html', name='amis')`），**由后端同源托管** |
| `/static/*` | GET | `STATIC_DIR` 存在时才挂载（仓库中无 `static/` 目录，实测未挂载） |

**`/api/v1/*` 已挂载**：`app/api/__init__.py` 用
`Blueprint.group(v1_bp, database_bp, compression_bp, url_prefix='/api')` 装配。
实测 `GET /api/v1/settings` → 200，OpenAPI 规范 66 条 path。
注意 `/api/v1/health` 这个路由在代码中**从未存在**，它 404 不代表蓝图没挂载。

**无需认证即可访问的端点**（实测）：

| 路径 | 说明 |
|---|---|
| `/health` | 健康检查 |
| `/auth/login`、`/auth/register`、`/auth/verify`、`/auth/validate-2fa` | 认证流程本身 |
| `/capt/request`、`/capt/image` | 验证码 |
| `/swagger`、`/swagger/index.html`、`/redoc`、`/swagger.json`、`/docs/*` | API 文档，**受 `ENABLE_API_DOCS` 控制**（development 默认开，production 默认关） |
| `/amis/*` | 管理界面静态页 |

**实测 404 / 不可用**：

| 路径 | 状态 |
|---|---|
| `/uploads/*` | **404** —— 上传目录**不做静态托管**（M1 已移除），文件下载走需鉴权的 `GET /api/v1/files/<id>/download` |
| `/roles`、`/account`、`/two-step` | `app/auth/routes.py` 定义了 `two_step_bp`/`role_bp`/`account_bp`，但**没有路由挂在上面**（只有 `auth_bp`/`capt_bp` 有装饰器路由） |
| `/docs/openapi.json` | development 下 **404**（`setup_docs()` 接管了 `/docs` 前缀）；production 下 200，是 sanic-ext 自带的**另一份** OAS |
| `/login`、`/index` | `app/web/routes.py` 的 `register_web_blueprints()` **从未被调用**；且它渲染的 `frontend/templates/` 目录不存在 |

> `README.md` 里的 Swagger 入口（`http://127.0.0.1:22222/swagger`）在 **development 下可用**，
> production 下需显式设 `ENABLE_API_DOCS=true`。

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
| 1 | `app.models.permission` 模块缺失 | 已由 M1 补齐，权限注册表移到 `app/auth/permissions.py` | 已解决 |
| 2 | `app.cache.backends` 模块缺失 | 已由 M1 补齐，实际结构 `app/cache/{base,memory,redis}.py` | 已解决 |
| 3 | `BlueprintGroup.add_blueprint` 不存在 | M1 改用 `Blueprint.group(v1_bp, database_bp, compression_bp, url_prefix='/api')` | 已解决：`/api/v1` 正常挂载，OpenAPI 规范 66 条 path |
| 4 | `create_app()` 未调用 `setup_docs()` | M1 已接线，由 `ENABLE_API_DOCS` 控制（开发开、生产关） | 已解决：`/swagger` 302→200、`/redoc` 200、`/swagger.json` 200 |
| 5 | `tests/test_docs/` 两个同名 `Sanic("test_app")` fixture | 测试套件已重建 | 已解决 |
| 6 | `test_openapi_spec_generation` 尾斜杠断言 | 测试套件已重建 | 已解决 |
| 7 | `two_step_bp` / `role_bp` / `account_bp` 无路由 | M1 已补齐 | 已解决 |
| 8 | `app/web/routes.py` 的 `register_web_blueprints()` 从未调用 | 仍未调用；`frontend/templates/` 不存在 | `/login`、`/index` 仍 404。该模块是 Vue 实验线，AMIS 主线不依赖它 |
| 9 | `frontend/` 缺 `.eslintrc` / `babel.config.js` | 未处理（Vue 实验线不维护） | `npm run lint` exit 1，8 个 Parsing error |
| 10 | `amis/index.html` | M1 已补齐，`server.js` 兜底可用 | 已解决 |
| 11 | production 模式启动 | 实测：**四个密钥齐备 + 真实 Redis + SQLite `DATABASE_URL` 时可正常启动**（`Goin' Fast`） | 已解决。但 production 默认 `CACHE_TYPE=redis`，Redis 不可达即拒绝启动；`DATABASE_URL` 默认拼装 MySQL 而 `aiomysql` 不在依赖里 |
| 12 | `.gitignore` 未忽略 `uploads/` | 未处理 | 上传测试文件可能被误提交 |
| 13 | 真实 `docker compose up` | 本机 Docker daemon 需特权助手 `com.docker.vmnetd`（sudo 授权）才能启动 | 容器行为由 CI 的 `.github/workflows/docker.yml` 承接 |

---

## 10. 已知问题速查（写 PR 描述时可直接引用）

- **pytest 全绿**：`171 passed`，0 失败 0 错误（§3.2）。
- **覆盖率 52%**（§3.2）——本版本已知的短板。
- **`ruff check .` 通过**（exit 0）。
- **`/api/v1` 已挂载**，OpenAPI 规范 66 条 path。注意 `/api/v1/health` 这个路由**在代码中从未存在**，
  它返回 404 不代表 API 蓝图没挂载。
- **`/swagger`、`/redoc`、`/swagger.json` 在开发环境可用**；生产环境需显式 `ENABLE_API_DOCS=true`。
- **`/docs` 是 302 跳转到 `/swagger`**，规范在 `/swagger.json`，**不在** `/docs/openapi.json`（后者 404）。
- **管理界面在 `/amis/login.html`**（`/amis/` 带尾斜杠显示登录页，`/amis` 不带尾斜杠返回 404）。
- **`/uploads/*` 返回 404** —— 上传目录不做静态托管，下载走需鉴权的 `GET /api/v1/files/<id>/download`。
- **部分动态路由的方法不匹配返回 404 而非 405**（例如 `DELETE /api/v1/settings/key/<key>`）——
  M1 的 405 兜底只覆盖 account / role / profile 三个模块。
- **`frontend/npm run lint` 失败**（exit 1，8 Parsing error，§9 #9）——Vue 实验线，不维护。
- **production 缺 `JWT_PRIVATE_KEY` 或 `INITIAL_ADMIN_PASSWORD` 会拒绝启动**；
  `SECRET_KEY` 与 `PASSWORD_SALT` 不参与门禁（§5.1）。
- **真实 `docker compose up` 未在本机执行**（§9 #13）——Docker daemon 需 sudo 授权才能启动，
  容器路径由 CI 承接。

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

## 12. 测试与脚本里不要写死「当前有哪些」的名称或版本号

**这是踩过两次的坑，两次都是「今天写的判据，明天会因为正常演进而假失败」。**

### 实例一：`check_dialect_ddl.py` 写死增量版本号

判据原为 `not m.startswith("1_")`（认为「不是 `1_*` 就是基线重跑」）。
加第 2 条增量（M3 的 ticket 迁移，`2_*`）后立刻误报：

```
- 存量库不应重跑基线，实际应用了 ['2_20261024184457_specgen.py']
```

**正确做法**：按**基线文件名**判断，而不是版本号前缀：

```python
baseline_names = {p.name for p in models_dir.glob("0_*.py")}
reran_baseline = [m for m in applied if m in baseline_names]
```

### 实例二：`test_permissions_and_menu_auto_registered` 写死资源名

断言 `generated == ["customer", "order"]`。加 `ticket` 资源后假失败——
而该用例的本意是「**所有**生成资源都注册了权限与菜单」，
不是「恰好只有这两个」。

**正确做法**：从权威来源动态取期望集合：

```python
expected = sorted(load_specs(ROOT / "specs", "specs"))
assert generated == expected
```

### 判据

写测试/校验时先问一句：

> **这个断言里出现的名称、数量、版本号，是「规则」还是「今天的现状」？**

- 是**现状**（当前有哪几个资源、当前最大版本号是几、当前有几个路由）→ 必须动态取，
  从权威来源算（`specs/`、目录 glob、schema 定义）
- 是**规则**（字段必须非空、类型必须匹配、权限必须四项）→ 可以写死

写死现状的代价：每次正常演进都要改测试，而改的人往往会顺手把断言改松——
**门禁就这样一点点失效**。

### 修完一处，先 grep 找全同类再改

**同一天这个错误出现了四次**，前两次修完就以为结束了，结果 CI 第三、四次又红：

| 位置 | 写死了什么 |
|---|---|
| `scripts/check_dialect_ddl.py` | `not m.startswith("1_")` |
| `test_permissions_and_menu_auto_registered` | `["customer", "order"]` |
| `tests/test_migrations_aerich.py`（**两处**） | `not m.startswith("1_")` |
| `test_positive_control_failure_reason_is_visible` | 删增量的方式会先触发别的检查 |

关键教训：**我修完前两处、写完这一节文档，同一轮 CI 还是红在第三、四处上。**

所以规矩是——修这类问题时，**先 grep 找全所有出现位置，再逐个改**，
不要只改眼前报错的那一处：

```bash
grep -rn 'startswith("[0-9]_")\|== \["customer", "order"\]' tests/ scripts/ tools/
```

改完再跑一次同样的 grep 确认无残留（注释里提到旧写法是正常的）。

**只改一处 = 下一次 CI 还会红。**

### 附：枚举取值要从类型定义读，不要手抄

`FieldType` 这样的 `Literal` 用 `typing.get_args()` 取全部取值：

```python
args = typing.get_args(FieldType)   # ('string', 'text', 'int', ...)
```

手抄的列表会在类型扩展时漏掉新值——M3 的 date/datetime 缺陷正是「类型加了、
映射没加」，而手抄的测试列表也不会发现。

---

## 13. 参考文件

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
