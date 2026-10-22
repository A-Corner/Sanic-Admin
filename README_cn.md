# Sanic-Admin（中文）

> **完整文档请看英文版 [README.md](README.md)。** 本文件是精简版：只保留最常用的信息，特性清单、证据表和限制说明以英文版为准。
>
> **项目状态**：正在为 **v0.2.0** 重建，当前基线**尚不可用于生产环境**。仓库内**不含任何默认口令或密钥**——初始管理员口令由启动时生成（仅开发环境）或通过 `INITIAL_ADMIN_PASSWORD` 提供。安全问题请私下报告，见 [SECURITY.md](SECURITY.md)。
>
> **许可证**：Apache-2.0，见 [LICENSE](LICENSE)。

基于 **Sanic**（异步 Python Web 框架）+ **Tortoise ORM** 的后台管理框架，内置 **RBAC** 权限、**RS256 签名 JWT** 会话；管理界面采用 **AMIS** 低代码框架（由 JSON 页面定义驱动）。

---

## 特性

- **认证与会话**：注册 / 验证 / 登录 / 登出 / 会话关联、图形验证码、两步验证流程；RS256 签名的 JWT 会话，同时通过 `HttpOnly` Cookie 和 `Authorization` 响应头下发。真实路由前缀为 `/auth`、`/capt`、`/two-step`、`/roles`、`/account`（`app/auth/routes.py:27-31`）。
- **RBAC 权限**：角色模型携带 `{资源: [操作]}` 权限表；提供权限检查、角色检查、角色分配与回收；`is_admin` 账户拥有全部权限。
- **管理 API**：账户、角色、个人资料、系统设置、操作日志、文件上传、仪表盘、缓存、只读 SQL 分析。这些是**类式 CRUD 资源**（继承 `app/api/base.py` 的 `CRUDResource`），不是独立的 `@bp.route` 蓝图装饰器。
- **缓存**：内存 / Redis 双后端，共用一套接口；Redis 不可达时开发环境降级为内存，**生产环境拒绝降级启动**。
- **安全基线**：生产环境缺少必需密钥时 **fail-closed**（直接退出，rc=1）；仓库内无密钥；SQL 分析只接受单条 `SELECT`/`WITH`；上传文件使用生成的文件名，不使用原始文件名拼路径。
- **API 文档**：OpenAPI 3.0 生成器与 `@api_tags` / `@api_summary` / `@api_response` 等装饰器，由 `ENABLE_API_DOCS` 控制（开发环境开、生产环境关）。实测 `/swagger` 302 跳转后 200、`/redoc` 200、`/swagger.json` 200 且规范含 57 条 path（详见英文版 README）。

**已知限制**（详见英文版 README 与 [Release Notes](docs/release/v0.2.0-release-notes.md)）：注册接口存在账户枚举风险；**2FA 目前是全局开关（`REQUIRE_TWO_FACTOR`，由服务端配置决定、忽略客户端参数），尚不支持按账户开关**；测试覆盖率 50%；若干 404/405 与静态公开文件的边界问题留到 v0.3。

---

## 快速开始

### 系统依赖

**必须安装 libmagic**（`python-magic` 依赖它，用于上传文件的 MIME 识别）：

- macOS：`brew install libmagic`
- Debian / Ubuntu：`apt install libmagic1`
- Alpine：`apk add libmagic`

Python 版本：**3.10 – 3.12**（CI 在这三个版本上运行）。

### 方式一：Docker 一键运行

> **Docker 路径已真机跑通。** 镜像构建成功、容器启动、`/health` 返回 200、管理员经 HTTP 登录成功、可选 Redis profile 启动并返回 `PONG`。镜像以非 root 用户运行，内置 `libmagic`，**不含任何密钥**——所有密钥在运行时由 `.env` 注入。
>
> 有一处必须如实说明：上述测量是在**仅运行时打补丁**（未改动仓库任何文件）的情况下完成的。仓库中提交的镜像仍会停在第一个上游导入缺陷上，因此在未修复的代码树上执行 `docker compose up` 会因 `ConfigError` 退出。这些缺陷位于 `app/**`，另行跟踪；完整清单见 [Release Notes](docs/release/v0.2.0-release-notes.md)。
>
> `Dockerfile`、`docker-compose.yml`、`.env.example`、`.dockerignore` 都在本仓库中。GitHub Actions（`.github/workflows/docker.yml`）为该路径提供持续回归。

```bash
cp .env.example .env      # 把 .env 里所有占位符替换成真实值
docker compose up -d --build
```

访问 **http://localhost:22230**（宿主机映射端口；容器内为 22222）。Redis 是可选 profile：`CACHE_TYPE=redis` 时用 `docker compose --profile redis up -d` 启用。

容器内固定 `SANIC_ENV=production`，因此密钥没通过 `.env` 真正提供时容器会直接拒绝启动——**「容器起来了」本身就是配置已正确提供的证据**。

### 方式二：pip（已实测）

```bash
git clone https://github.com/<owner>/Sanic-Admin.git
cd Sanic-Admin

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export INITIAL_ADMIN_PASSWORD='<换成你自己的强口令>'   # 管理员口令（不是邮箱）
python main.py
```

Windows PowerShell 用 `$env:INITIAL_ADMIN_PASSWORD='<换成你自己的强口令>'` 设置。

服务监听 **http://127.0.0.1:22222**（`127.0.0.1` 与 `localhost` 是同一个地址）。

**管理员的两个值是两回事：**

| | 值 | 来源 |
|---|---|---|
| **邮箱**（登录框里填的用户名） | `SAdmin@Sanic.com` | 默认值；可用 `INITIAL_ADMIN_EMAIL` 覆盖 |
| **口令** | 你 `export` 的 `INITIAL_ADMIN_PASSWORD` | 若**没有** export，开发环境会在启动时随机生成并**只打印一次**： |

```text
[开发环境] 已自动生成临时初始管理员口令（仅显示这一次，重启后失效）:
    账号: SAdmin@Sanic.com
    口令: 8VjvxJJhex3EAfzw
设置环境变量 INITIAL_ADMIN_PASSWORD 可固定口令。
```

这段由 Sanic 的 **worker 子进程**打印，若把输出重定向到日志文件，请在文件里搜 `口令:`，否则容易
在启动日志里漏掉。随机口令在进程重启后失效。

**首次启动约需 30–40 秒**（等待 worker 进程起来）。看到下面两行即表示就绪：

```text
[INFO] Goin' Fast @ http://127.0.0.1:22222
[INFO] Starting worker [xxxxx]
```

管理界面入口在 **http://127.0.0.1:22222/amis/login.html**，用上面的邮箱与口令登录即可。
管理界面由后端自己托管，与 API 同源，不涉及 CORS。

验证服务：

```bash
curl http://127.0.0.1:22222/health
# {"status":"ok","env":"development"}
```

登录（管理员邮箱默认为 `SAdmin@Sanic.com`，可用 `INITIAL_ADMIN_EMAIL` 覆盖）：

```bash
curl -X POST http://127.0.0.1:22222/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"SAdmin@Sanic.com","password":"<你上面 export 的口令>"}' -c cookies.txt

# 带 Cookie 访问受保护接口
curl -X POST -b cookies.txt http://127.0.0.1:22222/auth
```

> 生产环境必须通过环境变量提供 `INITIAL_ADMIN_PASSWORD`，缺失时直接退出。

运行测试：

```bash
pip install -r requirements-dev.txt
pytest
```

> **当前测试状态**：`pytest` 报 **`95 passed`，0 失败，0 错误**（收集 95 个用例，约 54 秒）。`app/` 的覆盖率为 **50%**，用例集中在认证、鉴权、账户与角色 CRUD、上传路径穿越、SQL 只读约束与生产环境 fail-closed 门禁。`ruff check . --select E9,F63,F7,F82` 通过，且在 CI 中是硬门禁。

---

## 配置要点

全部配置通过环境变量。权威来源是 **`app/config.py`**（每个变量都在那里读取），下表直接取自该文件。

> 完整参考（每个变量、类型、默认值、各环境下的行为）见 **[docs/configuration.md](docs/configuration.md)**，内容直接对照 `app/config.py` 写成。下表是常用变量摘要。

| 变量 | 说明 |
|---|---|
| `SANIC_ENV` | `development`（默认）/ `testing` / `production` |
| `SECRET_KEY` | 应用密钥，可选——当前不参与任何签名或加密 |
| `JWT_PRIVATE_KEY` | RS256 签名私钥 PEM，**生产环境必需**；公钥由私钥推导 |
| `INITIAL_ADMIN_PASSWORD` | 初始管理员口令，**生产环境必需** |
| `INITIAL_ADMIN_EMAIL` | 管理员邮箱，默认 `SAdmin@Sanic.com` |
| `PASSWORD_SALT` | 口令盐，可选——口令哈希用 argon2 自带随机盐 |
| `ENABLE_API_DOCS` | 是否挂载 Swagger / ReDoc 路由，**开发环境开、生产环境关** |
| `REQUIRE_TWO_FACTOR` | 登录后是否要求二次验证，默认关 |
| `DATABASE_URL` | Tortoise ORM 连接串；开发默认本地 SQLite，测试默认内存 SQLite |
| `CACHE_TYPE` | `memory` 或 `redis`；生产默认 `redis` 且不可降级 |
| `HOST` / `PORT` | 监听地址与端口，默认 `127.0.0.1` / `22222` |

---

## 部署

有两项设置决定 production 实例能否启动。两者都是**失败即拒绝**（方向正确，但只配了四个密钥的人常在这里意外）。

**1. Redis 必须可达，除非你主动关掉。** production 下 `CACHE_TYPE` 默认 `redis`，
Redis 不可达时应用拒绝降级为内存缓存：

```
ConfigError: production 环境 Redis 缓存不可用，拒绝降级启动
```

要么给出可达的 Redis（设 `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD`），
要么显式设 `CACHE_TYPE=memory`——内存缓存是进程内的，重启即失效，也不能横向扩展。

**2. `DATABASE_URL` 必须设置，且默认是 MySQL。** 未设置 `DATABASE_URL` 时，
应用会从 `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` 拼出 MySQL 连接串。
而 **`aiomysql` 不在 `requirements.txt` 里**，所以 MySQL 部署会先在导入阶段报
`ModuleNotFoundError: No module named 'aiomysql'`，除非你自己装驱动。

想用本地文件快速跑一个 production：

```bash
export DATABASE_URL='sqlite:///./sanic_admin_prod.sqlite3'
export CACHE_TYPE=memory
export JWT_PRIVATE_KEY="$(openssl genrsa 2048 | sed ':a;N;$!ba;s/\n/\\n/g')"
export INITIAL_ADMIN_PASSWORD='<换成你自己的强口令>'
python main.py
```

真正的启动门禁是 `JWT_PRIVATE_KEY` 与 `INITIAL_ADMIN_PASSWORD` 两个；
`SECRET_KEY` 与 `PASSWORD_SALT` 可以填但当前用不到。

---

## 文档链接

| 文档 | 内容 |
|---|---|
| [README.md](README.md) | **完整版 README（英文）**：特性证据表、已知限制、完整文档索引 |
| [docs/configuration.md](docs/configuration.md) | 全部环境变量说明 |
| [docs/architecture.md](docs/architecture.md) | 架构与模块划分 |
| [docs/release/v0.2.0-release-notes.md](docs/release/v0.2.0-release-notes.md) | v0.2.0 Release Notes（草稿）：版本范围、逐项验证方式与已知限制 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南与 PR 流程 |
| [SECURITY.md](SECURITY.md) | 安全漏洞私下报告渠道 |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | 行为准则 |
| [CHANGELOG.md](CHANGELOG.md) | 变更日志 |

> v0.2.0 的版本范围、每一项功能的验证方式与已知限制，见 [Release Notes](docs/release/v0.2.0-release-notes.md)。上面的「配置」小节是摘要，完整的环境变量参考在 `docs/configuration.md`，内容直接对照 `app/config.py` 写成。

---

## 贡献

请先阅读 **[CONTRIBUTING.md](CONTRIBUTING.md)**：开发环境搭建、分支与 PR 流程、代码风格、测试要求。安全问题**不要**在公开 Issue 中披露，请按 [SECURITY.md](SECURITY.md) 私下报告。

---

## 许可证

**Apache License 2.0** —— 见 [LICENSE](LICENSE)。

---

致谢：[Sanic](https://github.com/sanic-org/sanic)、[Tortoise ORM](https://github.com/tortoise/tortoise-orm)、[AMIS](https://github.com/baidu/amis)。
