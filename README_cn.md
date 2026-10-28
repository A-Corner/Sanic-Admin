# Sanic-Admin（中文）
**让 AI 改后台，但每一次改动都走 PR。**

（英文版 [README.md](README.md) 是完整文档，本文件为精简中文版。）

本框架基于 **Sanic**（异步 Python Web 框架）+ **Tortoise ORM**，内置 **RBAC** 权限与 **RS256 签名 JWT** 会话，管理界面采用 **AMIS**。你用一份 YAML 规格描述业务模块，确定性生成器产出模型、CRUD API、权限点、AMIS 页面、测试与三方言迁移——所有改动都以可评审的 diff 落地，而不是运行时直接改状态。

## 三个核心点

- **规格即代码**。一个模块一份 YAML；生成器确定性地产出模型、CRUD API、权限点、AMIS 页面、测试与 SQLite/MySQL/PostgreSQL 迁移。同样规格产出逐字节相同的结果——变更以 diff 评审，而不是对比两次数据库状态。证据：[v0.4.0 发布](https://github.com/A-Corner/Sanic-Admin/releases/tag/v0.4.0)与[十分钟演示](https://github.com/A-Corner/Sanic-Admin/blob/master/docs/demo/ai-module-in-10-minutes.md)。
- **AI 出提案，人来做合并**。MCP 服务提供五个只读工具，写入路径**默认关闭**；开启后也只能建 `proposal/` 分支与归属 ref——不改工作区、不 push、不合并，四层独立机制保证这一点，合并永远是人的动作。见 [docs/mcp.md](https://github.com/A-Corner/Sanic-Admin/blob/master/docs/mcp.md) 与[四层机制论证](https://github.com/A-Corner/Sanic-Admin/blob/master/docs/mcp-write-path.md)。
- **门禁真跑**。v0.4.0 发布树全量 **640 passed / 0 failed**；真实浏览器跑 **22 条 E2E 断言**；CI 起 MySQL 8 与 PostgreSQL 16 实跑迁移并对着 `information_schema` 断言列类型；Docker 验收真起容器——每道门禁都被设计成能够失败。证据：[v0.4.0 发布说明](https://github.com/A-Corner/Sanic-Admin/blob/v0.4.0/docs/release/v0.4.0-release-notes.md)。

## 与 Directus / NocoBase 的对比

| | Sanic-Admin | Directus | NocoBase |
|---|---|---|---|
| Schema 放在哪 | Git 里的 YAML 规格 | 数据库里（另有可导出的 schema snapshot） | 数据库里 |
| AI 的改动怎么生效 | 改规格 → 生成器产出 diff → PR | 直接作用于运行实例；snapshot 可导出比对 | 直接作用于运行实例 |
| 能否审查与回滚 | 每个改动都是 PR diff；回滚即 `git revert` | snapshot 可比对，但运行时改动不经代码评审 | 同 Directus |

这些工具并不差——差别在事实源的位置：这里是一份可 diff 的文本住在 Git 里，AI 的产出在运行之前就能被逐行评审。

## 五分钟上手

```bash
# 1) 起服务（compose 路径由 CI 的 Docker Acceptance 每次 push 实跑验证：
#    https://github.com/A-Corner/Sanic-Admin/actions/workflows/docker.yml ）
docker compose up -d        # 打开 http://127.0.0.1:22222

# 2) 一份规格生成一个模块（输出为 2026-10-25 在 v0.4.1 基线上的实跑结果）
cat > specs/asset.yaml <<'YAML'
resource: asset
table: assets
plural: assets
label: 资产
description: 固定资产登记
fields:
  - name: name
    type: string
    max_length: 128
    required: true
    label: 名称
    list: true
    searchable: true
  - name: serial_no
    type: string
    max_length: 64
    required: true
    label: 序列号
    list: true
  - name: purchased_at
    type: date
    label: 购入日期
    list: true
YAML
python -m tools.specgen generate   # 完成：8 个文件更新，0 个陈旧文件清理
python -m tools.specgen migrate    # migrations/dialects/{sqlite,mysql,postgres}/3_*_specgen.py 三方言各一份
python -m tools.specgen check      # OK: 生成物与规格一致

# 3) 接 MCP 只读层（完整配置见 docs/mcp.md）
```

```json
{
  "mcpServers": {
    "sanic-admin-specgen": {
      "command": "python",
      "args": ["-m", "tools.mcp_server"],
      "cwd": "/absolute/path/to/Sanic-Admin"
    }
  }
}
```

五个只读工具：`list_resources`、`describe_resource`、`validate_spec`、`preview_generate`、`check`。

## 演示：AI 加一个模块

[ai-module-in-10-minutes.md](https://github.com/A-Corner/Sanic-Admin/blob/master/docs/demo/ai-module-in-10-minutes.md) 记录了一次真实完整过程（含命令与输出）。顺利路径约 **8.5 分钟**；首次实跑用了 **1.5–2 小时**——浏览器 E2E 抓到了全绿 CI 漏掉的缺陷，这个差额正是门禁起作用的证据。

## 已知限制

- 生成器只处理**新增**：删列、改类型等破坏性迁移刻意要求手写。
- MCP 写入路径是**原型**（默认关闭）；账户级 `spec:write` 权限已在 v0.4.2 发布。
- 管理界面为 **AMIS 6.13.0**（v0.4.1 从 3.4.0 升级）。
- **单一维护者**，尚无外部贡献者。
- 尚不可用于生产环境——见下方项目状态。

---

> **项目状态**：最新版本为 **[v0.4.2](https://github.com/A-Corner/Sanic-Admin/releases/tag/v0.4.2)**（2026-10-27，MCP 写入路径接入账户级 `spec:write` 权限），其前依次为 [v0.4.1](https://github.com/A-Corner/Sanic-Admin/releases/tag/v0.4.1)（时间字段 ISO 8601、AMIS 6.13.0）与 v0.4.0（规格生成器）；原始重构版本为 v0.2.0。当前基线**尚不可用于生产环境**。仓库内**不含任何默认口令或密钥**——初始管理员口令由启动时生成（仅开发环境）或通过 `INITIAL_ADMIN_PASSWORD` 提供；自 v0.3.4 起该值若强度不足，**生产环境拒绝启动**。安全问题请私下报告，见 [SECURITY.md](SECURITY.md)。
>
> **从 v0.3.1 及更早版本升级**需先运行 [v0.3.2 发布说明](docs/release/v0.3.2-release-notes.md) 中的迁移脚本（新增 `account.must_change_password`）；全新安装无需迁移。
>
> **许可证**：Apache-2.0，见 [LICENSE](LICENSE)。

## 特性

- **认证与会话**：注册 / 验证 / 登录 / 登出 / 会话关联、图形验证码、两步验证流程；RS256 签名的 JWT 会话，同时通过 `HttpOnly` Cookie 和 `Authorization` 响应头下发。真实路由前缀为 `/auth`、`/capt`、`/roles`、`/account`（`app/auth/routes.py:27-31`）。
- **鉴权加固（v0.3.4）**：认证路径写入操作日志（登录成功/失败、登出、改密、2FA，不含口令与 token）；改密需校验当前口令并限速（达阈值 429）；新口令强度与拒绝清单校验，**收敛到 `Account.set_password()`，注册与管理员建账户同样受约束**；改密成功后**当前会话一并作废并轮换**（`token_rotated: true`，breaking）。
- **资源审计（v0.4.2）**：生成资源的 `POST`/`PUT`/`DELETE` 成功后自动写 `OperationLog`——记操作者、资源名、动作、对象 id、IP 与**变更字段名（不记值）**；审计写失败只记 warning，**不影响主请求**。见 [docs/specgen.md](docs/specgen.md#操作审计v042-起自动生成)。
- **强制改密（v0.3.2）**：由 `INITIAL_ADMIN_PASSWORD` 创建的管理员首次登录必须改密，未完成前其余 API 返回 `403 PASSWORD_CHANGE_REQUIRED`。
- **RBAC 权限**：角色模型携带 `{资源: [操作]}` 权限表；提供权限检查、角色检查、角色分配与回收；`is_admin` 账户拥有全部权限。
- **管理 API**：账户、角色、个人资料、系统设置、操作日志、文件上传、仪表盘、缓存、只读 SQL 分析。这些是**类式 CRUD 资源**（继承 `app/api/base.py` 的 `CRUDResource`），不是独立的 `@bp.route` 蓝图装饰器。
- **缓存**：内存 / Redis 双后端，共用一套接口；Redis 不可达时开发环境降级为内存，**生产环境拒绝降级启动**。
- **安全基线**：生产环境缺少必需密钥时 **fail-closed**（直接退出，rc=1）；仓库内无密钥；SQL 分析只接受单条 `SELECT`/`WITH`；上传文件使用生成的文件名，不使用原始文件名拼路径。
- **API 文档**：OpenAPI 3.0 生成器与 `@api_tags` / `@api_summary` / `@api_response` 等装饰器，由 `ENABLE_API_DOCS` 控制（开发环境开、生产环境关）。实测 `/swagger` 302 跳转后 200、`/redoc` 200、`/swagger.json` 200 且规范含 66 条 path（详见英文版 README）。

**已知限制**（详见英文版 README 与 [Release Notes](docs/release/v0.3.0-release-notes.md)）：注册接口存在账户枚举风险；**2FA 目前是全局开关（`REQUIRE_TWO_FACTOR`，由服务端配置决定、忽略客户端参数），尚不支持按账户开关**；**生产环境下自助注册的账户无法完成验证、因而无法登录**——注册得到的账户为 `verified=False`，登录时被 `UnverifiedError` 拒绝；完成验证需向 `POST /auth/verify` 提交两步验证码，而该验证码**只在 `DEBUG` 时进入响应体**，全仓也没有任何链路把它送到注册者手上（唯一的 `await deliver(` 属于密码重置路径），且 `verified` 不在账户 API 白名单内、管理员同样无法经 API 置位，结果是注册者永远拿不到验证码、账户停在未验证状态，能登录的只有初始管理员；这是**已知的未完成能力，不是缺陷**，与顶部「尚不可用于生产环境」的声明一致，部署者若要开放自助注册，必须自行接入投递渠道（实现 `app/services/delivery.py` 的 `Backend` 抽象）**并**确保账户 `verified` 被置位，或自行决定关闭自助注册；测试覆盖率 68% 仍不足；登录页缺独立的 login-CSRF token（`TRUSTED_PROXIES` 亦暂无环境变量接线）。v0.2.x 遗留的 value 长度与请求体上限问题已在 v0.3.0 修复（value ≤ 8192、`REQUEST_MAX_SIZE` 16MB 真实生效）。

---

## 快速开始

### 系统依赖

**必须安装 libmagic**（`python-magic` 依赖它，用于上传文件的 MIME 识别）：

- macOS：`brew install libmagic`
- Debian / Ubuntu：`apt install libmagic1`
- Alpine：`apk add libmagic`

Python 版本：**3.10 – 3.12**（CI 在这三个版本上运行）。

### 方式一：Docker 一键运行

> **Docker 路径已真机跑通（无任何运行时补丁）。** 2026-10-22 在一台真实的 Linux Docker 宿主机上从仓库源码直接构建并验收：`/health` 返回 200、管理员经 HTTP 登录成功、`/amis/login.html` 返回 200、容器日志 `[降级]` 计数为 0、去掉 `JWT_PRIVATE_KEY` 后容器以退出码 1 重启（fail-closed 生效）。构建用时约 49 分钟——绝大部分耗在受限网络的 apt 与 pip 下载上（见下面的换源说明），不是应用本身的问题。镜像以非 root 用户运行，内置 `libmagic`，**不含任何密钥**——所有密钥在运行时由 `.env` 注入。
>
> **注意**：上述 `/amis/login.html` 200 只验证了页面可达性，**未**验证控制台的功能可用性；浏览器端功能验收见 `scripts/amis_e2e_check.py`。
>
> `Dockerfile`、`docker-compose.yml`、`.env.example`、`.dockerignore` 都在本仓库中。GitHub Actions（`.github/workflows/docker.yml`）为该路径提供持续回归。

```bash
cp .env.example .env      # 把 .env 顶部「启动必改」的 2 项换成真实值
docker compose up -d --build
```

访问 **http://localhost:22230**（宿主机映射端口；容器内为 22222）。Redis 是可选 profile：`CACHE_TYPE=redis` 时用 `docker compose --profile redis up -d` 启用。

**受限网络（无法直连 pypi.org）**：在 `.env` 里设 `PIP_INDEX_URL` 指向可用的镜像源即可换源，
然后照常执行 `docker compose up -d --build`，**无需手工加 `--build-arg`**：

```bash
# 在 .env 里加一行（示例为阿里云镜像源，按所在网络选可用的）
echo "PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/" >> .env
docker compose up -d --build
```

不设这一行时用的是官方源 `https://pypi.org/simple`，默认行为不变。

**构建期 apt 也可能很慢**：同样的受限网络下，Debian 源（`deb.debian.org`）往往比 pip 更慢——
一次实测仅 apt 拉取编译工具链就花了约 2800 秒。镜像当前没有 apt 换源参数；需要时请自行
替换 `Dockerfile` 里的 apt 源，v0.3 会提供构建参数。

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

开发模式下这一个变量就是全部准备：`JWT_PRIVATE_KEY` 未设置时应用会在启动时自动生成
临时签名私钥并打印提示（`config.py` 对初始口令做同样的处理）。production 不同——
`JWT_PRIVATE_KEY` 与 `INITIAL_ADMIN_PASSWORD` 两项都是硬性要求（见下面的 production 快速启动）。

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
在启动日志里漏掉。

**请保留首次启动打印的那个口令。** 管理员账户只在不存在时创建，所以首次打印的口令一直有效；
之后重启虽然会再打印一个随机口令，但**并不会生效**——因为账户已经存在了。
要跨重启固定口令，请在首次启动前设置 `INITIAL_ADMIN_PASSWORD`。

**服务启动需要几秒**（实测 2–6 秒，等待 worker 进程起来）。看到下面两行即表示就绪：

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

> **当前测试状态**：`pytest` 报 **`171 passed`，0 失败，0 错误**（收集 171 个用例，约 65 秒；加 `--cov` 约 80 秒）。`app/` 的覆盖率为 **52%**，用例集中在认证、鉴权、账户与角色 CRUD、上传路径穿越、SQL 只读约束与生产环境 fail-closed 门禁。`ruff check . --select E9,F63,F7,F82` 通过，且在 CI 中是硬门禁。

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
# 注意只有两个斜杠：Tortoise 把 sqlite 的文件路径解析为 netloc+path，
# 写成 sqlite:///<名字> 会指向文件系统根目录的 /<名字>（普通用户无权创建，
# 启动时直接报 unable to open database file）。下面这种写法在当前目录建库——
# 已实测可启动，且重启后数据保留。
export DATABASE_URL='sqlite://sanic_admin_prod.sqlite3'
export CACHE_TYPE=memory
# PEM 是多行内容；环境变量里必须写成「换行替换为字面量 \n」的单行。
# 不要用 sed 做这个替换——BSD/GNU 两个方言对 \n 的处理不同，引号会被破坏。
# 下面这条命令只用 openssl + python3 标准库，已实测可启动：
export JWT_PRIVATE_KEY="$(openssl genrsa 2048 2>/dev/null | python3 -c 'import sys; print(sys.stdin.read().strip().replace(chr(10), chr(92)+"n"))')"
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
| [docs/release/v0.3.2-release-notes.md](docs/release/v0.3.2-release-notes.md) | v0.3.2：首登强制改密、2FA 修复；**从 v0.3.1 及更早升级需跑迁移** |
| [docs/release/v0.3.3-release-notes.md](docs/release/v0.3.3-release-notes.md) | v0.3.3：控制台角色弹窗热修、E2E 门禁修复、新增 `amis-e2e` CI |
| [docs/release/v0.3.4-release-notes.md](docs/release/v0.3.4-release-notes.md) | v0.3.4：鉴权加固——审计日志、改密限速、口令强度、会话轮换（含两处 breaking） |
| [docs/release/v0.4.0-release-notes.md](docs/release/v0.4.0-release-notes.md) | v0.4.0：规格即代码——一份 YAML 生成模型、CRUD API、AMIS 页面与三方言迁移；生产环境要求 `aerich` 账本（breaking） |
| [docs/release/v0.4.1-release-notes.md](docs/release/v0.4.1-release-notes.md) | v0.4.1：时间字段改 ISO 8601、AMIS 升级 6.13.0、`discard_proposal` 归属校验（含一处 breaking） |
| [docs/release/v0.4.2-release-notes.md](docs/release/v0.4.2-release-notes.md) | v0.4.2：账户级 `spec:write`、`GET /auth/whoami`、生成资源 CRUD 审计日志（含一处 breaking） |
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
