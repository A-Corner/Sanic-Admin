# Sanic-Admin

**Spec-as-code admin backend where AI proposes changes as PRs, never edits production directly.**

Sanic-Admin is a backend administration framework built on **Sanic** (async Python web framework) and **Tortoise ORM**, with **RBAC** authorization and **RS256-signed JWT** sessions; the admin console is **AMIS**. You describe a business module in one YAML spec, a deterministic generator turns it into models, CRUD APIs, permission points, AMIS pages, tests and three-dialect migrations — and every change lands as a reviewable diff instead of a runtime mutation.

## Why Sanic-Admin

- **Spec as code.** One YAML file per module; the generator deterministically produces models, CRUD APIs, permission points, AMIS pages, tests and SQLite/MySQL/PostgreSQL migrations. Same spec in, byte-identical result out — so a change is reviewed as a diff, not by comparing two databases. See the [v0.4.0 release](https://github.com/A-Corner/Sanic-Admin/releases/tag/v0.4.0) and the [10-minute demo](https://github.com/A-Corner/Sanic-Admin/blob/master/docs/demo/ai-module-in-10-minutes.md).
- **AI proposes, humans merge.** An MCP server exposes five read-only tools plus a write path that is **off by default**: proposals land in `proposal/` branches, and four independent layers make it impossible for the AI to push or merge — merging is a human act by design. See [docs/mcp.md](https://github.com/A-Corner/Sanic-Admin/blob/master/docs/mcp.md) and the [four-layer guarantee](https://github.com/A-Corner/Sanic-Admin/blob/master/docs/mcp-write-path.md).
- **Gates actually run.** The v0.4.0 release tree passed **640 tests / 0 failed**; a real browser executes **22 E2E assertions**; CI boots MySQL 8 and PostgreSQL 16 to run migrations and assert column types against `information_schema`; Docker acceptance starts the real container — and every gate is built so that it can fail. Evidence: [v0.4.0 release notes](https://github.com/A-Corner/Sanic-Admin/blob/v0.4.0/docs/release/v0.4.0-release-notes.md).

## How it compares

| | Sanic-Admin | Directus | NocoBase |
|---|---|---|---|
| Where the schema lives | YAML specs in Git | In the database (plus exportable schema snapshots) | In the database |
| How an AI change takes effect | Edit the spec → generator emits a diff → PR | Applies to the running instance; snapshots can be exported for comparison | Applies to the running instance |
| Review & rollback | Every change is a PR diff; rollback is `git revert` | Snapshots can be diffed, but runtime changes do not pass through code review | Same as Directus |

These tools are not bad — the difference is where the source of truth lives. Here it is diff-able text in Git, so an AI's output can be reviewed line by line before it ever runs.

## Try it in 5 minutes

### 1) Start the stack

```bash
docker compose up -d
# then open http://127.0.0.1:22222 — the compose path is exercised on every
# push by the Docker Acceptance workflow:
# https://github.com/A-Corner/Sanic-Admin/actions/workflows/docker.yml
```

### 2) Generate a module from one spec

```bash
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

python -m tools.specgen generate
# 写入 app/generated/models/asset.py
# 写入 app/generated/resources/asset.py
# 写入 amis/pages/asset-list.json
# 完成：8 个文件更新，0 个陈旧文件清理

python -m tools.specgen migrate
# migrations/dialects/{sqlite,mysql,postgres}/3_20261025060909_specgen.py — 三方言各一份

python -m tools.specgen check
# OK: 生成物与规格一致
```

（输出为 2026-10-25 在 v0.4.1 基线上的实跑结果。）

### 3) Hook up the MCP read-only layer

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

The five tools are read-only: `list_resources`, `describe_resource`, `validate_spec`, `preview_generate`, `check`. Full setup and the optional write path (off by default): [docs/mcp.md](https://github.com/A-Corner/Sanic-Admin/blob/master/docs/mcp.md).

## Demo: adding a module with AI

[ai-module-in-10-minutes.md](https://github.com/A-Corner/Sanic-Admin/blob/master/docs/demo/ai-module-in-10-minutes.md) walks through one real run, commands and outputs included. The smooth path takes about **8.5 minutes**; the first real run took **1.5–2 hours** because browser E2E caught defects that a green CI had missed — that gap is the point of the gates.

## Limitations

- The generator only **adds**: column drops, type changes and other destructive migrations are handwritten on purpose.
- The MCP write path is a **prototype** (off by default); account-level `spec:write` permission shipped in v0.4.2.
- The admin console is **AMIS 6.13.0** (upgraded from 3.4.0 in v0.4.1).
- **Single maintainer**, no external contributors yet.
- Not production-ready yet — see the status notes below.

---

> **Project status — read this first**
>
> - The latest release is **[v0.4.2](https://github.com/A-Corner/Sanic-Admin/releases/tag/v0.4.2)** (2026-10-27), which puts the MCP write path behind account-level `spec:write` permission, on top of [v0.4.1](https://github.com/A-Corner/Sanic-Admin/releases/tag/v0.4.1) (ISO 8601 time fields, AMIS 6.13.0) and v0.4.0 (the spec generator). The original rebuild landed in **v0.2.0**. Everything below was verified by running it, and anything that could not be verified is listed under *Known limitations* in the per-release [release notes](docs/release/).
> - **Upgrading from v0.3.1 or earlier** requires running the migration script described in the [v0.3.2 release notes](docs/release/v0.3.2-release-notes.md) — it adds `account.must_change_password`. Fresh installations need no migration.
> - **Not production-ready yet.** Do not deploy this to a public environment.
> - **No credentials are baked into the repository.** There is no default administrator password. The first-run administrator password is generated at startup (development only) or must be supplied via `INITIAL_ADMIN_PASSWORD`. Since v0.3.4 that value is held to the password strength rule and **production refuses to start** if it is too weak.
> - Secrets are **environment variables only** — the repository contains none. The JWT signing key and the initial administrator password are the two that production requires; a sample key that existed in the repository history must be treated as compromised and rotated.
> - Report security issues privately — see [SECURITY.md](SECURITY.md).

## Features

Every entry below is traced to code in this repository and was verified by running it.

### Authentication and sessions

| Feature | Evidence |
|---|---|
| Register / verify / login / logout / session association | `app/auth/routes.py` — `POST /auth/register`, `/auth/verify`, `/auth/login`, `/auth/logout`, `/auth/associated` |
| CAPTCHA on the credential endpoints | `app/auth/routes.py` — `GET /capt/request`, `GET /capt/image` |
| Two-step verification flow (a single **global** switch, not per-account) | `app/auth/routes.py` — `POST /auth/validate-2fa`; the server-side `REQUIRE_TWO_FACTOR` setting decides whether it is required, and any client-supplied parameter is ignored (`app/auth/routes.py:178`) |
| RS256-signed JWT sessions (private key via `JWT_PRIVATE_KEY`) | `app/models/session.py` (`SESSION_ENCODING_ALGORITHM = "RS256"`), `app/config.py` (`load_jwt_keys`) |
| Sessions delivered as an `HttpOnly` cookie **and** an `Authorization` header | `app/models/session.py` — `Session.encode` |
| Rejects unauthenticated access to protected endpoints | `app/auth/authentication.py` — `requires_authentication`; verified: `POST /auth` without a session returns HTTP 401 |
| No administrator password in source; generated at startup or supplied by env var | `app/config.py` — `_generate_admin_password`, `_env_secret` |
| Forced password change on first login (v0.3.2) | `app/models/account.py` — `must_change_password`; an administrator created from `INITIAL_ADMIN_PASSWORD` must change it before the rest of the API answers |
| Authentication events written to the operation log (v0.3.4) | `app/services/audit.py` — `record_auth_event`; login success/failure, logout, password change and 2FA outcomes recorded as `operation_type="auth"`. No passwords, tokens or codes are written |
| Generated resources audited on write (v0.4.2) | `app/services/audit.py` — `record_resource_event`; every `POST`/`PUT`/`DELETE` on a generated resource records actor, resource name, action, object id, IP and **changed field names only, never values**. Audit failures log a warning and never fail the request. See [docs/specgen.md](docs/specgen.md#operation-audit-automatic-since-v042) |
| Password-change rate limiting and strength rules (v0.3.4) | `app/auth/authentication.py` — `validate_password_strength`, `validate_not_banlisted`; enforced in `Account.set_password()`, so registration, admin-created accounts and admin resets are covered too. **Breaking:** 429 after repeated wrong current-password entries; after a successful change every session for the account is revoked and a fresh one is issued (`token_rotated: true`) |
| Login rate limiting (v0.3.0) | `app/auth/rate_limit.py` — `LoginRateLimiter`, counted per account and per IP |

### RBAC authorization

| Feature | Evidence |
|---|---|
| Role model with a JSON permission map (`{resource: [actions]}`) | `app/models/role.py` — `Role.permissions` |
| Permission checks, role checks, role assignment/removal | `app/auth/authorization.py` — `check_permissions`, `check_roles`, `assign_role`, `remove_role`, `get_account_permissions` |
| `is_admin` accounts hold every permission | `app/auth/authorization.py` — `has_permission()` short-circuits to `True` for `account.is_admin` (`:144`) |
| Per-resource permission check decorators on the management API | `app/api/resources/*.py` — `check_permissions` / `check_roles` |

> The management API is mounted under `/api/v1` and was exercised live: the role, account, profile, settings, log and upload CRUD endpoints answer, and the permission checks are enforced (an unauthenticated request is rejected with 401, an under-privileged one with 403).

### Management API

`app/api/resources/` contains one resource module per domain. These are **class-style CRUD resources**: each resource class subclasses Sanic's `HTTPMethodView` and exposes `get`/`post`/`put`/`delete` handlers, rather than declaring standalone `@bp.route` blueprint handlers. The shared `BaseResource` / `CRUDResource` helpers in `app/api/base.py` provide the shared paging, sorting, searching and response-envelope behaviour:

`account` · `role` · `profile` · `setting` · `log` (operation log) · `upload` · `dashboard` · `dashboard_user` · `dashboard_performance` · `cache` · `database` (read-only SQL analysis) · `compression`

- **Account management** — `app/api/resources/account.py`
- **Role management** — `app/api/resources/role.py`
- **Personal profile** — `app/api/resources/profile.py`
- **System settings** — `app/api/resources/setting.py`
- **Operation log** — `app/api/resources/log.py` (backed by `app/models/operation_log.py`)
- **File upload** — `app/api/resources/upload.py`
- **Dashboard** — `app/api/resources/dashboard.py`, `dashboard_user.py`, `dashboard_performance.py`

Each resource module declares its own field allow-lists as **module-level constants** — `ACCOUNT_CREATE_FIELDS` / `ACCOUNT_UPDATE_FIELDS` in `account.py`, `ROLE_CREATE_FIELDS` / `ROLE_UPDATE_FIELDS` in `role.py`, `WRITABLE_FIELDS` in `setting.py` — and filters the payload against them, so a request cannot mass-assign fields outside the list. Access is gated with the `check_permissions` / `check_roles` decorators from `app/auth/authorization.py`.

> The `/v1` API blueprint is mounted: `app/api/__init__.py` assembles the resource blueprints with `Blueprint.group(...)`, and the generated OpenAPI spec lists **66 paths**. Verified live — `GET /api/v1/settings` answers 200 with a paginated body, and `GET /api/v1/settings/key/<key>` for a missing key answers 404 with `RESOURCE_NOT_FOUND`.

### API documentation

- OpenAPI 3.0 spec generation and the `@api_tags` / `@api_summary` / `@api_description` / `@api_body` / `@api_response` decorator family — `app/docs/decorators.py`, `app/docs/openapi.py`, `app/docs/models.py`.
- A Swagger UI page and a ReDoc page — `app/docs/swagger.py`, `app/docs/routes.py`.

`setup_docs()` is wired in `app/__init__.py` and is controlled by `ENABLE_API_DOCS`, which defaults to **on in development** and **off in production**. Verified against a running server in development:

| Endpoint | Result |
|---|---|
| `GET /swagger` | 302 → `/swagger/index.html` → **200** (Swagger UI) |
| `GET /redoc` | **200** (ReDoc) |
| `GET /swagger.json` | **200** — an OpenAPI 3.0.3 spec with **66 paths** |
| `GET /docs/` | 302 → `/swagger` |
| `GET /docs/models`, `/docs/tags`, `/docs/paths`, `/docs/redoc` | **200** |

In production the same routes return 404 unless `ENABLE_API_DOCS=true` is set explicitly. Note that `sanic-ext` also serves an OpenAPI document of its own at `/docs/openapi.json` (200 in production, 56 paths) — that is a *different* generator from `app/docs/`, and it lists only the routes Sanic has registered.

### Admin console (AMIS)

**The console is served by the backend itself.** Open **http://127.0.0.1:22222/amis/login.html** — the AMIS pages are mounted by the Sanic application under `/amis`, so the page and the API are same-origin and the `HttpOnly` session cookie is sent automatically, with no CORS involved.

- The AMIS SDK and page definitions live in `amis/` (`amis/sdk/`, `amis/pages/*.json`, `amis/index.html`, `amis/login.html`).
- The static directory is configured by `AMIS_DIR` (default: the `amis/` folder next to the application). Point it at an empty value or a missing directory and the console is not mounted — a way to switch the admin UI off in production.
- `amis/server.js` is a **zero-dependency Node development server** that proxies `/auth`, `/capt`, `/api`, `/health` and friends to the backend. It is **optional**: the backend already hosts the console, so this server exists only to preview pages while you work on them.

> The console is mounted by the application itself (`app.static("/amis", ..., index="login.html", name="amis")`). Two details worth knowing: `name="amis"` is required because Sanic 23.6 rejects duplicate route names — `/static` and `/amis` would otherwise both default to the name `static` and the service would refuse to start; and the path needs its trailing slash — `/amis/` shows the login page, while bare `/amis` returns 404, because Sanic's `DirectoryHandler` only performs the index lookup for paths ending in `/`.

### Caching

- Two interchangeable backends behind one interface — `app/cache/base.py`.
- In-process memory cache — `app/cache/memory.py`.
- Redis cache with a 2-second connect/read timeout — `app/cache/redis.py`.
- Selected by `CACHE_TYPE` (`memory` or `redis`) — `app/cache/__init__.py` — `get_cache`.
- Redis unavailability degrades to the memory cache in development/testing, and **refuses to start in production** — `app/cache/__init__.py` — `_build_redis` raises `ConfigError` when `ENV == "production"`.

### Security baseline

| Control | Evidence |
|---|---|
| Production fails closed when required secrets are missing | `app/config.py` — `_env_secret` raises `ConfigError`. Verified: with `JWT_PRIVATE_KEY` missing, `SANIC_ENV=production python main.py` prints `配置错误: 生产环境必须通过环境变量 JWT_PRIVATE_KEY 提供 JWT 签名私钥` and exits with **rc=1**; the same happens for `INITIAL_ADMIN_PASSWORD`. `SECRET_KEY` and `PASSWORD_SALT` are **not** gates — they take part in no signing or encryption today |
| No secret, key or default password in the repository | `app/config.py` — all secrets read from environment variables; verified: `git grep -nIE "BEGIN (RSA )?PRIVATE KEY"` returns only the **placeholder** in `.env.example` (body: `change-me-generate-a-real-rsa-private-key…`), which is not a loadable key |
| Administrator password generated at startup, printed once to stdout in development only | `app/config.py` — `_generate_admin_password` |
| SQL analysis accepts a single read-only `SELECT`/`WITH` statement and issues only `EXPLAIN` | `app/database/query_analyzer.py` — `validate_readonly_sql`, `_FORBIDDEN_SQL_RE`, `_FORBIDDEN_FUNC_RE`; verified: `DELETE FROM account`, `SELECT 1; DROP TABLE x` and `PRAGMA table_info(account)` are all rejected |
| Uploads are stored under a generated filename inside a fixed upload directory | `app/api/resources/upload.py` — `store_upload()` builds `{uuid4().hex}{ext}`; the original filename is never used as a path |
| CORS driven by an explicit allow-list, `*` never sends credential headers | `app/middleware/security_middleware.py` |
| **CSRF protection is in force for cookie-authenticated writes** | `app/middleware/security_middleware.py` — `enforce_csrf` is registered as a **global request middleware** (`setup_security_middleware`, called from `app/middleware/__init__.py:59`), not a per-route decorator. It rejects every non-`GET`/`HEAD`/`OPTIONS` request that authenticates by session cookie unless the `X-CSRF-Token` header matches the `csrf_token` cookie (`secrets.compare_digest`), returning 403 `CSRF_TOKEN_INVALID` otherwise. Exemptions: `/auth/login` and `/auth/register` (`CSRF_EXEMPT_PREFIXES`), plus requests carrying an explicit `Authorization` header or no session cookie (the latter are handled by the auth layer) |
| Database URL redacted in logs | `app/models/__init__.py` — `_redact_db_url` |

### Known security limitations (also listed in the v0.2.0 release notes)

1. **The registration endpoint is vulnerable to account enumeration.** `POST /auth/register` answers with a distinct `该邮箱已被注册` / `该用户名已被注册` / `该手机号已被注册` message when the identifier is taken. The *login* path does not enumerate (it deliberately returns a uniform `用户名或密码错误` and matches timing), but registration does not.
2. **Per-account two-factor toggling is not implemented.** Two-step verification is a single **global** switch — the server-side configuration `REQUIRE_TWO_FACTOR` (`app/auth/routes.py:178` reads it and ignores any client-supplied parameter), settable through the environment. There is no per-account toggle: an administrator cannot enable 2FA for one user and leave it off for another. The switch defaults to off, so two-step verification is disabled unless it is turned on explicitly. Login rate limiting (v0.3.0) and forced password change on first login (v0.3.2) are implemented: an administrator created from `INITIAL_ADMIN_PASSWORD` must change it before the rest of the API becomes usable, and repeated failed logins are throttled.
3. **An account created through self-registration cannot be verified in production, so its owner cannot log in.** `POST /auth/register` stores the account with `verified=False` (`app/auth/authentication.py:171`), and login refuses unverified accounts — `Account.validate()` raises `UnverifiedError` (`app/models/account.py:173-174`) and is called from the login path (`app/auth/authentication.py:284`). Verification means posting the two-step code to `POST /auth/verify` (`app/auth/routes.py:145`, `app/auth/verification.py:62`), but that code is placed in the API response **only when `DEBUG` is on** (`app/auth/routes.py:66`–`72`), and nothing sends it to the registrant any other way: the single `deliver(...)` call in the codebase belongs to the password-reset path (`app/auth/verification.py:351`), not to registration. `verified` is also outside the account API whitelists (`ACCOUNT_CREATE_FIELDS` at `app/api/resources/account.py:44`, `ACCOUNT_UPDATE_FIELDS` at `app/api/resources/account.py:46`), so an administrator cannot set it through the API either. The net effect under a production configuration is that a registrant never receives a code, the account stays unverified, and the only account that can log in is the first-run administrator — created with `verified=True` (`app/auth/authentication.py:223`). This is a **known incomplete capability, not a defect**, and it is consistent with the *Not production-ready* statement at the top of this README. A deployer who wants self-registration must connect a delivery channel — `Backend` in `app/services/delivery.py:45` is the seam to implement — **and** make sure `verified` is actually set for the account (by routing the code through the verification flow, or by an equivalent deployment-side step); deciding to turn self-registration off instead is an equally valid deployment choice.

---

## Quick start

### System requirements

- **Python 3.10 – 3.12** (CI runs on all three).
- **libmagic** — required by `python-magic`, which the upload resource uses for MIME sniffing:
  - macOS: `brew install libmagic`
  - Debian / Ubuntu: `apt install libmagic1`
  - Alpine: `apk add libmagic`
- Docker (only for the container path below).

### Option A — Docker one-command run

> **The Docker path has been run for real.** On a Linux host with a real Docker daemon the image was built, the container was started, `/health` answered **200**, an administrator logged in over HTTP, the admin console was served at `/amis/login.html`, and the container log contained **no** `[降级]` entries. The image runs as a non-root user, installs `libmagic`, and carries **no secrets** — every secret is injected at run time through `.env`.
>
> Removing `JWT_PRIVATE_KEY` from `.env` makes the container exit with code 1 and a `配置错误:` message — production is fail-closed. `SECRET_KEY` and `PASSWORD_SALT` are not gates; the container starts without them.
>
> `Dockerfile`, `docker-compose.yml`, `.env.example` and `.dockerignore` are in this repository. GitHub Actions (`.github/workflows/docker.yml`) keeps this path under continuous regression. The [release notes](docs/release/v0.2.0-release-notes.md) record the full measurement table, including the two build-environment accommodations needed on a host without IPv6 egress.

```bash
cp .env.example .env      # then replace the two startup-required values (see the .env.example header)
docker compose up -d --build
```

The application is then reachable at **http://localhost:22230** (the host port; the port inside the container is 22222). Redis is an optional profile — enable it with `docker compose --profile redis up -d` when `CACHE_TYPE=redis`.

**Restricted network (no direct access to pypi.org):** set `PIP_INDEX_URL` in `.env` to a reachable
mirror, then run `docker compose up -d --build` as usual — **no manual `--build-arg` needed**:

```bash
# add one line to .env (example: the Aliyun mirror — pick whichever your network can reach)
echo "PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/" >> .env
docker compose up -d --build
```

Without that line the official source `https://pypi.org/simple` is used, so the default behaviour is unchanged.

**Slow apt during the build:** on such networks the Debian mirror (`deb.debian.org`) can be the slow
part, not pip — one measured build spent roughly 2800 s in `apt-get` fetching the compiler toolchain
before pip even ran. The image currently has no apt-mirror switch; if you need one, replace the apt
sources inside the `Dockerfile` yourself. A build argument for this is planned for v0.3.

The container runs with `SANIC_ENV=production`, so it refuses to start unless the secrets are actually supplied through `.env` — "the container came up" is itself evidence that the configuration was supplied correctly.

### Option B — pip (verified locally)

```bash
git clone https://github.com/<owner>/Sanic-Admin.git
cd Sanic-Admin

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export INITIAL_ADMIN_PASSWORD='<choose-a-strong-password>'   # the administrator PASSWORD (not the e-mail)
python main.py
```

On Windows PowerShell set the password with `$env:INITIAL_ADMIN_PASSWORD='<choose-a-strong-password>'`.

In development mode that one variable is the whole setup: when `JWT_PRIVATE_KEY` is not set, the
application generates a temporary signing key at startup and prints a note to that effect
(`config.py` does the same for the initial password). Production is different — both
`JWT_PRIVATE_KEY` and `INITIAL_ADMIN_PASSWORD` are hard requirements there (see the quick
production run below).

The server listens on **http://127.0.0.1:22222** (`127.0.0.1` and `localhost` are the same address).

**The two administrator values are different things:**

| | Value | Where it comes from |
|---|---|---|
| **e-mail** (the username you type into the login form) | `SAdmin@Sanic.com` | defaults to this; override with `INITIAL_ADMIN_EMAIL` |
| **password** | the value you exported as `INITIAL_ADMIN_PASSWORD` | if you did **not** export one, development mode generates a random password and prints it to stdout **once**: |

```text
[开发环境] 已自动生成临时初始管理员口令（仅显示这一次，重启后失效）:
    账号: SAdmin@Sanic.com
    口令: 8VjvxJJhex3EAfzw
设置环境变量 INITIAL_ADMIN_PASSWORD 可固定口令。
```

That block is printed by the Sanic **worker process**, so if you redirect the server's output to a log file, search it for `口令:` — it is easy to miss among the startup noise.

**Keep the password from the first start.** The account is created only if it does not exist yet, so the password printed on the first run stays valid; on later restarts a *new* random password is printed but **not** applied, because the account already exists. To pin the password across restarts, set `INITIAL_ADMIN_PASSWORD` before the first start.

**The server needs a few seconds to start** (2–6 s measured) while the worker process spins up. Wait until the log shows:

```text
[INFO] Goin' Fast @ http://127.0.0.1:22222
[INFO] Starting worker [xxxxx]
```

Then open the admin console at **http://127.0.0.1:22222/amis/login.html** and sign in with the e-mail and password above. The console is served by the backend itself, so the page and the API are same-origin.

Verify it is up:

```bash
curl http://127.0.0.1:22222/health
# {"status":"ok","env":"development"}
```

Log in with the administrator account. The account name defaults to `SAdmin@Sanic.com` (override with `INITIAL_ADMIN_EMAIL`):

```bash
curl -X POST http://127.0.0.1:22222/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"SAdmin@Sanic.com","password":"<the password you exported>"}' -c cookies.txt
```

The response contains the session payload. The session is stored in the `session` cookie (`HttpOnly`, `SameSite=Lax`) and is also returned in the `Authorization: Bearer <token>` header. Verify the protected endpoint with that cookie:

```bash
curl -X POST -b cookies.txt http://127.0.0.1:22222/auth
# {"status":0,"msg":"认证成功!", ...}
```

Run the test suite:

```bash
pip install -r requirements-dev.txt
pytest
```

> **Current test status:** `pytest` reports **`171 passed`, 0 failed, 0 errors** (collection: 171 tests, ~65 s; about 80 s with `--cov=app`). Coverage over `app/` is **52 %** — the suite concentrates on authentication, authorisation, account and role CRUD, upload path traversal, SQL read-only enforcement and the production fail-closed gates. `ruff check . --select E9,F63,F7,F82` passes, and that is a hard gate in CI.

**Browser E2E gate (console changes).** The API suite cannot see AMIS page behaviour. If you change
anything under `amis/`, run the console gate before merging:

```bash
python scripts/amis_e2e_check.py --base-url http://127.0.0.1:22222 \
    --admin-password '<one-shot password>' --new-password '<new password>'
# prove the gate can actually fail:
python scripts/amis_e2e_check.py ... --negative-control dialog
```

A green run is **19/19 assertions**. CI runs the same gate as the `amis-e2e` job. A separate
`amis-e2e-probe` job decides whether a browser is usable and exposes it as an output; the gate job
itself is gated on that output, so when no browser is available the **job is reported as `skipped`**
by GitHub — not as a green pass with silently skipped steps. This gate was itself broken until v0.3.3 —
its assertions could not fail, which is how a console-breaking change reached v0.3.2.

---

## Configuration

All configuration is environment-driven. The authoritative source is **`app/config.py`** — every variable is read there, and the values below are taken directly from it.

> The full reference — every variable, its type, its default and its behaviour per environment — is in **[docs/configuration.md](docs/configuration.md)**, written directly from `app/config.py`. The table below is the short version.

The handful that matter most:

| Variable | Purpose |
|---|---|
| `SANIC_ENV` | `development` (default), `testing` or `production`. Selects the config class and the fail-closed behaviour. |
| `SECRET_KEY` | Application key. Optional — it currently takes part in no signing or encryption. |
| `JWT_PRIVATE_KEY` | RSA private key PEM for RS256 session signing. **Required in production.** `JWT_PUBLIC_KEY` is derived from it when not given. Newlines may be written as literal `\n`. |
| `INITIAL_ADMIN_PASSWORD` | Password for the first-run administrator account. **Required in production.** In development a random one is generated and printed once to stdout if this is unset. |
| `INITIAL_ADMIN_EMAIL` | Administrator e-mail. Defaults to `SAdmin@Sanic.com`. |
| `PASSWORD_SALT` | Password salt. Optional — password hashing uses argon2's own random salt. |
| `ENABLE_API_DOCS` | Mount the Swagger / ReDoc routes. **On in development, off in production.** |
| `REQUIRE_TWO_FACTOR` | Require the two-step verification after login. Off by default. |
| `DATABASE_URL` | Tortoise ORM connection string. Defaults to a local SQLite file in development, in-memory SQLite in testing. Falls back to assembling a MySQL URL from `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME`. |
| `CACHE_TYPE` | `memory` or `redis`. Production defaults to `redis` and refuses to degrade to memory if Redis is unreachable. |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` / `REDIS_PASSWORD` | Redis connection settings. |
| `HOST` / `PORT` | Listen address and port. Defaults to `127.0.0.1` and `22222`. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allow-list. Production defaults to empty (no cross-origin access). |
| `TRUSTED_PROXIES` | Comma-separated IPs / CIDR blocks of your reverse proxy. **Empty by default.** Login rate limiting only trusts `X-Forwarded-For` when the direct peer is on this list. See [Deploying › behind a reverse proxy](#behind-a-reverse-proxy-rate-limiting). |

---

## Deploying

Two settings decide whether a production instance can start at all. Both fail **closed**, which is the right default but surprises people who only set the four secrets.

**1. Redis must be reachable — unless you opt out.** `CACHE_TYPE` defaults to `redis` in production, and the application refuses to degrade to the in-memory cache there:

```
ConfigError: production 环境 Redis 缓存不可用，拒绝降级启动
```

Either provide a reachable Redis (set `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD`), or set `CACHE_TYPE=memory` deliberately — in-memory caching is per-process and does not survive a restart or scale beyond one worker.

**2. `DATABASE_URL` must be set, and the default is MySQL.** When `DATABASE_URL` is not given, the application assembles a MySQL URL from `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME`. **`aiomysql` is not in `requirements.txt`**, so a MySQL deployment fails at import time with `ModuleNotFoundError: No module named 'aiomysql'` until you install a driver yourself.

For a quick production run against a local file:

```bash
# Note the two slashes: Tortoise reads the sqlite file path as netloc + path, so
# sqlite:///<name> points at /<name> in the filesystem ROOT (start-up then fails
# with "unable to open database file"). The form below creates the file in the
# current directory — verified, and the data survives a restart.
export DATABASE_URL='sqlite://sanic_admin_prod.sqlite3'
export CACHE_TYPE=memory
# PEM is multi-line; the variable must be a single line with the newlines written
# as literal "\n". Avoid sed for this — the BSD and GNU dialects disagree on how
# "\n" is handled and the quoting breaks. The command below uses only openssl and
# the Python standard library and was tested end to end:
export JWT_PRIVATE_KEY="$(openssl genrsa 2048 2>/dev/null | python3 -c 'import sys; print(sys.stdin.read().strip().replace(chr(10), chr(92)+"n"))')"
export INITIAL_ADMIN_PASSWORD='<choose-a-strong-password>'
python main.py
```

The secrets are the two that gate startup — `JWT_PRIVATE_KEY` and `INITIAL_ADMIN_PASSWORD`. `SECRET_KEY` and `PASSWORD_SALT` are accepted but currently unused.

### Behind a reverse proxy: rate limiting

Login rate limiting counts failures along two dimensions: the submitted account and the **client IP**. The client IP is taken from the socket peer, and only falls back to `X-Forwarded-For` when that peer is listed in `TRUSTED_PROXIES`.

**If you run behind nginx / a load balancer and leave `TRUSTED_PROXIES` empty, every user looks like the proxy.** One person mistyping their password then locks the shared bucket for the whole 15-minute window — and the real client IP in `X-Forwarded-For` is ignored entirely.

```nginx
# nginx
location / {
    proxy_pass http://127.0.0.1:22222;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $host;
}
```

```bash
# the address nginx connects FROM (the proxy's own address, not the client's)
export TRUSTED_PROXIES='127.0.0.1'      # nginx on the same host
export TRUSTED_PROXIES='10.0.0.0/8'     # a private network of proxies
export TRUSTED_PROXIES='10.0.0.1,10.0.0.0/8'   # comma-separated, IPs and CIDR mixed
```

With the gate open, the **rightmost** entry of `X-Forwarded-For` that is *not* in `TRUSTED_PROXIES` is used as the client IP — the chain is walked from right to left, skipping trusted hops.

**Why rightmost and not leftmost:** every proxy *appends* to `X-Forwarded-For`, so the rightmost entries are the ones written by infrastructure you control. Anything to the left of them was sent by the client and can be fabricated freely — a client can prepend any address it likes to make the limiter see a fresh IP on each request. Reading from the right is what makes the value unspoofable.

Invalid entries are rejected at startup in production (the process exits and names the offending entry); in development and testing they are logged as a warning and skipped, and valid entries still apply.

**The default is empty on purpose, in every environment.** Setting it to `0.0.0.0/0` would trust `X-Forwarded-For` from anyone — which lets any client send a fresh fake IP per request and bypass the IP dimension of the limiter entirely. Configure the narrowest range that covers your proxies.

The account dimension is unaffected by this setting: it always counts per submitted account, so the limiter still works with the default empty value.

---

## AI-assisted development

This project is built around **specs as code**: a resource is declared once in
`specs/<resource>.yaml`, and the model, CRUD API, permissions, AMIS page, tests and
three-dialect migrations are all generated from it.

An AI can drive this loop through MCP (`tools/mcp_server`). Read-only tools list and
describe existing specs, validate a new one, and preview the exact diff. The write path is
**off by default**; when enabled it can only create a `proposal/*` branch plus an
ownership ref — it **never touches your working tree, never pushes, never merges**. Landing
the change is always a human action, via PR.

See **[docs/demo/ai-module-in-10-minutes.md](docs/demo/ai-module-in-10-minutes.md)** for a
real, reproducible walkthrough: adding a "ticket" module with every command, its actual
output and measured timings.

The walkthrough is honest about the cost: the browser E2E gate caught a real defect
(date/datetime fields were generated without a `type`, so the AMIS dialog could not be
submitted) that API tests, unit tests and CI all passed. That is precisely why the E2E
gate is not optional.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/configuration.md](docs/configuration.md) | Every environment variable, its default and its per-environment behaviour |
| [docs/architecture.md](docs/architecture.md) | Module layout, request flow and data model |
| [docs/release/v0.2.0-release-notes.md](docs/release/v0.2.0-release-notes.md) | v0.2.0 release notes: scope, what was verified and the known limitations |
| [docs/release/v0.3.2-release-notes.md](docs/release/v0.3.2-release-notes.md) | v0.3.2: forced password change on first login, 2FA fix, **migration required from v0.3.1 and earlier** |
| [docs/release/v0.3.3-release-notes.md](docs/release/v0.3.3-release-notes.md) | v0.3.3: console role-dialog hotfix, E2E gate repair, `amis-e2e` CI job |
| [docs/release/v0.3.4-release-notes.md](docs/release/v0.3.4-release-notes.md) | v0.3.4: authentication hardening — audit log, rate limiting, password strength, session rotation (two breaking changes) |
| [docs/release/v0.4.0-release-notes.md](docs/release/v0.4.0-release-notes.md) | v0.4.0: spec generator — one YAML to models, CRUD API, AMIS page and three-dialect migrations; production now requires an `aerich` ledger (breaking) |
| [docs/release/v0.4.1-release-notes.md](docs/release/v0.4.1-release-notes.md) | v0.4.1: ISO 8601 time fields, AMIS 6.13.0, ownership check for `discard_proposal` (one breaking change) |
| [docs/release/v0.4.2-release-notes.md](docs/release/v0.4.2-release-notes.md) | v0.4.2: account-level `spec:write`, `GET /auth/whoami`, CRUD audit log for generated resources (one breaking change) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, branch and PR workflow, code style |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability privately |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |
| [CHANGELOG.md](CHANGELOG.md) | Keep a Changelog format |

> The v0.2.0 scope, the verification performed for each item and the known limitations are described in the [release notes](docs/release/v0.2.0-release-notes.md). The configuration reference table in the *Configuration* section above is a summary; `docs/configuration.md` is the complete reference and is written directly from `app/config.py`.

---

## Screenshots

The admin console, served by the backend itself at `http://127.0.0.1:22222/amis/login.html`.

**Login**

![AMIS login page](docs/images/amis-login.png)

**Dashboard**

![AMIS dashboard](docs/images/amis-dashboard.png)

**Account list**

![AMIS account list](docs/images/amis-account-list.png)

---

## Contributing

Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** before opening a pull request. It covers the development setup, the branch and PR workflow, the code style rules, how to run the tests and the requirement to record user-visible changes in `CHANGELOG.md`.

Security problems must **not** be reported in a public issue — follow [SECURITY.md](SECURITY.md).

---

## License

**Apache License 2.0** — see [LICENSE](LICENSE).

---

## Acknowledgements

- [Sanic](https://github.com/sanic-org/sanic) — the async Python web framework.
- [Tortoise ORM](https://github.com/tortoise/tortoise-orm) — the async ORM.
- [AMIS](https://github.com/baidu/amis) — the low-code admin console framework.
