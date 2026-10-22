# Sanic-Admin

> **Project status — read this first**
>
> - Sanic-Admin is being rebuilt for **v0.2.0**. The baseline described below is what is verified on the current `sa-oss/integration` snapshot; parts of the management API are still being closed out and are marked `TODO(M1)` below.
> - **Not production-ready yet.** Do not deploy this to a public environment.
> - **No credentials are baked into the repository.** There is no default administrator password. The first-run administrator password is generated at startup (development only) or must be supplied via `INITIAL_ADMIN_PASSWORD`.
> - The JWT signing key, `SECRET_KEY` and the password salt are **environment variables only**. Sample keys that existed in the repository history must be treated as compromised and rotated.
> - Report security issues privately — see [SECURITY.md](SECURITY.md).

Sanic-Admin is a backend administration framework built on **Sanic** (async Python web framework) and **Tortoise ORM**, with **RBAC** authorization and **RS256-signed JWT** sessions. The admin console is built with **AMIS**, a low-code framework driven by JSON page definitions.

---

## Features

Every entry below is traced to code in this repository. Items that are not yet verified are marked `TODO(M1)`.

### Authentication and sessions

| Feature | Evidence |
|---|---|
| Register / verify / login / logout / session association | `app/auth/routes.py` — `POST /auth/register`, `/auth/verify`, `/auth/login`, `/auth/logout`, `/auth/associated` |
| CAPTCHA on the credential endpoints | `app/auth/routes.py` — `GET /capt/request`, `GET /capt/image` |
| Two-step verification flow (a single **global** switch, not per-account) | `app/auth/routes.py` — `POST /auth/validate-2fa`; the server-side `REQUIRE_TWO_FACTOR` setting decides whether it is required, and any client-supplied parameter is ignored (`app/auth/routes.py:95`) |
| RS256-signed JWT sessions (private key via `JWT_PRIVATE_KEY`) | `app/models/session.py` (`SESSION_ENCODING_ALGORITHM = "RS256"`), `app/config.py` (`load_jwt_keys`) |
| Sessions delivered as an `HttpOnly` cookie **and** an `Authorization` header | `app/models/session.py` — `Session.encode` |
| Rejects unauthenticated access to protected endpoints | `app/auth/authentication.py` — `requires_authentication`; verified: `POST /auth` without a session returns HTTP 401 |
| No administrator password in source; generated at startup or supplied by env var | `app/config.py` — `_generate_admin_password`, `_env_secret` |

### RBAC authorization

| Feature | Evidence |
|---|---|
| Role model with a JSON permission map (`{resource: [actions]}`) | `app/models/role.py` — `Role.permissions` |
| Permission checks, role checks, role assignment/removal | `app/auth/authorization.py` — `check_permissions`, `check_roles`, `assign_role`, `remove_role`, `get_account_permissions` |
| `is_admin` accounts hold every permission | `app/auth/authorization.py` — `has_role` |
| Per-resource permission check decorators on the management API | `app/api/resources/*.py` — `check_permissions` / `check_roles` |

> The management API surface for role and account CRUD is being closed out in the M1 iteration; the HTTP endpoints are marked `TODO(M1)` below.

### Management API

`app/api/resources/` contains one resource module per domain. These are **class-style CRUD resources** built on a shared `CRUDResource` base (`app/api/base.py`) — they subclass the base and expose `get`/`post`/`put`/`delete` handlers, rather than declaring standalone `@bp.route` blueprint handlers:

`account` · `role` · `profile` · `setting` · `log` (operation log) · `upload` · `dashboard` · `dashboard_user` · `dashboard_performance` · `cache` · `database` (read-only SQL analysis) · `compression`

- **Account management** — `app/api/resources/account.py`
- **Role management** — `app/api/resources/role.py`
- **Personal profile** — `app/api/resources/profile.py`
- **System settings** — `app/api/resources/setting.py`
- **Operation log** — `app/api/resources/log.py` (backed by `app/models/operation_log.py`)
- **File upload** — `app/api/resources/upload.py`
- **Dashboard** — `app/api/resources/dashboard.py`, `dashboard_user.py`, `dashboard_performance.py`

Each resource declares its own field allow-lists (`allowed_create_fields` / `allowed_update_fields`), search and filter fields, and required fields, and gates access with the `check_permissions` / `check_roles` decorators from `app/auth/authorization.py`.

> `TODO(M1)`: the `/v1` API blueprint is not yet mounted on the baseline snapshot — `app/api/__init__.py` fails with `AttributeError: 'BlueprintGroup' object has no attribute 'add_blueprint'` on Sanic 23.6, so `app/__init__.py` logs `[降级] API v1 路由 未启用`. The resource classes and their permission checks are in the tree but not yet reachable over HTTP. Verified: `/api/v1/health` returns HTTP 404 on the baseline.

### API documentation

> **TODO(M1) — this feature is not yet available on the current baseline.** The implementation exists in the tree, but the routes are not registered.

- OpenAPI 3.0 spec generation and the `@api_tags` / `@api_summary` / `@api_description` / `@api_body` / `@api_response` decorator family — `app/docs/decorators.py`, `app/docs/openapi.py`, `app/docs/models.py`.
- A Swagger UI page and a ReDoc page — `app/docs/swagger.py`, `app/docs/routes.py`.

The wiring is missing: `setup_docs()` in `app/docs/__init__.py` has **no call site** in `app/__init__.py`, so `GET /swagger`, `GET /redoc` and `GET /swagger.json` all return **HTTP 404** (verified by `curl` against a running server). The `ENABLE_API_DOCS` setting — `True` in development, `False` in production — and the `setup_docs(app)` call site at `app/__init__.py:74-76` are introduced by the `sa-oss/m1` branch and are **not** on this baseline.

The only documentation endpoint that answers today is the `sanic-ext` default at `/docs` (ReDoc, HTTP 200) with its spec at `/docs/openapi.json` (HTTP 200) — that is a *different* generator from `app/docs/`, and it only contains the routes that are actually registered.

### Admin console (AMIS)

- The AMIS SDK and page definitions live in `amis/` (`amis/sdk/`, `amis/pages/*.json`, `amis/site.html`).
- `amis/server.js` is a small Express host used for local AMIS authoring.

> `TODO(M1)`: the AMIS → backend wiring (login → dashboard → account list) is being delivered in the M1 iteration on a separate branch (`sa-oss/b7`, `feat(amis): 前端对接新后端登录与鉴权接口`). It is **not** merged into this baseline, and the AMIS console is **not** mounted by the Sanic application on this snapshot (`app/web/routes.py` defines `register_web_blueprints` but nothing calls it, and it renders `frontend/templates`, which does not exist).

### Caching

- Two interchangeable backends behind one interface — `app/cache/base.py`.
- In-process memory cache — `app/cache/memory.py`.
- Redis cache with a 2-second connect/read timeout — `app/cache/redis.py`.
- Selected by `CACHE_TYPE` (`memory` or `redis`) — `app/cache/__init__.py` — `get_cache`.
- Redis unavailability degrades to the memory cache in development/testing, and **refuses to start in production** — `app/cache/__init__.py` — `_build_redis` raises `ConfigError` when `ENV == "production"`.

### Security baseline

| Control | Evidence |
|---|---|
| Production fails closed when required secrets are missing | `app/config.py` — `_env_secret` raises `ConfigError`; verified: `SANIC_ENV=production python main.py` prints `配置错误: 生产环境必须通过环境变量 SECRET_KEY 提供应用密钥` and exits with **rc=1** |
| No secret, key or default password in the repository | `app/config.py` — all secrets read from environment variables; verified: `git grep -nIE "BEGIN (RSA )?PRIVATE KEY"` finds no key material |
| Administrator password generated at startup, printed once to stdout in development only | `app/config.py` — `_generate_admin_password` |
| SQL analysis accepts a single read-only `SELECT`/`WITH` statement and issues only `EXPLAIN` | `app/database/query_analyzer.py` — `validate_readonly_sql`, `_FORBIDDEN_SQL_RE`, `_FORBIDDEN_FUNC_RE`; verified: `DELETE FROM account`, `SELECT 1; DROP TABLE x` and `PRAGMA table_info(account)` are all rejected |
| Uploads are stored under a generated filename inside a fixed upload directory | `app/api/resources/upload.py` — `_process_file` builds `{timestamp}_{uuid}{ext}`; the original filename is never used as a path |
| CORS driven by an explicit allow-list, `*` never sends credential headers | `app/middleware/security_middleware.py` |
| CSRF protection decorator for non-`GET` requests | `app/middleware/security_middleware.py` — `csrf_protect` |
| Database URL redacted in logs | `app/models/__init__.py` — `_redact_db_url` |

### Known security limitations (also listed in the v0.2.0 release notes)

1. **The registration endpoint is vulnerable to account enumeration.** `POST /auth/register` answers with a distinct `该邮箱已被注册` / `该用户名已被注册` / `该手机号已被注册` message when the identifier is taken. The *login* path does not enumerate (it deliberately returns a uniform `用户名或密码错误` and matches timing), but registration does not.
2. **Per-account two-factor toggling is not implemented.** Two-step verification is a single **global** switch — the server-side configuration `REQUIRE_TWO_FACTOR` (`app/auth/routes.py:95` reads it and ignores any client-supplied parameter). There is no per-account toggle: an administrator cannot enable 2FA for one user and leave it off for another. On this baseline `REQUIRE_TWO_FACTOR` is not yet wired into `app/config.py` (`settings.REQUIRE_TWO_FACTOR` does not exist here); the configuration knob and its call site are added on the `sa-oss/m1` branch, and until then the attribute resolves to `False`, so two-step verification is off. There is also no login rate limiting and no forced password change on first login.

---

## Quick start

### System requirements

- **Python 3.10 – 3.12** (CI runs on all three).
- **libmagic** — required by `python-magic`, which the upload resource uses for MIME sniffing:
  - macOS: `brew install libmagic`
  - Debian / Ubuntu: `apt install libmagic1`
  - Alpine: `apk add libmagic`
- Docker (only for the container path below).

### Option A — Docker one-command run (validation runs in CI)

> **The Docker path is validated by GitHub Actions, not by hand.** The image build and the compose orchestration are exercised in CI. Until those runs are green, do not read anything below as "verified" — the commands are the intended contract, and the local checks that *were* run are the compose static parse and the production fail-closed equivalence.
>
> `Dockerfile`, `docker-compose.yml`, `.env.example` and `.dockerignore` are in this repository. The image runs as a non-root user, installs `libmagic`, and carries **no secrets** — every secret is injected at run time through `.env`.

```bash
cp .env.example .env      # then replace every placeholder value in .env
docker compose up -d --build
```

The application is then reachable at **http://localhost:22230** (the host port; the port inside the container is 22222). Redis is an optional profile — enable it with `docker compose --profile redis up -d` when `CACHE_TYPE=redis`.

The container runs with `SANIC_ENV=production`, so it refuses to start unless the secrets are actually supplied through `.env` — "the container came up" is itself evidence that the configuration was supplied correctly.

### Option B — pip (verified locally)

```bash
git clone https://github.com/<owner>/Sanic-Admin.git
cd Sanic-Admin

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export INITIAL_ADMIN_PASSWORD='<choose-a-strong-password>'   # first-run admin password
python main.py
```

The server listens on **http://localhost:22222**.

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

> **Current baseline test status:** the suite does **not** collect cleanly yet. On this snapshot `pytest` reports `20 tests collected, 6 errors` — `tests/test_account_api.py`, `tests/test_auth.py`, `tests/test_cache.py`, `tests/test_db_optimizer.py`, `tests/test_integration.py` and `tests/test_performance.py` fail at import time because they reference modules that no longer exist (`app.models.permission`, `app.cache.backends.memory`). The 20 tests that do collect live in `tests/test_docs/`. This is tracked as part of the M1 test-suite rebuild, not a property of your setup. `ruff check . --select E9,F63,F7,F82` passes.

---

## Configuration

All configuration is environment-driven. The authoritative source is **`app/config.py`** — every variable is read there, and the values below are taken directly from it.

> The full reference — every variable, its type, its default and its behaviour per environment — is in **[docs/configuration.md](docs/configuration.md)**, written directly from `app/config.py`. The table below is the short version.

The handful that matter most:

| Variable | Purpose |
|---|---|
| `SANIC_ENV` | `development` (default), `testing` or `production`. Selects the config class and the fail-closed behaviour. |
| `SECRET_KEY` | Application key. **Required in production.** |
| `JWT_PRIVATE_KEY` | RSA private key PEM for RS256 session signing. **Required in production.** `JWT_PUBLIC_KEY` is derived from it when not given. Newlines may be written as literal `\n`. |
| `INITIAL_ADMIN_PASSWORD` | Password for the first-run administrator account. **Required in production.** In development a random one is generated and printed once to stdout if this is unset. |
| `INITIAL_ADMIN_EMAIL` | Administrator e-mail. Defaults to `SAdmin@Sanic.com`. |
| `PASSWORD_SALT` | Password salt. **Required in production.** |
| `DATABASE_URL` | Tortoise ORM connection string. Defaults to a local SQLite file in development, in-memory SQLite in testing. Falls back to assembling a MySQL URL from `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME`. |
| `CACHE_TYPE` | `memory` or `redis`. Production defaults to `redis` and refuses to degrade to memory if Redis is unreachable. |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` / `REDIS_PASSWORD` | Redis connection settings. |
| `HOST` / `PORT` | Listen address and port. Defaults to `127.0.0.1` and `22222`. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allow-list. Production defaults to empty (no cross-origin access). |

> `REQUIRE_TWO_FACTOR` and `ENABLE_API_DOCS` are **not** read by the configuration module on this snapshot; they exist on the `sa-oss/m1` branch. Do not rely on them here.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/configuration.md](docs/configuration.md) | Every environment variable, its default and its per-environment behaviour |
| [docs/architecture.md](docs/architecture.md) | Module layout, request flow and data model |
| [docs/release/v0.2.0-release-notes.md](docs/release/v0.2.0-release-notes.md) | v0.2.0 release notes: scope, what was verified and the known limitations |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, branch and PR workflow, code style |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability privately |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |
| [CHANGELOG.md](CHANGELOG.md) | Keep a Changelog format |

> The v0.2.0 scope, the verification performed for each item and the known limitations are described in the [release notes](docs/release/v0.2.0-release-notes.md). The configuration reference table in the *Configuration* section above is a summary; `docs/configuration.md` is the complete reference and is written directly from `app/config.py`.

---

## Screenshots

<!-- TODO(M1): 替换为 v0.2.0 实际界面截图 -->

<!--
The `Readme_image*.png` files in the repository root are screenshots of the
2023 interface. They do not show v0.2.0 and are deliberately not referenced
here. Remove them once the new screenshots are in place.
-->

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
