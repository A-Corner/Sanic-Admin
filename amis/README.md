# AMIS 管理界面

基于 [amis](https://github.com/baidu/amis) 的 Sanic-Admin 管理界面。

M1 起，本目录**由后端直接托管**（同源），不再依赖 Node 开发服务器。

---

## 一、后端同源托管（M1 的正式部署方式）

浏览器打开 `http://127.0.0.1:22222/amis/login.html`，页面与 API 同源，
因此：

* 静态资源用相对路径（`./sdk/...`、`./pages/...`）；
* API 调用用绝对路径（`/auth/...`、`/api/v1/...`）；
* 会话由后端通过 HttpOnly 的 `session` Cookie 下发，浏览器自动带上，**不涉及 CORS**。

### 后端托管的实现（已在 `app/__init__.py` 中落地）

```python
# app/__init__.py —— create_app() 内，静态目录挂载那一段旁边
# 托管 AMIS 管理界面（与 API 同源，便于复用 HttpOnly 会话 Cookie）
# AMIS_DIR 置空或目录不存在时不挂载（生产环境可据此关闭管理界面）
# name='amis' 是必需的：Sanic 23.6 拒绝重名路由，/static 与 /amis 若都用
# 默认名 'static'，服务启动时直接抛 Duplicate route names detected。
amis_dir = app.config.get("AMIS_DIR")
if amis_dir and os.path.isdir(amis_dir):
    app.static("/amis", amis_dir, index="login.html", name="amis")
```

访问路径：**<http://127.0.0.1:22222/amis/login.html>**。
`/amis/`（带尾斜杠）会显示登录页；`/amis`（不带尾斜杠）返回 404 —— Sanic 的
`DirectoryHandler` 只在路径带尾斜杠时才做 index 查找。

### 配置项

| 配置项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `AMIS_DIR` | str | `str(BASE_DIR / "amis")` | AMIS 静态资源目录；置空字符串或不存在的目录则不挂载（生产环境可据此关闭管理界面）。**支持 `AMIS_DIR` 环境变量覆盖**（容器内为 `/app/amis`） |

对应 `app/config.py`（`DefaultConfig`）：

```python
# AMIS 管理界面静态目录（由后端同源托管；留空则不挂载）
AMIS_DIR = str(BASE_DIR / "amis")
```

---

## 二、开发用 Node 服务器（保留，勿删）

`server.js` 是一个**零依赖**的 Node 开发服务器。后端已直接托管 `amis/` 目录，
它**不再是运行必需**，仅保留供本地预览 / 调试界面。它会：

* 静态托管本目录下的页面与资源；
* 把 `/auth` `/capt` `/api` `/health` `/refapi` `/account`
  反向代理到后端，使浏览器同源访问。

> 注意：它**不代理** `/uploads` —— 后端已移除上传目录的静态挂载（否则任何人都能
> 直接下载他人上传的文件），上传文件下载走需要鉴权的
> `GET /api/v1/files/<id>/download`。

```bash
npm start                       # 默认 http://127.0.0.1:3000
PORT=3001 API_TARGET=http://127.0.0.1:22222 npm start
```

M1 之后后端直接托管，`server.js` **不再是运行必需**，保留下来是为了：
后端尚未集成静态托管时仍可预览界面；调试前端改动时用独立端口起服务，
避免每次改后端都要重启。

---

## 三、目录结构

```
amis/
├── index.html          主框架（菜单 + 路由）；启动前校验登录态
├── login.html          登录页（POST /auth/login）
├── pages/
│   ├── site.json           菜单定义
│   ├── dash_board.json     仪表盘（GET /api/v1/dashboard/summary）
│   ├── account-list.json   账户管理（GET/POST/PUT/DELETE /api/v1/accounts）
│   ├── role-list.json      角色管理（GET/POST/PUT/DELETE /api/v1/roles）
│   ├── log-list.json       操作日志（GET /api/v1/logs）
│   └── setting-list.json   系统设置（GET/POST/PUT /api/v1/settings）
├── sdk/                amis 运行时（3.31.0，本地化，不依赖 CDN）
├── vendor/             bootstrap / jquery / select2 等第三方依赖
├── css/ fonts/ images/ public/
└── server.js           开发用 Node 反代服务器（可选）
```

## 四、页面与后端接口的对应关系

| 页面 | 后端接口 | 方法 |
|---|---|---|
| 登录页 | `/auth/login` | POST |
| 框架启动校验 | `/auth/associated` | POST |
| 退出登录 | `/auth/logout` | POST |
| 仪表盘 | `/api/v1/dashboard/summary` | GET |
| 账户列表 | `/api/v1/accounts`、`/api/v1/accounts/{id}` | GET / POST / PUT / DELETE |
| 角色列表 | `/api/v1/roles`、`/api/v1/roles/{id}` | GET / POST / PUT / DELETE |
| 操作日志 | `/api/v1/logs` | GET |
| 系统设置 | `/api/v1/settings`、`/api/v1/settings/key/{key}` | GET / POST / PUT |

后端统一响应格式为 `{"success": bool, "message": str, "error": "<CODE>"}`，
页面里的 `adaptor` 负责把它转成 amis 认识的 `{status, msg, data}` 结构。

## 五、已移除的示例页

以下页面原本是 amis 模板自带的**演示页**，依赖并不存在的 mock 接口
（`/api/amis-mock/...`、`/refapi/...`、`${API_HOST}/api/amis-mock/sample/...`），
在本项目里点开必然报错，因此已从 `pages/` 删除、也从菜单里移除：

| 已移除页面 | 原因 |
|---|---|
| `pages/console.json` | 纯占位页（body 是 "body..."），无任何真实数据 |
| `pages/login.json` | amis 模板的登录**演示**，调用 `/amis/api/mock2/form/saveForm`；本项目登录页是独立的 `login.html` |
| `pages/crud-list.json` | 指向不存在的 `/refapi/account/0` |
| `pages/crud-new.json` | 指向不存在的 `/refapi/account/0` |
| `pages/crud-view.json` | 指向不存在的 `${API_HOST}/api/amis-mock/sample/${params.id}` |
| `pages/crud-edit.json` | 指向不存在的 `${API_HOST}/api/amis-mock/sample/$id` |
| `pages/crud-advance.json` | 高级表格演示，依赖 mock 数据 |
| `pages/editor.json` | 富文本编辑器演示，依赖 mock 数据 |
| `pages/form-basic.json` | 表单演示，依赖 mock 数据 |
| `pages/wizard.json` | 向导表单演示，依赖 mock 数据 |
| `pages/jsonp.js` | JSONP 示例，配合不存在的 mock 接口 |

替代关系：账户列表 → `pages/account-list.json`；角色列表 → `pages/role-list.json`；
"部门管理 / 权限配置 / 菜单管理" 这三项在本项目**没有对应后端资源**
（权限由 `Role.permissions` 承载，菜单由 amis 框架自身提供），已从菜单中移除。

## 六、注意

* amis SDK 版本较老（3.31.0），M1 不升级 SDK，只做页面对接。
* `sdk/` 与 `vendor/` 均为本地副本，页面不依赖外部 CDN。
* 页面里的 API 路径都是**根路径绝对路径**（`/api/v1/...`），与后端实际路由一致；
  若把界面挂到别的前缀下，需要同步改 `pages/*.json` 里的 `url`。
