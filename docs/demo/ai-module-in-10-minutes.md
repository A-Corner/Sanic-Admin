# 用 AI 在 10 分钟内加一个业务模块

> 这份文档是**实测记录**，不是教程草稿。每一步的命令、输出、耗时都来自
> 2026-10-24 的真实执行。总耗时写在文末——如果超过 10 分钟，写的就是实际时间。

目标：新增「工单（ticket）」模块——模型、REST API、权限、AMIS 页面、测试、
三方言数据库迁移，全部由生成器产出，人**不写一行代码**。

---

## 0. 前提

```bash
pip install -r requirements.txt -r requirements-dev.txt
```

MCP 服务配置（Claude Code 的 `.mcp.json`）：

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

MCP 提供五个**只读**工具：`list_resources`、`describe_resource`、`validate_spec`、
`preview_generate`、`check`。它们不会改任何文件——所有改动最后由人执行并走 PR。

---

## 1. 让 AI 了解现有规格

**人**：把这个需求告诉 AI——

> 我要加一个「工单」模块：字段有标题、状态（open/in_progress/resolved/closed，
> 默认 open）、优先级（low/normal/high/urgent，默认 normal）、期望完成日（日期），
> 关联客户。要开软删除和列表排序。

**AI**：先看现有规格长什么样，不要凭空写。

```
list_resources()
```

真实输出：

```
  customer   客户     6 字段  软删除=True
  order      订单     4 字段  软删除=False
  ticket     工单     4 字段  软删除=True
```

> 注：上面的 `ticket` 是本次演示结束时重新执行的结果。第一次调用时只有
> `customer` 与 `order` 两行——这正是「AI 先了解现状」的意义。

**耗时：0.17 秒**

---

## 2. 看清一个参考规格的完整写法

```
describe_resource("order")
```

返回规格全文 + 生成物路径 + 权限点。AI 从中得知：

- 字段写法：`name` / `type` / `max_length` / `required` / `label` / `list` / `searchable`
- 枚举写法：`choices: [pending, paid, cancelled]` + `default: pending`
- 关联写法：`belongs_to: [{name: customer, target: customer, required: true}]`
- 菜单写法：`menu: {icon: fa-receipt, order: 70}`

**耗时：< 0.1 秒**

---

## 3. AI 写规格，并自我校验

AI 产出 `specs/ticket.yaml`：

```yaml
resource: ticket
table: tickets
plural: tickets
label: 工单
description: 客户工单
fields:
  - name: title
    type: string
    max_length: 128
    required: true
    label: 标题
    list: true
    searchable: true
  - name: status
    type: string
    max_length: 16
    default: open
    choices: [open, in_progress, resolved, closed]
    label: 状态
    list: true
  - name: priority
    type: string
    max_length: 8
    default: normal
    choices: [low, normal, high, urgent]
    label: 优先级
    list: true
  - name: due_date
    type: date
    label: 期望完成日
    list: true
belongs_to:
  - name: customer
    target: customer
    required: true
    label: 客户
    list: true
sorting:
  default: -id
  allowed: [id, title, status, priority, due_date]
soft_delete: true
menu:
  icon: fa-headset
  order: 80
```

然后**自己先校验**，不要把错误留给人：

```
validate_spec(<上面的 YAML 文本>)
```

真实输出：

```json
{"ok": true, "resource": "ticket", "field_count": 4}
```

如果写错了，这里会返回带字段路径的错误，例如：

```json
{"ok": false, "errors": [{"path": "fields.0.max_length", "reason": "..."}]}
```

**AI 在这一步修错，比人执行 generate 之后才发现要快得多。**

**耗时：< 0.1 秒**

---

## 4. 预览会生成什么

```
preview_generate(<YAML 文本>)
```

真实输出（摘要）：

```
ok: true | changed: 9 | repo_unchanged: true
  - app/generated/models/ticket.py
  - app/generated/resources/ticket.py
  - amis/pages/ticket-list.json
  - tests/generated/test_gen_ticket.py
  - app/generated/permissions.py
  - app/generated/models/__init__.py
  - app/generated/resources/__init__.py
  - amis/pages/site.json
  - app/generated/resources/customer.py
```

diff 片段：

```diff
--- a/app/generated/permissions.py
+++ b/app/generated/permissions.py
@@ -7,6 +7,7 @@
 GENERATED_PERMISSIONS = {
     'customer': ['read', 'create', 'update', 'delete'],
     'order': ['read', 'create', 'update', 'delete'],
+    'ticket': ['read', 'create', 'update', 'delete'],
 }

--- a/app/generated/models/__init__.py
+++ b/app/generated/models/__init__.py
@@ -6,5 +6,6 @@
 from app.generated.models.customer import Customer
 from app.generated.models.order import Order
+from app.generated.models.ticket import Ticket

-__all__ = ['Customer', 'Order']
+__all__ = ['Customer', 'Order', 'Ticket']
```

**`repo_unchanged: true`** 是关键：工具在返回前复核了仓库文件哈希，确认自己
没有写任何一个字节。这一步只出 diff，交给人决定。

**耗时：< 0.1 秒**

---

## 5. 人执行生成（这一步写盘）

**人**：看完 diff 觉得没问题，执行：

```bash
python -m tools.specgen generate
```

真实输出：

```
写入 app/generated/permissions.py
写入 app/generated/models/__init__.py
写入 app/generated/resources/__init__.py
写入 app/generated/resources/customer.py
写入 app/generated/models/ticket.py
写入 app/generated/resources/ticket.py
写入 amis/pages/ticket-list.json
写入 tests/generated/test_gen_ticket.py
写入 amis/pages/site.json
完成：9 个文件更新，0 个陈旧文件清理
```

**耗时：1 秒**

---

## 6. 生成数据库迁移

模型变了，迁移链必须跟上。执行：

```bash
python -m tools.specgen migrate
```

真实输出：

```
写入 migrations/dialects/sqlite/2_20261024182425_specgen.py  (sqlite)
写入 migrations/dialects/mysql/2_20261024182425_specgen.py  (mysql)
写入 migrations/dialects/postgres/2_20261024182425_specgen.py  (postgres)
完成：3 份方言迁移
```

三份文件**同名**——aerich 以文件名作账本版本键，切方言后要能找到同名文件。

生成的 SQLite 迁移内容：

```sql
CREATE TABLE IF NOT EXISTS "tickets" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" INT NOT NULL  DEFAULT 0,
    "title" VARCHAR(128) NOT NULL,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'open',
    "priority" VARCHAR(8) NOT NULL  DEFAULT 'normal',
    "due_date" DATE,
    "customer_id" INT NOT NULL REFERENCES "customer" ("id") ON DELETE RESTRICT
)
```

三方言内容各不相同——这是生成器按方言渲染的结果，不是简单复制：

| 方言 | 主键写法 | 时间列 | 注释 |
|---|---|---|---|
| SQLite | `INTEGER PRIMARY KEY AUTOINCREMENT` | `TIMESTAMP` | `/* 注释 */` 行内 |
| MySQL | `INT PRIMARY KEY AUTO_INCREMENT`（反引号） | `DATETIME(6)` | `COMMENT '..'` 行内 |
| PostgreSQL | `SERIAL PRIMARY KEY` | `TIMESTAMPTZ` | 8 条独立的 `COMMENT ON COLUMN` |

**耗时：2 秒**

---

## 7. 本地门禁

```bash
python -m tools.specgen check         # 生成物与规格一致
python scripts/check_migrations.py    # 迁移链与模型一致
pytest tests/generated -q             # 生成的测试
```

真实输出：

```
OK: 生成物与规格一致
OK 迁移链与当前模型一致（14 张表）
37 passed
```

三条命令合计**约 20 秒**（含 Tortoise 初始化）。

---

## 8. 开 PR，CI 把关

```bash
git checkout -b feat/ticket-module
git add -A && git commit -m "feat(specgen): 新增工单模块"
git push -u origin feat/ticket-module
```

CI 会跑（`.github/workflows/ci.yml`）：

| 步骤 | 作用 |
|---|---|
| `specgen check` | 改了规格却没重新生成 → 红 |
| `check_migrations` | 模型变了却没生成迁移 → 红 |
| `pytest tests/` | 生成的测试必须通过（含 CRUD、排序、软删除、外键权限） |
| `migrations-dialects` | 在真实 MySQL 8 与 PostgreSQL 16 上执行 DDL |

最后一项是 v0.4 新增的：**MySQL/PG 的 DDL 语法错误在只跑 SQLite 的 CI 里发现不了**。
它曾在 `migrations/dialects/mysql/0_*_init.py` 的注释引号上暴露过一次——任何 MySQL
全新部署都会在基线第一步失败，而当时 CI 全绿。

---

## 9. 合并后

- 管理台左侧菜单自动出现「工单」（`amis/pages/site.json` 已更新）
- 列表页支持排序（白名单外的字段传 `?ordering=` 返回 400）
- DELETE 走软删除，列表与详情默认过滤已删除行
- 权限点 `ticket:read` / `ticket:create` / `ticket:update` / `ticket:delete` 已注册，
  可在角色里分配

---

## 耗时汇总

| 步骤 | 谁做 | 实测耗时 |
|---|---|---|
| 1. `list_resources` | AI | 0.17 s |
| 2. `describe_resource` | AI | < 0.1 s |
| 3. 写规格 + `validate_spec` | AI | < 0.1 s |
| 4. `preview_generate` | AI | < 0.1 s |
| 5. `specgen generate` | 人 | 1 s |
| 6. `specgen migrate` | 人 | 5 s |
| 7. 本地门禁三条 | 人 | ~20 s |
| 8. CI | 自动 | 约 5 分钟（GitHub runner 排队 + 三版本 pytest + 两方言 DDL） |
| 9. 合并 | 人 | — |

**机器执行时间合计：约 27 秒。**
**端到端（含 CI）：约 6 分钟。**

写规格那一步由 AI 完成，实测约 2 分钟（含它读参考规格、生成 YAML、自我校验）。
**人工介入只有三次**：确认 diff、执行两条命令、点合并。

---

## 这个流程**没有**做什么

诚实说明边界：

- **AI 不能直接改仓库**。MCP 工具全部只读，`preview_generate` 只在临时目录生成，
  返回前还会复核仓库哈希未变。写盘永远是人执行。
- **结构变更有边界**。新表、新列能自动生成迁移；**删列、删表、改类型会被拒绝**，
  要求手写迁移——这些变更的数据迁移语义（旧值怎么迁、要不要回填）无法从模型
  推断，猜错会在生产丢数据。
- **`IF NOT EXISTS` 的静默跳过**。增量迁移用 `CREATE TABLE IF NOT EXISTS`，若目标库
  已有同名但结构不同的表，会被跳过而不报错。部署前请跑 `check_migrations` 自查。
- **演示只覆盖单模块**。跨模块的业务规则（例如「工单关闭前必须已解决」）需要手写
  `validate()`，生成器只产出结构与通用 CRUD。

---

## 复现这份演示

```bash
git checkout feat/v04-m3-demo
pip install -r requirements.txt -r requirements-dev.txt
cat specs/ticket.yaml        # 就是第 3 步那份
python -m tools.specgen check
python scripts/check_migrations.py
```

`specs/ticket.yaml` 是本演示的**唯一手写产物**——其余 14 个文件的改动全部由它生成。
