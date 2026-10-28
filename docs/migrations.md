# 数据库迁移（aerich）

迁移工具：aerich 0.7.2（已写入 `requirements.txt`），配置见 `app/aerich_config.py`（`TORTOISE_ORM`）与 `pyproject.toml` 的 `[tool.aerich]`。

`TORTOISE_ORM` 的数据库地址直接取 `app.config.settings.DATABASE_URL`，与 `app.models.init_db` 同源，受 `SANIC_ENV` 和 `DATABASE_URL` 环境变量控制，没有第二份连接配置。迁移文件在 `migrations/models/`，当前 1 条基线（`0_*`）+ 2 条增量（`1_*`、`2_*`）。

以下命令均在仓库根目录执行，已按目标环境设置好 `SANIC_ENV` / `DATABASE_URL`。

## 1. 新库（全新部署）

```bash
python scripts/migrations/baseline_existing_db.py <库文件> migrations/models --fresh   # SQLite：只建 aerich 账本表
python scripts/migrations/upgrade.py                                                    # 应用基线迁移，建全部业务表
```

**按方言选基线（必读）**：aerich 0.7.2 的基线是**单一方言**的——`init-db` 生成的是当前连接
方言的 DDL。SQLite 版含 `AUTOINCREMENT`，在 MySQL/PG 上执行会报语法错误（UB26 实测：
MySQL `1064`、PG `syntax error at or near "AUTOINCREMENT"`）。因此仓库按方言各存一份：

```bash
python scripts/migrations/select_dialect_baseline.py mysql    # 或 sqlite / postgres / --auto
```

它把 `migrations/dialects/<方言>/0_20261024125437_init.py` 装进 `migrations/models/`（替换现有同名基线）。
**部署前务必确认装的是目标方言的那份。**

MySQL / PostgreSQL 新库：`aerich upgrade` 会在目标库上创建 `aerich` 账本表——**已在 UB26 的
MySQL 8 与 PG 16 上实测成立**（12 张表全部建出，`account.must_change_password` 分别为
`tinyint(1)` / `boolean`）。SQLite 需要先跑 `--fresh` 建账本（见上）。

基线迁移已含 `account.must_change_password`。新库不需要运行 `scripts/migrate_v0_3_2_must_change_password.py`。

## 2. 存量 v0.3.1 库（`generate_schemas` 建的库，没有账本）

顺序固定为三步：

```bash
# 1) 手写脚本：补 account.must_change_password 列，并把口令仍等于 INITIAL_ADMIN_PASSWORD 的管理员置位
python scripts/migrate_v0_3_2_must_change_password.py
# 2) 基线化：创建 aerich 账本表，把「当前模型快照」写成基线版本（SQLite）
python scripts/migrations/baseline_existing_db.py <库文件> migrations/models
# 3) 此后 upgrade 为 no-op，只会应用以后新增的迁移
python scripts/migrations/upgrade.py
```

为什么手写脚本在前、基线化在后：基线迁移代表的是“当前模型对应的完整结构”（含 `must_change_password`）。基线化只写账本，不检查也不修改表结构。如果先基线化，库里仍缺这一列，账本却宣称已对齐，之后 `aerich upgrade` 永远不会补列，运行时才会因缺列报错。手写脚本还负责置位管理员（这是数据修正，aerich 的 DDL 迁移做不了）。先补列再基线化，账本才和真实结构一致。测试 `test_c_without_handwritten_script_schema_diff_is_detected` 复现了颠倒顺序的后果。

基线化写入账本的 `content` 是 aerich 约定的模型快照（JSON），不是迁移文件文本，后续 `aerich migrate` 以它为比较基准。

注意：手写脚本与 aerich 统一读 `DATABASE_URL`。旧的 `DB_URL` 仍可用（打印 deprecation 提示），新部署请只用 `DATABASE_URL`。

MySQL / PostgreSQL 存量库：`baseline_existing_db.py --url <dsn>` 已支持（账本表 DDL 按方言生成）。实操步骤见 §2b。

## 2b. v0.3.2 生产库 → v0.4 的升级路径（必读）

> **统一用 `scripts/migrations/upgrade.py` 而不是裸 `aerich upgrade`**：它在升级前先做方言
> 一致性校验（md5 比对 `migrations/models/` 与 `migrations/dialects/<方言>/`）。
> 退出码 **4** 表示「装的基线不是目标方言那份」——先执行
> `python scripts/migrations/select_dialect_baseline.py <方言>` 再重试；
> 其它方言基线在 MySQL/PG 上会直接语法报错，在 SQLite 上会静默建出错误类型。

v0.4 起 production 环境**不再跑 `generate_schemas`**，改为检查 aerich 账本表存在与否，
缺失即拒绝启动。因此 v0.3.2 的存量生产库必须先完成迁移链接入，顺序固定为四步：

```bash
# 0) 备份（SQLite 复制库文件；MySQL/PG 逻辑备份或快照）——这一步不可跳过
# 1) 补列 + 置位管理员（v0.3.2 已发布的手写脚本）
DATABASE_URL="<生产库 DSN>" python scripts/migrate_v0_3_2_must_change_password.py
# 2) 基线化：按方言选基线 → 校验结构一致 → 写入账本
python scripts/migrations/select_dialect_baseline.py --auto     # 或显式 sqlite/mysql/postgres
DATABASE_URL="<生产库 DSN>" python scripts/migrations/baseline_existing_db.py --url "<生产库 DSN>" migrations/models
# 3) 应用迁移（此时应为 no-op，只校验账本对齐）
DATABASE_URL="<生产库 DSN>" python scripts/migrations/upgrade.py
# 4) 启动应用（production 会检查账本表已存在）
```

**顺序不可颠倒**：基线化只写账本、不改表结构。跳过第 1 步直接基线化会以 rc=3
被拒绝（脚本会比对库结构与模型并点名缺失的列）；即便绕过，账本会宣称已对齐而库里
实际缺列，`aerich upgrade` 永远不会补，运行期才报错。

**MySQL / PostgreSQL 版本**：`baseline_existing_db.py --url <dsn>` 已支持（账本表 DDL
按方言生成、PG 用 `current_schema()` 而非硬编码 `public`）。新库与存量库两条路径
已由 `migrations-dialects` CI job 在真实 MySQL 8 / PostgreSQL 16 上覆盖
（`.github/workflows/ci.yml:197` 起的 job，`:268` 的 `Existing database: increment only`
在存量库上跑 `scripts/check_dialect_ddl.py <dialect> <url> --existing`；v0.4.2 CI 全绿，
见 `docs/release/v0.4.2-release-notes.md:263-264`）；生产前仍建议先在副本上演练。

## 3. 开发与生产：`generate_schemas` 与 aerich 的分工

`app.models.init_db` 的行为按环境区分：**development/testing 仍执行 `generate_schemas(safe=True)`**（只建缺失的表，不加列、不改列、不记版本）；**production 不再执行它**，改为检查 aerich 账本表存在，缺失即拒绝启动——因为 `safe=True` 只建表不加列，在生产跑会让「缺迁移」被静默掩盖。

| 场景 | 做法 |
|---|---|
| 开发 / 测试（SQLite、内存库） | 保持 `generate_schemas(safe=True)`，库随时可删可重建。改了模型后，仍要生成迁移：`aerich migrate --name <说明>`，检查生成的文件后提交。 |
| 生产 | 先 `python scripts/migrations/upgrade.py`，再启动应用（启动时检查账本表，缺失即拒绝）。**不跑** `generate_schemas`。 |
| 提交前 / CI | 运行 `python scripts/check_migrations.py`。它在临时 SQLite 里 upgrade 全部迁移，再与当前模型 `generate_schemas` 的结构逐表对比；模型改了没生成迁移，退出码为 1（脚本自身出错为 2）。 |

不使用 `aerich migrate` 做 CI 守门，原因是 aerich 的比较基准是账本里的模型快照，而 `upgrade` 会用“当前模型”写快照，先 upgrade 再 migrate 永远判定“无变化”。

迁移日常流程：改模型 → `aerich migrate --name xxx` → 审阅 `migrations/models/` 下新文件 → `python scripts/check_migrations.py` → 提交 → 部署时 `python scripts/migrations/upgrade.py`。

## 4. 回滚

- 应用层回滚：`aerich downgrade`（回退最近一个版本，`-v <版本号>` 指定目标），执行迁移文件里的 `downgrade()`。基线版本（`0_*_init.py`）的 downgrade 是空的，不能用它删库。
- 生产回滚的第一选择：升级前备份（SQLite 复制库文件；MySQL / PostgreSQL 做逻辑备份或快照），出问题时直接还原备份，并回退到上一版应用代码。涉及数据变更的迁移（如置位脚本）不要依赖 `downgrade`。
- 手写脚本（补列）不可自动回退；v0.3.2 之前的代码不读 `must_change_password`，多出的列不影响旧版本运行，回滚代码时可以保留这一列。
- 账本被误写：SQLite 里 `DELETE FROM aerich WHERE version = '<文件名>'` 后重新基线化；该操作只改账本，不动业务表。

## 5. 已知限制

- `baseline_existing_db.py` 已支持 SQLite / MySQL / PostgreSQL（`--url <dsn>`）。
  **MySQL/PG 的存量非空库已实测通过**（改造 v0.3.1 形态库 → 四步走完 → upgrade 为
  no-op → production 启动成功且原数据保留）。
- 方言基线的 `downgrade()` 未实测。
- **基线化的放行行为**：结构核对只拦「缺表 / 缺列」；库里**多出来的列**与**类型差异**
  当前直接放行、不阻断。理由是存量库常有手写脚本或历史迁移留下的额外列，一律拦会
  让基线化无法进行。`scripts/check_migrations.py` 只比对 **SQLite** 上「迁移链建出的
  结构」与「模型 generate_schemas 的结构」，**不覆盖 MySQL/PG 的类型差异**；
  需要严格类型校验时请在该脚本支持的方言上单独跑，或走 UB26 手工门禁。
- CI 里做 SQLite 的模型比对与「三份方言基线文件名一致性」检查；**MySQL / PG 的
  结构与迁移验证在 MySQL 8 与 PostgreSQL 16 上实测**：按 §2b 四步走完后
  `upgrade` 为 no-op、production 启动成功、原种子数据保留。
- 手写脚本在 SQLite 上补列已统一用 `INT`（与 aerich 基线一致），守门脚本不再做类型归一。
