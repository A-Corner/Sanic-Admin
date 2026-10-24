# 数据库迁移（aerich）

迁移工具：aerich 0.7.2（已写入 `requirements.txt`），配置见 `app/aerich_config.py`（`TORTOISE_ORM`）与 `pyproject.toml` 的 `[tool.aerich]`。

`TORTOISE_ORM` 的数据库地址直接取 `app.config.settings.DATABASE_URL`，与 `app.models.init_db` 同源，受 `SANIC_ENV` 和 `DATABASE_URL` 环境变量控制，没有第二份连接配置。迁移文件在 `migrations/models/`，当前只有基线 `0_*_init.py`。

以下命令均在仓库根目录执行，已按目标环境设置好 `SANIC_ENV` / `DATABASE_URL`。

## 1. 新库（全新部署）

```bash
python scripts/migrations/baseline_existing_db.py <库文件> migrations/models --fresh   # SQLite：只建 aerich 账本表
aerich upgrade                                                                          # 应用基线迁移，建全部业务表
```

MySQL / PostgreSQL 新库：`aerich upgrade` 会自行创建 `aerich` 账本表，不需要 `--fresh` 那一步（`baseline_existing_db.py` 目前只支持 SQLite）。

基线迁移已含 `account.must_change_password`。新库不需要运行 `scripts/migrate_v0_3_2_must_change_password.py`。

## 2. 存量 v0.3.1 库（`generate_schemas` 建的库，没有账本）

顺序固定为三步：

```bash
# 1) 手写脚本：补 account.must_change_password 列，并把口令仍等于 INITIAL_ADMIN_PASSWORD 的管理员置位
python scripts/migrate_v0_3_2_must_change_password.py
# 2) 基线化：创建 aerich 账本表，把「当前模型快照」写成基线版本（SQLite）
python scripts/migrations/baseline_existing_db.py <库文件> migrations/models
# 3) 此后 upgrade 为 no-op，只会应用以后新增的迁移
aerich upgrade
```

为什么手写脚本在前、基线化在后：基线迁移代表的是“当前模型对应的完整结构”（含 `must_change_password`）。基线化只写账本，不检查也不修改表结构。如果先基线化，库里仍缺这一列，账本却宣称已对齐，之后 `aerich upgrade` 永远不会补列，运行时才会因缺列报错。手写脚本还负责置位管理员（这是数据修正，aerich 的 DDL 迁移做不了）。先补列再基线化，账本才和真实结构一致。测试 `test_c_without_handwritten_script_schema_diff_is_detected` 复现了颠倒顺序的后果。

基线化写入账本的 `content` 是 aerich 约定的模型快照（JSON），不是迁移文件文本，后续 `aerich migrate` 以它为比较基准。

注意：手写脚本读环境变量 `DB_URL`（缺省取 `SANIC_ENV` 对应配置的 `DATABASE_URL`），aerich 读 `DATABASE_URL`。给两者指向同一个库，或者两个变量都设置。

MySQL / PostgreSQL 存量库：`baseline_existing_db.py` 当前仅支持 SQLite。用这两种库的存量部署，先在维护窗口里按脚本逻辑手工创建 `aerich` 表并写入基线行，或补一个方言版本的基线脚本（未完成，见文末）。

## 3. 开发与生产：`generate_schemas` 与 aerich 的分工

当前 `app.models.init_db` 启动时仍执行 `generate_schemas(safe=True)`。它只建缺失的表，不加列、不改列，也不记录版本。

| 场景 | 做法 |
|---|---|
| 开发 / 测试（SQLite、内存库） | 保持 `generate_schemas(safe=True)`，库随时可删可重建。改了模型后，仍要生成迁移：`aerich migrate --name <说明>`，检查生成的文件后提交。 |
| 生产 | 先 `aerich upgrade`，再启动应用。`generate_schemas(safe=True)` 对已存在的表是空操作，可以保留作兜底；它不会和 aerich 冲突，但**不能**替代迁移（不会加列）。 |
| 提交前 / CI | 运行 `python scripts/check_migrations.py`。它在临时 SQLite 里 upgrade 全部迁移，再与当前模型 `generate_schemas` 的结构逐表对比；模型改了没生成迁移，退出码为 1（脚本自身出错为 2）。 |

不使用 `aerich migrate` 做 CI 守门，原因是 aerich 的比较基准是账本里的模型快照，而 `upgrade` 会用“当前模型”写快照，先 upgrade 再 migrate 永远判定“无变化”。

迁移日常流程：改模型 → `aerich migrate --name xxx` → 审阅 `migrations/models/` 下新文件 → `python scripts/check_migrations.py` → 提交 → 部署时 `aerich upgrade`。

## 4. 回滚

- 应用层回滚：`aerich downgrade`（回退最近一个版本，`-v <版本号>` 指定目标），执行迁移文件里的 `downgrade()`。基线版本（`0_*_init.py`）的 downgrade 是空的，不能用它删库。
- 生产回滚的第一选择：升级前备份（SQLite 复制库文件；MySQL / PostgreSQL 做逻辑备份或快照），出问题时直接还原备份，并回退到上一版应用代码。涉及数据变更的迁移（如置位脚本）不要依赖 `downgrade`。
- 手写脚本（补列）不可自动回退；v0.3.2 之前的代码不读 `must_change_password`，多出的列不影响旧版本运行，回滚代码时可以保留这一列。
- 账本被误写：SQLite 里 `DELETE FROM aerich WHERE version = '<文件名>'` 后重新基线化；该操作只改账本，不动业务表。

## 5. 已知限制

- `baseline_existing_db.py` 仅支持 SQLite；MySQL / PostgreSQL 存量库的基线化待补。
- 手写脚本在 SQLite 上补列的声明类型是 `BOOLEAN`，aerich 生成的是 `INT`，两者读写行为一致；`scripts/check_migrations.py` 对比时按同类归一。
