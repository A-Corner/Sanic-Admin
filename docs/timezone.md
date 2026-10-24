# 时间字段的时区约定

本文是 v0.4.1 起的时间语义契约。**改任何与时间有关的代码前先读一遍。**

## 1. 三条约定

| 环节 | 约定 |
|---|---|
| **存储** | 所有 `DatetimeField` 以 **UTC aware** 保存 |
| **输出** | 带偏移的 **ISO 8601**，例如 `2026-12-01T02:00:00+00:00` |
| **输入** | 带偏移的值换算为 UTC；**不带偏移的值按 UTC 解释** |

进程的 `TZ` 环境变量**不影响**上述任何一条。同一绝对时刻在任何部署环境
（`TZ=UTC`、`TZ=Asia/Shanghai`、`TZ=America/New_York`）写入与读出的结果等价。

## 2. 配置在哪

两处**必须同值**，否则「迁移时按 naive、运行时按 aware」会在类型映射上打架：

- `app/models/__init__.py` 的 `Tortoise.init(..., use_tz=True, timezone="UTC")`
- `app/aerich_config.py` 的 `build_tortoise_config()` 里 `apps.models.use_tz` / `timezone`

v0.4.1 之前这两个参数没有显式写，依赖 Tortoise 的默认值。实测（Tortoise 0.20 +
SQLite）默认行为恰好相同，所以**运行时行为不变**——这次改动是把隐含依赖变成
显式契约，防止将来升级 ORM 时默认值变化导致行为漂移。

## 3. 输出为什么必须是 `T` 分隔

Python 的 `str(datetime)` 产出 `2026-10-24 12:55:31+00:00`——**空格分隔**，
不是合法 ISO 8601。

**准确的说法**是：`datetime.fromisoformat()` 在 Python 3.10 及更早**只接受**
`T` 分隔的形式（3.11 起才放宽到接受任意单字符分隔符）。所以空格形式在 3.10 上
会抛 `ValueError`；3.11+ 上能解析但仍是**非标准**形式，其他语言的解析器
（如 JavaScript 的 `new Date()` 在部分引擎）行为不一致。

结论不变——输出必须用 `T`，理由是**跨语言互操作与标准一致性**，而不只是
某个 Python 版本的兼容性。

因此模型层一律用 `.isoformat()`：

```python
# 正确
"created_at": self.created_at.isoformat(),
# 错误——不要写回来
"created_at": str(self.created_at),
```

**全仓守卫**：`tests/test_timezone_contract.py::test_all_api_datetime_fields_are_iso8601_source_guard`
会扫描 `app/` 下所有 `str(<something>.<时间字段>)` 写法并报错。

## 4. 两条序列化路径都要小心

这一点容易踩坑，实测发现：

| 路径 | 走法 | 谁负责格式化 |
|---|---|---|
| **API 资源层**（多数列表/详情端点） | 直接把 `datetime` 对象传给 `APIResponse.serialize` | `app/api/responses.py` 的 `isinstance(data, datetime)` 分支统一 `.isoformat()` |
| **模型 `.json` 属性** | 模型自己拼字典（`Account.json`、`Session.json` 等） | **模型自己**，必须显式 `.isoformat()` |

也就是说：改 API 资源层不需要动格式化（它传对象）；改模型的 `.json` 属性
**必须**用 `.isoformat()`。两条路径的测试覆盖分别来自：

- 资源层：`test_all_api_datetime_fields_are_iso8601`（扫各端点列表）
- 模型层：同测试里对**认证响应**（`session.bearer.json`）的断言

## 5. AMIS 前端

AMIS 的 `input-datetime` 默认把用户看到的**本地时间**原样提交，例如上海用户
输入 `2026-12-01 10:00:00` 就提交这个字符串。按第 1 条约定，服务端会把它
**当作 UTC**——于是库里存的是 10:00 UTC，而用户以为是本地 10:00，差 8 小时。

**这不是服务端能修的**：服务端无法区分「用户本地的 10:00」和「UTC 的 10:00」，
因为它拿不到时区信息。正确做法是在前端声明时区语义（AMIS 的 `utc: true`），
让它在提交前把本地时间换算成 UTC。

> **状态：v0.4.1 已处理。** 生成器给 `input-datetime` 加了 `utc: true`，
> `valueFormat` 改为 `"YYYY-MM-DDTHH:mm:ssZ"`（见 `tools/specgen/render_amis.py`）。
>
> 实测（TZ=Asia/Shanghai 真实浏览器）：
> - 库里 `2026-12-01T02:00:00+00:00` → 编辑弹窗显示 `2026-12-01 10:00:00`
> - DatePicker 选本地 `2026-10-07 00:00:00` → 请求体 `"onboarded_at": "2026-10-06T16:00:00+00:00"`
>
> 即：提交前本地→UTC、回显时 UTC→本地，都不再由用户或后端猜。
>
> **注意 AMIS 6.13 的 DOM 变化**：`input-datetime` 的输入框**没有 `name` 属性**
> （只有 `class="cxd-DatePicker-input"`），弹层是 react-datetime 的 `.rdtDay`
> 网格而非 AMIS 自己的 Picker。写自动化测试时不能按 `input[name="..."]` 定位，
> 也不能用普通 `fill()`——它不会触发 AMIS 的 onChange。

## 6. 存量数据

v0.4.1 **不做数据迁移**。理由：实测存量值本来就是 UTC aware（Tortoise 0.20
行为），格式变化只发生在输出层（`str()` → `.isoformat()`），不涉及库内数据。

如果将来发现某个方言确实存了 naive 值，那需要单独评估——届时优先按 UTC
解释（与第 1 条一致），并在发布说明里写明。

## 7. 三种方言的存储细节

| 方言 | 类型 | 时区处理 |
|---|---|---|
| SQLite | `TEXT` | 存 ISO 文本；Tortoise 读写时归一到 UTC aware |
| MySQL | `DATETIME(6)` | **本身不带时区**；依赖驱动/ORM 保证写入的是 UTC |
| PostgreSQL | `TIMESTAMPTZ` | 数据库自己带时区，按 UTC 存储 |

MySQL 的 `DATETIME` 不带时区这件事意味着**写入前必须确保是 UTC**——这正是
第 2 条里 `use_tz=True` 的作用。
