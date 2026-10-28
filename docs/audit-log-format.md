# 审计日志 `detail` 字段格式与迁移

> 面向**消费审计日志的人**（报表、告警、外部采集、排障）。本文件回答三件事：
> 两种格式长什么样、怎么用一份代码同时读两种、以及旧格式为什么**无法完全还原**。

## 两种格式

审计日志的 `detail` 列由 [`app/services/audit.py`](../app/services/audit.py) 的
`record_resource_event()` 生成，形如 `id=<对象 id> fields=<字段名列表>`。

| 版本 | `fields=` 后面的格式 | 示例 |
|---|---|---|
| v0.4.2 及以前 | 逗号拼接 | `id=42 fields=username,email` |
| v0.4.3 起 | JSON 数组 | `id=42 fields=["username", "email"]` |

**注意 JSON 数组版本里逗号后面有空格** —— 那是 `json.dumps` 的默认分隔符
（`, ` 而不是 `,`）。按空格切分或按逗号切分的解析器都会在这里出错，见下文。

## 为什么改

**字段名本身可以含逗号。** 规格生成器允许字段名为任意字符，于是：

```
fields = ["a,b", "c"]
旧格式 → fields=a,b,c        ← 三个字段？还是 "a,b" 和 "c" 两个？
```

**旧格式在这个输入下是有损的**：`a,b,c` 既可能是 `["a","b","c"]`，也可能是
`["a,b","c"]`，读回时无法区分。v0.4.3 改为 JSON 数组编码，
数组是自定界的，任何字段名都能无损往返（缺陷池 BL-01）。

背景与测试见 [`docs/release/v0.4.3-release-notes.md`](release/v0.4.3-release-notes.md)
的「修复」节。

## 如何同时兼容两种格式

```python
import json


def parse_detail(detail):
    """把 detail 拆成 object_id 与字段名列表，兼容 v0.4.2 前后两种格式。

    Returns:
        {"id": str|None, "fields": list[str], "format": str|None}
        format 取值：'json-array' / 'comma' / None（无 fields=）
    """
    if not detail:
        return {"id": None, "fields": [], "format": None}

    object_id = None
    if detail.startswith("id="):
        object_id = detail[3:].split(" ", 1)[0] or None

    idx = detail.find("fields=")
    if idx < 0:
        return {"id": object_id, "fields": [], "format": None}

    raw = detail[idx + len("fields="):].strip()
    if not raw:
        return {"id": object_id, "fields": [], "format": None}

    if raw.startswith("["):
        # JSON 数组里可能有空格和逗号，必须整体交给 json.loads。
        # 不要用非贪婪正则 r"fields=(.+?)(?:\s|$)" —— 它会在
        # '["username", "email"]' 的第一个空格处截断，从而解析失败。
        try:
            return {"id": object_id, "fields": json.loads(raw), "format": "json-array"}
        except json.JSONDecodeError:
            return {"id": object_id, "fields": [], "format": "json-array-malformed"}

    return {"id": object_id, "fields": [f for f in raw.split(",") if f], "format": "comma"}
```

**为什么不用正则**：`r"fields=(.+?)(?:\s|$)"` 这类非贪婪写法看起来能用，
但 JSON 数组的默认输出带空格（`["a", "b"]`），非贪婪会在第一个空格截断。
本文件的写法用 `find` 定位 + `startswith("[")` 分支判断，不依赖空格的位置。

**注意**：旧格式在字段名含逗号时**本身就是有损的，无法完全还原** ——
这正是改格式的原因，不是解析器的缺陷。

## 如何识别新旧格式

看 `fields=` 后面第一个非空白字符：

- 是 `[` → 新格式（JSON 数组），用 `json.loads`
- 其他 → 旧格式（逗号拼接），用 `split(",")`
- 没有 `fields=` → 该记录没有字段名信息

## `object_id` 的格式约束

> **`object_id` 不得包含空格或 `fields=` 子串。**

原因：`object_id` 被裸拼进 `detail` 的 `id=` 段
（`app/services/audit.py` 的 `parts = [f"id={object_id}"]`），而 `detail` 是
**空格分隔的 `key=value` 格式** —— 本页的 `parse_detail` 按两处取值：

```python
object_id = detail[3:].split(" ", 1)[0]      # 按空格截断
idx = detail.find("fields=")                 # 按子串定位
```

所以含空格会**截断 id 段**，含 `fields=` 会**伪造 fields 段**（后者更隐蔽：
id 段看起来正常，整条记录格式合法）。

**这个约束由调用方保证** —— 用 `app/services/audit.py` 的
`validate_audit_object_id()`：

```python
from app.services.audit import validate_audit_object_id

try:
    validate_audit_object_id(pattern, field_name="pattern")
except ValueError as exc:
    return _bad_request(str(exc))
```

**审计函数本身不校验** —— `record_resource_event` 的契约是「永不抛出」
（审计是旁路，不能影响主请求）。所以校验属于调用方，不属于审计函数。

> **注意**：制表符 / 换行**不在**这条通用约束里 —— 它们不破坏 `detail` 解析
> （`split(" ", 1)` 只认 ASCII 空格）。拒绝它们是**下游日志系统**的要求
> （按行收集时 `\n` 会伪造记录），属各调用方的额外约束。

## 迁移期注意事项

1. **新旧记录共存。** v0.4.3 之前落库的记录仍是逗号格式，**本版不提供回填迁移**。
2. **审计日志只记字段名，不记字段值。** 任何从 `detail` 里「读出字段值」的期望都是错的
   —— 值从来没有写进去过（这是有意的脱敏设计）。
3. **`detail` 是 `TextField`，无长度上限约束下的固定结构。** 新增字段会追加在
   `fields=` 之后，解析时不要在 `fields` 之后假设没有其他内容。

## 验证记录

以下输出来自本文件的示例实现，可直接复现。

### 两种格式与边界输入

```
旧格式                | id=42 fields=username,email          | {'id': '42', 'fields': ['username', 'email'], 'format': 'comma'}
新格式-带空格(实际输出)  | id=42 fields=["username", "email"]   | {'id': '42', 'fields': ['username', 'email'], 'format': 'json-array'}
新格式-字段名含逗号      | id=42 fields=["a,b", "c"]            | {'id': '42', 'fields': ['a,b', 'c'], 'format': 'json-array'}
旧格式-三字段(有损)      | id=42 fields=a,b,c                   | {'id': '42', 'fields': ['a', 'b', 'c'], 'format': 'comma'}
无 fields              | id=42                                | {'id': '42', 'fields': [], 'format': None}
新格式-单字段           | id=42 fields=["title"]               | {'id': '42', 'fields': ['title'], 'format': 'json-array'}
fields 后为空           | id=42 fields=                        | {'id': '42', 'fields': [], 'format': None}
新格式-空数组           | id=7 fields=[]                       | {'id': '7', 'fields': [], 'format': 'json-array'}
空 detail              |                                      | {'id': None, 'fields': [], 'format': None}
新格式-非 ASCII         | id=9 fields=["名称", "邮箱"]           | {'id': '9', 'fields': ['名称', '邮箱'], 'format': 'json-array'}
```

### 往返对照（用仓库真实编码逻辑生成，再解析回来）

```
=== 新格式往返（全部无损）===
  ✓ ['username'] → 'id=42 fields=["username"]' → ['username']
  ✓ ['username', 'email'] → 'id=42 fields=["username", "email"]' → ['username', 'email']
  ✓ ['a,b', 'c'] → 'id=42 fields=["a,b", "c"]' → ['a,b', 'c']
  ✓ ['中文', 'e-mail'] → 'id=42 fields=["中文", "e-mail"]' → ['中文', 'e-mail']
  ✓ [] → 'id=42' → []

=== 旧格式往返（字段名含逗号时有损）===
  ✓ 可还原        'id=42 fields=username'
  ✗ 有损：['a,b', 'c'] → ['a', 'b', 'c'] 'id=42 fields=a,b,c'
```

最后一行就是 v0.4.3 改格式的理由：**旧格式把 `["a,b", "c"]` 压成 `a,b,c`，
读回时得到三个字段，无法知道原本是两个。**
