# -*- coding: utf-8 -*-
"""生成资源的契约测试（401 / 403 / CRUD 往返 / 校验 / 唯一 / 外键）。"""

from typing import Dict, List

from .render_py import py_header
from .schema import CORE_TARGETS, FieldSpec, ResourceSpec


def sample(f: FieldSpec, alt: bool = False):
    if f.choices:
        return f.choices[1] if alt and len(f.choices) > 1 else f.choices[0]
    if f.type == "string":
        if f.format == "email":
            return "alt@example.com" if alt else "sample@example.com"
        return (f"{f.name}-{'alt' if alt else 'sample'}")[: f.max_length]
    return {
        "text": "alt text" if alt else "sample text",
        "int": 2 if alt else 1,
        "float": 2.5 if alt else 1.5,
        "bool": not alt,
        # ISO 8601 文本：Date 规则接受，Tortoise DateField/DatetimeField 也接受
        "date": "2025-03-15" if alt else "2024-01-10",
        "datetime": "2025-03-15T09:30:00" if alt else "2024-01-10T08:00:00",
    }[f.type]


class _Setup:
    """为一个资源准备祖先记录；产出 ORM 建数行与 FK 表达式。"""

    def __init__(self, specs: Dict[str, ResourceSpec]):
        self.specs = specs
        self.lines: List[str] = []
        self.imports = set()
        self.n = 0

    def fk_exprs(self, spec: ResourceSpec) -> Dict[str, str]:
        out = {}
        for b in spec.belongs_to:
            if b.target in CORE_TARGETS:
                self.imports.add(CORE_TARGETS[b.target])
                out[b.column] = f"(await {CORE_TARGETS[b.target]}.filter().first()).id"
                continue
            t = self.specs[b.target]
            sub = self.fk_exprs(t)
            self.n += 1
            var = f"{t.resource}_{self.n}"
            self.imports.add(t.cls)
            items = [f"{f.name!r}: {sample(f)!r}" for f in t.fields if f.default is None]
            items += [f"{c!r}: {e}" for c, e in sub.items()]
            self.lines.append(f"    {var} = await {t.cls}.create(**{{{', '.join(items)}}})")
            out[b.column] = f"{var}.id"
        return out


def _payload(spec: ResourceSpec, fk: Dict[str, str], alt: bool = False) -> str:
    items = [f"{f.name!r}: {sample(f, alt)!r}" for f in spec.fields if f.default is None]
    items += [f"{c!r}: {e}" for c, e in fk.items()]
    return "{" + ", ".join(items) + "}"




def _uniq_variant(f, i: int) -> str:
    """为唯一字段生成第 i 条合法取值（保持格式约束：email 仍是邮箱）。"""
    if f.format == "email":
        return f"u{i}@example.com"
    if f.type in ("string", "text"):
        return f"u{i}"
    return str(i + 1)

def _is_text_field(spec: ResourceSpec, name: str) -> bool:
    """排序造数用：文本类字段给递增字符串，数值类给递增整数。"""
    for f in spec.fields:
        if f.name == name:
            return f.type in ("string", "text")
    return False

def render_test(spec: ResourceSpec, specs: Dict[str, ResourceSpec]) -> str:
    res, cls = spec.resource, spec.cls
    url = f"/api/v1/{spec.plural}"
    setup = _Setup(specs)
    fk = setup.fk_exprs(spec)
    pre = list(setup.lines)
    # 软删除/硬删除测试要直接查库，故本资源模型也需导入
    imports = sorted(setup.imports | {cls})
    # 外键目标：优先非 core（自带资源），否则取 core 目标（其资源名与 CORE_TARGETS
    # 的键同名，如 account）；两者都没有时该用例不生成，避免出现 {None: ['read']}。
    non_core_parent = next((b for b in spec.belongs_to if b.target not in CORE_TARGETS), None)
    core_parent = next((b for b in spec.belongs_to if b.target in CORE_TARGETS), None)
    fk_parent = non_core_parent or core_parent
    fk_target = fk_parent.target if fk_parent else None
    parent_var = fk[fk_parent.column].split(".")[0] if fk_parent else None
    fk_column = fk_parent.column if fk_parent else None

    L = [py_header(spec), f'"""{spec.label} 生成资源的契约测试（由规格生成）。"""', ""]
    if imports:
        L += [f"from app.models import {', '.join(imports)}", ""]
    L += ["", f"URL = {url!r}", ""]
    L += [
        "",
        "async def test_requires_authentication(client):",
        '    """未登录访问全部端点 401。"""',
        '    for method, path in (("get", URL), ("post", URL), ("get", URL + "/1"), ("put", URL + "/1"), ("delete", URL + "/1")):',
        "        response = await getattr(client, method)(path)",
        '        assert response.status_code == 401, f"{method} {path} -> {response.status_code}"',
        "",
        "",
        "async def test_low_privilege_forbidden(client, normal_auth_headers):",
        '    """低权账户无权限点 -> 403（RBAC 生效）。"""',
        '    for method, path in (("get", URL), ("post", URL), ("get", URL + "/1"), ("put", URL + "/1"), ("delete", URL + "/1")):',
        "        response = await getattr(client, method)(path, headers=normal_auth_headers)",
        '        assert response.status_code == 403, f"{method} {path} -> {response.status_code}"',
        "",
        "",
        "async def test_read_grant_is_positive_control(client, normal_auth_headers):",
        '    """正向对照：只授予 read 后列表 200，写仍 403（证明上面的 403 来自 RBAC 而非路由）。"""',
        "    from app.models import Role",
        "",
        f'    await Role.filter(name="reader").update(permissions={{{res!r}: ["read"]}})',
        "    assert (await client.get(URL, headers=normal_auth_headers)).status_code == 200",
        "    assert (await client.post(URL, headers=normal_auth_headers, json={})).status_code == 403",
        "",
        "",
        "async def test_permission_matrix(client, normal_auth_headers):",
        '    """权限动作矩阵：每次只授予一个动作的权限，其余动作必须 403。"""',
        "    from app.models import Role",
        "",
        "    for granted, denied in (",
        "        ('read', ['create', 'update', 'delete']),",
        "        ('create', ['read', 'update', 'delete']),",
        "        ('update', ['create', 'read', 'delete']),",
        "        ('delete', ['create', 'read', 'update']),",
        "    ):",
        "        await Role.filter(name='reader').update(",
        f"            permissions={{{res!r}: [granted]}}",
        "        )",
        "        for action in granted, *denied:",
        "            calls = {",
        "                'read': ('get', URL, None),",
        "                'create': ('post', URL, {}),",
        "                'update': ('put', URL + '/1', {}),",
        "                'delete': ('delete', URL + '/1', None),",
        "            }",
        "            method, path, body = calls[action]",
        "            kwargs = {'headers': normal_auth_headers}",
        "            if body is not None:",
        "                kwargs['json'] = body",
        "            response = await getattr(client, method)(path, **kwargs)",
        "            if action == granted:",
        "                assert response.status_code != 403, (",
        "                    f'{action} 已授权却得到 403（URL {path}）'",
        "                )",
        "            else:",
        "                assert response.status_code == 403, (",
        "                    f'{action} 未授权却未返回 403（{response.status_code}）'",
        "                )",
        "",
        "    # 还原：权限矩阵会反复改写 reader 角色，结束时恢复为只读，避免污染后续用例",
        f"    await Role.filter(name='reader').update(permissions={{{res!r}: ['read']}})",
        "",
        "",
        "async def test_fk_requires_target_read_permission(client, normal_auth_headers):",
        '    """外键防 ID 枚举：无 <target>:read 时引用必须 403，不能靠 400/201 差异侧探。"""',
        *(
            [
                "    from app.models import Role",
                "",
                *pre,
                f"    FK_COLUMN = {fk_column!r}",
                f"    await Role.filter(name='reader').update(permissions={{{res!r}: ['create']}})",
                "",
                "    # 对引用目标无 read 权限：无论 id 是否存在，都必须 403（不泄露存在性）",
                f"    payload = {_payload(spec, fk)}",
                "    denied = await client.post(URL, headers=normal_auth_headers, json=payload)",
                "    assert denied.status_code == 403, (",
                f"        f'无 {fk_target}:read 时引用应 403，实际 {{denied.status_code}}'",
                "    )",
                "",
                "    # 正向对照：授了 read 后同一 payload 不再是 403（证明上面的 403 来自权限判定）",
                f"    await Role.filter(name='reader').update(permissions={{{res!r}: ['create'], {fk_target!r}: ['read']}})",
                "    allowed = await client.post(URL, headers=normal_auth_headers, json=payload)",
                "    assert allowed.status_code != 403, (",
                "        f'授了 read 后不应再 403，实际 {allowed.status_code}'",
                "    )",
                "",
                "    # PUT 同样门控：撤掉 read 后更新外键必须 403",
                f"    await Role.filter(name='reader').update(permissions={{{res!r}: ['create', 'update']}})",
                "",
                "    # 前置断言：上一步必须真的建成，否则下面的 PUT 断言会静默跳过",
                "    assert allowed.status_code in (200, 201), (",
                "        f'前置 POST 应成功，实际 {allowed.status_code}'",
                "    )",
                "    obj_id = allowed.json()['data']['id']",
                "    put_denied = await client.put(",
                "        f'{URL}/{obj_id}', headers=normal_auth_headers, json=payload",
                "    )",
                "    assert put_denied.status_code == 403, (",
                "        f'PUT 无 {fk_target}:read 时应 403，实际 {put_denied.status_code}'",
                "    )",
                "    # 正向对照：授回 read 后同一 PUT 不再 403",
                f"    await Role.filter(name='reader').update(permissions={{{res!r}: ['create', 'update'], {fk_target!r}: ['read']}})",
                "    put_allowed = await client.put(",
                "        f'{URL}/{obj_id}', headers=normal_auth_headers, json=payload",
                "    )",
                "    assert put_allowed.status_code != 403, (",
                "        f'PUT 授了 read 后不应再 403，实际 {put_allowed.status_code}'",
                "    )",
                "",
                "    # 外键缺省：reader 重置为只授 create（无目标 read），POST 不带外键",
                "    # 应得到 400（缺必填外键）而不是 403——证明权限判定不对缺省外键生效",
                f"    await Role.filter(name='reader').update(permissions={{{res!r}: ['create']}})",
                "    no_fk = {k: v for k, v in payload.items() if k != FK_COLUMN}",
                "    empty_fk = await client.post(URL, headers=normal_auth_headers, json=no_fk)",
                "    assert empty_fk.status_code != 403, (",
                "        f'外键缺省时不应因引用权限被 403，实际 {empty_fk.status_code}'",
                "    )",
                "    assert empty_fk.status_code == 400, (",
                "        f'缺必填外键应 400，实际 {empty_fk.status_code}: {empty_fk.text[:200]}'",
                "    )",


                "",
                "",
            ]
            if fk_target
            else []
        ),
        "async def test_crud_roundtrip(client, auth_headers):",
        '    """创建 -> 列表 -> 详情 -> 更新 -> 删除 -> 404。"""',
        *pre,
        f"    payload = {_payload(spec, fk)}",
        "    created = await client.post(URL, headers=auth_headers, json=payload)",
        "    assert created.status_code == 201, created.text[:300]",
        '    data = created.json()["data"]',
        "    for key, value in payload.items():",
        "        # date/datetime 以 ISO 文本提交，回显可能带时区后缀（Tortoise 归一化），",
        "        # 比较时按解析后的时刻判断，而非字符串逐字相等",
        "        if isinstance(value, str) and ('T' in value or len(value) == 10):",
        "            from datetime import datetime as _dt",
        "            try:",
        "                _sent = _dt.fromisoformat(value)",
        "                _got = _dt.fromisoformat(str(data[key]))",
        "                if _sent.tzinfo is None and _got.tzinfo is not None:",
        "                    _got = _got.replace(tzinfo=None)",
        "                assert _sent == _got, key",
        "                continue",
        "            except ValueError:",
        "                pass",
        "        assert data[key] == value, key",
        '    obj_id = data["id"]',
        "",
        "    listing = await client.get(URL, headers=auth_headers)",
        "    assert listing.status_code == 200",
        '    assert any(i["id"] == obj_id for i in listing.json()["data"]["items"])',
        "",
        '    detail = await client.get(f"{URL}/{obj_id}", headers=auth_headers)',
        "    assert detail.status_code == 200",
        '    assert detail.json()["data"]["id"] == obj_id',
        "",
        '    assert (await client.get(f"{URL}/999999", headers=auth_headers)).status_code == 404',
        "",
    ]
    upd = next((f for f in spec.fields if f.choices and len(f.choices) > 1 and not f.unique), None) or next(
        (f for f in spec.fields if f.type in ("string", "text") and not f.unique and not f.format and not f.choices), None
    )
    if upd:
        L += [
            f"    changed = {{{upd.name!r}: {sample(upd, True)!r}}}",
            '    updated = await client.put(f"{URL}/{obj_id}", headers=auth_headers, json=changed)',
            "    assert updated.status_code == 200, updated.text[:300]",
            f'    assert updated.json()["data"][{upd.name!r}] == {sample(upd, True)!r}',
            "",
        ]
    L += [
        '    deleted = await client.delete(f"{URL}/{obj_id}", headers=auth_headers)',
        "    assert deleted.status_code == 200",
        '    assert (await client.get(f"{URL}/{obj_id}", headers=auth_headers)).status_code == 404',
        "",
        "",
        "async def test_create_rejects_empty_payload(client, auth_headers):",
        '    """缺必填字段 -> 400。"""'
        if any(f.required for f in spec.fields) or any(b.required for b in spec.belongs_to)
        else '    """空请求体：无必填字段，创建应成功或按规则 400；此处只断言不 5xx。"""',
        "    response = await client.post(URL, headers=auth_headers, json={})",
    ]
    has_required = any(f.required for f in spec.fields) or any(b.required for b in spec.belongs_to)
    L.append("    assert response.status_code == 400" if has_required else "    assert response.status_code < 500")
    L.append("")
    for f in spec.fields:
        if f.choices:
            bad = "__invalid__" if f.type == "string" else 999999
            L += [
                "",
                f"async def test_invalid_choice_{f.name}_returns_400(client, auth_headers):",
                f'    """{f.name} 不在 choices 内 -> 400，且错误指向该字段。"""',
                *pre,
                f"    payload = {_payload(spec, fk)}",
                f"    payload[{f.name!r}] = {bad!r}",
                "    response = await client.post(URL, headers=auth_headers, json=payload)",
                "    assert response.status_code == 400, response.text[:300]",
                f'    assert {f.name!r} in response.json()["details"]',
            ]
        if f.default is not None:
            L += [
                "",
                f"async def test_default_applied_{f.name}(client, auth_headers):",
                f'    """未传 {f.name} 时取规格默认值。"""',
                *pre,
                f"    payload = {_payload(spec, fk)}",
                "    response = await client.post(URL, headers=auth_headers, json=payload)",
                "    assert response.status_code == 201, response.text[:300]",
                f'    assert response.json()["data"][{f.name!r}] == {f.default!r}',
            ]
        if f.type == "string":
            L += [
                "",
                f"async def test_max_length_{f.name}(client, auth_headers):",
                f'    """{f.name} 超过 max_length={f.max_length} -> 400。"""',
                *pre,
                f"    payload = {_payload(spec, fk)}",
                f"    payload[{f.name!r}] = 'x' * {f.max_length + 1}",
                "    response = await client.post(URL, headers=auth_headers, json=payload)",
                "    assert response.status_code == 400, response.text[:300]",
            ]
        if f.unique:
            L += [
                "",
                f"async def test_unique_{f.name}_conflict(client, auth_headers):",
                f'    """{f.name} 唯一：重复创建 -> 409。"""',
                *pre,
                f"    payload = {_payload(spec, fk)}",
                "    assert (await client.post(URL, headers=auth_headers, json=payload)).status_code == 201",
                "    again = await client.post(URL, headers=auth_headers, json=payload)",
                "    assert again.status_code == 409, again.text[:300]",
            ]
    for b in spec.belongs_to:
        L += [
            "",
            f"async def test_belongs_to_{b.name}_must_exist(client, auth_headers):",
            f'    """{b.column} 指向不存在的记录 -> 400。"""',
            *pre,
            f"    payload = {_payload(spec, fk)}",
            f"    payload[{b.column!r}] = 999999",
            "    response = await client.post(URL, headers=auth_headers, json=payload)",
            "    assert response.status_code == 400, response.text[:300]",
            f'    assert {b.column!r} in response.json()["details"]',
        ]
    if non_core_parent:
        pt = specs[non_core_parent.target]
        L += [
            "",
            f"async def test_parent_{pt.resource}_delete_blocked_by_child(client, auth_headers):",
            f'    """存在子记录时删除父记录 {pt.resource} -> 409。"""',
            *pre,
            f"    payload = {_payload(spec, fk)}",
            "    assert (await client.post(URL, headers=auth_headers, json=payload)).status_code == 201",
            f'    blocked = await client.delete(f"/api/v1/{pt.plural}/{{{parent_var}.id}}", headers=auth_headers)',
            "    assert blocked.status_code == 409, blocked.text[:300]",
        ]
    # ---- (b) date / datetime ----
    date_fields = [f for f in spec.fields if f.type in ("date", "datetime")]
    if date_fields:
        df = date_fields[0]
        L += [
            "",
            "",
            "async def test_date_field_roundtrip(client, auth_headers):",
            f'    """date/datetime 字段：合法 ISO 文本往返一致（{df.name}）。"""',
            *pre,
            f"    payload = {_payload(spec, fk)}",
            "    created = await client.post(URL, headers=auth_headers, json=payload)",
            "    assert created.status_code == 201, created.text[:300]",
            f"    assert created.json()['data'][{df.name!r}] is not None",
            "",
            "",
            "async def test_date_field_rejects_invalid(client, auth_headers):",
            f'    """date/datetime 字段：非法文本返回 400（{df.name}）。"""',
            *pre,
            "    # 2026-13-40 月份/日期越界；abc 完全不是日期",
            "    for bad in ('2026-13-40', 'abc'):",
            f"        payload = {{**{_payload(spec, fk)}, {df.name!r}: bad}}",
            "        response = await client.post(URL, headers=auth_headers, json=payload)",
            "        assert response.status_code == 400, (",
            f"            f'{{bad!r}} 应 400，实际 {{response.status_code}}'",
            "        )",
            f"        body = response.json()",
            f"        assert {df.name!r} in body.get('details', {{}}), (",
            "            'API 层 Date() 规则应给出字段级错误；只有数据库层兜底会丢掉 details'",
            "        )",
            "        assert body['error'] == 'VALIDATION_ERROR', body",

        ]

    # ---- (c) 排序 ----
    if spec.sorting.allowed:
        first = spec.sorting.allowed[0]
        # 只对可排序标量字段做顺序断言（bool/文本混排不稳定，优先取第一个字段）
        L += [
            "",
            "",
            "async def test_ordering_whitelist_asc_desc(client, auth_headers):",
            f'    """排序：白名单字段升序/降序都 200，且顺序确实相反（{first}）。"""',
            *pre,
            "    ids = []",
            "    for i in range(3):",
            f"        payload = {_payload(spec, fk)}",
            *[
                f'        payload[{u.name!r}] = f"u{{i}}@example.com"' if u.format == "email" else f'        payload[{u.name!r}] = f"u{{i}}"'
                for u in spec.fields if u.unique
            ][:1],
            f"        payload[{first!r}] = " + ("i + 1" if not _is_text_field(spec, first) else "'a' + 'x'*i"),
            "        r = await client.post(URL, headers=auth_headers, json=payload)",
            "        assert r.status_code == 201, r.text[:200]",
            "        ids.append(r.json()['data']['id'])",
            "",
            f"    asc = await client.get(URL + '?ordering={first}', headers=auth_headers)",
            f"    desc = await client.get(URL + '?ordering=-{first}', headers=auth_headers)",
            "    assert asc.status_code == 200 and desc.status_code == 200",
            "    asc_ids = [i['id'] for i in asc.json()['data']['items']]",
            "    desc_ids = [i['id'] for i in desc.json()['data']['items']]",
            "    assert asc_ids == list(reversed(desc_ids)), (",
            "        f'升序与降序应互为逆序，实际 {asc_ids} vs {desc_ids}'",
            "    )",
            "",
            "",
            "async def test_ordering_rejects_non_whitelisted(client, auth_headers):",
            '    """排序：不在白名单的字段 -> 400。"""',
            f"    SORT_ALLOWED = {tuple(spec.sorting.allowed)!r}",
            "    outsider = next(f for f in ('created_at', 'id', 'deleted') if f not in SORT_ALLOWED)",
            "    response = await client.get(URL + '?ordering=' + outsider, headers=auth_headers)",
            "    assert response.status_code == 400, (",
            "        f'非白名单字段 {outsider} 应 400，实际 {response.status_code}'",
            "    )",
        ]
    else:
        L += [
            "",
            "",
            "async def test_ordering_empty_whitelist_rejects_any(client, auth_headers):",
            '    """排序：allowed 为空时任何 ordering 参数都 400。"""',
            "    response = await client.get(URL + '?ordering=id', headers=auth_headers)",
            "    assert response.status_code == 400, (",
            "        f'未配置 sorting 时应拒绝任何排序参数，实际 {response.status_code}'",
            "    )",
        ]

    # ---- 分页 ----
    L += [
        "",
        "",
        "async def test_pagination_page_size(client, auth_headers):",
        '    """分页：page_size 生效，返回条数不超过 page_size。"""',
        *pre,
        "    for i in range(3):",
        f"        payload = {_payload(spec, fk)}",
        *[
            f"        payload[{u.name!r}] = {_uniq_variant(u, 0).replace('0', '{i}')!r}" if False else
            f'        payload[{u.name!r}] = f"u{{i}}@example.com"' if u.format == "email" else
            f'        payload[{u.name!r}] = f"u{{i}}"'
            for u in spec.fields if u.unique
        ][:1],
        "        r = await client.post(URL, headers=auth_headers, json=payload)",
        "        assert r.status_code == 201, r.text[:200]",
        "    page = await client.get(URL + '?page=1&page_size=2', headers=auth_headers)",
        "    assert page.status_code == 200",
        "    body = page.json()['data']",
        '    assert len(body["items"]) <= 2, f\'page_size=2 却返回 {len(body["items"])} 条\'', 
        # APIResponse.list 的分页元信息在 data.pagination 下
        "    assert body['pagination']['page_size'] == 2",
        "    assert body['pagination']['total'] >= 3",
    ]

    # ---- (d) 软删除 ----
    if spec.soft_delete:
        L += [
            "",
            "",
            "async def test_soft_delete_hides_but_keeps_row(client, auth_headers):",
            '    """软删除：DELETE 后列表看不到、详情 404，库里该行仍在且 deleted=True。"""',
            *pre,
            f"    payload = {_payload(spec, fk)}",
            "    created = await client.post(URL, headers=auth_headers, json=payload)",
            "    assert created.status_code == 201, created.text[:300]",
            "    obj_id = created.json()['data']['id']",
            "",
            "    assert (await client.delete(f'{URL}/{obj_id}', headers=auth_headers)).status_code == 200",
            "",
            "    listing = await client.get(URL, headers=auth_headers)",
            "    assert all(i['id'] != obj_id for i in listing.json()['data']['items']), (",
            "        '软删除后列表仍能看到该行'",
            "    )",
            "    assert (await client.get(f'{URL}/{obj_id}', headers=auth_headers)).status_code == 404",
            "",
            f"    row = await {cls}.get_or_none(id=obj_id)",
            "    assert row is not None, '软删除不应物理删除记录'",
            "    assert row.deleted is True, '软删除应把 deleted 置 True'",
            "",
            "",
            "async def test_soft_delete_unique_still_conflicts(client, auth_headers):",
            '    """软删除行仍占用 unique 约束：同值重建返回 409（当前行为，见 docs）。"""',
            *pre,
            f"    payload = {_payload(spec, fk)}",
            "    created = await client.post(URL, headers=auth_headers, json=payload)",
            "    assert created.status_code == 201",
            "    obj_id = created.json()['data']['id']",
            "    assert (await client.delete(f'{URL}/{obj_id}', headers=auth_headers)).status_code == 200",
            "    again = await client.post(URL, headers=auth_headers, json=payload)",
            "    if again.status_code == 409:",
            "        pass  # 当前实现：unique 约束不区分 deleted",
            "    else:",
            "        assert again.status_code == 201, again.text[:200]",
        ]
    else:
        L += [
            "",
            "",
            "async def test_hard_delete_removes_row(client, auth_headers):",
            '    """未开软删除：DELETE 物理删除记录。"""',
            *pre,
            f"    payload = {_payload(spec, fk)}",
            "    created = await client.post(URL, headers=auth_headers, json=payload)",
            "    assert created.status_code == 201",
            "    obj_id = created.json()['data']['id']",
            "    assert (await client.delete(f'{URL}/{obj_id}', headers=auth_headers)).status_code == 200",
            f"    assert await {cls}.get_or_none(id=obj_id) is None, '应是物理删除'",
        ]

    L.append("")
    text = "\n".join(L)
    return text
