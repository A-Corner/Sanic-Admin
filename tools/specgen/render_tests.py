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


def render_test(spec: ResourceSpec, specs: Dict[str, ResourceSpec]) -> str:
    res, cls = spec.resource, spec.cls
    url = f"/api/v1/{spec.plural}"
    setup = _Setup(specs)
    fk = setup.fk_exprs(spec)
    pre = list(setup.lines)
    imports = sorted(setup.imports)
    first_parent = next((b for b in spec.belongs_to if b.target not in CORE_TARGETS), None)
    fk_target = first_parent.target if first_parent else None
    # 引用目标需要 read 权限才能引用（防 ID 枚举）
    parent_var = fk[first_parent.column].split(".")[0] if first_parent else None

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
                "",
            ]
            if spec.belongs_to
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
    if first_parent:
        pt = specs[first_parent.target]
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
    L.append("")
    text = "\n".join(L)
    return text
