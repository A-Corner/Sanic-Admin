#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
授权测试：未认证访问全部受保护接口 → 401；权限不足 → 403；管理员 → 200。

覆盖 CPL 验收口径第 2、3、4 项。

路由来源是 **动态提取** 的：``app.router.routes`` 里所有 ``/api/`` 前缀的路由，
在测试运行时提取并逐条访问。app 侧新增资源时本用例自动跟着覆盖，不需要改测试。
"""

import pytest


def _route_ids_for_api(routes):
    """把路由表转成 ``(method, path)`` 列表。"""
    ids = []
    for method, path in routes:
        ids.append((method, path))
    return ids


@pytest.fixture(scope="session")
def protected_api_routes(registered_api_routes):
    """所有受保护的 API 路由（``/api/`` 前缀），已去重。"""
    seen = set()
    unique = []
    for method, path in registered_api_routes:
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(key)
    return unique


def test_protected_route_set_is_not_empty(protected_api_routes):
    """
    守卫：路由提取本身要有效。

    如果 app 侧路由注册出了问题（``v1_bp`` 变成孤儿蓝图等），这里会先失败，
    比让下面 40+ 条用例集体 404 更容易定位。
    """
    assert len(protected_api_routes) >= 20, (
        f"只提取到 {len(protected_api_routes)} 条 API 路由，路由注册可能有问题: "
        f"{protected_api_routes}"
    )
    paths = {path for _, path in protected_api_routes}
    # 关键管理接口必须出现在路由表里
    for expected in ("/api/v1/accounts", "/api/v1/roles"):
        assert expected in paths, f"路由表缺少 {expected}: {sorted(paths)}"


@pytest.mark.parametrize(
    "method,path",
    _route_ids_for_api(
        [
            ("GET", "/api/v1/accounts"),
            ("POST", "/api/v1/accounts"),
            ("GET", "/api/v1/roles"),
            ("POST", "/api/v1/roles"),
        ]
    ),
)
async def test_unauthenticated_known_routes_return_401(client, method, path):
    """未认证访问受保护接口 → 401（抽样断言）。"""
    response = await client.request(method, path, json={})
    assert response.status_code == 401, (
        f"{method} {path} 未认证时返回 {response.status_code}，应为 401：{response.text}"
    )
    body = response.json()
    assert body["success"] is False
    assert body["error"]


async def test_all_protected_routes_require_authentication(client, protected_api_routes):
    """
    遍历**全部**受保护接口：未认证访问一律 401。

    不能是 500（服务端错误），也不能是 404（路由没注册上）。
    """
    failures = []
    for method, path in protected_api_routes:
        response = await client.request(method, path, json={})
        if response.status_code != 401:
            failures.append(
                f"{method} {path} → {response.status_code}（期望 401）"
            )

    assert not failures, (
        "以下受保护接口在未认证时没有返回 401：\n" + "\n".join(failures)
    )


async def test_all_protected_routes_reject_forged_token(client, protected_api_routes):
    """遍历全部受保护接口：伪造 token 一律 401。"""
    failures = []
    headers = {"Authorization": "Bearer forged.token.value"}
    for method, path in protected_api_routes:
        response = await client.request(method, path, json={}, headers=headers)
        if response.status_code != 401:
            failures.append(
                f"{method} {path} → {response.status_code}（期望 401）"
            )

    assert not failures, (
        "以下受保护接口接受伪造 token：\n" + "\n".join(failures)
    )


async def test_normal_user_gets_403_on_admin_endpoints(client, normal_auth_headers):
    """
    权限不足 → 403。

    普通账户（只读角色，无任何管理权限）访问管理接口 → 403，不是 401 也不是 200。
    """
    response = await client.get("/api/v1/accounts", headers=normal_auth_headers)
    assert response.status_code == 403, (
        f"普通账户访问账户列表返回 {response.status_code}，应为 403：{response.text}"
    )
    body = response.json()
    assert body["success"] is False
    assert body["error"]


async def test_normal_user_gets_403_on_role_management(client, normal_auth_headers):
    """普通账户访问角色管理 → 403。"""
    response = await client.post(
        "/api/v1/roles",
        headers=normal_auth_headers,
        json={"name": "forbidden-role", "permissions": {}},
    )
    assert response.status_code == 403, (
        f"普通账户创建角色返回 {response.status_code}，应为 403：{response.text}"
    )


async def test_normal_user_gets_403_on_settings_management(client, normal_auth_headers):
    """普通账户访问系统设置 → 403。"""
    response = await client.get("/api/v1/settings", headers=normal_auth_headers)
    assert response.status_code == 403, (
        f"普通账户读取设置返回 {response.status_code}，应为 403：{response.text}"
    )


async def test_admin_has_full_access(client, auth_headers):
    """管理员全权限 → 200。"""
    for path in (
        "/api/v1/accounts",
        "/api/v1/roles",
        "/api/v1/settings",
        "/api/v1/logs",
        "/api/v1/dashboard/summary",
        "/api/database/query-logs",
        "/api/compression/stats",
    ):
        response = await client.get(path, headers=auth_headers)
        assert response.status_code == 200, (
            f"管理员访问 {path} 返回 {response.status_code}，应为 200：{response.text}"
        )
        body = response.json()
        assert body["success"] is True, f"{path} 返回 success=false：{response.text}"


async def test_admin_can_write(client, auth_headers):
    """
    管理员的写操作也放行（创建 + 更新两个写路径）。

    设置键有白名单（``ALLOWED_SETTING_KEYS``），且测试库没有预置设置项，
    所以这里先用白名单里的 ``site_name`` 创建，再更新它的值。
    """
    created = await client.post(
        "/api/v1/settings",
        headers=auth_headers,
        json={
            "key": "site_name",
            "value": "Lane E Admin Write",
            "value_type": "string",
        },
    )
    assert created.status_code == 201, (
        f"管理员创建设置返回 {created.status_code}，应为 201：{created.text}"
    )

    updated = await client.put(
        "/api/v1/settings/key/site_name",
        headers=auth_headers,
        json={"value": "Lane E Admin Write 2"},
    )
    assert updated.status_code == 200, (
        f"管理员更新设置返回 {updated.status_code}，应为 200：{updated.text}"
    )


def test_specgen_resources_are_in_route_table(protected_api_routes):
    """
    specgen 生成的资源必须出现在受保护路由表里（于是上面的全路由 401/伪造 token 检查自动覆盖它们）。

    期望路径由 ``specs/*.yaml`` 推出，规格新增资源时本用例自动跟着变。
    """
    from pathlib import Path

    from tools.specgen.schema import load_specs

    specs = load_specs(Path(__file__).resolve().parent.parent / "specs")
    assert specs, "specs/ 下应至少有一份规格"
    routes = set(protected_api_routes)
    for spec in specs.values():
        for method, path in (
            ("GET", f"/api/v1/{spec.plural}"),
            ("POST", f"/api/v1/{spec.plural}"),
            ("GET", f"/api/v1/{spec.plural}/1"),
            ("PUT", f"/api/v1/{spec.plural}/1"),
            ("DELETE", f"/api/v1/{spec.plural}/1"),
        ):
            assert (method, path) in routes, f"路由表缺少 {method} {path}"
