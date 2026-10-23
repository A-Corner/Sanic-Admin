#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
权限注册表模块：定义系统内的权限资源、动作，以及权限串的归一化规则。

背景：``requires_permission`` 用 ``rpartition(":")`` 拆分权限串，即**最后一个冒号**
之后是动作、之前是资源。由此产生两类"含冒号资源名"：

* ``system`` 与 ``system:database`` / ``system:compression``：普通资源名与含冒号资源名共存；
* ``system:database:connectionpool``（读连接池）与
  ``system:database:connectionpool:manage``（改连接池）：二者拆分出的 resource **不同**
  （前者 ``system:database``，后者 ``system:database:connectionpool``），
  导致同一个"连接池"功能的读与写无法用同一份授权覆盖。

解决办法（本模块）：

1. 注册表把 ``system:database:connectionpool`` 明确登记为独立资源（动作 ``manage``），
   同时把 ``connectionpool`` 列入 ``system:database`` 的动作，使读有归属；
2. 通过**显式**父子关系（不靠前缀猜测，避免 ``system`` 吞掉 ``system:database``）
   把子资源折叠到规范形式：``system:database:connectionpool`` + ``manage``
   折叠为基资源 ``system:database`` + 复合动作 ``connectionpool:manage``；
3. ``has_permission`` 用折叠后的形式比对，授权与校验两侧口径一致。

本模块只含纯数据与纯函数，不导入模型，避免循环依赖。
"""

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# 资源注册表
# ---------------------------------------------------------------------------

#: 资源 -> 该资源下允许的动作（"all" 表示该资源全部动作）
ALL_PERMISSIONS: Dict[str, List[str]] = {
    # 账户
    "account": ["read", "create", "update", "delete"],
    # 角色
    "role": ["read", "create", "update", "delete"],
    # 个人资料
    "profile": ["read", "update", "manage"],
    # 操作日志
    "log": ["read"],
    # 系统设置
    "setting": ["read", "create", "update", "delete"],
    # 文件
    "file": ["upload", "read", "delete", "manage"],
    # 客户（SA-v04-S0 spike）
    "customer": ["read", "create", "update", "delete"],
    # 仪表盘
    "dashboard": ["read"],
    # 系统级（含冒号资源名的普通基资源）
    "system": ["admin"],
    "system:database": ["query", "manage", "connectionpool"],
    "system:database:connectionpool": ["manage"],
    "system:compression": ["view", "manage"],
}

#: 资源 -> 父资源。显式声明，不做前缀推断。
#:
#: 只登记真正需要折叠的子资源。``system:database`` **不在**此表中：
#: ``system`` 与 ``system:database`` 是并列的基资源，否则 ``system:admin``
#: （解析为 resource=system, action=admin）会被误折叠掉。
RESOURCE_PARENTS: Dict[str, str] = {
    "system:database:connectionpool": "system:database",
}

#: 反向索引：父资源 -> 子资源
_CHILDREN: Dict[str, List[str]] = {}
for _child, _parent in RESOURCE_PARENTS.items():
    _CHILDREN.setdefault(_parent, []).append(_child)


def admin_all_permissions() -> Dict[str, List[str]]:
    """
    管理员角色应持有的全量权限。

    键集合与 ``ALL_PERMISSIONS`` 的键集合一致（每个资源都是 ``["all"]``）。
    """
    return {resource: ["all"] for resource in ALL_PERMISSIONS}


def all_resources() -> List[str]:
    """注册表中的全部资源名。"""
    return list(ALL_PERMISSIONS.keys())


def is_known_resource(resource: str) -> bool:
    """资源是否在注册表中登记。"""
    return resource in ALL_PERMISSIONS


def known_actions(resource: str) -> List[str]:
    """资源的已知动作列表（未登记时返回空列表）。"""
    return list(ALL_PERMISSIONS.get(resource, []))


# ---------------------------------------------------------------------------
# 归一化
# ---------------------------------------------------------------------------

def base_resource(resource: str) -> str:
    """
    资源折叠后的基资源：子资源返回其父资源，基资源返回自身。
    """
    seen = set()
    current = resource
    while current in RESOURCE_PARENTS and current not in seen:
        seen.add(current)
        current = RESOURCE_PARENTS[current]
    return current


def normalize_permission(resource: str, action: str) -> Tuple[str, str]:
    """
    把 ``(resource, action)`` 折叠成规范形式 ``(基资源, 复合动作)``。

    * ``("system:database", "query")`` -> ``("system:database", "query")``
    * ``("system:database:connectionpool", "manage")``
      -> ``("system:database", "connectionpool:manage")``
    * ``("system", "admin")`` -> ``("system", "admin")``

    未登记为子资源的资源原样返回（保持既有 ``rpartition`` 语义）。
    """
    base = base_resource(resource)
    if base == resource:
        return resource, action

    sub = resource[len(base) + 1:]
    return base, f"{sub}:{action}"


def normalize_permission_string(permission: str) -> Tuple[str, str]:
    """
    把权限串（``资源:动作``）拆分成规范形式的 ``(基资源, 复合动作)``。

    拆分规则与 ``requires_permission`` 一致：最后一个冒号之后为动作，之前为资源。
    """
    resource, sep, action = permission.rpartition(":")
    if not sep:
        return normalize_permission(resource, "all")
    return normalize_permission(resource, action)


def effective_permissions(granted: Dict[str, Iterable[str]]) -> Dict[str, Set[str]]:
    """
    把角色授权字典折叠成"基资源 -> 复合动作集合"的有效权限表。

    授权与校验两侧都经过同一套折叠，因此 ``{"system:database": ["connectionpool"]}``
    与 ``{"system:database:connectionpool": ["manage"]}`` 落在同一个基资源上，
    可以被同一份授权分别覆盖读与写。

    Args:
        granted: ``{资源: [动作, ...]}`` 形式的合并后授权

    Returns:
        Dict[str, Set[str]]: 基资源 -> 复合动作集合
    """
    effective: Dict[str, Set[str]] = {}

    for resource, actions in (granted or {}).items():
        base = base_resource(resource)
        sub = resource[len(base) + 1:] if base != resource else ""

        bucket = effective.setdefault(base, set())

        for action in actions or []:
            action = str(action)
            if sub:
                if action == "all":
                    # 子资源的 "all" 覆盖该子资源下的全部动作，
                    # 包括基资源上以子资源命名的读动作（"connectionpool"）。
                    bucket.add(f"{sub}:all")
                    bucket.add(sub)
                else:
                    bucket.add(f"{sub}:{action}")
            else:
                bucket.add(action)

    return effective


#: 蕴含规则：``X:manage`` 蕴含 ``X``（能改就能看）。
#:
#: 只对"管理类动作"生效，且**只蕴含同一前缀下不带冒号的那个动作**。
#: 因此：
#: * ``system:database:connectionpool:manage`` -> 蕴含 ``system:database:connectionpool``（读连接池）；
#: * ``system:admin`` 不会蕴含任何子资源（``admin`` 不是 manage 型动作）；
#: * ``system:database:query`` 不会蕴含 ``connectionpool``（query 不是 manage 型动作）。
#:
#: **蕴含是单向的**：只有"写"推出"读"，绝不反向。
#: 只读授权（``{"system:database": ["connectionpool"]}``）**不得**推出写权限
#: （``connectionpool:manage``），否则只读账户即可执行写操作（潜伏越权）。
IMPLYING_ACTIONS = ("manage",)


def _implied_paths(path: str) -> Tuple[str, ...]:
    """
    授权侧动作 ``X:manage`` -> 它蕴含的读动作路径集合；非 manage 型动作返回空元组。

    对 ``X = "connectionpool"``，蕴含的读动作有**两种拼法**：

    * ``"connectionpool"`` —— 裸动作名，这是 ``requires_permission(
      "system:database:connectionpool")`` 拆分后得到的实际请求形态
      （resource=``system:database``、action=``connectionpool``）；
    * ``"connectionpool:read"`` —— 显式的 ``:read`` 形态，
      对应 ``has_permission(account, "system:database:connectionpool", "read")``。
    """
    if ":" not in path:
        return ()

    head, _, tail = path.rpartition(":")
    if tail not in IMPLYING_ACTIONS or not head:
        return ()

    return head, f"{head}:read"


def permission_granted(effective: Dict[str, Set[str]], resource: str,
                       action: str) -> bool:
    """
    在折叠后的有效权限表里判断 ``resource:action`` 是否被授予。

    判定顺序：

    * 动作精确命中即通过；
    * 该基资源带 ``all`` 通配则通过；
    * 存在 ``子资源:all`` 通配且动作落在该子资源下也通过；
    * **蕴含规则（单向）**：bucket 中存在 ``X:manage`` 时，请求的只读动作
      ``X``（或 ``X:read``）也通过（manage 蕴含 read：能改就能看）。

    蕴含**只从 manage 推出 read**，不存在反向蕴含：
    bucket 中只有只读 ``X`` 时，请求写动作 ``X:manage`` **被拒**
    （否则只读账户即可执行写操作 = 潜伏越权）。

    因此：

    * ``{"system:database": ["connectionpool"]}`` → 只读连接池通过，
      写连接池（``connectionpool:manage``）**被拒**；
    * ``{"system:database": ["connectionpool:manage"]}`` → 读写**都通过**；
    * ``{"system:database:connectionpool": ["manage"]}``（存量别名）
      → 读写**都通过**；
    * ``system:admin`` 不蕴含任何其他动作；``query`` 不蕴含 ``connectionpool``。
    """
    base, path = normalize_permission(resource, action)
    bucket = effective.get(base)
    if not bucket:
        return False

    if "all" in bucket:
        return True
    if path in bucket:
        return True

    for entry in bucket:
        if entry.endswith(":all"):
            prefix = entry[:-len(":all")]
            if path.startswith(prefix + ":"):
                return True

    # 蕴含规则（单向，只从"写"推出"读"）：
    # bucket 中存在 "X:manage" 时，请求的只读动作 "X" 也被授予（manage 蕴含 read）。
    #
    # 注意方向：这里是**授权侧**的 "X:manage" 推出**请求侧**的 "X"，
    # 而不是反过来。授权侧只有 "X"（只读）时，请求 "X:manage"（写）**不被授予**，
    # 否则只读账户即可执行写操作（潜伏越权）。
    for entry in bucket:
        if path in _implied_paths(entry):
            return True

    return False


def describe_permission(resource: str, action: str) -> str:
    """权限的可读描述（用于错误信息）。"""
    return f"{resource}:{action}"


def validate_permissions_dict(permissions: Any) -> Tuple[bool, List[str]]:
    """
    校验权限字典的结构与注册表一致性（写入角色权限前的最后一道闸）。

    检查项：

    * 必须是字典；
    * 资源名必须是非空字符串，且已在注册表登记（子资源允许，但需能折叠到基资源）；
    * 动作必须是非空字符串列表，且该资源下允许该动作（或该资源允许 "all"）。

    Args:
        permissions: 待校验的权限字典 ``{资源: [动作, ...]}``

    Returns:
        Tuple[bool, List[str]]: ``(是否通过, 错误信息列表)``
    """
    errors: List[str] = []

    if not isinstance(permissions, dict):
        return False, ["permissions 必须是字典"]

    for resource, actions in permissions.items():
        if not isinstance(resource, str) or not resource.strip():
            errors.append("资源名必须是非空字符串")
            continue

        if not is_known_resource(resource):
            errors.append(f"未知资源 '{resource}'（未在权限注册表中登记）")
            continue

        if not isinstance(actions, list):
            errors.append(f"资源 '{resource}' 的动作必须是列表")
            continue

        allowed = set(known_actions(resource))

        for action in actions:
            if not isinstance(action, str) or not action.strip():
                errors.append(f"资源 '{resource}' 的动作必须是非空字符串")
                continue
            if allowed and "all" not in allowed and action not in allowed:
                errors.append(
                    f"资源 '{resource}' 不支持动作 '{action}'"
                    f"（允许: {', '.join(sorted(allowed))}）"
                )

    return (not errors), errors
