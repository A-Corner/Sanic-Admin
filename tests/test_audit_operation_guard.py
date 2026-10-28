# -*- coding: utf-8 -*-
"""
审计操作名守卫：`record_auth_event()` 的所有调用点必须用白名单内的操作名。

## 为什么需要这条

`record_auth_event()` 对白名单外的操作名是**静默丢弃**——只记一条 warning 就返回
（`app/services/audit.py`）。这意味着：

- 新增一个鉴权功能、写了个新操作名、忘了加进 `OPERATIONS`
- 所有测试照常通过
- 生产上这条审计**永远不会出现**，而且没有任何报错

2026-10-28 的 AUTH-03 就撞上了这条：两个新端点调用 `record_auth_event()`，
操作名不在白名单里，直到手动核对才发现。

**本测试用 AST 扫描源码里的字面量操作名**，而不是正则——正则会被注释、
字符串拼接、多行调用骗过去。

## 正向对照

`test_guard_detects_unknown_operation()` 故意构造一个含未知操作名的源码片段，
断言扫描器能发现。**没有这条，守卫本身可能是空的**：如果扫描器写的路径永远
匹配不到任何调用，它会永远返回「没问题」。
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app.services.audit import OPERATIONS

#: 仓库根（tests/ 的上一级）
REPO_ROOT = Path(__file__).resolve().parent.parent

#: 扫描范围：这些目录下的 .py 文件里出现的 `record_auth_event(...)` 调用
SCAN_DIRS = ("app",)


def _iter_py_files() -> list[Path]:
    files: list[Path] = []
    for d in SCAN_DIRS:
        root = REPO_ROOT / d
        if root.is_dir():
            files.extend(sorted(root.rglob("*.py")))
    return files


def _is_record_auth_event_call(node: ast.Call) -> bool:
    """调用是否是 `record_auth_event(...)`（含 `x.record_auth_event(...)` 形式）。"""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "record_auth_event"
    if isinstance(func, ast.Attribute):
        return func.attr == "record_auth_event"
    return False


def _extract_operation_name(call: ast.Call) -> str | None:
    """
    从 `record_auth_event(request, "<op>", ...)` 里取操作名。

    第二个位置参数是操作名（第一个是 request）。也接受 `operation="<op>"` 关键字
    形式。**只认字符串字面量**——变量传参无法静态验证，返回 None 由调用方决定
    如何处理（当前策略：跳过并记录，见下面的断言信息）。
    """
    # 关键字形式
    for kw in call.keywords:
        if kw.arg == "operation" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    # 位置形式：第 2 个参数
    if len(call.args) >= 2:
        second = call.args[1]
        if isinstance(second, ast.Constant) and isinstance(second.value, str):
            return second.value
    return None


def collect_operation_names(source: str, filename: str = "<test>") -> tuple[set[str], int]:
    """
    扫描源码，返回 `(发现的操作名集合, 无法静态解析的调用数)`。

    无法静态解析 = 操作名是变量或表达式（非字面量）。这类调用本身不算违规，
    但要计数并在测试里报出来——否则「全都解析不了」会伪装成「全都合法」。
    """
    tree = ast.parse(source, filename=filename)
    found: set[str] = set()
    unresolved = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_record_auth_event_call(node):
            name = _extract_operation_name(node)
            if name is None:
                unresolved += 1
            else:
                found.add(name)
    return found, unresolved


# ---------------------------------------------------------------------------
# 正向对照：守卫本身必须能发现问题
# ---------------------------------------------------------------------------


def test_guard_detects_unknown_operation():
    """
    **正向对照**：给一段含未知操作名的源码，扫描器必须把它找出来。

    没有这条，`test_all_call_sites_use_whitelisted_operations` 可能因为
    「一个调用点都没扫到」而恒绿。
    """
    sample = """
async def f(request):
    await record_auth_event(request, "nonexistent_op", status="success")
"""
    found, unresolved = collect_operation_names(sample)
    assert "nonexistent_op" in found, "扫描器没找到已知存在的调用，守卫是空的"
    assert unresolved == 0
    # 且它确实不在白名单里
    assert "nonexistent_op" not in OPERATIONS


def test_guard_detects_keyword_form_and_attribute_call():
    """关键字形式与 `module.record_auth_event` 形式也要被扫到。"""
    sample = """
from app.services import audit
async def f(request):
    await audit.record_auth_event(request, operation="kw_form_op")
"""
    found, _ = collect_operation_names(sample)
    assert found == {"kw_form_op"}


# ---------------------------------------------------------------------------
# 真正的守卫
# ---------------------------------------------------------------------------


def test_all_call_sites_use_whitelisted_operations():
    """
    `app/` 下所有 `record_auth_event(...)` 调用的字面量操作名都必须 ∈ OPERATIONS。

    失败时打印全部非法名与所在文件，便于直接定位。
    """
    violations: list[str] = []
    total_unresolved = 0
    total_found = 0

    files = _iter_py_files()
    assert files, f"没扫到任何 .py 文件（SCAN_DIRS={SCAN_DIRS}，REPO_ROOT={REPO_ROOT}）"

    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "record_auth_event" not in source:
            continue
        try:
            found, unresolved = collect_operation_names(source, str(path))
        except SyntaxError as exc:  # pragma: no cover - 源码本身有语法错，另有 CI 拦
            violations.append(f"{path}: 无法解析（{exc}）")
            continue
        total_found += len(found)
        total_unresolved += unresolved
        for name in sorted(found):
            if name not in OPERATIONS:
                violations.append(
                    f"{path.relative_to(REPO_ROOT)}: 操作名 {name!r} 不在 OPERATIONS 白名单里（会被静默丢弃，审计缺失）"
                )

    # 正向对照的一部分：必须真的扫到了调用点，否则本测试等于没跑
    assert total_found > 0, (
        "没有扫到任何字面量操作名——扫描路径或 AST 匹配可能失效，"
        "此时本测试会假绿。请检查 SCAN_DIRS 与 _is_record_auth_event_call。"
    )

    assert not violations, (
        "发现未登记的审计操作名：\n  " + "\n  ".join(violations) + f"\n\n请把它们加进 app/services/audit.py 的 OPERATIONS。"
    )

    # 非字面量操作名（变量传参）无法静态验证 —— 单独断言，而不是只在失败消息里提一句。
    # 否则将来有人把某处 "login_success" 改成 op_name 变量，该调用点会静默退出
    # 守卫覆盖，测试依旧全绿。
    assert total_unresolved == 0, (
        f"有 {total_unresolved} 处 record_auth_event() 调用的操作名不是字面量，"
        "守卫无法静态验证它们。请改为字面量，或在此显式登记为已审查的例外。"
    )


def test_operations_whitelist_covers_password_reset():
    """
    AUTH-03 的具体回归：密码重置的两个操作名必须在白名单里。

    这条比上面的通用守卫更早失败、更直白——如果将来有人把白名单重构坏了，
    上面那条可能因为扫描逻辑一起坏而看不出来，这条会直接红。
    """
    assert "password_reset_request" in OPERATIONS
    assert "password_reset_confirm" in OPERATIONS
