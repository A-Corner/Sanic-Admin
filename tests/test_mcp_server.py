#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MCP 服务（只读层）的测试。

每个工具一条正例 + 一条反例；另有安全边界用例：
路径穿越必须被拒、输入上限（超长 / 别名炸弹 / 深嵌套）、
preview 前后仓库文件快照一致（含「篡改必须被发现」的正向对照）、
错误与预览输出不泄露绝对路径 / HOME / 临时目录前缀、
已注册工具名与 docs 契约一致、真实 stdio 握手可列出工具。
"""

import json
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import pytest

from tools.mcp_server import (
    MAX_SPEC_TEXT_BYTES,
    ToolError,
    _guard_resource_name,
    _guard_spec_text,
    _redact,
    _repo_digest_snapshot,
    check,
    describe_resource,
    list_resources,
    preview_generate,
    validate_spec,
)
from tools.specgen.schema import SpecError, parse_spec_text, safe_load_spec

ROOT = pathlib.Path(__file__).resolve().parent.parent
CUSTOMER_SPEC = (ROOT / "specs" / "customer.yaml").read_text(encoding="utf-8")

#: stdio 冒烟的单次读超时：服务端挂起时用它判失败，而不是把 CI 拖到 job 超时。
STDIO_TIMEOUT_SECS = 30.0


def _drain_stderr(proc, timeout: float = 1.0) -> str:
    """尽力取一小段 stderr 供断言消息使用；拿不到就返回空串（不能让诊断本身挂住）。"""
    try:
        fd = proc.stderr.fileno()
    except (AttributeError, ValueError, OSError):
        return ""
    try:
        import select

        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready:
            return ""
        chunk = os.read(fd, 4096)
    except (OSError, ValueError):
        return ""
    return chunk.decode("utf-8", "replace")


#: 典型「billion laughs」：约 300 字节，展开后是指数级节点。
BILLION_LAUGHS = (
    "a: &a [x, x, x, x, x, x, x, x, x]\n"
    "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
    "c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
    "d: [*c, *c, *c, *c, *c, *c, *c, *c, *c]\n"
)


def _blob(*objs) -> str:
    """把工具返回值压成一段文本，用于「不得泄露」类断言。"""
    return "\n".join(str(o) for o in objs)


def _forbidden_needles() -> list:
    """错误/预览输出里绝不允许出现的片段：本机绝对路径、HOME、临时目录。"""
    needles = [str(ROOT), str(ROOT.resolve())]
    home = os.environ.get("HOME")
    if home:
        needles.append(home)
    needles.append(str(pathlib.Path(tempfile.gettempdir()).resolve()))
    needles.append(tempfile.gettempdir())
    return [n for n in needles if n]


def assert_no_local_paths(blob: str, context: str = ""):
    """输出不得含绝对路径 / HOME / 临时目录前缀。"""
    for needle in _forbidden_needles():
        assert needle not in blob, f"{context}泄露了本机路径前缀 {needle!r}"
    # 兜底：不应出现典型的绝对路径片段
    assert "/Users/" not in blob, f"{context}泄露了 /Users/ 绝对路径"
    assert "/Volumes/" not in blob, f"{context}泄露了 /Volumes/ 绝对路径"
    assert "specgen-preview-" not in blob, f"{context}泄露了临时目录名"


# ---------------------------------------------------------------------------
# list_resources
# ---------------------------------------------------------------------------


def test_list_resources_returns_specs():
    """正例：列出仓库内全部规格及字段摘要。"""
    items = list_resources()
    names = {i["resource"] for i in items}
    assert {"customer", "order"} <= names
    customer = next(i for i in items if i["resource"] == "customer")
    assert customer["field_count"] >= 3
    assert any(f["name"] == "name" for f in customer["fields"])


def test_list_resources_reports_soft_delete_and_sorting():
    """正例：摘要里带 soft_delete 与排序白名单（AI 需要据此理解资源）。"""
    customer = next(i for i in list_resources() if i["resource"] == "customer")
    assert customer["soft_delete"] is True
    assert "birthday" in customer["sorting_allowed"]


# ---------------------------------------------------------------------------
# describe_resource
# ---------------------------------------------------------------------------


def test_describe_resource_returns_spec_and_paths():
    """正例：返回规格全文、生成物路径、权限点。"""
    info = describe_resource("customer")
    assert info["resource"] == "customer"
    assert "resource: customer" in info["spec_yaml"]
    assert set(info["generated"]) == {"model", "resource", "amis_page", "test"}
    assert "customer:read" in info["permissions"]
    # 路径是仓库相对路径，不带本机绝对前缀
    assert info["spec_path"] == "specs/customer.yaml"


def test_describe_resource_missing_raises():
    """反例：不存在的资源名报错（不返回空结构）。"""
    with pytest.raises(ToolError) as exc:
        describe_resource("no_such_resource")
    assert_no_local_paths(str(exc.value), "describe_resource 错误：")


# ---------------------------------------------------------------------------
# validate_spec
# ---------------------------------------------------------------------------


def test_validate_spec_accepts_valid_yaml():
    """正例：合法规格校验通过并回报资源名。"""
    result = validate_spec(CUSTOMER_SPEC)
    assert result["ok"] is True
    assert result["resource"] == "customer"


def test_validate_spec_reports_field_path_on_error():
    """反例：非法规格返回带字段路径的错误，而不是抛异常或只给一句话。"""
    bad = "resource: thing\nfields: []\n"
    result = validate_spec(bad)
    assert result["ok"] is False
    assert result["errors"], "应返回具体错误"
    assert any(e["path"] for e in result["errors"]), "错误应带字段路径"


def test_validate_spec_rejects_unknown_key():
    """反例：未知键（拼写错误）必须报错，不静默忽略。"""
    bad = CUSTOMER_SPEC + "\nunknown_key: 1\n"
    result = validate_spec(bad)
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# 输入上限：超长文本 / 别名炸弹 / 深嵌套（validate_spec 与 preview_generate 都要挡）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", [validate_spec, preview_generate])
def test_oversized_input_is_rejected(tool):
    """超长输入必须被拒：64KB 上限，错误信息报出上限与实际大小。"""
    oversized = "# pad\n" + "x" * (MAX_SPEC_TEXT_BYTES + 1)
    result = tool(oversized)
    assert result["ok"] is False, "超长输入不应进入解析/生成流程"
    reasons = " ".join(e["reason"] for e in result["errors"])
    assert "上限" in reasons and str(MAX_SPEC_TEXT_BYTES) in reasons, reasons


@pytest.mark.parametrize("tool", [validate_spec, preview_generate])
def test_billion_laughs_aliases_are_rejected(tool):
    """billion laughs 别名炸弹必须被拒（不是「碰巧校验失败」）。"""
    result = tool(BILLION_LAUGHS)
    assert result["ok"] is False
    reasons = " ".join(e["reason"] for e in result["errors"])
    assert "锚点" in reasons or "别名" in reasons, f"应因锚点/别名被拒，实际：{reasons}"


def test_yaml_anchor_bomb_rejected_by_loader():
    """底层 loader 直接拒绝锚点；普通规格文本仍可解析（正向对照）。"""
    with pytest.raises(SpecError) as exc:
        safe_load_spec(BILLION_LAUGHS, "inline")
    assert "锚点" in str(exc.value) or "别名" in str(exc.value)
    assert safe_load_spec(CUSTOMER_SPEC, "inline")["resource"] == "customer"


def test_deeply_nested_yaml_is_rejected():
    """深嵌套（递归）同样拒绝，避免解析期爆栈。"""
    deep = "".join(" " * i + "k:\n" for i in range(80)) + " " * 80 + "v: 1\n"
    with pytest.raises(SpecError) as exc:
        safe_load_spec(deep, "inline")
    assert "嵌套" in str(exc.value)


def test_guard_spec_text_rejects_non_text_and_oversize():
    """入口守卫：非文本与超长都要在进 YAML 之前被挡。"""
    with pytest.raises(ToolError):
        _guard_spec_text(b"resource: customer\n")
    with pytest.raises(ToolError):
        _guard_spec_text("x" * (MAX_SPEC_TEXT_BYTES + 1))
    assert _guard_spec_text(CUSTOMER_SPEC) == CUSTOMER_SPEC


# ---------------------------------------------------------------------------
# preview_generate
# ---------------------------------------------------------------------------


def test_preview_generate_returns_diff_without_writing_repo():
    """正例：返回 diff，且仓库文件快照前后一致（正向对照）。"""
    before = _repo_digest_snapshot()
    changed_spec = CUSTOMER_SPEC.replace("label: 客户", "label: 客户档案（改）")
    result = preview_generate(changed_spec)
    after = _repo_digest_snapshot()

    assert result["ok"] is True
    assert result["repo_unchanged"] is True
    assert result["diff"], "应返回非空 diff"
    assert "客户档案（改）" in result["diff"], "diff 应体现本次改动"
    assert before == after, "preview 不得修改仓库任何文件"


def test_preview_generate_rejects_invalid_spec():
    """反例：非法规格在预览阶段就报错，不进入生成。"""
    result = preview_generate("resource: thing\nfields: []\n")
    assert result["ok"] is False
    assert result["errors"]


def test_preview_generate_diff_is_scoped_to_changed_resource():
    """正例：预览单个资源时，不应出现「删除其它资源」的误导性 diff。"""
    changed_spec = CUSTOMER_SPEC.replace("label: 客户", "label: 客户档案（改）")
    result = preview_generate(changed_spec)
    # order 资源没被改动，它的权限点不应出现在 diff 的删除行里
    assert "'order'" not in result["diff"], (
        "预览不应把其它资源渲染成被删除——临时目录需要包含全部现有规格"
    )


# ---------------------------------------------------------------------------
# 快照范围：specs / site.json / 权限点 / 生成包 __init__ 都要在内
# ---------------------------------------------------------------------------


def test_snapshot_covers_specs_site_permissions_and_package_inits():
    """快照不得只覆盖「生成物」：规格源、菜单、权限点、包 __init__ 都必须在内。"""
    snapshot = _repo_digest_snapshot()
    for rel in (
        "specs/customer.yaml",
        "specs/order.yaml",
        "amis/pages/site.json",
        "amis/pages/customer-list.json",
        "app/auth/permissions.py",
        "app/generated/__init__.py",
        "app/generated/permissions.py",
        "app/generated/models/__init__.py",
        "app/generated/resources/__init__.py",
        "app/generated/models/customer.py",
        "tests/generated/test_gen_customer.py",
    ):
        assert rel in snapshot, f"快照漏了 {rel}"


def test_snapshot_detects_tampering_positive_control(tmp_path, monkeypatch):
    """
    正向对照：快照之后篡改任一被覆盖的文件，比对必须报出差异。

    逐一篡改 specs / site.json / permissions.py / 包 __init__，确认每一类都能被发现；
    否则「快照范围」的扩大就是空的。
    """
    import tools.mcp_server as mcp_server

    mini = _mini_repo(tmp_path)
    monkeypatch.setattr(mcp_server, "ROOT", mini)

    baseline = _repo_digest_snapshot()
    assert mini.name and baseline, "迷你仓库快照不应为空"

    targets = (
        "specs/order.yaml",
        "amis/pages/site.json",
        "app/auth/permissions.py",
        "app/generated/__init__.py",
    )
    for rel in targets:
        target = mini / rel
        original = target.read_text(encoding="utf-8")
        target.write_text(original + "\n# tampered\n", encoding="utf-8")
        after = _repo_digest_snapshot()
        assert baseline != after, f"篡改 {rel} 后快照比对没有发现差异"
        assert baseline.get(rel) != after.get(rel), f"{rel} 的摘要未变化"
        target.write_text(original, encoding="utf-8")
        assert _repo_digest_snapshot() == baseline, f"还原 {rel} 后摘要应恢复"


def test_preview_raises_when_repo_file_changes_during_preview(tmp_path, monkeypatch):
    """
    正向对照：若 preview 期间实现误写仓库（这里由 wrapper 模拟），必须抛错而不是静默通过。
    """
    import tools.mcp_server as mcp_server
    from tools.specgen import generate

    mini = _mini_repo(tmp_path)
    monkeypatch.setattr(mcp_server, "ROOT", mini)

    real_run = generate.run

    def tampering_run(root, spec_dir, check=False):
        out = real_run(root, spec_dir, check=check)
        (mini / "specs" / "customer.yaml").write_text("resource: customer\nfields: []\n", encoding="utf-8")
        return out

    monkeypatch.setattr(generate, "run", tampering_run)
    with pytest.raises(ToolError) as exc:
        preview_generate(CUSTOMER_SPEC)
    assert "修改了仓库文件" in str(exc.value)
    assert "specs/customer.yaml" in str(exc.value)


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def test_check_reports_consistent():
    """正例：当前仓库生成物与规格一致。"""
    result = check()
    assert result["ok"] is True
    assert result["drift"] == [] and result["stale"] == []


# ---------------------------------------------------------------------------
# 安全边界：路径穿越 / 正则必须以整串匹配
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [
    "../customer",
    "../../etc/passwd",
    "/etc/passwd",
    "customer/../../etc",
    "sub/dir/customer",
    "customer\\x",
    "",
    "Customer",
    "customer-1",
    # 末尾换行：match + "$" 会放过，必须用 fullmatch 挡掉
    "customer\n",
    "customer\n../etc",
])
def test_resource_name_whitelist_rejects_traversal(bad):
    """路径穿越、非法资源名与末尾换行必须被拒（白名单，不是黑名单）。"""
    with pytest.raises(ToolError):
        _guard_resource_name(bad)


def test_describe_resource_rejects_traversal():
    """工具入口同样拦截路径穿越，不给「读取任意文件」的口子。"""
    for bad in ("../customer", "/etc/passwd", "../../etc/passwd", "customer\n"):
        with pytest.raises(ToolError):
            describe_resource(bad)


@pytest.mark.parametrize("bad", ["customer\n", "name\n", "thing\n\n"])
def test_spec_identifier_rejects_trailing_newline(bad):
    """标识符正则同样必须整串匹配：末尾换行不得被当作合法值。"""
    text = f"resource: {json.dumps(bad)}\nfields: [{{name: ok, type: string}}]\n"
    with pytest.raises(SpecError) as exc:
        parse_spec_text(text, "inline")
    assert "必须匹配" in str(exc.value), f"应因标识符不匹配被拒：{exc.value}"

    # 正向对照：同一文本去掉换行后必须是合法资源名——失败确实来自换行本身
    good = f"resource: {json.dumps(bad.rstrip(chr(10)))}\nfields: [{{name: ok, type: string}}]\n"
    assert parse_spec_text(good, "inline").resource == bad.rstrip("\n")


# ---------------------------------------------------------------------------
# 安全边界：不暴露环境变量 / 数据库 / 密钥 / 本机路径
# ---------------------------------------------------------------------------


def test_tools_do_not_leak_env_or_secrets(monkeypatch):
    """工具输出不得包含环境变量值、数据库连接串或密钥。"""
    monkeypatch.setenv("SECRET_KEY", "TOP-SECRET-DO-NOT-LEAK")
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pw@host/db")
    monkeypatch.setenv("JWT_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")

    blob = _blob(list_resources(), describe_resource("customer"), check(),
                 validate_spec(CUSTOMER_SPEC),
                 preview_generate(CUSTOMER_SPEC.replace("label: 客户", "label: leak-check")))
    for needle in ("TOP-SECRET-DO-NOT-LEAK", "postgres://user:pw@host/db",
                   "BEGIN PRIVATE KEY"):
        assert needle not in blob, f"工具输出泄露了 {needle!r}"


def test_error_paths_and_preview_output_do_not_leak_local_paths():
    """
    所有错误路径与 preview 输出都不得含绝对路径 / HOME / 临时目录前缀。

    这不是「空转」断言：错误信息确实可能带上底层异常的绝对路径，这里逐条覆盖
    校验失败、超长、别名炸弹、隐藏资源、preview 失败与 preview 成功六类出口。
    """
    changed_spec = CUSTOMER_SPEC.replace("label: 客户", "label: 泄露检查")
    outputs = {
        "validate_invalid": _blob(validate_spec("resource: thing\nfields: []\n")),
        "validate_oversized": _blob(validate_spec("x" * (MAX_SPEC_TEXT_BYTES + 1))),
        "validate_alias_bomb": _blob(validate_spec(BILLION_LAUGHS)),
        "validate_deep": _blob(validate_spec("".join(" " * i + "k:\n" for i in range(80)) + "v: 1\n")),
        "validate_bad_type": _blob(validate_spec(b"not text")),
        "preview_invalid": _blob(preview_generate("resource: thing\nfields: []\n")),
        "preview_oversized": _blob(preview_generate("x" * (MAX_SPEC_TEXT_BYTES + 1))),
        "preview_ok": _blob(preview_generate(changed_spec)),
    }
    for name, blob in outputs.items():
        assert_no_local_paths(blob, f"{name} 输出：")
    for bad in ("no_such_resource", "../customer", "/etc/passwd"):
        try:
            describe_resource(bad)
        except ToolError as exc:
            assert_no_local_paths(str(exc), f"describe_resource({bad!r}) 错误：")
        else:  # pragma: no cover - 不应走到
            pytest.fail(f"describe_resource({bad!r}) 应抛错")


def test_preview_failure_message_is_redacted(monkeypatch):
    """preview 生成失败时，底层异常里的绝对路径必须被脱敏（而不是原样回传）。"""
    from tools.specgen import generate

    secret_path = "/Users/someone/secret/place/x.py"
    real_run = generate.run

    def boom(root, spec_dir, check=False):
        raise RuntimeError(f"cannot write {secret_path}")

    monkeypatch.setattr(generate, "run", boom)
    with pytest.raises(ToolError) as exc:
        preview_generate(CUSTOMER_SPEC)
    assert "预览生成失败" in str(exc.value)
    assert secret_path not in str(exc.value), "错误信息泄露了绝对路径"
    assert "/Users/someone" not in str(exc.value)
    assert "<path>" in str(exc.value), "应替换为占位符，而不是删掉关键信息"
    assert_no_local_paths(str(exc.value), "preview 失败错误：")

    monkeypatch.setattr(generate, "run", real_run)
    assert _redact(secret_path) == "<path>"
    assert _redact("普通中文消息") == "普通中文消息"


# ---------------------------------------------------------------------------
# 统一脱敏：list_resources / describe_resource / check 三个出口也必须脱敏
# ---------------------------------------------------------------------------


def test_redact_leaves_ordinary_slashes_alone():
    """
    兜底正则收紧的正向对照：普通含斜杠文本不得被当成路径抹掉。

    这些字符串在错误消息里很常见（类型对比、分隔符说明、URL），一旦误伤，
    脱敏就会把原因改得看不懂——「不泄露」不能靠把文本清空来实现。
    """
    for text in (
        "a/b",
        "read/write",
        "类型 string/int 不匹配",
        "foo (/bar)",
        "http://example.com/x",
        "A/B 与 C/D 对照",
        " 和/或 ",
    ):
        assert _redact(text) == text, f"普通文本被误当作路径：{text!r} -> {_redact(text)!r}"
    # 反向对照：同样一段文本里真正的绝对路径仍必须被抹掉
    assert _redact("/etc/passwd") == "<path>"
    assert _redact("/Users/someone/secret/place/x.py") == "<path>"
    assert _redact("见 /api/v1/x") == "见 <path>"
    assert _redact("C:\\Users\\x\\y.py") == "<path>"


def test_max_spec_text_bytes_has_single_definition():
    """输入上限只允许一处定义：MCP 层必须导入 schema 的常量，而不是各写一份。"""
    import tools.mcp_server as mcp_server
    import tools.specgen.schema as schema_module

    assert mcp_server.MAX_SPEC_TEXT_BYTES is schema_module.MAX_SPEC_TEXT_BYTES, (
        "MCP 层又自己定义了一份 MAX_SPEC_TEXT_BYTES；两处各写一份会悄悄漂移"
    )
    source = pathlib.Path(mcp_server.__file__).read_text(encoding="utf-8")
    assert "MAX_SPEC_TEXT_BYTES = " not in source, "MCP 层不应再出现常量的赋值定义"


def test_list_resources_error_outlet_is_redacted(tmp_path, monkeypatch):
    """
    读坏规格：把 specs/order.yaml 改成非法 YAML，`load_specs` 会在读它时抛
    `SpecError`。出口必须把它转成**脱敏后的** `ToolError`，而不是让底层异常
    原样冒到 SDK。

    再补一条「异常消息本身带绝对路径」的用例：仅靠「异常类型被包住」不能证明
    脱敏生效，得确认路径真的被换成了占位符。
    """
    import tools.mcp_server as mcp_server
    from tools.specgen import schema as schema_module

    mini = _mini_repo(tmp_path)
    (mini / "specs" / "order.yaml").write_text("resource: [unclosed\n", encoding="utf-8")
    monkeypatch.setattr(mcp_server, "ROOT", mini)

    with pytest.raises(ToolError) as exc:
        list_resources()
    assert_no_local_paths(str(exc.value), "list_resources 非法 YAML 错误：")

    # 底层 OSError 的消息带绝对路径：出口必须抹掉
    real_load_specs = schema_module.load_specs

    def boom(spec_dir, rel_dir="specs"):
        raise OSError(f"cannot list {mini}/specs: 输入/输出错误")

    monkeypatch.setattr(schema_module, "load_specs", boom)
    with pytest.raises(ToolError) as exc2:
        list_resources()
    message = str(exc2.value)
    assert "<path>" in message, f"应把绝对路径换成占位符，实际：{message}"
    assert str(mini) not in message, f"泄露了仓库绝对路径：{message}"
    assert_no_local_paths(message, "list_resources OSError 错误：")
    monkeypatch.setattr(schema_module, "load_specs", real_load_specs)


def test_describe_resource_error_outlet_is_redacted(tmp_path, monkeypatch):
    """describe_resource 出口同样脱敏：非法 YAML 与带路径的底层 OSError 各一条。"""
    import tools.mcp_server as mcp_server
    from tools.specgen import schema as schema_module

    mini = _mini_repo(tmp_path)
    (mini / "specs" / "customer.yaml").write_text("resource: [unclosed\n", encoding="utf-8")
    monkeypatch.setattr(mcp_server, "ROOT", mini)

    with pytest.raises(ToolError) as exc:
        describe_resource("customer")
    assert_no_local_paths(str(exc.value), "describe_resource 非法 YAML 错误：")

    # 底层 OSError 的消息带绝对路径时，出口必须抹掉它（而不是原样回传）
    real_load = schema_module.load_spec

    def boom(path, rel):
        raise OSError(f"cannot read {mini}/specs/customer.yaml: 输入/输出错误")

    monkeypatch.setattr(schema_module, "load_spec", boom)
    with pytest.raises(ToolError) as exc2:
        describe_resource("customer")
    message = str(exc2.value)
    assert str(mini) not in message, f"泄露了仓库绝对路径：{message}"
    assert "<path>" in message, f"应替换为占位符，实际：{message}"
    assert_no_local_paths(message, "describe_resource OSError 错误：")
    monkeypatch.setattr(schema_module, "load_spec", real_load)


def test_check_error_outlet_is_redacted(tmp_path, monkeypatch):
    """check 出口脱敏：缺接线文件时 `wiring_problems` 抛 FileNotFoundError（带绝对路径）。"""
    import tools.mcp_server as mcp_server

    mini = _mini_repo(tmp_path)
    # 迷你仓库没有 app/models/__init__.py，wiring_problems 读它会带绝对路径抛错
    (mini / "app" / "models").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(mcp_server, "ROOT", mini)

    with pytest.raises(ToolError) as exc:
        check()
    message = str(exc.value)
    assert str(mini) not in message, f"泄露了仓库绝对路径：{message}"
    assert "<path>" in message, f"应替换为占位符，实际：{message}"
    assert_no_local_paths(message, "check 错误：")


async def test_mcp_tool_layer_forwards_redacted_reason(tmp_path, monkeypatch):
    """
    MCP 工具层出口：客户端不该只看到笼统的「执行失败」。

    本模块的 `ToolError` 在 SDK 眼里属于「未预料异常」，不转换的话客户端只会收到
    ``Error executing tool <name>``，脱敏后的原因被丢掉。这里走**公开的**
    `server.call_tool()`，断言 ①原因确实到达客户端、②路径已脱敏。
    """
    pytest.importorskip("mcp")
    import tools.mcp_server as mcp_server

    mini = _mini_repo(tmp_path)
    monkeypatch.setattr(mcp_server, "ROOT", mini)

    # 用底层读取失败（消息里带绝对路径）来触发「未预料异常」分支；
    # 比 chmod 更确定——root 用户的 CI 上 chmod 000 照样能读。
    from tools.specgen import schema as schema_module

    def boom(path, rel):
        raise OSError(f"cannot read {mini}/specs/customer.yaml")

    monkeypatch.setattr(schema_module, "load_spec", boom)

    server = mcp_server.build_server()
    with pytest.raises(Exception) as exc:
        await server.call_tool("describe_resource", {"name": "customer"})
    message = str(exc.value)
    assert "describe_resource" in message, f"应带上工具名，实际：{message}"
    assert "cannot read" in message, f"应带上可读原因而不是只有「执行失败」，实际：{message}"
    assert str(mini) not in message, f"客户端收到的错误里泄露了绝对路径：{message}"
    assert_no_local_paths(message, "MCP 工具层错误：")




def test_leak_detector_itself_is_effective():
    """
    正向对照：上面那条断言本身要能转红。

    若无此用例，「不泄露路径」可能只是断言写错了却一直绿。这里喂一段确实含绝对
    路径、HOME 与临时目录名的文本，检测器必须报错。
    """
    absolute = f"预览生成失败：cannot write {ROOT}/app/generated/x.py"
    with pytest.raises(AssertionError):
        assert_no_local_paths(absolute, "自检")
    home = os.environ.get("HOME")
    if home:
        with pytest.raises(AssertionError):
            assert_no_local_paths(f"failed: {home}/x", "自检")
    with pytest.raises(AssertionError):
        assert_no_local_paths("临时目录 /tmp/specgen-preview-abc123 残留", "自检")
    # 对照：干净文本必须通过，否则上面的 raises 可能是因为「总是抛」
    assert_no_local_paths("预览生成失败：<path> 不可写", "自检")


def test_preview_temporaries_are_cleaned_up():
    """preview 用的临时目录用完即删。"""
    before = set(pathlib.Path(tempfile.gettempdir()).glob("specgen-preview-*"))
    preview_generate(CUSTOMER_SPEC.replace("label: 客户", "label: tmp-check"))
    after = set(pathlib.Path(tempfile.gettempdir()).glob("specgen-preview-*"))
    assert not (after - before), f"临时目录未清理：{after - before}"


# ---------------------------------------------------------------------------
# 对外契约：MCP 工具名必须与 docs/mcp.md 一致（只用公开 API）
# ---------------------------------------------------------------------------


async def test_registered_tool_names_match_documented_contract():
    """注册给客户端的工具名须是文档里那五个，不能带 _tool 后缀。"""
    pytest.importorskip("mcp")
    from tools.mcp_server import build_server

    server = build_server()
    tools = await server.list_tools()  # 公开 API（不依赖私有的 _tool_manager）
    assert {t.name for t in tools} == {
        "list_resources",
        "describe_resource",
        "validate_spec",
        "preview_generate",
        "check",
    }, f"工具名与 docs/mcp.md 契约不符：{sorted(t.name for t in tools)}"


def test_stdio_handshake_lists_tools():
    """
    真实 stdio 冒烟：起子进程，发 initialize 与 tools/list，校验返回。

    覆盖「进程能起来、协议能握手、工具确实注册到线上」——单元测试用内存对象
    跑不出这一段。

    读响应**必须带超时**：`proc.stdout.readline()` 在服务端挂起时不会返回，
    整个测试会一直卡到 CI 的 job 超时（表现为「卡死」而不是「失败」）。这里用
    读线程 + 队列超时，超时即判失败并带上 stderr 摘要。
    """
    pytest.importorskip("mcp")
    proc = subprocess.Popen(
        [sys.executable, "-m", "tools.mcp_server", "--root", str(ROOT)],
        cwd=str(ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        lines: "queue.Queue[str | None]" = queue.Queue()

        def _pump():
            """把 stdout 的每一行推进队列；EOF 时放一个 None 表示「服务端关闭」。"""
            try:
                for line in proc.stdout:
                    lines.put(line)
            finally:
                lines.put(None)

        reader = threading.Thread(target=_pump, daemon=True)
        reader.start()

        def send(payload):
            proc.stdin.write(json.dumps(payload) + "\n")
            proc.stdin.flush()

        def recv(timeout: float = STDIO_TIMEOUT_SECS):
            try:
                line = lines.get(timeout=timeout)
            except queue.Empty:
                raise AssertionError(
                    f"服务端 {timeout}s 内没有响应（疑似挂起）；stderr={_drain_stderr(proc)[:2000]}"
                ) from None
            assert line is not None, f"服务端提前关闭了 stdout；stderr={_drain_stderr(proc)[:2000]}"
            return json.loads(line)

        send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke", "version": "0"},
            },
        })
        init = recv()
        assert init["id"] == 1 and "result" in init, init
        assert init["result"]["serverInfo"]["name"] == "sanic-admin-specgen"

        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listed = recv()
        assert listed["id"] == 2 and "result" in listed, listed
        names = {t["name"] for t in listed["result"]["tools"]}
        assert names == {
            "list_resources", "describe_resource", "validate_spec",
            "preview_generate", "check",
        }, sorted(names)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - 兜底
            proc.kill()
            proc.wait()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()
            except Exception:  # noqa: BLE001
                pass


def test_stdio_reader_times_out_on_silent_server():
    """
    正向对照：上面的超时机制本身要能转红。

    起一个「握手后什么都不回」的假服务端，`recv()` 必须在超时后判失败，而不是
    一直阻塞——否则「改成线程+超时」只是看起来改了，实际上照样会挂死 CI。
    """
    silent = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        lines: "queue.Queue[str | None]" = queue.Queue()

        def _pump():
            try:
                for line in silent.stdout:
                    lines.put(line)
            finally:
                lines.put(None)

        threading.Thread(target=_pump, daemon=True).start()

        def recv(timeout):
            try:
                line = lines.get(timeout=timeout)
            except queue.Empty:
                raise AssertionError("服务端没有响应") from None
            return line

        started = time.monotonic()
        with pytest.raises(AssertionError):
            recv(timeout=0.3)
        elapsed = time.monotonic() - started
        assert elapsed < 5, f"超时机制没生效，实际等了 {elapsed:.1f}s"
    finally:
        silent.terminate()
        try:
            silent.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            silent.kill()
            silent.wait()
        for stream in (silent.stdin, silent.stdout, silent.stderr):
            try:
                stream.close()
            except Exception:  # noqa: BLE001
                pass



# ---------------------------------------------------------------------------
# 测试辅助：迷你仓库（快照范围的用例需要可控的目录树）
# ---------------------------------------------------------------------------


def _mini_repo(tmp_path) -> pathlib.Path:
    """复制一份只含快照相关文件的迷你仓库，供 monkeypatch ROOT 使用。"""
    mini = tmp_path / "repo"
    for rel in ("specs", "amis/pages", "app/generated", "tests/generated"):
        shutil.copytree(ROOT / rel, mini / rel)
    (mini / "app/auth").mkdir(parents=True)
    shutil.copy(ROOT / "app/auth/permissions.py", mini / "app/auth/permissions.py")
    return mini
