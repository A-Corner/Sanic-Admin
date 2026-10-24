#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
MCP 写入工具（M2 第二段）。**默认不注册**，只有显式 ``--allow-write`` 才暴露。

设计见 ``docs/mcp-write-path.md``。三个工具：

- ``propose_spec_change``：在隔离 clone 里提交规格变更，把分支 fetch 回用户仓库
- ``list_proposals``：列出 ``proposal/`` 前缀的分支
- ``discard_proposal``：删除提案分支

## 为什么默认关闭

MCP 是 stdio 本地进程，**没有账户体系**——它不知道「谁」在调用。在这种前提下
默认暴露写能力，等于任何能拉起这个进程的东西都能写分支。所以写入工具必须由
启动方显式打开：不加 ``--allow-write``，它们连 ``tools/list`` 都不出现。

## 审计

每次调用（成功或失败）都往 **stderr** 写一行结构化 JSON。项目里的
``OperationLog`` 依赖数据库连接，MCP 侧不该为此强依赖一个运行中的服务——
stderr 由启动方捕获即可，`journalctl` / 重定向 / 父进程都能拿到。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.mcp_server.git_isolation import (
    DEFAULT_BASE_REF,
    PROPOSAL_PREFIX,
    GitNotAllowed,
    branch_exists,
    discard_proposal,
    list_proposal_branches,
    make_branch_name,
    make_proposal,
    validate_base_ref,
)

#: 写入工具名的集合，供 tools/list 断言与文档引用。
WRITE_TOOL_NAMES = frozenset(
    {
        "propose_spec_change",
        "list_proposals",
        "discard_proposal",
    }
)


def _audit(operation: str, *, status: str, detail: Dict[str, Any]) -> bool:
    """
    往 stderr 写一行结构化审计。**永不抛出**——审计失败不能拖垮主流程。

    刻意不写规格全文：规格里可能有业务敏感的字段定义。只写资源名、
    分支名、commit、diff 统计这类元数据。

    Returns:
        True 表示确实写出去了；False 表示写入失败（stderr 被关、编码异常等）。
        调用方据此决定是否在返回值里报 ``audit_written: false``——不能像早期
        版本那样恒为 True。那会让调用方以为审计成功，实际什么都没记。
    """
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "channel": "mcp-audit",
        "operation": operation,
        "operation_type": "mcp",
        "status": status,
        **detail,
    }
    try:
        print(json.dumps(record, ensure_ascii=False), file=sys.stderr, flush=True)
        return True
    except Exception:
        # 审计是旁路。stderr 被关掉、编码异常都不该影响提案结果。
        return False


def _resolve_commit(repo_root: Path, ref: str) -> str:
    """把 ref 解析成完整 commit SHA。失败返回空串（不影响提案结果）。"""
    try:
        from tools.mcp_server.git_isolation import _git

        return _git(["rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo_root).strip()
    except Exception:
        return ""


def propose_spec_change(
    resource: str,
    spec_yaml: str,
    *,
    note: str = "",
    base_ref: Optional[str] = None,
    repo_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    提交一次规格变更，返回提案分支与 diff。**不 push、不合并。**

    Args:
        resource: 资源名（小写字母开头，仅小写字母/数字/下划线）
        spec_yaml: 完整规格 YAML 文本
        note: 可选说明，进 commit message 与返回值；不参与 shell 拼接
        base_ref: 起点 ref，默认 ``master``（不取 HEAD，见设计 §9）
        repo_root: 仓库根，缺省用 MCP 服务配置的 ROOT

    Returns:
        ``{"proposal_id", "branch", "commit", "base_ref", "diff_stat", "diff",
           "next_step", "audit_written"}``
    """
    from tools.mcp_server import (
        _guard_resource_name,
        _guard_spec_text,
        _repo_root,
        validate_spec,
    )
    from tools.mcp_server.identity import IdentityError, require_spec_write

    root = (repo_root or _repo_root()).resolve()
    detail: Dict[str, Any] = {}
    try:
        # 身份校验最先执行（SA-v042-SPECWRITE）：任何失败都在建 clone、建分支
        # 之前发生——零副作用。审计记 reason 与账户（成功时），不含 token。
        account_id = require_spec_write()
        _guard_resource_name(resource)
        _guard_spec_text(spec_yaml)
        base = validate_base_ref(root, base_ref or DEFAULT_BASE_REF)

        # 先校验规格：不合法就**不产生任何分支**，连 clone 都不建
        verdict = validate_spec(spec_yaml)
        if not verdict.get("ok", False):
            _audit(
                "propose_spec_change",
                status="failure",
                detail={"resource": resource, "reason": "spec_invalid", "base_ref": base},
            )
            raise GitNotAllowed(f"规格校验未通过：{verdict.get('errors') or verdict}")

        branch = make_branch_name(resource)
        if branch_exists(root, branch):
            # 理论上 timestamp 精确到秒不会撞，但分支已存在时绝不覆盖。
            _audit(
                "propose_spec_change",
                status="failure",
                detail={"resource": resource, "reason": "branch_exists", "branch": branch},
            )
            raise GitNotAllowed(f"分支已存在，拒绝覆盖：{branch}")

        # Proposed-by 行：审计时能一眼区分「工具提案」与「人的提交」，
        # 不依赖 git author 字段（author 可能被 clone 配置覆盖）。
        message = f"proposal: {resource}" + (f" — {note}" if note else "")
        message += "\n\nProposed-by: MCP propose_spec_change"

        def _write(clone_dir: Path) -> None:
            specs = clone_dir / "specs"
            specs.mkdir(parents=True, exist_ok=True)
            (specs / f"{resource}.yaml").write_text(spec_yaml, encoding="utf-8")

        result = make_proposal(root, branch, message, _write, base_ref=base)
        # base_commit：人需要它来判断「这个提案基于哪个提交」，做冲突排查
        base_commit = _resolve_commit(root, base)
        detail = {
            "resource": resource,
            "branch": result["branch"],
            "commit": result["commit"],
            "base_ref": base,
            "base_commit": base_commit,
            "account_id": account_id,
        }
        audit_ok = _audit("propose_spec_change", status="success", detail=detail)

        return {
            "proposal_id": result["branch"],
            "branch": result["branch"],
            "commit": result["commit"],
            "base_ref": base,
            "base_commit": base_commit,
            "diff_stat": result["diff_stat"],
            "diff": result["diff"],
            "next_step": "由人执行 git push 并开 PR；本工具不会 push，也不会合并。",
            "audit_written": audit_ok,
        }
    except IdentityError as exc:
        if not detail:
            _audit("propose_spec_change", status="failure", detail={"resource": resource, "reason": exc.reason})
        raise
    except Exception as exc:
        if not detail:
            _audit("propose_spec_change", status="failure", detail={"resource": resource, "reason": type(exc).__name__})
        raise


def list_proposals(*, repo_root: Optional[Path] = None) -> List[Dict[str, Any]]:
    """列出提案分支（``proposal/`` 前缀）。只读，但同样要求 ``spec:write``
    （CPL 裁定：三个写入工具粒度一致，且提案内容不应向无权限方暴露）。"""
    from tools.mcp_server import _repo_root
    from tools.mcp_server.identity import IdentityError, require_spec_write

    root = (repo_root or _repo_root()).resolve()
    try:
        account_id = require_spec_write()
        items = list_proposal_branches(root)
    except IdentityError as exc:
        _audit("list_proposals", status="failure", detail={"reason": exc.reason})
        raise
    except Exception as exc:
        _audit("list_proposals", status="failure", detail={"reason": type(exc).__name__})
        raise
    _audit("list_proposals", status="success", detail={"count": len(items), "account_id": account_id})
    return items


def discard_proposal_tool(branch: str, *, force: bool = False, repo_root: Optional[Path] = None) -> Dict[str, Any]:
    """删除提案分支。只允许 ``proposal/`` 前缀。"""
    from tools.mcp_server import _repo_root
    from tools.mcp_server.identity import IdentityError, require_spec_write

    root = (repo_root or _repo_root()).resolve()
    try:
        account_id = require_spec_write()
        discard_proposal(root, branch, force=force)
    except IdentityError as exc:
        _audit("discard_proposal", status="failure", detail={"branch": branch, "reason": exc.reason})
        raise
    except Exception as exc:
        _audit("discard_proposal", status="failure", detail={"branch": branch, "reason": type(exc).__name__})
        raise
    audit_ok = _audit(
        "discard_proposal", status="success", detail={"branch": branch, "force": force, "account_id": account_id}
    )
    return {"discarded": branch, "force": force, "audit_written": audit_ok}


def register_write_tools(server) -> None:
    """
    把三个写入工具注册到 MCP server。**只应在 --allow-write 时调用。**

    每个 handler 都过 ``_mcp_tool``，与只读工具一致地把异常转成脱敏后的
    SDK ToolError。
    """
    from tools.mcp_server import _mcp_tool

    @server.tool(
        name="propose_spec_change",
        description=(
            "提交规格变更：在隔离 clone 中生成 diff 并提交到 proposal/ 分支，"
            "再 fetch 回本地仓库。不会 push，也不会合并——下一步由人执行。"
        ),
    )
    @_mcp_tool
    def propose_spec_change_tool(resource: str, spec_yaml: str, note: str = "", base_ref: str = "") -> Dict[str, Any]:
        """resource 为资源名；spec_yaml 为完整规格 YAML；base_ref 留空则用 master。"""
        return propose_spec_change(resource, spec_yaml, note=note, base_ref=base_ref or None)

    @server.tool(
        name="list_proposals",
        description="列出本地 proposal/ 前缀的提案分支。只读；每次调用需有效会话且账户拥有 spec:write 权限。",
    )
    @_mcp_tool
    def list_proposals_tool() -> List[Dict[str, Any]]:
        return list_proposals()

    @server.tool(
        name="discard_proposal",
        description="删除一个提案分支（仅 proposal/ 前缀）。",
    )
    @_mcp_tool
    def discard_proposal_handler(branch: str, force: bool = False) -> Dict[str, Any]:
        """branch 必须是 proposal/ 开头；force=True 才删有未合并提交的分支。"""
        return discard_proposal_tool(branch, force=force)
