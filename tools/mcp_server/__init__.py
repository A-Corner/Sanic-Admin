#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Sanic-Admin 规格即代码 MCP 服务（M2 第一段：只读与预演层）。

设计原则（见 docs/release/v0.4.0-iteration-plan.md §5 与 v04-s0.md）：

- **AI 只改规格、只出 diff**：本层所有工具都不写仓库文件。把改动交给人看，
  走 PR + 独立审核，而不是让 AI 直接改运行时。
- **只读**：`list_resources` / `describe_resource` / `validate_spec` /
  `preview_generate` / `check` 全部不落盘（`preview_generate` 只在临时目录生成，
  用完即删，并复核仓库文件哈希未变）。哈希快照是**事后检测**：只负责发现改动，
  不负责阻止写入；真正的只读保障是实现本身只在临时目录生成。
- **输入上限**：spec 文本 64KB；YAML 拒绝锚点/别名（防 billion laughs）并限制
  嵌套深度（`tools.specgen.schema.SpecLoader`）。
- **白名单**：资源名必须匹配 `^[a-z][a-z0-9_]*$`，不接受路径分隔符、`..`、
  绝对路径——防止经资源名做路径穿越。
- **不暴露**环境变量、数据库连接与密钥：工具只回规格与生成物本身。

传输：stdio（Claude Code / Codex 以子进程方式拉起）。

用法：
    python -m tools.mcp_server                 # 在当前仓库上运行
    python -m tools.mcp_server --root /path    # 指定仓库根
"""

from __future__ import annotations

import difflib
import functools
import hashlib
import logging
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.specgen.schema import MAX_SPEC_TEXT_BYTES

#: 资源名白名单：小写字母开头，仅小写字母/数字/下划线。
#: 显式拒绝路径分隔符与 '..'，避免经资源名做路径穿越。
RESOURCE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")

#: 仓库根（可用 --root 覆盖，见 main()）
ROOT = Path(__file__).resolve().parent.parent.parent

# 输入上限 ``MAX_SPEC_TEXT_BYTES`` 只有一处定义：``tools.specgen.schema``
# （解析器与 MCP 入口共用同一常量，避免两处各写一份后悄悄漂移）。


class ToolError(Exception):
    """工具层可安全展示给调用方的错误（不含路径/环境/密钥细节）。"""


def _redact(text: str) -> str:
    """
    把错误文本里的本机路径抹掉，再回给调用方。

    `ToolError` 的契约是「可安全展示」，但底层异常（生成器、临时目录、HOME）
    常把绝对路径带进消息。这里统一替换成占位符，避免泄露目录结构。
    """
    out = str(text)
    replacements = [str(_repo_root().resolve()), str(_repo_root())]
    for var in ("HOME", "TMPDIR", "TEMP", "TMP"):
        val = os.environ.get(var)
        if val:
            replacements.append(val)
    # MCP 会话 token（SA-v042-SPECWRITE）：即便结构性不打印之外出现意外路径
    # （第三方库把 env 值带进异常消息等），出口处再抹一道。
    try:
        from tools.mcp_server.identity import get_token

        _token = get_token()
        if _token:
            replacements.append(_token)
    except Exception:  # noqa: BLE001  身份模块不可用时跳过，不影响路径脱敏
        pass
    try:
        replacements.append(str(Path(tempfile.gettempdir()).resolve()))
    except (OSError, RuntimeError):
        pass
    # 长的先换，避免 /tmp 先把 /tmp/xxx 换掉一半
    for needle in sorted({r for r in replacements if r}, key=len, reverse=True):
        out = out.replace(needle, "<path>")
    # 兜底：仍残留的绝对路径（POSIX 与 Windows 盘符）整段抹掉。
    # POSIX 规则收紧为「至少两段」，并排除前面紧挨 `:`、`/`、`.` 的情况：
    # 既能抓住 `/Users/x/y`、`/etc/passwd` 这类真实泄露，又不会把正文里普通的
    # 含斜杠文本（`string/int`、`a/b`、`foo (/bar)`、`http://host/x`）当成路径。
    out = _ABS_POSIX_PATH_RE.sub("<path>", out)
    out = _ABS_WINDOWS_PATH_RE.sub("<path>", out)
    return out


#: 兜底用的绝对路径正则（见 :func:`_redact`）。
#: POSIX 侧要求**至少两段**（`/a/b`），这既是真实路径的常态（`/etc/passwd`、
#: `/Users/x/y.py`），也能避免把正文里普通的含斜杠文本（`a/b`、`foo (/bar)`）
#: 误判成路径；单段绝对路径由 `_redact` 前面的「已知前缀替换」覆盖。
_ABS_POSIX_PATH_RE = re.compile(r"(?<![\w.<:/>])/(?:[\w.\-]+/)+[\w.\-]+")
_ABS_WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[\w.\-]+\\)*[\w.\-]+")

#: 工具层统一出口日志（脱敏只会影响回给调用方的文本，服务端仍保留完整栈）
_log = logging.getLogger(__name__)


def _redact_errors(fn):
    """
    MCP 工具层统一出口：任何异常先脱敏，再回给调用方。

    `docs/mcp.md` 承诺「错误信息里的本机绝对路径、HOME 与临时目录前缀统一脱敏」。
    这条契约必须落在**所有**工具出口上，而不只是 `validate_spec` /
    `preview_generate` 自己 catch 到的那几条：`list_resources`、`describe_resource`、
    `check` 会让底层异常（读文件失败、YAML 解析、生成器）直接冒到 SDK，而
    `FileNotFoundError` / `IsADirectoryError` 的消息里带着绝对路径。

    做法：`ToolError` 也会过一遍 ``_redact``（历史上就有底层异常被包装成 ToolError
    时夹带路径的情况），其余异常记一条服务端日志后转成脱敏过的 `ToolError`——
    调用方拿到可读原因，本机路径不外泄。
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ToolError as exc:
            safe = _redact(exc)
            if safe == str(exc):
                raise
            raise ToolError(safe) from None
        except Exception as exc:  # noqa: BLE001  兜底：任何未预料的异常都要脱敏
            _log.exception("工具 %s 执行失败", getattr(fn, "__name__", "?"))
            raise ToolError(f"{getattr(fn, '__name__', '工具')} 执行失败：{_redact(exc)}") from None

    return wrapper


def _mcp_tool(fn):
    """
    MCP 注册层的出口包装：把「已脱敏的 ToolError」转成 SDK 的 `ToolError`。

    不这么做的话，本模块自己的 `ToolError` 在 SDK 眼里是**未预料异常**，客户端只会
    收到一句 ``Error executing tool <name>``，真实原因被丢掉。转换后，客户端拿到的
    是脱敏后的可读原因，而 SDK 也不会把它当崩溃记 `logger.exception`。

    `mcp` 只在真正起服务时才会 import，因此这里延迟导入，保证无 mcp 环境
    （如只跑纯单元测试）仍可 import 本模块。
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        from mcp.server.mcpserver.exceptions import ToolError as MCPToolError

        try:
            return fn(*args, **kwargs)
        except MCPToolError:
            raise
        except ToolError as exc:
            raise MCPToolError(_redact(exc)) from None

    return wrapper


def _repo_root() -> Path:
    return ROOT


def _specs_dir() -> Path:
    return _repo_root() / "specs"


def _guard_spec_text(yaml_text: Any) -> str:
    """
    校验 spec 文本入口（长度上限）。**在进入 YAML 解析器之前**执行。

    别名炸弹（billion laughs）在解析期才会爆炸，因此长度上限只能挡住「体积大」
    的一类；锚点/别名与嵌套深度由 ``tools.specgen.schema.SpecLoader`` 拒绝。
    """
    if not isinstance(yaml_text, str):
        raise ToolError(f"规格必须是文本，实际 {type(yaml_text).__name__}")
    size = len(yaml_text.encode("utf-8"))
    if size > MAX_SPEC_TEXT_BYTES:
        raise ToolError(f"规格文本超过上限 {MAX_SPEC_TEXT_BYTES} 字节（实际 {size}）")
    return yaml_text


def _guard_resource_name(name: str) -> str:
    """资源名白名单校验（防路径穿越）。"""
    if not isinstance(name, str) or not name:
        raise ToolError("资源名不能为空")
    if ".." in name or "/" in name or "\\" in name or os.path.isabs(name):
        raise ToolError(f"资源名不合法：{name!r}（不允许路径分隔符、'..' 或绝对路径）")
    if not RESOURCE_NAME_RE.fullmatch(name):
        raise ToolError(f"资源名不合法：{name!r}（必须匹配 {RESOURCE_NAME_RE.pattern}）")
    return name


def _spec_path(name: str) -> Path:
    """拼出规格文件路径，并复核它确实落在 specs/ 之内。"""
    _guard_resource_name(name)
    specs = _specs_dir().resolve()
    candidate = (specs / f"{name}.yaml").resolve()
    try:
        candidate.relative_to(specs)
    except ValueError:
        raise ToolError(f"资源名不合法：{name!r}（解析后越出 specs/ 目录）") from None
    return candidate


def _generated_paths(name: str) -> Dict[str, str]:
    """返回该资源对应生成物的仓库相对路径（只列存在与否，不读内容）。"""
    root = _repo_root()
    candidates = {
        "model": f"app/generated/models/{name}.py",
        "resource": f"app/generated/resources/{name}.py",
        "amis_page": f"amis/pages/{name}-list.json",
        "test": f"tests/generated/test_gen_{name}.py",
    }
    return {kind: rel for kind, rel in candidates.items() if (root / rel).exists()}


# ---------------------------------------------------------------------------
# 工具实现（每个都只读）
# ---------------------------------------------------------------------------


@_redact_errors
def list_resources() -> List[Dict[str, Any]]:
    """列出 specs/ 下全部资源规格及其字段摘要。只读。"""
    from tools.specgen.schema import load_specs

    specs_dir = _specs_dir()
    if not specs_dir.is_dir():
        raise ToolError("仓库里没有 specs/ 目录")

    specs = load_specs(specs_dir, "specs")
    out: List[Dict[str, Any]] = []
    for name in sorted(specs):
        spec = specs[name]
        out.append(
            {
                "resource": spec.resource,
                "label": spec.label,
                "plural": spec.plural,
                "field_count": len(spec.fields),
                "fields": [
                    {
                        "name": f.name,
                        "type": f.type,
                        "required": f.required,
                        "unique": f.unique,
                    }
                    for f in spec.fields
                ],
                "belongs_to": [{"target": b.target, "column": b.column} for b in spec.belongs_to],
                "soft_delete": spec.soft_delete,
                "sorting_allowed": list(spec.sorting.allowed),
            }
        )
    return out


@_redact_errors
def describe_resource(name: str) -> Dict[str, Any]:
    """返回某资源的规格全文、生成物路径与权限点。只读。"""
    from tools.specgen.schema import load_spec

    path = _spec_path(name)
    if not path.is_file():
        raise ToolError(f"规格不存在：{name}")

    spec = load_spec(path, "specs")
    yaml_text = path.read_text(encoding="utf-8")
    return {
        "resource": spec.resource,
        "label": spec.label,
        "plural": spec.plural,
        "spec_path": f"specs/{name}.yaml",
        "spec_yaml": yaml_text,
        "generated": _generated_paths(name),
        "permissions": [f"{spec.resource}:{a}" for a in spec.permissions.actions],
    }


@_redact_errors
def validate_spec(yaml_text: str) -> Dict[str, Any]:
    """用 pydantic 校验规格文本，返回带字段路径的错误。不落盘。"""
    from tools.specgen.schema import SpecError, parse_spec_text

    try:
        text = _guard_spec_text(yaml_text)
        spec = parse_spec_text(text, "inline")
    except ToolError as exc:
        return {"ok": False, "errors": [{"path": "<root>", "reason": _redact(exc)}]}
    except SpecError as exc:
        return {
            "ok": False,
            "errors": [{"path": path, "reason": _redact(reason)} for path, reason in exc.errors],
        }
    except Exception as exc:  # noqa: BLE001  解析期异常也按校验失败回，不暴露堆栈
        return {"ok": False, "errors": [{"path": "", "reason": _redact(exc)}]}
    return {"ok": True, "resource": spec.resource, "field_count": len(spec.fields)}


#: 快照要覆盖的仓库文件（glob，相对仓库根）。
#: 不限于「生成物」：规格源、AMIS 站点菜单、权限点定义、生成包的 __init__ 都在
#: 生成链路里被读或被写，漏掉任何一类都会让「仓库未被改动」的复核形同虚设。
SNAPSHOT_GLOBS = (
    "specs/*.yaml",
    "app/generated/models/*.py",
    "app/generated/resources/*.py",
    "app/generated/*.py",
    "tests/generated/*.py",
    "amis/pages/*-list.json",
    "amis/pages/site.json",
    "app/auth/permissions.py",
)


def _file_digest(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _repo_digest_snapshot() -> Dict[str, str]:
    """
    当前仓库相关文件的 sha256 快照（用于 preview 前后对照）。

    这是**事后检测**：它只能发现「已经发生的改动」，不能阻止写入。真正的只读
    保障是实现本身（生成全部发生在临时目录）；快照是兜底的正向对照。
    """
    root = _repo_root()
    digests: Dict[str, str] = {}
    for pattern in SNAPSHOT_GLOBS:
        for p in sorted(root.glob(pattern)):
            if p.is_file():
                digests[p.relative_to(root).as_posix()] = _file_digest(p)
    return digests


@_redact_errors
def preview_generate(yaml_text: str) -> Dict[str, Any]:
    """
    在临时目录里生成，返回与当前仓库生成物的 unified diff。**不写仓库。**

    安全措施：临时目录位于系统临时区、用后删除；返回前复核仓库生成物哈希未变
    （正向对照：若实现误写仓库，这里会抛错而不是静默通过）。
    """
    from tools.specgen import generate
    from tools.specgen.schema import SpecError, parse_spec_text

    try:
        text = _guard_spec_text(yaml_text)
        parsed = parse_spec_text(text, "inline")
    except ToolError as exc:
        return {"ok": False, "errors": [{"path": "<root>", "reason": _redact(exc)}]}
    except SpecError as exc:
        return {
            "ok": False,
            "errors": [{"path": path, "reason": _redact(reason)} for path, reason in exc.errors],
        }

    before = _repo_digest_snapshot()
    tmp_root = Path(tempfile.mkdtemp(prefix="specgen-preview-"))
    try:
        # 在临时根下铺一份最小骨架：specs/ + 生成器需要读取的现有生成物目录
        (tmp_root / "specs").mkdir(parents=True, exist_ok=True)
        for sub in ("app/generated/models", "app/generated/resources", "tests/generated", "amis/pages"):
            (tmp_root / sub).mkdir(parents=True, exist_ok=True)
        # 生成器渲染菜单时会读 amis/pages/site.json：把仓库现有版本作为基线复制过去，
        # 让 diff 只反映本次规格带来的变化（临时目录内操作，不碰仓库）
        # 同理复制当前生成物作为基线：diff 只体现本次规格的增量，
        # 而不是「从零开始」的全量内容（那些文件本次并未改变）
        for rel in (
            "amis/pages/site.json",
            "app/generated/__init__.py",
            "app/generated/permissions.py",
            "app/generated/models/__init__.py",
            "app/generated/resources/__init__.py",
        ):
            src = _repo_root() / rel
            if src.is_file():
                dst = tmp_root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        # 先复制仓库现有全部规格，再用待预览的文本覆盖对应资源：
        # 否则生成器会以为其它资源不存在，产出「删除其它资源」的误导性 diff。
        specs_src = _specs_dir()
        for src in sorted(specs_src.glob("*.yaml")):
            shutil.copy2(src, tmp_root / "specs" / src.name)
        spec_file = f"{parsed.resource}.yaml"
        (tmp_root / "specs" / spec_file).write_text(text, encoding="utf-8")
        try:
            changed, _stale = generate.run(tmp_root, tmp_root / "specs", check=False)
        except Exception as exc:  # noqa: BLE001
            # 不直接 str(exc)：底层异常常带临时目录/仓库绝对路径
            raise ToolError(f"预览生成失败：{_redact(exc)}") from None

        diffs: List[str] = []
        for rel in changed:
            new_text = (tmp_root / rel).read_text(encoding="utf-8")
            repo_file = _repo_root() / rel
            old_text = repo_file.read_text(encoding="utf-8") if repo_file.is_file() else ""
            diff = difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a/{rel}" if old_text else "/dev/null",
                tofile=f"b/{rel}",
            )
            diffs.append("".join(diff))
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    after = _repo_digest_snapshot()
    if before != after:
        # 正向对照：preview 绝不允许写仓库；一旦写入立即报错而非静默通过。
        # 这是**事后检测**（只能发现、不能阻止），真正的保障是「只在临时目录生成」。
        changed_paths = sorted({p for p in before.keys() | after.keys() if before.get(p) != after.get(p)})
        raise ToolError(f"内部错误：preview 修改了仓库文件，已中止（{', '.join(changed_paths)}）")

    return {
        "ok": True,
        "changed_files": list(changed),
        "diff": "\n".join(d for d in diffs if d),
        "repo_unchanged": True,
    }


@_redact_errors
def check() -> Dict[str, Any]:
    """等价于 `python -m tools.specgen check`：生成物与规格是否一致。只读。"""
    from tools.specgen import generate

    root = _repo_root()
    problems = generate.wiring_problems(root)
    if problems:
        return {"ok": False, "problems": problems}
    changed, stale = generate.run(root, _specs_dir(), check=True)
    return {
        "ok": not (changed or stale),
        "drift": list(changed),
        "stale": list(stale),
    }


# ---------------------------------------------------------------------------
# MCP 服务装配
# ---------------------------------------------------------------------------


#: 是否允许注册写入工具。由 ``--allow-write`` 启动参数置位，见 ``main()``。
#:
#: MCP 是 stdio 本地进程、没有账户体系，默认暴露写能力等于「谁能拉起进程谁就能写」。
#: 因此写入工具默认完全不注册——不加这个参数，``tools/list`` 里根本看不到它们。
ALLOW_WRITE = False


def build_server(allow_write: bool = False):
    """构建 MCP 服务（stdio）。默认只读；``allow_write=True`` 时追加写入工具。"""
    from mcp.server.mcpserver import MCPServer

    if allow_write:
        title = "Sanic-Admin 规格生成器（只读 + 提案写入）"
        description = (
            "读取/校验/预演资源规格，并可把规格变更提交到本地 proposal/ 分支，由人开 PR 与合并；不 push，不改运行时。"
        )
        instructions = (
            "本服务可用 propose_spec_change 产出提案分支与 diff，但**不会 push、不会合并**——下一步必须由人执行。"
            "写入工具每次调用需有效会话 JWT（环境变量 SANIC_ADMIN_MCP_TOKEN）且账户拥有 spec:write 权限。其余工具只读。"
        )
    else:
        title = "Sanic-Admin 规格生成器（只读）"
        description = "读取/校验/预演资源规格，输出 diff 供人工确认；不写仓库。"
        instructions = (
            "本服务只读：不会修改仓库任何文件。改动请通过 validate_spec / preview_generate 取得 diff，再走 PR 与独立审核。"
        )

    server = MCPServer(
        name="sanic-admin-specgen",
        title=title,
        description=description,
        instructions=instructions,
    )

    # 显式给 name=：否则 SDK 以函数名注册，客户端看到的会是 list_resources_tool，
    # 与 docs/mcp.md 的工具契约不符。
    # 每个 handler 都过一层 `_mcp_tool`：把本模块的 ToolError 转成 SDK 的
    # ToolError，客户端才能收到脱敏后的**原因**而不是笼统的「执行失败」。
    @server.tool(name="list_resources", description="列出 specs/ 下的资源规格与字段摘要（只读）。")
    @_mcp_tool
    def list_resources_tool() -> List[Dict[str, Any]]:
        return list_resources()

    @server.tool(name="describe_resource", description="返回指定资源的规格全文、生成物路径与权限点（只读）。")
    @_mcp_tool
    def describe_resource_tool(name: str) -> Dict[str, Any]:
        """资源名仅允许小写字母、数字与下划线。"""
        return describe_resource(name)

    @server.tool(name="validate_spec", description="校验规格文本（pydantic），返回带字段路径的错误；不落盘。")
    @_mcp_tool
    def validate_spec_tool(yaml_text: str) -> Dict[str, Any]:
        """yaml_text 为完整的规格 YAML 文本。"""
        return validate_spec(yaml_text)

    @server.tool(name="preview_generate", description="在临时目录生成并返回与仓库现状的 unified diff；不写仓库。")
    @_mcp_tool
    def preview_generate_tool(yaml_text: str) -> Dict[str, Any]:
        """yaml_text 为完整的规格 YAML 文本。"""
        return preview_generate(yaml_text)

    @server.tool(name="check", description="检查生成物与规格是否一致（等价 specgen check）。")
    @_mcp_tool
    def check_tool() -> Dict[str, Any]:
        return check()

    if allow_write:
        # 写入工具只在显式开启时注册；不开启时工具列表里没有它们。
        from tools.mcp_server.write_tools import register_write_tools

        register_write_tools(server)

    return server


def main(argv: List[str] | None = None) -> int:
    global ROOT, ALLOW_WRITE
    args = list(sys.argv[1:] if argv is None else argv)

    # --allow-write：显式开启写入工具。默认关闭——不加这个参数，
    # propose_spec_change / list_proposals / discard_proposal 不会出现在工具列表里。
    allow_write = False
    if "--allow-write" in args:
        args.remove("--allow-write")
        allow_write = True

    if "--root" in args:
        i = args.index("--root")
        if i + 1 >= len(args):
            print("--root 需要一个路径参数", file=sys.stderr)
            return 2
        ROOT = Path(args[i + 1]).resolve()
        del args[i : i + 2]
    if not (_specs_dir()).is_dir():
        print(f"未找到 specs/ 目录：{_specs_dir()}", file=sys.stderr)
        return 2

    ALLOW_WRITE = allow_write
    # 启动时清理过期临时目录。**只在开启写入模式时做**——只读模式根本不会
    # 产生临时工作区，不需要有删除动作。
    if allow_write:
        try:
            from tools.mcp_server.proposal_registry import cleanup_stale_workspaces

            removed = cleanup_stale_workspaces()
            if removed:
                print(f"已清理 {len(removed)} 个过期临时工作区。", file=sys.stderr)
        except Exception:
            # 清理是旁路：失败不能阻止服务启动
            logging.getLogger(__name__).warning("清理过期临时工作区失败（已忽略）", exc_info=True)
        print(
            "MCP 写入工具已启用（propose_spec_change / list_proposals / discard_proposal）；仍不会 push 或合并。",
            file=sys.stderr,
        )
        # AND 矩阵（docs/mcp-write-path.md §10.6）：--allow-write 是注册门槛，
        # 身份是调用门槛。token 缺失时写入工具仍注册（tools/list 可见、报错可引导），
        # 但每次调用都会被 identity.require_spec_write 以
        # identity_not_configured 拒绝——fail-closed。
        from tools.mcp_server.identity import TOKEN_ENV, get_token

        if get_token():
            print(
                "MCP 写入工具已启用（propose_spec_change / list_proposals / "
                "discard_proposal）；每次调用将经 whoami 校验 spec:write；"
                "仍不会 push 或合并。",
                file=sys.stderr,
            )
        else:
            print(
                f"MCP 写入工具已启用，但未配置 {TOKEN_ENV}（会话 JWT）：写入工具可见，调用会被拒绝。配置后重启本进程。",
                file=sys.stderr,
            )

    server = build_server(allow_write=allow_write)
    server.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
